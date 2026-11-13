//! Packaged config, command, cancellation and shutdown acceptance (V03 groups 2/3/7/9).
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use indoc::{formatdoc, indoc};
use rmcp::{
    model::{CallToolRequest, ClientRequest, ServerResult},
    service::PeerRequestOptions,
};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

use crate::{
    command_succeeded, isolated, observed_master_count, private_boundary, support, wire_tool,
};
use support::{Client, Log, WireServer, assert_masters_gone, masters, quote};

fn combined(results: impl IntoIterator<Item = (&'static str, Result<()>)>) -> Result<()> {
    let errors = results
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
        .collect::<Vec<_>>();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(())
}

fn audit_metadata(log: &Log) -> Result<()> {
    let records = log.final_records()?;
    for start in records.iter().filter(|record| record["event"] == "start") {
        ensure!(
            start["timestamp_ms"].is_u64()
                && start["host"].is_string()
                && start["tool"].is_string()
                && start["identity_role"].is_string()
                && start["sudo_mode"].is_string(),
            "missing command audit metadata"
        );
        let finishes = records
            .iter()
            .filter(|record| {
                record["event"] == "finish" && record["request_id"] == start["request_id"]
            })
            .collect::<Vec<_>>();
        ensure!(finishes.len() == 1, "request has no unique finish audit");
        let finish = finishes[0];
        for field in ["request_id", "tool", "host", "identity_role", "sudo_mode"] {
            ensure!(
                finish[field] == start[field],
                "audit metadata changed at finish"
            );
        }
        ensure!(
            finish["duration_ms"].is_u64()
                && finish["timestamp_ms"].is_u64()
                && finish["remote_state_unknown"].is_boolean(),
            "missing finish status metadata"
        );
    }
    Ok(())
}

fn fixture_files(config: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(config.parent().context("fixture config parent")?)? {
        let path = entry?.path();
        if path.is_file() {
            files.insert(path.clone(), fs::read(path)?);
        }
    }
    Ok(files)
}

async fn finish_client(client: Client, scenario: Result<()>, markers: &[String]) -> Result<()> {
    let log = client.log.clone();
    let stopped = client.stop().await.map(|_| ());
    let gone = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    };
    combined([
        ("scenario", scenario),
        ("server cleanup", stopped),
        ("master cleanup", gone),
        ("diagnostic privacy", private_boundary(&log.text(), markers)),
        ("audit metadata", audit_metadata(&log)),
    ])
}

async fn wait_remote(fixture: &isolated::Fixture, path: &str) -> Result<()> {
    timeout(Duration::from_secs(12), async {
        loop {
            let script = format!("if [ -f {} ]; then printf READY; fi", quote(path));
            if fixture.primary_exec(&script).await? == b"READY" {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("remote marker deadline")?
}

async fn check_master(fixture: &isolated::Fixture, owned: &(u32, PathBuf)) -> Result<()> {
    let output = support::run(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .arg("-S")
            .arg(&owned.1)
            .args(["-O", "check", "plain"]),
    )
    .await?;
    ensure!(
        owned.1.exists()
            && output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(&format!("(pid={})", owned.0)),
        "original owned master PID/socket no longer live"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_packaged_config_environment_and_privacy() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let scenario = async {
        let mut markers = fixture.credential_markers()?;
        markers.extend(["V03_BACKEND_DIAGNOSTIC_SECRET", "V03_HOST_SECRET", "V03_MATCH_SECRET",
            "V03_INCLUDE_SECRET", "V03_REJECTED_PAYLOAD"].map(str::to_owned));
        // Real direct sessions demonstrate that all three config paths are active,
        // rather than merely absent because sshd would reject the variables.
        for (alias, expected) in [("plain", "V03_INCLUDE=V03_INCLUDE_SECRET"),
            ("same", "V03_HOST=V03_HOST_SECRET"), ("split-admin", "V03_MATCH=V03_MATCH_SECRET")] {
            let direct = fixture.direct(alias, "/bin/env").await?;
            ensure!(direct.status.success() && String::from_utf8_lossy(&direct.stdout).lines().any(|line| line == expected),
                "direct config environment positive control failed for {alias}");
            if alias == "plain" {
                ensure!(String::from_utf8_lossy(&direct.stderr).contains("V03_BACKEND_DIAGNOSTIC_SECRET"),
                    "controlled backend diagnostic was not emitted");
            }
        }
        // A raw byte cursor is taken only after the controls' accepted-env records
        // arrive. Every later assertion is bounded to newly produced sshd bytes.
        let before = timeout(Duration::from_secs(5), async {
            loop {
                let bytes = fixture.primary_logs().await?;
                let text = String::from_utf8_lossy(&bytes);
                if ["V03_INCLUDE=V03_INCLUDE_SECRET", "V03_HOST=V03_HOST_SECRET", "V03_MATCH=V03_MATCH_SECRET"]
                    .iter().all(|marker| text.contains(marker)) { return Ok::<_, anyhow::Error>(bytes); }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("direct accepted-env log controls did not arrive")??;
        let client = Client::start(&fixture.config).await?;
        let calls = async {
            let environment = client.call("ssh_exec", json!({"host":"plain","command":"/bin/env"})).await?;
            ensure!(environment["error"].is_null() && environment["data"]["exit_code"] == 0);
            let env = environment["data"]["stdout"].as_str().context("environment stdout")?;
            ensure!(env.lines().any(|line| line == "SSH_MCP=1"));
            private_boundary(&environment.to_string(), &markers)?;
            for host in ["same", "split"] {
                let reply = client.call("ssh_sudo", json!({"host":host,"argv":["/usr/bin/id","-u"]})).await?;
                command_succeeded(&reply, "0\n")?;
                private_boundary(&reply.to_string(), &markers)?;
            }
            fixture.primary_exec("printf V03_READ_CONTENT > /tmp/v03-environment-read; chmod 644 /tmp/v03-environment-read").await?;
            let read = client.call("ssh_read_file", json!({"host":"plain","path":"/tmp/v03-environment-read"})).await?;
            ensure!(read["error"].is_null() && read["data"]["content"] == "V03_READ_CONTENT");
            private_boundary(&read.to_string(), &markers)?;
            timeout(Duration::from_secs(5), async {
                loop {
                    let logs = fixture.primary_logs().await?;
                    ensure!(logs.starts_with(&before), "sshd log cursor changed");
                    let window = String::from_utf8_lossy(&logs[before.len()..]);
                    private_boundary(&window, &["V03_HOST_SECRET".into(), "V03_MATCH_SECRET".into(), "V03_INCLUDE_SECRET".into()])?;
                    // OpenSSH V_10_6_P1 session.c session_env_req logs accepted
                    // requests at DEBUG2 before exec/sudo/subsystem dispatch.
                    let accepted = window.lines().filter(|line| line.contains("Setting env ") && line.contains(": SSH_MCP=1")).count();
                    ensure!(accepted <= 4, "extra MCP SSH sessions in isolated env window");
                    if accepted == 4 { return Ok::<_, anyhow::Error>(()); }
                    sleep(Duration::from_millis(20)).await;
                }
            }).await.context("each MCP exec/sudo/SFTP session must accept SSH_MCP=1")??;
            let jump = client.call("ssh_exec", json!({"host":"viajump","command":"/usr/bin/id -u"})).await?;
            command_succeeded(&jump, "1000\n")?;
            private_boundary(&jump.to_string(), &markers)?;
            let keys = crate::fixture_fingerprints(&fixture).await?;
            crate::observed_authentications(&fixture, &keys, &[
                ("mcp", 7), ("mcp-sudo", 3), ("mcp-admin", 2),
                ("mcp-password", 0), ("mcp-tty", 0),
            ]).await?;
            Ok(())
        }.await;
        finish_client(client, calls, &markers).await?;
        // Strict failures are real MCP operations, not a direct-ssh oracle.
        for fault in [isolated::HostKeyFault::Unknown, isolated::HostKeyFault::Mismatch] {
            let config = fixture.host_key_config(fault).await?;
            let known = fixture_files(&config)?;
            let accepted = fixture.authentication_keys().await?;
            // A fresh pool for each operation proves both exec and SFTP reject
            // the bad trust database during their own initial handshake. A
            // second call on a failed cached entry only proves it is unavailable.
            for (name, args) in [
                ("ssh_exec", json!({"host":"plain","command":"printf V03_REJECTED_PAYLOAD > /tmp/v03-hostkey-dispatched"})),
                ("ssh_read_file", json!({"host":"plain","path":"/tmp/v03-environment-read"})),
            ] {
                let client = Client::start(&config).await?;
                let rejected = async {
                    let reply = client.call(name, args).await?;
                    ensure!(reply["data"].is_null() && reply["error"]["code"] == "ssh_connect_failed"
                        && reply["error"]["remote_state_unknown"] == false, "strict key error contract differs");
                    private_boundary(&reply.to_string(), &markers)?;
                    ensure!(fixture.authentication_keys().await? == accepted, "host key failure authenticated");
                    ensure!(fixture_files(&config)? == known, "strict failure modified owned config/key/known-host files");
                    ensure!(fixture.primary_exec("if [ -e /tmp/v03-hostkey-dispatched ]; then printf BAD; fi").await?.is_empty(), "host key failure dispatched payload");
                    Ok(())
                }.await;
                finish_client(client, rejected, &markers).await?;
            }
        }
        let client = Client::start(&fixture.config).await?;
        let trusted = async {
            command_succeeded(&client.call("ssh_exec", json!({"host":"plain","command":"printf TRUSTED"})).await?, "TRUSTED")
        }.await;
        finish_client(client, trusted, &markers).await
    }.await;
    let cleanup = fixture.stop().await;
    combined([
        ("config/environment", scenario),
        ("fixture cleanup", cleanup),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_packaged_command_fidelity() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let scenario = async {
        // This is an owned fixture TOML override, not a production default change.
        fs::OpenOptions::new()
            .append(true)
            .open(&fixture.config)?
            .write_all(
                indoc! {"
            [limits]
            max_output_bytes = 1024
            max_file_bytes = 8388608
        "}
                .as_bytes(),
            )?;
        let markers = fixture.credential_markers()?;
        let client = Client::start(&fixture.config).await?;
        let commands = async {
            let rejected = client
                .call(
                    "ssh_exec",
                    json!({
                        "host":"plain", "command":"'".repeat(20_000)
                    }),
                )
                .await?;
            ensure!(
                rejected["error"]["code"] == "invalid_argument"
                    && rejected["error"]["remote_state_unknown"] == false
                    && rejected["data"].is_null(),
                "expanded SSH command was dispatched"
            );
            ensure!(
                masters(&client.log)?.is_empty(),
                "encoded-command rejection acquired a master"
            );
            for (command, out, err, exit) in [
                ("printf out; printf err >&2; exit 7", "out", "err", 7),
                ("exit 127", "", "", 127),
                ("exit 255", "", "", 255),
            ] {
                let reply = client
                    .call("ssh_exec", json!({"host":"plain","command":command}))
                    .await?;
                ensure!(
                    reply["error"]["code"] == "command_failed"
                        && reply["error"]["remote_state_unknown"] == false
                );
                let data = &reply["data"];
                ensure!(
                    data["stdout"] == out
                        && data["stderr"] == err
                        && data["exit_code"] == exit
                        && data["termination"] == "exited"
                        && data["remote_may_still_be_running"] == false
                );
                ensure!(data["duration_ms"].is_u64());
                for field in [
                    "stdout_lossy",
                    "stderr_lossy",
                    "stdout_truncated",
                    "stderr_truncated",
                ] {
                    ensure!(data[field] == false);
                }
                private_boundary(&reply.to_string(), &markers)?;
            }
            let owned = observed_master_count(&client.log, 1).await?;
            let local = tempfile::Builder::new()
                .prefix("v03-injection-")
                .tempdir_in("/tmp")?;
            let local_marker = local.path().join("EXECUTED");
            let injected = format!(
                "$(touch {})",
                quote(local_marker.to_str().context("local marker UTF-8")?)
            );
            let cwd = format!(
                "/tmp/v03 space ' quote\nnewline ; {injected} ; $(touch /tmp/v03-remote-injected)"
            );
            fixture
                .primary_exec(&format!(
                    "mkdir -p -- {}; chmod 755 -- {}",
                    quote(&cwd),
                    quote(&cwd)
                ))
                .await?;
            let reply = client
                .call(
                    "ssh_exec",
                    json!({"host":"plain","cwd":cwd,"command":"printf '%s' \"$PWD\""}),
                )
                .await?;
            command_succeeded(&reply, &cwd)?;
            let literal =
                format!("literal ; {injected} ' single\nnewline $(touch /tmp/v03-remote-injected)");
            command_succeeded(
                &client
                    .call(
                        "ssh_exec",
                        json!({"host":"plain","command":format!("printf %s {}", quote(&literal))}),
                    )
                    .await?,
                &literal,
            )?;
            ensure!(!local_marker.exists(), "local command injection executed");
            ensure!(
                fixture
                    .primary_exec("if [ -e /tmp/v03-remote-injected ]; then printf BAD; fi")
                    .await?
                    .is_empty(),
                "remote quoting executed literal text"
            );
            let stdin = "V03_STDIN_SECRET".repeat(32);
            let command = "printf V03_COMMAND_SECRET; printf V03_STDERR_SECRET >&2; cat";
            let reply = client
                .call(
                    "ssh_exec",
                    json!({"host":"plain","command":command,"stdin":stdin}),
                )
                .await?;
            ensure!(
                reply["error"].is_null()
                    && reply["data"]["exit_code"] == 0
                    && reply["data"]["stdout"] == format!("V03_COMMAND_SECRET{stdin}")
                    && reply["data"]["stderr"] == "V03_STDERR_SECRET"
            );
            let reply = client
                .call(
                    "ssh_exec",
                    json!({"host":"plain","command":"printf '\\377'; printf '\\376' >&2"}),
                )
                .await?;
            ensure!(
                reply["error"].is_null()
                    && reply["data"]["stdout"] == "\u{fffd}"
                    && reply["data"]["stderr"] == "\u{fffd}"
                    && reply["data"]["stdout_lossy"] == true
                    && reply["data"]["stderr_lossy"] == true
            );
            let reply = client
                .call(
                    "ssh_exec",
                    json!({
                        "host":"plain","timeout_secs":15,
                        "command":indoc! {"
                    /bin/head -c 4194304 /dev/zero | /bin/tr '\\000' x
                    /bin/head -c 4194304 /dev/zero | /bin/tr '\\000' y >&2
                    cat
                    exit 7
                "},
                        "stdin":"z".repeat(4_194_304)
                    }),
                )
                .await?;
            ensure!(
                reply["error"]["code"] == "command_failed"
                    && reply["data"]["exit_code"] == 7
                    && reply["data"]["stdout"] == "x".repeat(1024)
                    && reply["data"]["stderr"] == "y".repeat(1024)
                    && reply["data"]["stdout_truncated"] == true
                    && reply["data"]["stderr_truncated"] == true
                    && reply["data"]["stdout_lossy"] == false
                    && reply["data"]["stderr_lossy"] == false
            );
            ensure!(
                masters(&client.log)? == owned,
                "command cases replaced their shared master"
            );
            check_master(&fixture, &owned[0]).await?;
            Ok(())
        }
        .await;
        let mut audit_markers = markers;
        audit_markers.extend(
            [
                "V03_STDIN_SECRET",
                "V03_COMMAND_SECRET",
                "V03_STDERR_SECRET",
            ]
            .map(str::to_owned),
        );
        finish_client(client, commands, &audit_markers).await
    }
    .await;
    let cleanup = fixture.stop().await;
    combined([("command fidelity", scenario), ("fixture cleanup", cleanup)])
}

async fn await_finish(log: &Log, id: &Value, code: &str) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(record) = log
                .records()?
                .into_iter()
                .find(|record| record["event"] == "finish" && &record["request_id"] == id)
            {
                ensure!(
                    record["error_code"] == code
                        && record["remote_state_unknown"] == true
                        && record["exit_code"].is_null(),
                    "uncertain command audit lacks expected status"
                );
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("uncertain command audit did not finish")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_packaged_command_timeout_and_cancellation() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let scenario = async {
        let markers = fixture.credential_markers()?;
        let client = Client::start(&fixture.config).await?;
        let commands = async {
            let warm = client.call("ssh_exec", json!({"host":"plain","command":"printf '%s' \"$SSH_CONNECTION\""})).await?;
            ensure!(warm["error"].is_null() && warm["data"]["exit_code"] == 0);
            let transport = warm["data"]["stdout"].as_str().context("warm transport")?;
            ensure!(transport.split_ascii_whitespace().count() == 4);
            let owned = observed_master_count(&client.log, 1).await?;
            let authentications = fixture.authentication_keys().await?;
            for cancel in [false, true] {
                let label = if cancel { "cancel" } else { "timeout" };
                let prefix = format!("/tmp/v03-{label}");
                let script = formatdoc! {"
                    trap '' HUP
                    printf dispatch >> {prefix}-dispatch
                    printf started > {prefix}-started
                    printf PARTIAL
                    printf PARTIAL_ERR >&2
                    sleep 5
                    printf done > {prefix}-done
                "};
                let mut request = client.service.send_cancellable_request(
                    ClientRequest::CallToolRequest(CallToolRequest::new(support::params("ssh_exec", json!({
                        "host":"plain", "command":script, "timeout_secs":if cancel { 12 } else { 2 }
                    })))), PeerRequestOptions::default()).await?;
                let id = serde_json::to_value(&request.id)?;
                let marker = format!("{prefix}-started");
                let started = wait_remote(&fixture, &marker);
                tokio::pin!(started);
                tokio::select! {
                    _ = &mut request.rx => anyhow::bail!("command finished before independent start observation"),
                    result = &mut started => result?,
                }
                // This is a second concurrently active channel on precisely the
                // same logical target and original master, not another target.
                command_succeeded(&client.call("ssh_exec", json!({"host":"plain","command":"printf '%s' \"$SSH_CONNECTION\""})).await?, transport)?;
                if cancel {
                    timeout(Duration::from_secs(5), request.cancel(Some("V03 explicit cancellation".into()))).await??;
                } else {
                    let response = timeout(Duration::from_secs(6), request.await_response()).await??;
                    let ServerResult::CallToolResult(result) = response else { anyhow::bail!("non-tool timeout result"); };
                    let reply = support::envelope(result)?;
                    ensure!(reply["error"]["code"] == "timeout" && reply["error"]["remote_state_unknown"] == true
                        && reply["data"]["termination"] == "timeout" && reply["data"]["exit_code"].is_null()
                        && reply["data"]["remote_may_still_be_running"] == true);
                    private_boundary(&reply.to_string(), &markers)?;
                }
                await_finish(&client.log, &id, if cancel { "cancelled" } else { "timeout" }).await?;
                command_succeeded(&client.call("ssh_exec", json!({"host":"plain","command":"printf '%s' \"$SSH_CONNECTION\""})).await?, transport)?;
                check_master(&fixture, &owned[0]).await?;
                wait_remote(&fixture, &format!("{prefix}-done")).await?;
                ensure!(fixture.primary_exec(&format!("cat {prefix}-dispatch")).await? == b"dispatch", "uncertain command was replayed");
                ensure!(masters(&client.log)? == owned && fixture.authentication_keys().await? == authentications,
                    "channel timeout/cancellation replaced or reauthenticated its shared master");
            }
            Ok(())
        }.await;
        finish_client(client, commands, &markers).await
    }.await;
    let cleanup = fixture.stop().await;
    combined([
        ("timeout/cancellation", scenario),
        ("fixture cleanup", cleanup),
    ])
}

async fn external_transport(fixture: &isolated::Fixture, socket: &Path) -> Result<String> {
    let output = support::run(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .arg("-S")
            .arg(socket)
            .args(["-T", "plain", "printf '%s' \"$SSH_CONNECTION\""]),
    )
    .await?;
    ensure!(output.status.success(), "external master channel failed");
    let transport = String::from_utf8(output.stdout)?;
    ensure!(
        transport.split_ascii_whitespace().count() == 4,
        "external channel has no SSH_CONNECTION"
    );
    Ok(transport)
}

async fn shutdown_once(fixture: &isolated::Fixture, sigterm: bool, index: usize) -> Result<()> {
    let markers = fixture.credential_markers()?;
    let mut server = WireServer::start(&fixture.config)?;
    let log = server.log.clone();
    let scenario = async {
        server.initialize().await?;
        command_succeeded(&wire_tool(&mut server, 2, "ssh_exec", json!({"host":"plain","command":"printf SHUTDOWN_READY"}), &markers).await?, "SHUTDOWN_READY")?;
        let owned = observed_master_count(&log, 1).await?;
        check_master(fixture, &owned[0]).await?;
        let script = formatdoc! {"
            trap '' HUP
            printf dispatch >> /tmp/v03-shutdown-{index}-dispatch
            printf started > /tmp/v03-shutdown-{index}-started
            sleep 3
            printf done > /tmp/v03-shutdown-{index}-done
        "};
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_exec","arguments":{"host":"plain","command":script,"timeout_secs":10}}})).await?;
        wait_remote(fixture, &format!("/tmp/v03-shutdown-{index}-started")).await?;
        Ok(())
    }.await;
    // WireServer retains its stdin until after SIGTERM has been handled.
    let stopped = server
        .stop(sigterm.then_some(nix::sys::signal::Signal::SIGTERM))
        .await
        .map(|_| ());
    let gone = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    };
    combined([
        ("shutdown scenario", scenario),
        ("server shutdown", stopped),
        ("owned master cleanup", gone),
        (
            "shutdown diagnostics",
            private_boundary(&log.text(), &markers),
        ),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_packaged_eof_sigterm_and_external_master() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let scenario = async {
        let directory = tempfile::Builder::new()
            .prefix("v03-other-")
            .tempdir_in("/tmp")?;
        let socket = directory.path().join("c");
        let mut external = support::Process::start(
            Command::new(&fixture.ssh)
                .arg("-F")
                .arg(&fixture.ssh_config)
                .args(["-M", "-N", "-T", "-S"])
                .arg(&socket)
                .args(["-o", "ControlMaster=yes", "plain"]),
        )?;
        let external_pid = external.child.id();
        let shutdowns = async {
            let external_pid = external_pid.context("external owned master PID")?;
            let owned = (external_pid, socket.clone());
            timeout(Duration::from_secs(10), async {
                loop {
                    let check = support::run(
                        Command::new(&fixture.ssh)
                            .arg("-F")
                            .arg(&fixture.ssh_config)
                            .arg("-S")
                            .arg(&socket)
                            .args(["-O", "check", "plain"]),
                    )
                    .await?;
                    if check.status.success() {
                        return Ok::<_, anyhow::Error>(());
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("external master readiness deadline")??;
            check_master(&fixture, &owned).await?;
            let transport = external_transport(&fixture, &socket).await?;
            for (index, sigterm) in [false, true, false].into_iter().enumerate() {
                shutdown_once(&fixture, sigterm, index).await?;
                check_master(&fixture, &owned).await?;
                ensure!(
                    external_transport(&fixture, &socket).await? == transport,
                    "app shutdown replaced external transport"
                );
                // Finite remote work is observed, never assumed killed by closing
                // the app's channel. Failed scenarios are bounded by fixture stop.
                wait_remote(&fixture, &format!("/tmp/v03-shutdown-{index}-done")).await?;
                ensure!(
                    fixture
                        .primary_exec(&format!("cat /tmp/v03-shutdown-{index}-dispatch"))
                        .await?
                        == b"dispatch"
                );
            }
            Ok(())
        }
        .await;
        // Let the externally managed master unlink its own socket before
        // reaping it; Process::stop alone would SIGKILL a live process.
        let exited = async {
            let output = support::run(
                Command::new(&fixture.ssh)
                    .arg("-F")
                    .arg(&fixture.ssh_config)
                    .arg("-S")
                    .arg(&socket)
                    .args(["-O", "exit", "plain"]),
            )
            .await?;
            ensure!(
                output.status.success(),
                "external master control exit failed"
            );
            Ok(())
        }
        .await;
        let graceful = if exited.is_ok() {
            async {
                timeout(support::CLEANUP, external.child.wait())
                    .await
                    .context("external master graceful exit deadline")??;
                Ok(())
            }
            .await
        } else {
            Ok(())
        };
        let reaped = external.stop().await;
        let gone = match external_pid {
            Some(pid) => assert_masters_gone(&[(pid, socket)]).await,
            None => Ok(()),
        };
        combined([
            ("shutdowns", shutdowns),
            ("external master exit", exited),
            ("external graceful reaping", graceful),
            ("external master reaping", reaped),
            ("external socket cleanup", gone),
        ])
    }
    .await;
    let cleanup = fixture.stop().await;
    combined([("EOF/SIGTERM", scenario), ("fixture cleanup", cleanup)])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit Docker-compatible daemon"]
async fn ssh_packaged_complete_wire_budget() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let scenario = async {
        fs::OpenOptions::new()
            .append(true)
            .open(&fixture.config)?
            .write_all(
                indoc! {"
            [limits]
            max_output_bytes = 16777216
        "}
                .as_bytes(),
            )?;
        let mut markers = fixture.credential_markers()?;
        markers.push("V03_BACKEND_DIAGNOSTIC_SECRET".to_owned());
        let mut wire = WireServer::start(&fixture.config)?;
        let log = wire.log.clone();
        let response = async {
            wire.initialize().await?;
            let (mut frame, size) = wire
                .request_with_size(
                    json!("V03-wire-'\\\n".repeat(128)),
                    "tools/call",
                    json!({
                        "name":"ssh_exec","arguments":{
                            "host":"plain","timeout_secs":15,
                            "command":indoc! {"
                            /bin/printf V03_WIRE_PREFIX
                            /bin/head -c 8388608 /dev/zero
                            /bin/head -c 8388608 /dev/zero >&2
                            exit 7
                        "}
                        }
                    }),
                )
                .await?;
            ensure!(
                size <= 16_777_216,
                "complete response exceeded the wire ceiling"
            );
            private_boundary(&frame.to_string(), &markers)?;
            let result = frame
                .get_mut("result")
                .context("wire-budget result")?
                .take();
            let reply = support::envelope(serde_json::from_value(result)?)?;
            ensure!(
                reply["error"]["code"] == "command_failed"
                    && reply["error"]["remote_state_unknown"] == false
                    && reply["data"]["exit_code"] == 7
                    && reply["data"]["termination"] == "exited"
                    && reply["data"]["remote_may_still_be_running"] == false
            );
            let data = &reply["data"];
            let out = data["stdout"].as_str().context("wire-budget stdout")?;
            let err = data["stderr"].as_str().context("wire-budget stderr")?;
            ensure!(
                out.strip_prefix("V03_WIRE_PREFIX")
                    .context("lost stdout prefix")?
                    .bytes()
                    .all(|byte| byte == 0)
                    && err.bytes().all(|byte| byte == 0)
            );
            ensure!(
                out.len() < 8_388_608
                    && err.len() < 8_388_608
                    && data["stdout_truncated"] == true
                    && data["stderr_truncated"] == true
                    && data["stdout_lossy"] == false
                    && data["stderr_lossy"] == false,
                "wire clipping lost its execution/truncation evidence"
            );
            let owned = observed_master_count(&log, 1).await?;
            check_master(&fixture, &owned[0]).await?;
            println!("V03_COMPLETE_RESPONSE_BYTES={size}");
            Ok(())
        }
        .await;
        let stopped = wire.stop(None).await.map(|_| ());
        let gone = match masters(&log) {
            Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        };
        markers.push("V03_WIRE_PREFIX".to_owned());
        combined([
            ("complete wire response", response),
            ("server cleanup", stopped),
            ("master cleanup", gone),
            (
                "wire diagnostic privacy",
                private_boundary(&log.text(), &markers),
            ),
            ("wire audit metadata", audit_metadata(&log)),
        ])
    }
    .await;
    let cleanup = fixture.stop().await;
    combined([("wire budget", scenario), ("fixture cleanup", cleanup)])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit Docker-compatible daemon"]
async fn ssh_packaged_channel_loss_preserves_healthy_master() -> Result<()> {
    let fixture = isolated::Fixture::start_with_sshd_config("ChannelTimeout session=1s\n").await?;
    let scenario = async {
        let markers = fixture.credential_markers()?;
        let client = Client::start(&fixture.config).await?;
        let channels = async {
            let warm = client
                .call(
                    "ssh_exec",
                    json!({
                        "host":"plain","command":"printf '%s' \"$SSH_CONNECTION\""
                    }),
                )
                .await?;
            ensure!(warm["error"].is_null() && warm["data"]["exit_code"] == 0);
            let transport = warm["data"]["stdout"]
                .as_str()
                .context("channel-loss transport")?;
            ensure!(transport.split_ascii_whitespace().count() == 4);
            let owned = observed_master_count(&client.log, 1).await?;
            let keys = crate::fixture_fingerprints(&fixture).await?;
            crate::observed_authentications(
                &fixture,
                &keys,
                &[
                    ("mcp", 4),
                    ("mcp-sudo", 1),
                    ("mcp-admin", 0),
                    ("mcp-password", 0),
                    ("mcp-tty", 0),
                ],
            )
            .await?;
            let accepted = fixture.authentication_keys().await?;
            let active = client
                .service
                .send_cancellable_request(
                    ClientRequest::CallToolRequest(CallToolRequest::new(support::params(
                        "ssh_exec",
                        json!({
                            "host":"plain","timeout_secs":10,"command":indoc! {"
                        printf started > /tmp/v03-r1-active-started
                        i=0
                        while [ \"$i\" -lt 30 ]; do
                            printf 'alive\\n'
                            sleep 0.2
                            i=$((i+1))
                        done
                        printf '%s' \"$SSH_CONNECTION\"
                    "}
                        }),
                    ))),
                    PeerRequestOptions::default(),
                )
                .await?;
            let idle = client
                .service
                .send_cancellable_request(
                    ClientRequest::CallToolRequest(CallToolRequest::new(support::params(
                        "ssh_exec",
                        json!({
                            "host":"plain","timeout_secs":10,"command":indoc! {"
                        trap '' HUP
                        printf dispatch >> /tmp/v03-r1-idle-dispatch
                        printf PARTIAL
                        printf started > /tmp/v03-r1-idle-started
                        sleep 4
                        printf done > /tmp/v03-r1-idle-done
                    "}
                        }),
                    ))),
                    PeerRequestOptions::default(),
                )
                .await?;
            let idle_id = serde_json::to_value(&idle.id)?;
            wait_remote(&fixture, "/tmp/v03-r1-active-started").await?;
            wait_remote(&fixture, "/tmp/v03-r1-idle-started").await?;
            let response = timeout(Duration::from_secs(5), idle.await_response()).await??;
            let ServerResult::CallToolResult(result) = response else {
                anyhow::bail!("channel-only loss returned a non-tool result");
            };
            let lost = support::envelope(result)?;
            ensure!(
                lost["error"]["code"] == "connection_lost"
                    && lost["error"]["remote_state_unknown"] == true
                    && lost["data"]["termination"] == "connection_lost"
                    && lost["data"]["exit_code"].is_null()
                    && lost["data"]["remote_may_still_be_running"] == true
                    && lost["data"]["stdout"] == "PARTIAL",
                "missing channel exit status lost its uncertainty/partial output"
            );
            await_finish(&client.log, &idle_id, "connection_lost").await?;
            private_boundary(&lost.to_string(), &markers)?;
            let response = timeout(Duration::from_secs(8), active.await_response()).await??;
            let ServerResult::CallToolResult(result) = response else {
                anyhow::bail!("active sibling returned a non-tool result");
            };
            command_succeeded(
                &support::envelope(result)?,
                &format!("{}{transport}", "alive\n".repeat(30)),
            )?;
            command_succeeded(
                &client
                    .call(
                        "ssh_exec",
                        json!({
                            "host":"plain","command":"printf '%s' \"$SSH_CONNECTION\""
                        }),
                    )
                    .await?,
                transport,
            )?;
            check_master(&fixture, &owned[0]).await?;
            wait_remote(&fixture, "/tmp/v03-r1-idle-done").await?;
            ensure!(
                fixture
                    .primary_exec("cat /tmp/v03-r1-idle-dispatch")
                    .await?
                    == b"dispatch",
                "channel-only loss replayed the command"
            );
            ensure!(
                masters(&client.log)? == owned && fixture.authentication_keys().await? == accepted,
                "channel-only loss replaced or reauthenticated the healthy master"
            );
            Ok(())
        }
        .await;
        finish_client(client, channels, &markers).await
    }
    .await;
    let cleanup = fixture.stop().await;
    combined([
        ("channel-only loss", scenario),
        ("fixture cleanup", cleanup),
    ])
}
