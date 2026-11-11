//! Packaged config, command fidelity and complete-response budget acceptance.
use crate::{command_succeeded, isolated, observed_master_count, private_boundary, support};
use anyhow::{Context, Result, ensure};
use indoc::indoc;
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use support::{Client, Log, WireServer, assert_masters_gone, masters, quote};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};
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
        let stopped = wire.stop(false).await.map(|_| ());
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
