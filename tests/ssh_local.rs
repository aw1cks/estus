//! Real native command and SFTP acceptance; isolated sudo remains separate.
mod support;

use std::{
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use indoc::{formatdoc, indoc};
use rmcp::{
    model::{CallToolRequest, ClientRequest},
    service::PeerRequestOptions,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{
    Client, Fixture, Log, Process, WireServer, assert_masters_gone, masters, params, quote,
};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

fn succeeded(reply: &Value) -> Result<&Value> {
    ensure!(reply["error"].is_null(), "unexpected tool failure: {reply}");
    ensure!(reply["data"].is_object(), "missing success data: {reply}");
    Ok(&reply["data"])
}

fn failed(reply: &Value, code: &str) -> Result<()> {
    ensure!(reply["error"]["code"] == code, "expected {code}: {reply}");
    Ok(())
}

async fn exec(client: &Client, command: &str) -> Result<Value> {
    client
        .call("ssh_exec", json!({"host":"plain","command":command}))
        .await
}

async fn await_audit(log: &Log, event: &str, code: &str) -> Result<Value> {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(record) = log
                .records()?
                .into_iter()
                .find(|record| record["event"] == event && record["error_code"] == code)
            {
                return Ok::<_, anyhow::Error>(record);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("expected audit event not emitted")?
}

async fn observed_masters(log: &Log, expected: usize) -> Result<Vec<(u32, PathBuf)>> {
    timeout(Duration::from_secs(5), async {
        loop {
            let owned = masters(log)?;
            if owned.len() >= expected {
                ensure!(owned.len() == expected, "unexpected additional SSH master");
                return Ok(owned);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("master lifecycle log did not catch up")?
}

async fn live_transport(
    fixture: &Fixture,
    client: &Client,
    master: &(u32, PathBuf),
    expected_masters: usize,
    expected_auth: usize,
) -> Result<String> {
    observed_masters(&client.log, expected_masters).await?;
    let before = fixture.listeners[0].log.text();
    let mut reply = exec(client, "printf %s \"$SSH_CONNECTION\"").await?;
    succeeded(&reply)?;
    let Value::String(connection) = reply["data"]["stdout"].take() else {
        anyhow::bail!("missing SSH_CONNECTION transport identity");
    };
    let mut fields = connection.split_ascii_whitespace();
    let port = fields.nth(1).context("missing SSH client port")?;
    ensure!(
        fields.count() == 2,
        "invalid SSH_CONNECTION transport identity"
    );
    let port = format!(" port {port} ");
    let closed = |text: &str| {
        text.lines()
            .filter(|line| line.contains("Close session:") && line.contains(&port))
            .count()
    };
    let before_closed = closed(&before);
    // This persistent-connection close is a positive log-drain barrier, unlike
    // merely sampling an append-only authentication counter after cancellation.
    timeout(Duration::from_secs(5), async {
        while closed(&fixture.listeners[0].log.text()) <= before_closed {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("transport probe close record did not arrive")?;
    let check = support::run(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .arg("-S")
            .arg(&master.1)
            .args(["-O", "check", "plain"]),
    )
    .await?;
    ensure!(
        check.status.success()
            && String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={})", master.0)),
        "original master PID/control socket is no longer live"
    );
    observed_masters(&client.log, expected_masters).await?;
    fixture.await_authentications(expected_auth).await?;
    Ok(connection)
}

fn capacity_script(
    start: &Path,
    release: &Path,
    expired: &Path,
    done: &Path,
    label: &str,
) -> String {
    // Polling is not a capacity duration: only the controller can release a
    // successful worker. The finite deadline fails closed and still marks done.
    formatdoc! {r#"
        trap '' HUP
        printf ready > {start}
        i=0
        while [ ! -f {release} ] && [ "$i" -lt 100 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        if [ ! -f {release} ]; then
            printf expired > {expired}
            printf done > {done}
            exit 90
        fi
        printf done > {done}
        printf %s {label}
        "#,
        start = quote(&start.to_string_lossy()),
        release = quote(&release.to_string_lossy()),
        expired = quote(&expired.to_string_lossy()),
        done = quote(&done.to_string_lossy()),
        label = quote(label),
    }
}

async fn command_cases(fixture: &mut Fixture, client: &Client) -> Result<()> {
    let listed = timeout(Duration::from_secs(5), client.service.list_tools(None)).await??;
    for name in [
        "ssh_targets",
        "ssh_exec",
        "ssh_run",
        "ssh_sudo",
        "ssh_read_file",
        "ssh_stat",
        "ssh_list_directory",
        "ssh_write_file",
    ] {
        let tool = listed
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .with_context(|| format!("missing {name}"))?;
        ensure!(tool.output_schema.is_some(), "{name} missing outputSchema");
    }
    let initial_auth = fixture.authentications();
    let targets = client.call("ssh_targets", json!({})).await?;
    ensure!(succeeded(&targets)?["mode"] == "configured");
    // Every policy-negative case runs before the first valid command. No sudo is executed.
    for (name, args, code) in [
        (
            "ssh_exec",
            json!({"host":"unknown-logical-target","command":"printf NEVER"}),
            "policy_denied",
        ),
        (
            "ssh_exec",
            json!({"host":"jump","command":"printf NEVER"}),
            "policy_denied",
        ),
        (
            "ssh_sudo",
            json!({"host":"plain","argv":["/usr/bin/true"]}),
            "policy_denied",
        ),
        (
            "ssh_sudo",
            json!({"host":"restricted","user":"not-allowed","argv":["/usr/bin/true"]}),
            "policy_denied",
        ),
        (
            "ssh_sudo",
            json!({"host":"restricted","argv":["/bin/sh","-c","printf NEVER"]}),
            "policy_denied",
        ),
        (
            "ssh_sudo",
            json!({"host":"restricted","argv":["relative"]}),
            "invalid_argument",
        ),
        (
            "ssh_exec",
            json!({"host":"plain","command":"true","timeout_secs":0}),
            "invalid_argument",
        ),
        (
            "ssh_exec",
            json!({"host":"plain","command":"true","timeout_secs":16}),
            "invalid_argument",
        ),
        (
            "ssh_run",
            json!({"host":"plain","argv":[]}),
            "invalid_argument",
        ),
        (
            "ssh_run",
            json!({"host":"plain","argv":[""]}),
            "invalid_argument",
        ),
        (
            "ssh_run",
            json!({"host":"plain","argv":["bad\u{0000}program"]}),
            "invalid_argument",
        ),
        (
            "ssh_run",
            json!({"host":"plain","argv":["/bin/sh","bad\u{0000}argument"]}),
            "invalid_argument",
        ),
    ] {
        failed(&client.call(name, args).await?, code)?;
    }
    ensure!(
        fixture.authentications() == initial_auth,
        "policy rejection authenticated to SSH"
    );
    ensure!(
        masters(&client.log)?.is_empty(),
        "policy rejection launched a master"
    );

    for (command, stdout, stderr, exit) in [
        ("printf out; printf err >&2; exit 7", "out", "err", 7),
        ("exit 127", "", "", 127),
        ("exit 255", "", "", 255),
    ] {
        let reply = exec(client, command).await?;
        failed(&reply, "command_failed")?;
        let data = &reply["data"];
        ensure!(
            data["stdout"] == stdout && data["stderr"] == stderr && data["exit_code"] == exit,
            "command fidelity: {reply}"
        );
        ensure!(data["termination"] == "exited" && data["remote_may_still_be_running"] == false);
        ensure!(data["duration_ms"].is_u64());
    }
    let first_masters = observed_masters(&client.log, 1).await?;
    ensure!(
        first_masters.len() == 1,
        "sequential commands did not share one owned master"
    );
    let auth_after_first = initial_auth + 1;
    fixture.await_authentications(auth_after_first).await?;
    let (left, right) = tokio::join!(
        exec(client, "sleep 1; printf LEFT"),
        exec(client, "printf RIGHT")
    );
    ensure!(succeeded(&left?)?["stdout"] == "LEFT");
    ensure!(succeeded(&right?)?["stdout"] == "RIGHT");
    fixture.await_authentications(auth_after_first).await?;
    ensure!(
        masters(&client.log)? == first_masters,
        "concurrent channels replaced the master"
    );

    let injected = fixture.root.path().join("INJECTED");
    let injection = format!("$(touch {})", quote(&injected.to_string_lossy()));
    let unusual = fixture
        .root
        .path()
        .join(format!("space ' single\nnewline ; {injection}"));
    fs::create_dir_all(&unusual)?;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"plain","command":"printf '%s' \"$PWD\"","cwd":unusual}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?["stdout"] == unusual.to_string_lossy().as_ref(),
        "cwd quoting: {reply}"
    );
    ensure!(!injected.exists(), "cwd was evaluated as shell syntax");
    let literal = format!("space ; {injection} ' quote\nnewline");
    let reply = exec(client, &format!("printf %s {}", quote(&literal))).await?;
    ensure!(succeeded(&reply)?["stdout"] == literal);
    ensure!(
        !injected.exists(),
        "argument text was evaluated as shell syntax"
    );
    let baseline = exec(client, "printf %s \"$PWD\"").await?;
    let baseline_cwd = succeeded(&baseline)?["stdout"]
        .as_str()
        .context("initial channel cwd")?;
    let arguments = [
        "",
        "two words",
        "single' and double\" quotes",
        "line one\nline two",
        "; & | < > * ? [ ] { } \\ $HOME",
        "日本語 🦀",
        &injection,
    ];
    let mut argv = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        indoc! {r#"
            printf '%s\000' "$PWD" "$@"
            cat
            printf RUN_STDERR >&2
            exit 23
        "#}
        .to_owned(),
        "argv-probe".to_owned(),
    ];
    argv.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    let stdin = "stdin before\0after\n日本語";
    let reply = client
        .call(
            "ssh_run",
            json!({"host":"plain","argv":argv,"cwd":unusual,"stdin":stdin}),
        )
        .await?;
    failed(&reply, "command_failed")?;
    let data = &reply["data"];
    let expected = format!(
        "{}\0{}\0{stdin}",
        unusual.to_string_lossy(),
        arguments.join("\0"),
    );
    ensure!(
        data["stdout"] == expected && data["stderr"] == "RUN_STDERR" && data["exit_code"] == 23,
        "literal argv, cwd, stdin, or stream fidelity: {reply}"
    );
    ensure!(
        data["termination"] == "exited"
            && data["remote_may_still_be_running"] == false
            && data["stdout_lossy"] == false
            && data["stderr_lossy"] == false
    );
    ensure!(reply["error"]["remote_state_unknown"] == false);
    ensure!(
        !injected.exists(),
        "ssh_run evaluated caller text as shell syntax"
    );
    let reply = client
        .call(
            "ssh_run",
            json!({"host":"plain","argv":["/bin/sh","-c","printf %s \"$PWD\""]}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?["stdout"] == baseline_cwd,
        "ssh_run cwd carried over to a later channel"
    );
    let reply = client
        .call("ssh_run", json!({"host":"plain","argv":["true"]}))
        .await?;
    ensure!(
        succeeded(&reply)?["exit_code"] == 0,
        "bare PATH executable failed"
    );
    for program in [
        "SSH_MCP_MISSING_EXECUTABLE_8f19=value",
        "if",
        "-SSH_MCP_MISSING_EXECUTABLE_8f19",
    ] {
        let reply = client
            .call("ssh_run", json!({"host":"plain","argv":[program]}))
            .await?;
        failed(&reply, "command_failed")?;
        ensure!(
            reply["data"]["exit_code"] == 127
                && reply["data"]["termination"] == "exited"
                && reply["data"]["remote_may_still_be_running"] == false,
            "executable was not treated literally ({program:?}): {reply}"
        );
        ensure!(reply["error"]["remote_state_unknown"] == false);
    }
    let secret = "SYNTHETIC_STDIN_PAYLOAD_77c940";
    let reply = client.call("ssh_exec", json!({"host":"plain","command":"printf SYNTHETIC_COMMAND_MARKER_07b9; printf SYNTHETIC_STDERR_MARKER_319a >&2; cat","stdin":secret})).await?;
    let data = succeeded(&reply)?;
    ensure!(
        data["stdout"] == format!("SYNTHETIC_COMMAND_MARKER_07b9{secret}")
            && data["stderr"] == "SYNTHETIC_STDERR_MARKER_319a"
    );
    // POSIX printf octal escapes generate invalid UTF-8 on both streams.
    let reply = client
        .call(
            "ssh_run",
            json!({"host":"plain","argv":["/bin/sh","-c","printf '\\377'; printf '\\376' >&2"]}),
        )
        .await?;
    let data = succeeded(&reply)?;
    ensure!(
        data["stdout_lossy"] == true && data["stderr_lossy"] == true,
        "binary output must disclose lossy decoding"
    );
    ensure!(data["stdout"] == "\u{fffd}" && data["stderr"] == "\u{fffd}");
    let reply = client.call("ssh_run", json!({"host":"plain","argv":["/bin/sh","-c","i=0; while [ \"$i\" -lt 4096 ]; do printf x; printf y >&2; i=$((i+1)); done; cat; exit 7"],"stdin":"z".repeat(8192)})).await?;
    failed(&reply, "command_failed")?;
    let data = &reply["data"];
    ensure!(
        data["stdout"].as_str().context("stdout")?.len() == 1024
            && data["stderr"].as_str().context("stderr")?.len() == 1024
    );
    ensure!(
        data["stdout_truncated"] == true
            && data["stderr_truncated"] == true
            && data["exit_code"] == 7
    );
    ensure!(data["stdout_lossy"] == false && data["stderr_lossy"] == false);

    let before_jump = auth_after_first;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"viajump","command":"printf JUMP_OK"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "JUMP_OK");
    fixture.await_authentications(before_jump + 2).await?;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"nosftp","command":"printf NO_SUBSYSTEM_NEEDED"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "NO_SUBSYSTEM_NEEDED");
    let expected_auth = before_jump + 3;
    fixture.await_authentications(expected_auth).await?;
    let expected_masters = first_masters.len() + 2;
    let transport = live_transport(
        fixture,
        client,
        &first_masters[0],
        expected_masters,
        expected_auth,
    )
    .await?;

    // Finite remote work intentionally survives channel teardown. Register its completion
    // marker before dispatch so cleanup also awaits it when an assertion fails.
    let timeout_started = fixture.root.path().join("timeout-started");
    let timeout_done = fixture.root.path().join("timeout-done");
    fixture.eventual_markers.push(timeout_done.clone());
    let command = format!(
        "trap '' HUP PIPE; printf started > {}; printf partial; printf error >&2; sleep 3; printf done > {}",
        quote(&timeout_started.to_string_lossy()),
        quote(&timeout_done.to_string_lossy())
    );
    let (timed, unaffected) = tokio::join!(
        client.call(
            "ssh_run",
            json!({"host":"plain","argv":["/bin/sh","-c",command],"timeout_secs":1})
        ),
        async {
            Fixture::await_file(&timeout_started).await?;
            exec(client, "printf TIMEOUT_CHANNEL_UNAFFECTED").await
        }
    );
    ensure!(succeeded(&unaffected?)?["stdout"] == "TIMEOUT_CHANNEL_UNAFFECTED");
    let timed = timed?;
    failed(&timed, "timeout")?;
    ensure!(timed["data"]["stdout"] == "partial" && timed["data"]["stderr"] == "error");
    ensure!(
        timed["data"]["termination"] == "timeout"
            && timed["data"]["exit_code"].is_null()
            && timed["data"]["remote_may_still_be_running"] == true
    );
    ensure!(timed["error"]["remote_state_unknown"] == true);
    await_audit(&client.log, "finish", "timeout").await?;
    Fixture::await_file(&timeout_done).await?;
    ensure!(
        live_transport(
            fixture,
            client,
            &first_masters[0],
            expected_masters,
            expected_auth
        )
        .await?
            == transport,
        "timeout changed the authenticated transport"
    );

    let cancel_started = fixture.root.path().join("cancel-started");
    let cancel_done = fixture.root.path().join("cancel-done");
    fixture.eventual_markers.push(cancel_done.clone());
    let command = format!(
        "trap '' HUP PIPE; printf started > {}; printf cancel-partial; sleep 3; printf done > {}",
        quote(&cancel_started.to_string_lossy()),
        quote(&cancel_done.to_string_lossy())
    );
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
        "ssh_run",
        json!({"host":"plain","argv":["/bin/sh","-c",command],"timeout_secs":10}),
    )));
    let handle = timeout(
        Duration::from_secs(5),
        client
            .service
            .send_cancellable_request(request, PeerRequestOptions::default()),
    )
    .await??;
    Fixture::await_file(&cancel_started).await?;
    // RMCP cancel consumes the handle and unregisters its response. The request's
    // terminal audit is the observable cancellation result; do not fake a reply.
    timeout(
        Duration::from_secs(5),
        handle.cancel(Some("native cancellation".into())),
    )
    .await??;
    let audit = await_audit(&client.log, "finish", "cancelled").await?;
    ensure!(audit["exit_code"].is_null());
    ensure!(
        audit["remote_state_unknown"] == true,
        "cancel audit must acknowledge remote uncertainty"
    );
    ensure!(
        succeeded(&exec(client, "printf CANCEL_CHANNEL_UNAFFECTED").await?)?["stdout"]
            == "CANCEL_CHANNEL_UNAFFECTED"
    );
    Fixture::await_file(&cancel_done).await?;
    ensure!(
        live_transport(
            fixture,
            client,
            &first_masters[0],
            expected_masters,
            expected_auth
        )
        .await?
            == transport,
        "cancellation changed the authenticated transport"
    );
    Ok(())
}

fn audit_boundary(log: &Log) -> Result<()> {
    let text = log.text();
    for secret in [
        "SYNTHETIC_STDIN_PAYLOAD_77c940",
        "SYNTHETIC_COMMAND_MARKER_07b9",
        "SYNTHETIC_STDERR_MARKER_319a",
        "SYNTHETIC_BACKEND_DIAGNOSTIC_641d",
        "PRIVATE KEY",
    ] {
        ensure!(
            !text.contains(secret),
            "audit leaked synthetic payload: {secret}"
        );
    }
    let records = log.final_records()?;
    ensure!(
        records.iter().any(|record| record["event"] == "reject"),
        "missing policy rejection audit"
    );
    ensure!(records.iter().any(|record| record["event"] == "finish"
        && record["error_code"] == "timeout"
        && record["remote_state_unknown"] == true));
    for record in records.iter().filter(|record| {
        ["start", "finish", "reject"].contains(&record["event"].as_str().unwrap_or(""))
    }) {
        for field in ["timestamp_ms", "request_id", "tool", "identity_role"] {
            ensure!(
                record.get(field).is_some(),
                "audit missing {field}: {record}"
            );
        }
        if record["tool"] != "ssh_targets" {
            ensure!(
                record.get("host").is_some(),
                "remote request audit missing logical host"
            );
        }
        if record["tool"] == "ssh_run" {
            ensure!(record["identity_role"] == "ordinary");
            ensure!(
                record.get("program").is_none() && record.get("user").is_none(),
                "ordinary argv payload leaked into audit metadata"
            );
        }
        for forbidden in [
            "command",
            "stdin",
            "stdout",
            "stderr",
            "argv",
            "destination",
        ] {
            ensure!(
                record.get(forbidden).is_none(),
                "audit includes payload field {forbidden}"
            );
        }
    }
    Ok(())
}

async fn strict_keys_and_diagnostics(fixture: &Fixture) -> Result<()> {
    let original = fs::read_to_string(&fixture.ssh_config)?;
    let known_path = fixture.root.path().join("known_hosts");
    let known = fs::read_to_string(&known_path)?;
    for mode in ["unknown", "mismatched", "diagnostic"] {
        let known_case = fixture.root.path().join(format!("{mode}.known_hosts"));
        if mode == "mismatched" {
            let wrong = fs::read_to_string(fixture.root.path().join("wrong.pub"))?;
            let mut fields = wrong.split_whitespace();
            fs::write(
                &known_case,
                format!(
                    "[127.0.0.1]:{} {} {}\n",
                    fixture.ports[0],
                    fields.next().context("wrong key type")?,
                    fields.next().context("wrong key bytes")?
                ),
            )?;
        } else {
            fs::write(&known_case, if mode == "unknown" { "" } else { &known })?;
        }
        let ssh_case = fixture.root.path().join(format!("{mode}.ssh_config"));
        let mut config = original.replace(
            known_path.to_str().context("UTF-8 known path")?,
            known_case.to_str().context("UTF-8 case path")?,
        );
        if mode == "diagnostic" {
            config = format!(
                "Host plain\n ProxyCommand /bin/sh -c 'printf SYNTHETIC_BACKEND_DIAGNOSTIC_641d >&2; exit 1'\n{config}"
            );
        }
        fs::write(&ssh_case, config)?;
        let server_case = fixture.root.path().join(format!("{mode}.toml"));
        fixture.write_server_config(&server_case, &ssh_case)?;
        let client = Client::start(&server_case).await?;
        let scenario = async {
            let reply = exec(&client, "printf MUST_NOT_EXECUTE").await?;
            failed(&reply, "ssh_connect_failed")?;
            ensure!(reply["data"].is_null());
            ensure!(!serde_json::to_string(&reply)?.contains("SYNTHETIC_BACKEND_DIAGNOSTIC_641d"));
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = client.stop().await;
        scenario?;
        let log = log?;
        ensure!(
            !log.text().contains("SYNTHETIC_BACKEND_DIAGNOSTIC_641d"),
            "backend stderr leaked into audit"
        );
    }
    Ok(())
}

async fn shutdown_case(fixture: &Fixture, sigterm: bool) -> Result<()> {
    let work = tempfile::Builder::new()
        .prefix("shutdown-")
        .tempdir_in(fixture.root.path())?;
    let started = work.path().join("started");
    let done = work.path().join("done");
    let mut dispatched = false;
    let mut server = WireServer::start(&fixture.config)?;
    let scenario = async {
        server.initialize().await?;
        let response = server.request(2, "tools/call", json!({"name":"ssh_exec","arguments":{"host":"plain","command":"printf SHUTDOWN_READY"}})).await?;
        ensure!(response["result"]["structuredContent"]["data"]["stdout"] == "SHUTDOWN_READY", "shutdown setup did not run a real command: {response}");
        let command = format!("printf started > {}; sleep 3; printf done > {}", quote(&started.to_string_lossy()), quote(&done.to_string_lossy()));
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_exec","arguments":{"host":"plain","command":command,"timeout_secs":10}}})).await?;
        dispatched = true;
        Fixture::await_file(&started).await?;
        masters(&server.log)
    }.await;
    let stopped = server.stop(sigterm).await;
    // Closing a listener/master is not proof that remote descendants stopped.
    let completed = if dispatched {
        Fixture::await_file(&done).await
    } else {
        Ok(())
    };
    let owned = scenario?;
    stopped?;
    completed?;
    assert_masters_gone(&owned).await
}

async fn shutdown_cases(fixture: &Fixture) -> Result<()> {
    // This master is owned by the test, not by MCP; shutdown must leave it alone.
    let socket_directory = tempfile::Builder::new()
        .prefix("sm-other-")
        .tempdir_in("/tmp")?;
    let socket = socket_directory.path().join("c");
    let unrelated = Process::start(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .args(["-M", "-N", "-T", "-S"])
            .arg(&socket)
            .args(["-o", "ControlMaster=yes", "plain"]),
    )?;
    let scenario = async {
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
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        for sigterm in [false, true, false] {
            shutdown_case(fixture, sigterm).await?;
            let check = support::run(
                Command::new(&fixture.ssh)
                    .arg("-F")
                    .arg(&fixture.ssh_config)
                    .arg("-S")
                    .arg(&socket)
                    .args(["-O", "check", "plain"]),
            )
            .await?;
            ensure!(
                check.status.success() && socket.exists(),
                "MCP shutdown affected unrelated master"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleaned = unrelated.stop().await;
    scenario?;
    cleaned
}

async fn bounded_channels(fixture: &mut Fixture, client: &Client) -> Result<()> {
    let before_auth = fixture.authentications();
    let release = fixture.root.path().join("channel-release");
    let expired = fixture.root.path().join("channel-expired");
    let before_masters = masters(&client.log)?.len();
    let mut requests = Vec::new();
    let mut ready = Vec::new();
    for index in 0..4 {
        let start = fixture.root.path().join(format!("channel-{index}-started"));
        let done = fixture.root.path().join(format!("channel-{index}-done"));
        fixture.eventual_markers.push(done.clone());
        let command = capacity_script(
            &start,
            &release,
            &expired,
            &done,
            &format!("CHANNEL_{index}"),
        );
        requests.push(json!({"host":"resource","command":command,"timeout_secs":15}));
        ready.push(start);
    }
    let forbidden = fixture.root.path().join("excess-channel-dispatched");
    let calls = futures_util::future::join_all(
        requests
            .into_iter()
            .map(|request| client.call("ssh_exec", request)),
    );
    let rejection = async {
        let outcome = async {
            for path in ready {
                Fixture::await_file(&path).await?;
            }
            ensure!(!expired.exists(), "channels expired before rejection");
            let reply = client
                .call(
                    "ssh_exec",
                    json!({
                        "host":"resource",
                        "command":format!("printf WRONG > {}", quote(&forbidden.to_string_lossy())),
                    }),
                )
                .await?;
            failed(&reply, "resource_limit")?;
            ensure!(reply["data"].is_null());
            await_audit(&client.log, "finish", "resource_limit").await?;
            ensure!(!expired.exists(), "channels expired during rejection");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let released = fs::write(&release, b"release");
        outcome?;
        released?;
        Ok::<_, anyhow::Error>(())
    };
    let (outputs, rejected) = tokio::join!(calls, rejection);
    rejected?;
    for (index, output) in outputs.into_iter().enumerate() {
        ensure!(succeeded(&output?)?["stdout"] == format!("CHANNEL_{index}"));
    }
    ensure!(
        !forbidden.exists(),
        "excess channel was queued or dispatched"
    );
    ensure!(
        !expired.exists(),
        "capacity was released by deadline rather than controller"
    );
    fixture.await_authentications(before_auth + 1).await?;
    observed_masters(&client.log, before_masters + 1).await?;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"resource","command":"printf REUSED_AFTER_LIMIT"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "REUSED_AFTER_LIMIT");
    Ok(())
}

async fn lost_command_is_not_replayed(fixture: &mut Fixture, client: &Client) -> Result<()> {
    // bounded_channels left this logical target on the most recently created master.
    let owned = masters(&client.log)?
        .last()
        .cloned()
        .context("resource master")?;
    let before_auth = fixture.authentications();
    let started = fixture.root.path().join("lost-started");
    let done = fixture.root.path().join("lost-done");
    let effects = fixture.root.path().join("lost-effects");
    fixture.eventual_markers.push(done.clone());
    let command = format!(
        "trap '' HUP; printf effect >> {}; printf started > {}; sleep 2; printf done > {}",
        quote(&effects.to_string_lossy()),
        quote(&started.to_string_lossy()),
        quote(&done.to_string_lossy()),
    );
    let request = client.call(
        "ssh_run",
        json!({"host":"resource","argv":["/bin/sh","-c",command]}),
    );
    let disconnect = async {
        Fixture::await_file(&started).await?;
        let closed = support::run(
            Command::new(&fixture.ssh)
                .arg("-F")
                .arg(&fixture.ssh_config)
                .arg("-S")
                .arg(&owned.1)
                .args(["-O", "exit", "plain"]),
        )
        .await?;
        ensure!(
            closed.status.success(),
            "could not close the test-owned master"
        );
        Ok::<_, anyhow::Error>(())
    };
    let (reply, closed) = tokio::join!(request, disconnect);
    closed?;
    let reply = reply?;
    failed(&reply, "connection_lost")?;
    ensure!(reply["error"]["remote_state_unknown"] == true);
    ensure!(reply["data"]["termination"] == "connection_lost");
    ensure!(reply["data"]["exit_code"].is_null());
    ensure!(reply["data"]["remote_may_still_be_running"] == true);
    Fixture::await_file(&done).await?;
    assert_masters_gone(std::slice::from_ref(&owned)).await?;
    let recovered = client
        .call(
            "ssh_exec",
            json!({"host":"resource","command":"printf RECONNECTED_WITHOUT_REPLAY"}),
        )
        .await?;
    ensure!(succeeded(&recovered)?["stdout"] == "RECONNECTED_WITHOUT_REPLAY");
    fixture.await_authentications(before_auth + 1).await?;
    ensure!(
        fs::read(&effects)? == b"effect",
        "lost command was replayed"
    );
    ensure!(
        succeeded(&exec(client, "printf UNRELATED_MASTER_ALIVE").await?)?["stdout"]
            == "UNRELATED_MASTER_ALIVE"
    );
    Ok(())
}

async fn independent_connection_deadlines(fixture: &Fixture, client: &Client) -> Result<()> {
    let before_auth = fixture.authentications();
    let proxy_started = fixture.root.path().join("delayed-started");
    let short = client.call(
        "ssh_exec",
        json!({"host":"delayed","command":"printf SHORT_MUST_NOT_RUN","timeout_secs":1}),
    );
    let follower = async {
        Fixture::await_file(&proxy_started).await?;
        client.call("ssh_exec", json!({"host":"delayed","command":"printf LONG_FOLLOWER_SUCCEEDED","timeout_secs":10})).await
    };
    let (short, follower) = tokio::join!(short, follower);
    let short = short?;
    failed(&short, "timeout")?;
    ensure!(
        short["data"].is_null(),
        "short request dispatched before delayed authentication"
    );
    ensure!(short["error"]["remote_state_unknown"] == false);
    ensure!(
        succeeded(&follower?)?["stdout"] == "LONG_FOLLOWER_SUCCEEDED",
        "creator timeout poisoned a live follower's connection"
    );
    fixture.await_authentications(before_auth + 2).await?;
    Ok(())
}

async fn global_operation_limit(fixture: &mut Fixture, client: &Client) -> Result<()> {
    let before_auth = fixture.authentications();
    let before_masters = masters(&client.log)?.len();
    let mut requests = Vec::new();
    let mut ready = Vec::new();
    let release = fixture.root.path().join("global-release");
    let expired = fixture.root.path().join("global-expired");
    for index in 0..16 {
        let start = fixture.root.path().join(format!("global-{index}-started"));
        let done = fixture.root.path().join(format!("global-{index}-done"));
        fixture.eventual_markers.push(done.clone());
        let command = capacity_script(
            &start,
            &release,
            &expired,
            &done,
            &format!("GLOBAL_{index}"),
        );
        requests.push(
            json!({"host":format!("slots-{}", index / 4),"command":command,"timeout_secs":15}),
        );
        ready.push(start);
    }
    let calls = futures_util::future::join_all(
        requests
            .into_iter()
            .map(|request| client.call("ssh_exec", request)),
    );
    let rejection = async {
        let outcome = async {
            for path in ready {
                Fixture::await_file(&path).await?;
            }
            ensure!(!expired.exists(), "operations expired before rejection");
            let reply = client.call("ssh_targets", json!({})).await?;
            failed(&reply, "resource_limit")?;
            ensure!(
                reply["data"].is_null(),
                "the seventeenth operation was admitted"
            );
            await_audit(&client.log, "reject", "resource_limit").await?;
            ensure!(!expired.exists(), "operations expired during rejection");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let released = fs::write(&release, b"release");
        outcome?;
        released?;
        Ok::<_, anyhow::Error>(())
    };
    let (outputs, rejected) = tokio::join!(calls, rejection);
    rejected?;
    for (index, output) in outputs.into_iter().enumerate() {
        ensure!(succeeded(&output?)?["stdout"] == format!("GLOBAL_{index}"));
    }
    ensure!(
        !expired.exists(),
        "operation capacity was released by deadline"
    );
    fixture.await_authentications(before_auth + 4).await?;
    observed_masters(&client.log, before_masters + 4).await?;
    let targets = client.call("ssh_targets", json!({})).await?;
    ensure!(
        succeeded(&targets)?["mode"] == "configured",
        "completed work did not release operation permits"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_local() -> Result<()> {
    let mut fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let commands = async {
            command_cases(&mut fixture, &client)
                .await
                .context("command fidelity/cancellation scenarios")?;
            bounded_channels(&mut fixture, &client)
                .await
                .context("bounded channel admission")?;
            lost_command_is_not_replayed(&mut fixture, &client)
                .await
                .context("connection loss/no replay")?;
            independent_connection_deadlines(&fixture, &client)
                .await
                .context("independent initialization deadlines")?;
            global_operation_limit(&mut fixture, &client)
                .await
                .context("global operation admission")
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        commands?;
        let log = stopped?;
        assert_masters_gone(&owned?).await?;
        audit_boundary(&log)?;
        strict_keys_and_diagnostics(&fixture).await?;
        shutdown_cases(&fixture).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_channel_timeout() -> Result<()> {
    let mut fixture = Fixture::start_with_sshd_config(indoc! {"
        ChannelTimeout session=1s
    "})
    .await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let commands = async {
            ensure!(succeeded(&exec(&client, "printf PRIMED").await?)?["stdout"] == "PRIMED");
            let owned = masters(&client.log)?;
            ensure!(owned.len() == 1, "expected one ordinary master");
            // Both fixture readiness connections and the application connection
            // have authenticated. Wait for the asynchronously drained log.
            timeout(Duration::from_secs(5), async {
                while fixture.authentications() < 3 {
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("authentication log did not catch up")?;
            let authentications = fixture.authentications();
            let started = fixture.root.path().join("channel-started");
            let done = fixture.root.path().join("channel-done");
            let effects = fixture.root.path().join("channel-effects");
            let sibling_started = fixture.root.path().join("sibling-started");
            let sibling_done = fixture.root.path().join("sibling-done");
            let release = fixture.root.path().join("sibling-release");
            fixture
                .eventual_markers
                .extend([done.clone(), sibling_done.clone()]);
            let quiet = formatdoc! {"
                trap '' HUP
                printf effect >> {effects}
                printf started > {started}
                printf PARTIAL
                printf PARTIAL_ERR >&2
                sleep 5
                printf done > {done}
                ",
                effects = quote(&effects.to_string_lossy()),
                started = quote(&started.to_string_lossy()),
                done = quote(&done.to_string_lossy()),
            };
            // Periodic output prevents this sibling's own inactivity timeout.
            // Its finite loop also bounds host work if an assertion fails.
            let sibling = formatdoc! {r#"
                printf started > {started}
                i=0
                while [ ! -f {release} ] && [ "$i" -lt 60 ]; do
                    printf .
                    sleep 0.1
                    i=$((i + 1))
                done
                printf done > {done}
                printf SIBLING_ALIVE
                "#,
                started = quote(&sibling_started.to_string_lossy()),
                release = quote(&release.to_string_lossy()),
                done = quote(&sibling_done.to_string_lossy()),
            };
            let loss = async {
                Fixture::await_file(&sibling_started).await?;
                let reply = client
                    .call(
                        "ssh_run",
                        json!({"host":"plain","argv":["/bin/sh","-c",quiet]}),
                    )
                    .await?;
                Fixture::await_file(&started).await?;
                failed(&reply, "connection_lost")?;
                ensure!(reply["data"]["termination"] == "connection_lost");
                ensure!(reply["data"]["exit_code"].is_null());
                ensure!(reply["data"]["stdout"] == "PARTIAL");
                ensure!(reply["data"]["stderr"] == "PARTIAL_ERR");
                ensure!(reply["error"]["remote_state_unknown"] == true);
                ensure!(reply["data"]["remote_may_still_be_running"] == true);
                ensure!(!done.exists(), "reply arrived only after remote completion");
                let audit = await_audit(&client.log, "finish", "connection_lost").await?;
                ensure!(audit["exit_code"].is_null());
                ensure!(audit["remote_state_unknown"] == true);
                fs::write(&release, b"release")?;
                Ok::<_, anyhow::Error>(())
            };
            let (loss, sibling) = tokio::join!(loss, exec(&client, &sibling));
            loss?;
            let sibling = sibling?;
            ensure!(
                succeeded(&sibling)?["stdout"]
                    .as_str()
                    .context("sibling stdout")?
                    .ends_with("SIBLING_ALIVE"),
                "channel loss disrupted the active sibling"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read(&effects)? == b"effect",
                "uncertain command was replayed"
            );
            ensure!(succeeded(&exec(&client, "printf REUSED").await?)?["stdout"] == "REUSED");
            let checked = support::run(
                Command::new(&fixture.ssh)
                    .arg("-F")
                    .arg(&fixture.ssh_config)
                    .arg("-S")
                    .arg(&owned[0].1)
                    .args(["-O", "check", "plain"]),
            )
            .await?;
            ensure!(checked.status.success(), "original master is unavailable");
            ensure!(
                String::from_utf8_lossy(&checked.stderr).contains(&format!("pid={}", owned[0].0)),
                "control socket no longer belongs to the original master"
            );
            ensure!(
                masters(&client.log)? == owned,
                "application replaced the healthy master"
            );
            ensure!(
                fixture.authentications() == authentications,
                "channel loss caused additional authentication"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = assert_masters_gone(&owned?).await;
        commands?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_response_wire_budget() -> Result<()> {
    const MIB: usize = 1_048_576;
    const FRAME_LIMIT: usize = 16 * MIB;

    fn output_prefixes(reply: &Value, stdout: &[u8], stderr: &[u8]) -> Result<()> {
        let data = &reply["data"];
        for (stream, emitted) in [("stdout", stdout), ("stderr", stderr)] {
            let expected = String::from_utf8_lossy(emitted);
            let retained = data[stream].as_str().context("missing captured stream")?;
            ensure!(
                expected.starts_with(retained),
                "{stream} is not a valid UTF-8 prefix of the lossily decoded emitted bytes"
            );
            ensure!(
                data[format!("{stream}_truncated")] == (retained.len() < expected.len()),
                "{stream} truncation flag disagrees with retained prefix"
            );
            ensure!(
                data[format!("{stream}_lossy")] == std::str::from_utf8(emitted).is_err(),
                "{stream} lossy flag lost execution evidence"
            );
        }
        ensure!(
            data["stdout_truncated"] == true || data["stderr_truncated"] == true,
            "wire-budget scenario did not truncate either stream"
        );
        ensure!(
            !data["stdout"].as_str().context("stdout")?.is_empty(),
            "wire budget discarded every stdout byte"
        );
        ensure!(data["termination"] == "exited");
        ensure!(data["remote_may_still_be_running"] == false);
        ensure!(data["duration_ms"].is_u64());
        Ok(())
    }

    let mut fixture = Fixture::start().await?;
    let scenario = async {
        let original_config = fs::read_to_string(&fixture.config)?;
        // Omit the fixture's tiny override: both capture and the SDK's incoming
        // frame limit must use their real defaults in this scenario.
        fs::write(
            &fixture.config,
            original_config.replace("max_output_bytes = 1024\n", ""),
        )?;
        let client = Client::start(&fixture.config).await?;
        let sdk = async {
            let effects = fixture.root.path().join("wire-sdk-effects");
            let done = fixture.root.path().join("wire-sdk-done");
            fixture.eventual_markers.push(done.clone());
            let command = formatdoc! {"
                set -e
                printf effect >> {effects}
                dd if=/dev/zero bs=1048576 count=1 2>/dev/null
                {{ dd if=/dev/zero bs=1048576 count=1 2>/dev/null; }} >&2
                printf done > {done}
                exit 0
                ",
                effects = quote(&effects.to_string_lossy()),
                done = quote(&done.to_string_lossy()),
            };
            let reply = exec(&client, &command).await?;
            ensure!(succeeded(&reply)?["exit_code"] == 0);
            let emitted = vec![0; MIB];
            output_prefixes(&reply, &emitted, &emitted)?;
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read(&done)? == b"done",
                "SDK command did not drain to completion"
            );
            ensure!(
                succeeded(&exec(&client, "printf SDK_AFTER_BUDGET").await?)?["stdout"]
                    == "SDK_AFTER_BUDGET",
                "default SDK stopped responding after oversized output"
            );
            ensure!(fs::read(&effects)? == b"effect", "SDK command was replayed");
            ensure!(
                masters(&client.log)?.len() == 1,
                "SDK command replaced its master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let sdk_log = client.log.clone();
        let stopped = client.stop().await;
        let gone = match masters(&sdk_log) {
            Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        };
        sdk?;
        stopped?;
        gone?;

        fs::write(
            &fixture.config,
            original_config.replace("max_output_bytes = 1024", "max_output_bytes = 33554432"),
        )?;
        let mut server = WireServer::start(&fixture.config)?;
        let raw = async {
            server.initialize().await?;
            let effects = fixture.root.path().join("wire-raw-effects");
            let done = fixture.root.path().join("wire-raw-done");
            fixture.eventual_markers.push(done.clone());
            // Invalid UTF-8, multibyte UTF-8, controls, quotes and backslashes
            // precede output well above the default capture cap on each stream.
            let command = formatdoc! {r#"
                set -e
                printf effect >> {effects}
                printf '\377\342\202\254\000\001"\\\n'
                dd if=/dev/zero bs=1048576 count=4 2>/dev/null
                printf '\377\342\202\254\000\001"\\\n' >&2
                dd if=/dev/zero bs=1048576 count=4 2>/dev/null | tr '\000' '\001' >&2
                printf done > {done}
                exit 7
                "#,
                effects = quote(&effects.to_string_lossy()),
                done = quote(&done.to_string_lossy()),
            };
            let id = json!(format!("H02-{}", "\"\\\n\t\u{0000}é".repeat(257)));
            let (response, frame_bytes) = server
                .request_with_size(
                    id.clone(),
                    "tools/call",
                    json!({
                        "name":"ssh_exec",
                        "arguments":{"host":"plain","command":command},
                    }),
                )
                .await?;
            ensure!(response["id"] == id, "escaped string request ID changed");
            ensure!(
                frame_bytes <= FRAME_LIMIT,
                "complete JSON-RPC frame including newline exceeded 16 MiB: {frame_bytes}"
            );
            ensure!(response.get("error").is_none(), "unexpected JSON-RPC error");
            let result = &response["result"];
            let reply = &result["structuredContent"];
            let content = result["content"].as_array().context("raw content array")?;
            ensure!(content.len() == 1 && content[0]["type"] == "text");
            let text: Value = serde_json::from_str(
                content[0]["text"]
                    .as_str()
                    .context("raw compatibility text")?,
            )?;
            ensure!(&text == reply, "raw text and structuredContent disagree");
            ensure!(result["isError"] == true, "exit 7 lost tool error status");
            failed(reply, "command_failed")?;
            ensure!(reply["data"]["exit_code"] == 7, "exit 7 evidence was lost");
            let prefix = b"\xff\xe2\x82\xac\x00\x01\"\\\n";
            let mut stdout = prefix.to_vec();
            stdout.resize(prefix.len() + 4 * MIB, 0);
            let mut stderr = prefix.to_vec();
            stderr.resize(prefix.len() + 4 * MIB, 1);
            output_prefixes(reply, &stdout, &stderr)?;
            ensure!(
                reply["data"]["stdout"]
                    .as_str()
                    .context("raw stdout")?
                    .len()
                    > MIB,
                "elevated capture cap did not retain output beyond the default cap"
            );
            ensure!(reply["error"]["remote_state_unknown"] == false);
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read(&done)? == b"done",
                "raw command did not drain to completion"
            );
            let after = server
                .request(
                    3,
                    "tools/call",
                    json!({"name":"ssh_exec","arguments":{
                        "host":"plain","command":"printf RAW_AFTER_BUDGET",
                    }}),
                )
                .await?;
            ensure!(
                after["result"]["structuredContent"]["data"]["stdout"] == "RAW_AFTER_BUDGET",
                "raw server stopped responding after clipped output"
            );
            ensure!(fs::read(&effects)? == b"effect", "raw command was replayed");
            ensure!(
                masters(&server.log)?.len() == 1,
                "raw command replaced its master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let raw_log = server.log.clone();
        let stopped = server.stop(false).await;
        let gone = match masters(&raw_log) {
            Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        };
        raw?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_encoded_command_budget() -> Result<()> {
    const LIMIT: usize = 65_536;

    fn activity(fixture: &Fixture) -> (usize, usize, usize) {
        let count = |needle: &str| {
            fixture
                .listeners
                .iter()
                .map(|listener| {
                    listener
                        .log
                        .text()
                        .lines()
                        .filter(|line| line.contains(needle))
                        .count()
                })
                .sum()
        };
        (
            count("Accepted publickey"),
            count("Starting session: command"),
            count("Close session:"),
        )
    }

    async fn await_rejections(client: &Client, count: usize) -> Result<()> {
        timeout(Duration::from_secs(5), async {
            loop {
                let rejected = client
                    .log
                    .records()?
                    .iter()
                    .filter(|record| {
                        record["event"] == "reject" && record["error_code"] == "invalid_argument"
                    })
                    .count();
                if rejected >= count {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("encoded-size rejection audit did not catch up")?
    }

    let fixture = Fixture::start().await?;
    let scenario = async {
        // Readiness clients disconnect their entire connections rather than
        // closing channels on a persistent master. Await those disconnect logs.
        timeout(Duration::from_secs(5), async {
            while !fixture.listeners.iter().all(|listener| {
                let text = listener.log.text();
                text.contains("Accepted publickey") && text.contains("Disconnected from user ")
            }) {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("readiness disconnect logs did not catch up")?;
        let baseline = activity(&fixture);
        let client = Client::start(&fixture.config).await?;
        let commands = async {
            let mut argv = vec![""; 100_001];
            argv[0] = "/usr/bin/true";
            for (name, arguments) in [
                (
                    "ssh_exec",
                    json!({"host":"plain","command":format!("#{}", "'".repeat(LIMIT - 1))}),
                ),
                (
                    "ssh_exec",
                    json!({"host":"plain","command":"true","cwd":format!("/{}", "'".repeat(8192))}),
                ),
                // This authorized target must never connect, much less run host sudo.
                (
                    "ssh_sudo",
                    json!({"host":"restricted","user":"root","argv":argv}),
                ),
            ] {
                let reply = client.call(name, arguments).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(
                    reply["data"].is_null(),
                    "oversize request returned execution data"
                );
                ensure!(reply["error"]["remote_state_unknown"] == false);
            }
            await_rejections(&client, 3).await?;
            ensure!(
                masters(&client.log)?.is_empty(),
                "rejection acquired a master"
            );
            ensure!(
                activity(&fixture) == baseline,
                "rejection reached SSH authentication/session"
            );

            // Use the pinned public encoder as an independent size oracle.
            let encoded_len = |script: &str| {
                ["/bin/sh", "-c", script]
                    .into_iter()
                    .map(|arg| shell_escape::unix::escape(arg.into()).len())
                    .sum::<usize>()
                    + 2
            };
            let literal = "quotes ' \" bang! Unicode λ\n$HOME; `false` \\ end";
            let mut script = format!("printf %s {}\n#", quote(literal));
            let padding = LIMIT
                .checked_sub(encoded_len(&script))
                .context("boundary prefix too large")?;
            script.push_str(&"x".repeat(padding));
            ensure!(
                encoded_len(&script) == LIMIT,
                "test did not reach exact encoded boundary"
            );
            let reply = exec(&client, &script).await?;
            let data = succeeded(&reply)?;
            ensure!(
                data["stdout"] == literal && data["stderr"] == "" && data["exit_code"] == 0,
                "exact encoded boundary lost literal fidelity: {reply}"
            );
            timeout(Duration::from_secs(5), async {
                while activity(&fixture).2 < baseline.2 + 1 || masters(&client.log)?.is_empty() {
                    sleep(Duration::from_millis(20)).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .context("boundary session/master logs did not catch up")??;
            let connected = activity(&fixture);
            ensure!(connected == (baseline.0 + 1, baseline.1 + 1, baseline.2 + 1));
            let owned = masters(&client.log)?;
            ensure!(
                owned.len() == 1,
                "boundary command did not own exactly one master"
            );

            script.push('x');
            ensure!(encoded_len(&script) == LIMIT + 1);
            let reply = exec(&client, &script).await?;
            failed(&reply, "invalid_argument")?;
            ensure!(reply["data"].is_null());
            ensure!(reply["error"]["remote_state_unknown"] == false);
            await_rejections(&client, 4).await?;
            ensure!(
                masters(&client.log)? == owned,
                "one-byte-over request acquired a master"
            );
            ensure!(
                activity(&fixture) == connected,
                "one-byte-over request opened a channel"
            );
            let reply = exec(&client, "printf AFTER_H03").await?;
            ensure!(succeeded(&reply)?["stdout"] == "AFTER_H03");
            // The later successful session is a log-drain barrier: neither an
            // old readiness record nor a fixed sleep proves absence of dispatch.
            timeout(Duration::from_secs(5), async {
                while activity(&fixture).2 < connected.2 + 1 {
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("post-rejection session-close log did not catch up")?;
            ensure!(
                activity(&fixture) == (connected.0, connected.1 + 1, connected.2 + 1),
                "oversize request dispatched or replaced the authenticated connection"
            );
            ensure!(
                masters(&client.log)? == owned,
                "existing master was not reusable"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = client.log.clone();
        let stopped = client.stop().await;
        let gone = match masters(&log) {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        commands?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_setenv_isolation() -> Result<()> {
    let server = Fixture::sftp_server()?;
    // A trusted guard observes the subsystem's environment before real SFTP.
    // sshd reassembles subsystem argv for the login shell; nested apostrophes
    // would reach the inner exec literally. This validated Nix path needs none.
    let guard = format!(
        concat!(
            "[ \"$SSH_MCP\" = 1 ] && ",
            "[ \"${{SSH_MCP_H04_HOST+x}}\" != x ] && ",
            "[ \"${{SSH_MCP_H04_MATCH+x}}\" != x ] && ",
            "[ \"${{SSH_MCP_H04_INCLUDE+x}}\" != x ] || exit 93; exec {}"
        ),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&guard));
    let fixture = Fixture::start_with_sftp_subsystem(
        indoc! {"
        AcceptEnv SSH_MCP SSH_MCP_H04_HOST SSH_MCP_H04_MATCH SSH_MCP_H04_INCLUDE
    "},
        &subsystem,
    )
    .await?;
    let scenario = async {
        let controls = [
            (
                "plain",
                "SSH_MCP_H04_HOST",
                "h04-host-secret",
                "operator-host",
            ),
            (
                "viajump",
                "SSH_MCP_H04_MATCH",
                "h04-match-secret",
                "operator-match",
            ),
            (
                "nosftp",
                "SSH_MCP_H04_INCLUDE",
                "h04-include-secret",
                "operator-include",
            ),
        ];
        let inherited = fixture.root.path().join("inherited-env.conf");
        fs::write(
            &inherited,
            indoc! {"
            Host nosftp
                SetEnv SSH_MCP_H04_INCLUDE=h04-include-secret SSH_MCP=operator-include
            Host *
        "},
        )?;
        let original = fs::read_to_string(&fixture.ssh_config)?;
        fs::write(
            &fixture.ssh_config,
            formatdoc! {"
            Host plain
                SetEnv SSH_MCP_H04_HOST=h04-host-secret SSH_MCP=operator-host
            Match originalhost viajump
                SetEnv SSH_MCP_H04_MATCH=h04-match-secret SSH_MCP=operator-match
            Host nosftp
                Port {sftp_port}
            Host *
                Include {inherited}
            {original}
            ",
                inherited = inherited.display(),
                sftp_port = fixture.ports[0],
            },
        )?;

        // Positive controls prove each configured source reaches real sessions
        // when used by ordinary OpenSSH, rather than relying on ssh -G.
        for &(host, variable, secret, marker) in &controls {
            let command = format!("printf '%s:%s' \"${variable}\" \"$SSH_MCP\"");
            let output = fixture.direct(host, &command).await?;
            let expected = format!("{secret}:{marker}");
            ensure!(
                output.status.success(),
                "fixture SetEnv control failed for {host}"
            );
            ensure!(
                output.stdout.as_slice() == expected.as_bytes(),
                "fixture did not accept the configured environment for {host}"
            );
        }

        let client = Client::start(&fixture.config).await?;
        let probe = indoc! {r#"
            printf '%s:%s:%s:%s' "$SSH_MCP" \
                "${SSH_MCP_H04_HOST+x}" \
                "${SSH_MCP_H04_MATCH+x}" \
                "${SSH_MCP_H04_INCLUDE+x}"
        "#};
        let commands = async {
            for &(host, _, _, _) in &controls {
                let reply = client
                    .call("ssh_exec", json!({"host":host,"command":probe}))
                    .await?;
                let data = succeeded(&reply)?;
                ensure!(data["stdout"] == "1:::", "configured SetEnv reached {host}");
                ensure!(data["exit_code"] == 0);
            }
            let path = fixture.root.path().join("environment-read");
            fs::write(&path, b"SFTP_ENV_ISOLATED")?;
            for &(host, _, _, _) in &controls {
                let reply = client
                    .call("ssh_read_file", json!({"host":host,"path":path}))
                    .await?;
                ensure!(succeeded(&reply)?["content"] == "SFTP_ENV_ISOLATED");
                let reply = client
                    .call("ssh_stat", json!({"host":host,"path":path}))
                    .await?;
                ensure!(succeeded(&reply)? == &native_stat_data(&path, false)?);
                let reply = client
                    .call(
                        "ssh_list_directory",
                        json!({"host":host,"path":fixture.root.path()}),
                    )
                    .await?;
                let entries = succeeded(&reply)?["entries"]
                    .as_array()
                    .context("guarded listing")?;
                let entry = entries
                    .iter()
                    .find(|entry| entry["name"] == "environment-read")
                    .context("guarded SFTP omitted the created file")?;
                ensure!(entry["metadata"] == native_stat_data(&path, false)?);
                let destination = fixture
                    .root
                    .path()
                    .join(format!("environment-write-{host}"));
                let reply = client
                    .call(
                        "ssh_write_file",
                        json!({"host":host,"path":destination,"content":"WRITE_ENV_ISOLATED"}),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":18}));
                ensure!(fs::read(&destination)? == b"WRITE_ENV_ISOLATED");
            }
            let reply = exec(&client, probe).await?;
            ensure!(
                succeeded(&reply)?["stdout"] == "1:::",
                "reuse inherited SetEnv"
            );
            ensure!(
                masters(&client.log)?.len() == 3,
                "ordinary masters were not reused"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = client.log.clone();
        let stopped = client.stop().await;
        let gone = match masters(&log) {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        commands?;
        let log = stopped?;
        gone?;
        let audit = log.text();
        for &(_, _, secret, _) in &controls {
            ensure!(
                !audit.contains(secret),
                "synthetic environment value reached audit"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

// H05 uses a closed pipe, not a sink: every later diagnostic write gets EPIPE.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking and a usable non-root local account"]
async fn ssh_closed_stderr() -> Result<()> {
    fn connection_activity(fixture: &Fixture) -> (usize, usize) {
        let text = fixture.listeners[0].log.text();
        (
            text.lines()
                .filter(|line| line.contains("Accepted publickey"))
                .count(),
            text.lines()
                .filter(|line| {
                    line.contains("Disconnected from user ")
                        || line.contains("Connection closed by ")
                })
                .count(),
        )
    }

    async fn control(
        fixture: &Fixture,
        socket: &std::path::Path,
        operation: &str,
    ) -> Result<std::process::Output> {
        support::run(
            Command::new(&fixture.ssh)
                .arg("-F")
                .arg(&fixture.ssh_config)
                .arg("-S")
                .arg(socket)
                .args(["-O", operation, "plain"]),
        )
        .await
    }

    async fn call(
        server: &mut WireServer,
        id: u64,
        host: &str,
        command: &str,
        cwd: &std::path::Path,
    ) -> Result<Value> {
        let response = server.request(id, "tools/call",
            json!({"name":"ssh_exec","arguments":{"host":host,"command":command,"cwd":cwd,"timeout_secs":10}}))
            .await?;
        ensure!(response["error"].is_null(), "wire call failed: {response}");
        ensure!(
            response["result"]["structuredContent"].is_object(),
            "missing envelope: {response}"
        );
        Ok(response["result"]["structuredContent"].clone())
    }

    let fixture = Fixture::start().await?;
    let scenario = async {
        // Direct readiness clients close whole connections, not persistent channels.
        timeout(support::CLEANUP, async {
            while !fixture.listeners.iter().all(|listener| {
                listener.log.text().contains("Disconnected from user ")
            }) {
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("readiness clients did not disconnect")?;
        let initial = connection_activity(&fixture);

        let sockets = tempfile::Builder::new().prefix("sm-h05-").tempdir_in("/tmp")?;
        let socket = sockets.path().join("c");
        let external = Process::start(Command::new(&fixture.ssh)
            .arg("-F").arg(&fixture.ssh_config)
            .args(["-M", "-N", "-T", "-S"]).arg(&socket)
            .args(["-o", "ControlMaster=yes", "plain"]))?;
        let external_pid = external.child.id().context("external master PID")?;
        let cases = async {
            timeout(support::CLEANUP, async {
                loop {
                    if control(&fixture, &socket, "check").await?.status.success() {
                        break;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
                Ok::<_, anyhow::Error>(())
            }).await.context("external master was not ready")??;
            timeout(support::CLEANUP, async {
                while connection_activity(&fixture).0 < initial.0 + 1 {
                    sleep(Duration::from_millis(20)).await;
                }
            }).await.context("external master authentication log did not catch up")?;
            ensure!(connection_activity(&fixture).0 == initial.0 + 1,
                "external master opened extra authenticated connections");

            for sigterm in [false, true] {
                for phase in ["fresh", "ready", "delayed"] {
                    let work = tempfile::Builder::new().prefix("h05-")
                        .tempdir_in(fixture.root.path())?;
                    let started = work.path().join("started");
                    let done = work.path().join("done");
                    let shutdown_started = work.path().join("shutdown-started");
                    let shutdown_done = work.path().join("shutdown-done");
                    let proxy_started = fixture.root.path().join("delayed-started");
                    if proxy_started.exists() {
                        fs::remove_file(&proxy_started)?;
                    }
                    let baseline = connection_activity(&fixture);
                    let mut server = WireServer::start(&fixture.config)?;
                    let mut owned = Vec::new();
                    let commands = async {
                        server.initialize().await?;
                        if phase == "fresh" {
                            server.close_stderr().await?;
                        } else if phase == "ready" {
                            let reply = call(&mut server, 2, "plain", "printf READY", work.path()).await?;
                            ensure!(succeeded(&reply)?["stdout"] == "READY");
                            timeout(support::CLEANUP, async {
                                loop {
                                    owned = masters(&server.log)?;
                                    if !owned.is_empty() {
                                        break;
                                    }
                                    sleep(Duration::from_millis(20)).await;
                                }
                                Ok::<_, anyhow::Error>(())
                            }).await??;
                            let command = format!(
                                "trap '' HUP; cd {}; printf started > {}; sleep 1; printf done > {}; printf FINISHED",
                                quote(&work.path().to_string_lossy()),
                                quote(&started.to_string_lossy()), quote(&done.to_string_lossy()));
                            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                                "params":{"name":"ssh_exec","arguments":{"host":"plain","command":command}}})).await?;
                            Fixture::await_file(&started).await?;
                            server.close_stderr().await?;
                            let response = server.receive(json!(3)).await?.0;
                            ensure!(succeeded(&response["result"]["structuredContent"])?["stdout"] == "FINISHED");
                            Fixture::await_file(&done).await?;

                            // Force master_finish after diagnostics close, not just master_start.
                            ensure!(control(&fixture, &owned[0].1, "exit").await?.status.success());
                            assert_masters_gone(&owned).await?;
                            timeout(support::CLEANUP, async {
                                for id in 10..110 {
                                    let reply = call(&mut server, id, "plain", "printf RECOVERED", work.path()).await?;
                                    if reply["error"].is_null() {
                                        ensure!(succeeded(&reply)?["stdout"] == "RECOVERED");
                                        return Ok::<_, anyhow::Error>(());
                                    }
                                    // Explicitly retry only a known-not-dispatched read-only probe.
                                    failed(&reply, "connection_lost")?;
                                    ensure!(reply["data"].is_null());
                                    ensure!(reply["error"]["remote_state_unknown"] == false);
                                    sleep(Duration::from_millis(20)).await;
                                }
                                anyhow::bail!("finished pool entry was not removed")
                            }).await.context("pool recovery exceeded deadline")??;
                        } else {
                            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                                "params":{"name":"ssh_exec","arguments":{"host":"delayed",
                                    "command":"printf DELAYED_READY","cwd":work.path(),"timeout_secs":10}}})).await?;
                            Fixture::await_file(&proxy_started).await?;
                            timeout(support::CLEANUP, async {
                                loop {
                                    owned = masters(&server.log)?;
                                    if !owned.is_empty() {
                                        break;
                                    }
                                    sleep(Duration::from_millis(20)).await;
                                }
                                Ok::<_, anyhow::Error>(())
                            }).await??;
                            server.close_stderr().await?;
                            let response = server.receive(json!(4)).await?.0;
                            ensure!(succeeded(&response["result"]["structuredContent"])?["stdout"] == "DELAYED_READY");
                        }

                        let host = if phase == "delayed" { "delayed" } else { "plain" };
                        // More than both channel (4) and global (16) capacities:
                        // leaked permits or an unusable pooled channel cannot hide.
                        for id in 200..220 {
                            let reply = call(&mut server, id, host, "printf REUSED", work.path()).await?;
                            ensure!(succeeded(&reply)?["stdout"] == "REUSED");
                        }
                        let command = format!(
                            "cd {}; trap '' HUP; printf started > {}; sleep 2; printf done > {}",
                            quote(&work.path().to_string_lossy()),
                            quote(&shutdown_started.to_string_lossy()),
                            quote(&shutdown_done.to_string_lossy()));
                        server.send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
                            "params":{"name":"ssh_exec","arguments":{"host":host,"command":command}}})).await?;
                        Fixture::await_file(&shutdown_started).await?;
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    // Result-based teardown runs even if any assertion above failed.
                    let stopped = server.stop(sigterm).await;
                    let completed = async {
                        for (start, finish) in [
                            (&started, &done), (&shutdown_started, &shutdown_done),
                        ] {
                            if start.exists() {
                                Fixture::await_file(finish).await?;
                            }
                        }
                        Ok::<_, anyhow::Error>(())
                    }.await;
                    let gone = if owned.is_empty() {
                        Ok(())
                    } else {
                        assert_masters_gone(&owned).await
                    };
                    let disconnected = timeout(support::CLEANUP, async {
                        loop {
                            let current = connection_activity(&fixture);
                            if current.0 > baseline.0
                                && current.1 - baseline.1 >= current.0 - baseline.0 {
                                break;
                            }
                            sleep(Duration::from_millis(20)).await;
                        }
                    }).await.context("MCP fixture connections did not disconnect");
                    commands.with_context(|| format!("closed stderr {phase}, SIGTERM={sigterm}"))?;
                    stopped?;
                    completed?;
                    gone?;
                    disconnected?;
                    let expected_connections = if phase == "fresh" { 1 } else { 2 };
                    ensure!(connection_activity(&fixture).0 - baseline.0 == expected_connections,
                        "closed diagnostics prevented master reuse");
                    let check = control(&fixture, &socket, "check").await?;
                    ensure!(check.status.success() && socket.exists(), "external master was removed");
                    ensure!(String::from_utf8_lossy(&check.stderr)
                        .contains(&format!("pid={external_pid}")), "external master PID changed");
                    let command = format!("cd {}; printf EXTERNAL_ALIVE",
                        quote(&work.path().to_string_lossy()));
                    let usable = support::run(Command::new(&fixture.ssh)
                        .arg("-F").arg(&fixture.ssh_config).arg("-S").arg(&socket)
                        .args(["-T", "plain", &command])).await?;
                    ensure!(usable.status.success() && usable.stdout == b"EXTERNAL_ALIVE");
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let cleaned = external.stop().await;
        cases?;
        cleaned
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

// Independent local oracle for cases without a published SHA-256 vector.
// find_program canonicalizes Nix multicall applets, so preserve sha256sum argv[0].
async fn local_sha256(bytes: &[u8]) -> Result<String> {
    use std::io::Write;

    ensure!(
        bytes.len() <= 300_000,
        "local hash input exceeds test bound"
    );
    let program = support::find_program("sha256sum")?;
    ensure!(
        program.starts_with("/nix/store"),
        "sha256sum must be Nix-provided"
    );
    let mut input = tempfile::NamedTempFile::new()?;
    input.write_all(bytes)?;
    let output = support::run(
        Command::new(program)
            .arg0("sha256sum")
            .args(["--binary", "--zero", "--"])
            .arg(input.path()),
    )
    .await?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "local SHA-256 oracle failed"
    );
    ensure!(
        output.stdout.len() == 67 + input.path().as_os_str().len()
            && output.stdout[64..66] == *b" *"
            && output.stdout.last() == Some(&0),
        "unexpected bounded SHA-256 oracle output"
    );
    let digest = std::str::from_utf8(&output.stdout[..64])?;
    ensure!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    Ok(digest.to_owned())
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const MISMATCH_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn read_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let root = fixture.root.path();
    {
        let owned = observed_masters(&client.log, 1).await?;
        live_transport(fixture, client, &owned[0], 1, 3).await?;
    }
    let before_reads = fixture.listeners[0].log.text();
    let text = root.join("read-text");
    fs::write(&text, b"abcdef")?;
    let empty = root.join("read-empty");
    fs::write(&empty, b"")?;
    // Exact metadata also distinguishes lookahead from incorrectly consuming it.
    for (path, offset, limit, content, next, eof) in [
        (&text, 0, None, "abcdef", 6, true),
        (&text, 0, Some(3), "abc", 3, false),
        (&text, 3, Some(3), "def", 6, true),
        (&text, 5, Some(8), "f", 6, true),
        (&text, 6, Some(1), "", 6, true),
        (&text, 99, Some(1), "", 99, true),
        (&text, u64::MAX, Some(1), "", u64::MAX, true),
        (&empty, 0, None, "", 0, true),
    ] {
        let mut args = json!({"host":"plain","path":path,"offset":offset});
        if let Some(limit) = limit {
            args["max_bytes"] = json!(limit);
        }
        // Published empty/abc vectors also exercise case-insensitive verification.
        // The abc read has a fourth byte available: it must not enter the digest.
        let digest = match content {
            "" => EMPTY_SHA256.to_owned(),
            "abc" => ABC_SHA256.to_owned(),
            _ => local_sha256(content.as_bytes()).await?,
        };
        if content == "abc" {
            args["expected_content_sha256"] = json!(ABC_SHA256.to_ascii_uppercase());
        } else if content.is_empty() {
            args["expected_content_sha256"] = json!(EMPTY_SHA256);
        }
        let reply = client.call("ssh_read_file", args).await?;
        ensure!(
            succeeded(&reply)?
                == &json!({
                    "content":content,"encoding":"utf8","bytes_read":content.len(),
                    "next_offset":next,"eof":eof,"content_sha256":digest
                }),
            "read range offset={offset}, limit={limit:?}: {reply}"
        );
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .context("native prerequisite: current account")?;
    let home = fs::canonicalize(user.dir).context("native prerequisite: usable account home")?;
    let depth = home
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    let mut relative = PathBuf::with_capacity(depth * 3 + root.as_os_str().len() + 16);
    for _ in 0..depth {
        relative.push("..");
    }
    relative.push(root.strip_prefix("/")?);
    relative.push("read-text");
    let reply = client
        .call("ssh_read_file", json!({"host":"plain","path":relative}))
        .await?;
    ensure!(
        succeeded(&reply)?["content"] == "abcdef",
        "relative SFTP path used the wrong initial directory"
    );

    let large = root.join("read-multiple-packets");
    let contents = "0123456789".repeat(30_001);
    fs::write(&large, contents.as_bytes())?;
    let reply = client
        .call(
            "ssh_read_file",
            json!({"host":"plain","path":large,"max_bytes":300_000}),
        )
        .await?;
    let data = succeeded(&reply)?;
    ensure!(data["content"].as_str() == Some(&contents[..300_000]));
    ensure!(
        data["bytes_read"] == 300_000 && data["next_offset"] == 300_000 && data["eof"] == false
    );
    ensure!(data["content_sha256"] == local_sha256(&contents.as_bytes()[..300_000]).await?);
    let binary = root.join("read-binary");
    fs::write(&binary, [0, 255, 128, 65])?;
    let binary_digest = local_sha256(&[0, 255, 128, 65]).await?;
    let reply = client
        .call(
            "ssh_read_file",
            json!({"host":"plain","path":binary,"encoding":"base64",
                "expected_content_sha256":binary_digest}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":"AP+AQQ==","encoding":"base64","bytes_read":4,"next_offset":4,"eof":true,
                "content_sha256":binary_digest
            })
    );
    let unicode = root.join("read-unicode");
    fs::write(&unicode, "é!")?;
    for args in [
        json!({"host":"plain","path":unicode,"max_bytes":1}),
        json!({"host":"plain","path":unicode,"offset":1}),
        json!({"host":"plain","path":binary}),
    ] {
        let reply = client.call("ssh_read_file", args).await?;
        failed(&reply, "invalid_encoding")?;
        ensure!(reply["data"].is_null(), "lossy or partial UTF8 success");
        ensure!(reply["error"]["remote_state_unknown"] == false);
    }
    // Expansion would select a different path; the substitution is side-effect free.
    let unusual = root.join("quote' \" ; $(printf EVALUATED)\n*");
    fs::write(&unusual, b"LITERAL_PATH")?;
    let reply = client
        .call("ssh_read_file", json!({"host":"plain","path":unusual}))
        .await?;
    ensure!(succeeded(&reply)?["content"] == "LITERAL_PATH");

    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    let before = fixture.listeners[0].log.text();
    let sessions = |text: &str, kind: &str| {
        text.lines()
            .filter(|line| line.contains("Starting session:") && line.contains(kind))
            .count()
    };
    let reply = client
        .call(
            "ssh_read_file",
            json!({"host":"plain","path":unusual,"expected_content_sha256":MISMATCH_SHA256}),
        )
        .await?;
    failed(&reply, "checksum_mismatch")?;
    ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
    let serialized = serde_json::to_string(&reply)?;
    let actual_digest = local_sha256(b"LITERAL_PATH").await?;
    for secret in ["LITERAL_PATH", MISMATCH_SHA256, actual_digest.as_str()] {
        ensure!(
            !serialized.contains(secret),
            "checksum failure disclosed read payload"
        );
    }
    let audit = await_audit(&client.log, "finish", "checksum_mismatch").await?;
    ensure!(audit["identity_role"] == "ordinary" && audit["remote_state_unknown"] == false);
    ensure!(
        live_transport(fixture, client, &owned[0], 1, 3).await? == transport,
        "checksum mismatch replaced the healthy ordinary master"
    );
    // The transport probe drains listener logs. A mismatch opens exactly one
    // SFTP session, and the only shell command is that explicit health probe.
    let after = fixture.listeners[0].log.text();
    ensure!(
        sessions(&after, "subsystem 'sftp'") == sessions(&before, "subsystem 'sftp'") + 1,
        "checksum mismatch retried its SFTP session"
    );
    ensure!(
        sessions(&after, "command") == sessions(&before, "command") + 1,
        "SFTP verification executed an unexpected remote shell helper"
    );
    for secret in [
        "LITERAL_PATH",
        MISMATCH_SHA256,
        actual_digest.as_str(),
        ABC_SHA256,
        &ABC_SHA256.to_ascii_uppercase(),
        EMPTY_SHA256,
        binary_digest.as_str(),
    ] {
        ensure!(
            !client.log.text().contains(secret),
            "read audit disclosed content or digest"
        );
    }
    ensure!(
        sessions(&after, "command") == sessions(&before_reads, "command") + 2,
        "range hashing or expected-digest verification ran a remote shell helper"
    );

    let denied = root.join("read-denied");
    fs::write(&denied, b"PRIVATE")?;
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    for (path, code) in [
        (root.join("read-missing"), "not_found"),
        (denied, "permission_denied"),
    ] {
        let reply = client
            .call("ssh_read_file", json!({"host":"plain","path":path}))
            .await?;
        failed(&reply, code)?;
        ensure!(reply["data"].is_null());
        ensure!(reply["error"]["remote_state_unknown"] == false);
    }
    let default_range = root.join("read-default-range");
    fs::write(&default_range, vec![b'a'; 65_537])?;
    let default_digest = local_sha256(&vec![b'a'; 65_536]).await?;
    let reply = client
        .call(
            "ssh_read_file",
            json!({"host":"plain","path":default_range}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":"a".repeat(65_536),"encoding":"utf8","bytes_read":65_536,
                "next_offset":65_536,"eof":false,"content_sha256":default_digest
            }),
        "default read must be bounded with one-byte lookahead"
    );
    Ok(())
}

async fn blocked_reads() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-ready");
    let server = Fixture::sftp_server()?;
    for path in [&started, &done, &server] {
        ensure!(
            path.to_str().is_some_and(|path| path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_./+".contains(&byte))),
            "native prerequisite: shell-safe subsystem fixture path"
        );
    }
    // This finite fault delays the real protocol, not readiness observation.
    // Both markers are observed; no test passes merely by sleeping long enough.
    let script = format!(
        concat!(
            "trap \"\" HUP; printf started > {started}; ",
            "sleep 5; printf done > {done}; exec {server}",
        ),
        started = started.display(),
        done = done.display(),
        server = server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf BLOCKED_READ_MASTER").await?)?["stdout"]
                    == "BLOCKED_READ_MASTER"
            );
            let owned = observed_masters(&client.log, 1).await?;
            fixture.await_authentications(3).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let path = fixture.root.path().join("delayed-read");
            fs::write(&path, b"X")?;
            for cancel in [false, true] {
                for marker in [&started, &done] {
                    if marker.exists() {
                        fs::remove_file(marker)?;
                    }
                }
                let args = json!({"host":"plain","path":path,"max_bytes":1,
                    "timeout_secs":if cancel { 10 } else { 1 }});
                let result = async {
                    if cancel {
                        let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
                            "ssh_read_file",
                            args,
                        )));
                        let handle = timeout(
                            Duration::from_secs(5),
                            client
                                .service
                                .send_cancellable_request(request, PeerRequestOptions::default()),
                        )
                        .await??;
                        Fixture::await_file(&started).await?;
                        ensure!(
                            !done.exists(),
                            "subsystem fault finished before cancellation"
                        );
                        ensure!(
                            succeeded(&exec(&client, "printf SFTP_SIBLING").await?)?["stdout"]
                                == "SFTP_SIBLING"
                        );
                        timeout(
                            Duration::from_secs(5),
                            handle.cancel(Some("native SFTP cancellation".into())),
                        )
                        .await??;
                        let audit = await_audit(&client.log, "finish", "cancelled").await?;
                        ensure!(audit["remote_state_unknown"] == true);
                    } else {
                        let blocked = client.call("ssh_read_file", args);
                        let sibling = async {
                            Fixture::await_file(&started).await?;
                            let reply = exec(&client, "printf SFTP_SIBLING").await?;
                            ensure!(succeeded(&reply)?["stdout"] == "SFTP_SIBLING");
                            Ok::<_, anyhow::Error>(())
                        };
                        let (reply, sibling) = tokio::join!(blocked, sibling);
                        sibling?;
                        let reply = reply?;
                        failed(&reply, "timeout")?;
                        ensure!(reply["data"].is_null());
                        ensure!(reply["error"]["remote_state_unknown"] == true);
                        await_audit(&client.log, "finish", "timeout").await?;
                    }
                    ensure!(
                        !done.exists(),
                        "cancellation waited for remote startup to finish"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                // The channel close is not proof that the remote prefix ended.
                let completed = Fixture::await_file(&done).await;
                result?;
                completed?;
                ensure!(
                    live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                    "cancelled file read replaced the ordinary master"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_read_file() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf READ_MASTER").await?)?["stdout"] == "READ_MASTER"
            );
            read_cases(&fixture, &client).await?;
            blocked_reads().await?;
            let reply = client
                .call(
                    "ssh_read_file",
                    json!({
                        "host":"nosftp","path":fixture.root.path().join("read-text")
                    }),
                )
                .await?;
            let code = reply["error"]["code"]
                .as_str()
                .context("subsystem denial must fail")?;
            ensure!(
                matches!(code, "unsupported" | "io_error" | "connection_lost"),
                "untyped subsystem denial must not masquerade as authentication failure: {reply}"
            );
            ensure!(reply["data"].is_null(), "missing subsystem used a fallback");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client
                .call(
                    "ssh_exec",
                    json!({"host":"nosftp","command":"printf NO_FALLBACK_MASTER_ALIVE"}),
                )
                .await?;
            ensure!(succeeded(&reply)?["stdout"] == "NO_FALLBACK_MASTER_ALIVE");
            ensure!(
                masters(&client.log)? == before,
                "subsystem denial discarded a healthy master"
            );
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        ensure!(
            !log.text().contains("LITERAL_PATH"),
            "requested file content reached audit"
        );
        for record in log
            .final_records()?
            .iter()
            .filter(|record| record["tool"] == "ssh_read_file")
        {
            ensure!(
                record["identity_role"] == "ordinary",
                "read used a nonordinary identity"
            );
            for field in ["content", "content_sha256", "expected_content_sha256"] {
                ensure!(
                    record.get(field).is_none(),
                    "read audit includes payload field {field}"
                );
            }
        }
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_read_cleanup() -> Result<()> {
    let work = tempfile::tempdir()?;
    let done = work.path().join("channel-close-done");
    let protocol_done = work.path().join("protocol-done");
    let server = Fixture::sftp_server()?;
    for path in [&done, &protocol_done, &server] {
        ensure!(
            path.to_str().is_some_and(|path| path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_./+".contains(&byte))),
            "native prerequisite: shell-safe subsystem fixture path"
        );
    }
    // The real server exits successfully, then the configured session holds its
    // channel open. Observe both protocol and session completion, not a delay.
    let script = format!(
        "trap \"\" HUP; {server} && printf closed > {protocol_done}; sleep 5; printf done > {done}",
        done = done.display(),
        protocol_done = protocol_done.display(),
        server = server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf CLEANUP_MASTER").await?)?["stdout"]
                    == "CLEANUP_MASTER"
            );
            let owned = observed_masters(&client.log, 1).await?;
            fixture.await_authentications(3).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let path = fixture.root.path().join("cleanup-read");
            fs::write(&path, b"X")?;
            let reply = client
                .call(
                    "ssh_read_file",
                    json!({"host":"plain","path":path,"max_bytes":1,"timeout_secs":10}),
                )
                .await?;
            Fixture::await_file(&protocol_done).await?;
            failed(&reply, "io_error")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                !done.exists(),
                "normal cleanup waited for the remote session to finish"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "cleanup failure replaced the shared master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let completed = Fixture::await_file(&done).await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        completed?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

// The independent shared-filesystem oracle also rejects extra result fields,
// including paths, filenames, link targets, or authentication hints.
fn native_stat_data(path: &Path, follow: bool) -> Result<Value> {
    let metadata = if follow {
        fs::metadata(path)?
    } else {
        fs::symlink_metadata(path)?
    };
    let kind = if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };
    Ok(json!({
        "kind":kind,
        "size":metadata.len(),
        "permissions":metadata.mode() & 0o7777,
        "uid":metadata.uid(),
        "gid":metadata.gid(),
        "modified_unix_secs":u64::try_from(metadata.mtime())?,
    }))
}

async fn stat_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let root = fixture.root.path();
    let file = root.join("stat-file");
    fs::write(&file, b"STAT_SHARED_MASTER")?;
    // Nonexecutable owned data safely exercises setuid and sticky bits.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o5640))?;
    ensure!(fs::metadata(&file)?.mode() & 0o7777 == 0o5640);
    let directory = root.join("stat-directory");
    fs::create_dir(&directory)?;
    let link = root.join("stat-link");
    symlink(&file, &link)?;
    let dangling = root.join("stat-dangling");
    let missing = root.join("stat-missing");
    symlink(&missing, &dangling)?;
    let unusual = root.join("stat-é quote' \" ; $(printf EVALUATED)\n*");
    fs::write(&unusual, b"LITERAL_STAT_PATH")?;
    let socket_tree = tempfile::Builder::new()
        .prefix("sm-stat-")
        .tempdir_in("/tmp")?;
    let socket = socket_tree.path().join("s");
    let _socket = UnixListener::bind(&socket)?;

    ensure!(succeeded(&exec(client, "printf STAT_MASTER").await?)?["stdout"] == "STAT_MASTER");
    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    let before = fixture.listeners[0].log.text();
    for (path, follow) in [
        (&file, None),
        (&directory, None),
        (&link, None),
        (&link, Some(true)),
        (&dangling, None),
        (&unusual, None),
        (&socket, None),
    ] {
        let mut args = json!({"host":"plain","path":path});
        if let Some(follow) = follow {
            args["follow_symlinks"] = json!(follow);
        }
        let reply = client.call("ssh_stat", args).await?;
        ensure!(
            succeeded(&reply)? == &native_stat_data(path, follow.unwrap_or(false))?,
            "native metadata mismatch for {path:?}, follow={follow:?}: {reply}"
        );
    }

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .context("native prerequisite: current account")?;
    let home = fs::canonicalize(user.dir).context("native prerequisite: usable account home")?;
    let mut relative = PathBuf::new();
    for component in home.components() {
        if matches!(component, std::path::Component::Normal(_)) {
            relative.push("..");
        }
    }
    relative.push(file.strip_prefix("/")?);
    let reply = client
        .call("ssh_stat", json!({"host":"plain","path":relative}))
        .await?;
    ensure!(
        succeeded(&reply)? == &native_stat_data(&file, false)?,
        "relative stat path used the wrong initial directory"
    );

    let denied = root.join("stat-denied");
    fs::create_dir(&denied)?;
    let child = denied.join("private");
    fs::write(&child, b"PRIVATE_STAT")?;
    let permissions = fs::metadata(&denied)?.permissions();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    let failures = async {
        // A file's mode alone does not deny stat: traversal must be denied.
        ensure!(
            fs::symlink_metadata(&child)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
            "native prerequisite: owned parent must actually deny traversal"
        );
        for (path, follow, code) in [
            (&missing, false, "not_found"),
            (&dangling, true, "not_found"),
            (&child, false, "permission_denied"),
        ] {
            let reply = client
                .call(
                    "ssh_stat",
                    json!({"host":"plain","path":path,"follow_symlinks":follow}),
                )
                .await?;
            failed(&reply, code)?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            let serialized = serde_json::to_string(&reply)?;
            ensure!(
                !serialized.contains(path.to_str().context("UTF8 fixture path")?),
                "stat failure disclosed its path"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Restore before propagating any scenario failure or deleting the fixture.
    let restored = fs::set_permissions(&denied, permissions);
    failures?;
    restored?;

    let reply = client
        .call("ssh_read_file", json!({"host":"plain","path":file}))
        .await?;
    ensure!(succeeded(&reply)?["content"] == "STAT_SHARED_MASTER");
    ensure!(
        live_transport(fixture, client, &owned[0], 1, 3).await? == transport,
        "exec/read/stat did not reuse the same live ordinary master"
    );
    let sessions = |text: &str, kind: &str| {
        text.lines()
            .filter(|line| line.contains("Starting session:") && line.contains(kind))
            .count()
    };
    let after = fixture.listeners[0].log.text();
    ensure!(
        sessions(&after, "command") == sessions(&before, "command") + 1,
        "stat or read ran an unexpected remote shell helper"
    );
    let before = fixture.listeners[1].log.text();
    let reply = client
        .call("ssh_stat", json!({"host":"nosftp","path":file}))
        .await?;
    let code = reply["error"]["code"]
        .as_str()
        .context("subsystem denial must fail stat")?;
    ensure!(
        matches!(code, "unsupported" | "io_error" | "connection_lost"),
        "unexpected subsystem failure: {reply}"
    );
    ensure!(
        reply["data"].is_null(),
        "stat used a missing-subsystem fallback"
    );
    let owned = observed_masters(&client.log, 2).await?;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"nosftp","command":"printf STAT_NO_FALLBACK_MASTER_ALIVE"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "STAT_NO_FALLBACK_MASTER_ALIVE");
    ensure!(
        masters(&client.log)? == owned,
        "stat denial replaced a healthy master"
    );
    fixture.await_authentications(4).await?;
    timeout(Duration::from_secs(5), async {
        while sessions(&fixture.listeners[1].log.text(), "command")
            < sessions(&before, "command") + 1
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("missing subsystem health-probe log")?;
    ensure!(
        sessions(&fixture.listeners[1].log.text(), "command") == sessions(&before, "command") + 1,
        "missing subsystem ran a stat shell fallback"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_stat() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = stat_cases(&fixture, &client).await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        let records = log.final_records()?;
        let stats: Vec<_> = records
            .iter()
            .filter(|record| record["tool"] == "ssh_stat")
            .collect();
        ensure!(!stats.is_empty(), "stat emitted no audit records");
        for record in stats {
            ensure!(
                record["identity_role"] == "ordinary",
                "stat used a nonordinary identity"
            );
            for field in ["path", "filename", "target", "content", "uid", "gid"] {
                ensure!(record.get(field).is_none(), "stat audit disclosed {field}");
            }
        }
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

async fn list_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let directory = fixture.root.path().join("list-'\";~$*\n");
    fs::create_dir(&directory)?;
    let mut names = vec![
        b"z-last".to_vec(),
        b"a-first".to_vec(),
        "é-雪".as_bytes().to_vec(),
        b"quote'\";~$*\n\t\\control\x01".to_vec(),
    ];
    // APFS rejects invalid UTF-8; the approved Linux smoke covers these bytes.
    #[cfg(target_os = "linux")]
    names.push(b"nonutf8-\xff\xfe".to_vec());
    names.extend((0..201).map(|i| format!("entry-{i:03}").into_bytes()));
    for name in &names {
        fs::write(
            directory.join(std::ffi::OsString::from_vec(name.clone())),
            b"LIST_DATA",
        )?;
    }
    fs::create_dir(directory.join("subdirectory"))?;
    fs::write(
        directory.join("subdirectory/hidden-child"),
        b"NOT_RECURSIVE",
    )?;
    symlink("z-last", directory.join("symlink"))?;
    // Independent local readdir is the static native server's enumeration oracle,
    // not a sorted expectation or a copy of the tool's filename conversion.
    let expected: Vec<_> = fs::read_dir(&directory)?
        .map(|entry| {
            let entry = entry?;
            let name = entry.file_name();
            Ok(json!({
                "name": name.to_str(),
                "name_base64": STANDARD.encode(name.as_bytes()),
                "metadata": native_stat_data(&entry.path(), false)?,
            }))
        })
        .collect::<Result<_>>()?;
    let count = names.len() + 2;
    ensure!(expected.len() == count);
    ensure!(succeeded(&exec(client, "printf LIST_MASTER").await?)?["stdout"] == "LIST_MASTER");
    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    for (limit, count, truncated) in [
        (None, 200, true),
        (Some(1), 1, true),
        (Some(count - 1), count - 1, true),
        (Some(count), count, false),
        (Some(1000), count, false),
    ] {
        let mut args = json!({"host":"plain","path":directory});
        if let Some(limit) = limit {
            args["max_entries"] = json!(limit);
        }
        let reply = client.call("ssh_list_directory", args).await?;
        ensure!(
            succeeded(&reply)? == &json!({"entries": &expected[..count], "truncated":truncated}),
            "listing lost bytes, reordered entries, fabricated metadata or misreported lookahead"
        );
    }
    let empty = fixture.root.path().join("list-empty");
    fs::create_dir(&empty)?;
    let reply = client
        .call(
            "ssh_list_directory",
            json!({"host":"plain","path":empty,"max_entries":1}),
        )
        .await?;
    ensure!(succeeded(&reply)? == &json!({"entries":[],"truncated":false}));
    // Exercise a larger directory crossing multiple SFTP READDIR responses.
    for i in 201..1001 {
        fs::write(directory.join(format!("entry-{i:03}")), b"")?;
    }
    let reply = client
        .call(
            "ssh_list_directory",
            json!({"host":"plain","path":directory,"max_entries":1000}),
        )
        .await?;
    let data = succeeded(&reply)?;
    ensure!(data["truncated"] == true);
    let entries = data["entries"].as_array().context("directory entries")?;
    ensure!(entries.len() == 1000);
    let actual: Vec<_> = entries
        .iter()
        .map(|entry| entry["name_base64"].as_str())
        .collect();
    let expected: Vec<_> = fs::read_dir(&directory)?
        .take(1000)
        .map(|entry| Ok(STANDARD.encode(entry?.file_name().as_bytes())))
        .collect::<Result<_>>()?;
    ensure!(
        actual
            == expected
                .iter()
                .map(|name| Some(name.as_str()))
                .collect::<Vec<_>>()
    );

    let denied = fixture.root.path().join("list-denied");
    fs::create_dir(&denied)?;
    let permissions = fs::metadata(&denied)?.permissions();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    let failures = async {
        for (path, code) in [
            (fixture.root.path().join("list-missing"), "not_found"),
            (denied.clone(), "permission_denied"),
        ] {
            let reply = client
                .call("ssh_list_directory", json!({"host":"plain","path":path}))
                .await?;
            failed(&reply, code)?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let restored = fs::set_permissions(&denied, permissions);
    failures?;
    restored?;
    ensure!(live_transport(fixture, client, &owned[0], 1, 3).await? == transport);
    let reply = client
        .call(
            "ssh_list_directory",
            json!({"host":"nosftp","path":directory}),
        )
        .await?;
    let code = reply["error"]["code"]
        .as_str()
        .context("subsystem denial must fail listing")?;
    ensure!(matches!(
        code,
        "unsupported" | "io_error" | "connection_lost"
    ));
    ensure!(reply["data"].is_null(), "listing used a subsystem fallback");
    let owned = observed_masters(&client.log, 2).await?;
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"nosftp","command":"printf LIST_NO_FALLBACK"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "LIST_NO_FALLBACK");
    ensure!(masters(&client.log)? == owned);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_list_directory() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = list_cases(&fixture, &client).await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let records = stopped?.final_records()?;
        for record in records.iter().filter(|record| record["tool"] == "ssh_list_directory") {
            ensure!(record["identity_role"] == "ordinary");
            for field in ["path", "name", "name_base64", "metadata", "entries"] {
                ensure!(record.get(field).is_none(), "listing audit disclosed {field}");
            }
        }
        gone?;

        // An actual near-limit string ID leaves room for only a directory prefix.
        // The raw frame reader measures both SDK representations plus framing.
        let directory = fixture.root.path().join("list-'\";~$*\n");
        let expected: Vec<_> = fs::read_dir(&directory)?
            .map(|entry| Ok(STANDARD.encode(entry?.file_name().as_bytes())))
            .collect::<Result<_>>()?;
        let mut wire = WireServer::start(&fixture.config)?;
        let wire_case = async {
            wire.initialize().await?;
            let (frame, size) = wire.request_with_size(
                json!("x".repeat(16_774_000)),
                "tools/call",
                json!({"name":"ssh_list_directory","arguments":{"host":"plain","path":directory,"max_entries":1000}}),
            ).await?;
            ensure!(size <= 16_777_216);
            let result = &frame["result"];
            let reply = &result["structuredContent"];
            ensure!(serde_json::from_str::<Value>(result["content"][0]["text"].as_str().context("text result")?)? == *reply);
            let data = succeeded(reply)?;
            ensure!(data["truncated"] == true);
            let entries = data["entries"].as_array().context("wire entries")?;
            ensure!(!entries.is_empty() && entries.len() < 200, "wire budget was not exercised");
            for (entry, expected) in entries.iter().zip(&expected) {
                ensure!(entry["name_base64"] == *expected);
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&wire.log);
        let stopped = wire.stop(false).await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        wire_case?;
        stopped?;
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_startup_file_profiles() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let config = fixture.root.path().join("file-profiles.toml");
        let ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?;
        fs::write(
            &config,
            formatdoc! {"
            profile = 'files-only'
            [ssh]
            config_file = {ssh_config}
            [targets.allowed]
            ssh_host = 'plain'
            profile = 'baseline'
            [targets.allowed.sudo]
            mode = 'same-account'
            users = ['root']
            programs = ['/usr/bin/true']
            [targets.locked]
            ssh_host = 'plain'
            profile = 'read-only-files'
        "},
        )?;
        let directory = fixture.root.path().join("profile-owned-files");
        fs::create_dir(&directory)?;
        let file = directory.join("preserved");
        fs::write(&file, b"abc")?;
        let client = Client::start(&config).await?;
        let cases =
            async {
                let initial_auth = fixture.authentications();
                let listed =
                    timeout(Duration::from_secs(5), client.service.list_tools(None)).await??;
                let mut names: Vec<_> =
                    listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
                names.sort_unstable();
                ensure!(
                    names
                        == [
                            "ssh_list_directory",
                            "ssh_read_file",
                            "ssh_stat",
                            "ssh_targets",
                            "ssh_write_file",
                        ],
                    "files-only published an unexpected route: {names:?}"
                );

                // These valid payloads must fail routing, not argument validation.
                // The explicit baseline target must not restore global escape routes;
                // configured sudo availability must not restore ssh_sudo either.
                for host in ["allowed", "locked"] {
                    for (name, args) in [
                        ("ssh_exec", json!({"host":host,"command":"printf NEVER"})),
                        ("ssh_run", json!({"host":host,"argv":["/usr/bin/true"]})),
                        ("ssh_sudo", json!({"host":host,"argv":["/usr/bin/true"]})),
                    ] {
                        let result = timeout(
                            Duration::from_secs(5),
                            client.service.call_tool(params(name, args)),
                        )
                        .await?;
                        match result {
                            Err(rmcp::ServiceError::McpError(error)) => {
                                ensure!(
                                    serde_json::to_value(error)?["code"] == -32602,
                                    "{name} did not reject the hidden route"
                                );
                            }
                            other => anyhow::bail!("{name} remained reachable: {other:?}"),
                        }
                    }
                }
                let reply = client.call("ssh_write_file", json!({
                "host":"locked","path":file,"content":"MUST_NOT_REPLACE","overwrite":true,
            })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    fs::read(&file)? == b"abc",
                    "read-only target changed existing bytes"
                );
                ensure!(
                    masters(&client.log)?.is_empty(),
                    "profile denial started an SSH master"
                );
                ensure!(
                    fixture.authentications() == initial_auth,
                    "profile denial authenticated to SSH"
                );

                for host in ["locked", "allowed"] {
                    let reply = client
                        .call("ssh_read_file", json!({"host":host,"path":file}))
                        .await?;
                    ensure!(
                        succeeded(&reply)?
                            == &json!({
                                "content":"abc","encoding":"utf8","bytes_read":3,"next_offset":3,
                                "eof":true,"content_sha256":ABC_SHA256,
                            })
                    );
                    let reply = client
                        .call("ssh_stat", json!({"host":host,"path":file}))
                        .await?;
                    ensure!(succeeded(&reply)? == &native_stat_data(&file, false)?);
                    let reply = client
                        .call(
                            "ssh_list_directory",
                            json!({
                                "host":host,"path":directory,
                            }),
                        )
                        .await?;
                    ensure!(
                        succeeded(&reply)?
                            == &json!({
                                "entries":[{
                                    "name":"preserved","name_base64":STANDARD.encode(b"preserved"),
                                    "metadata":native_stat_data(&file, false)?,
                                }],
                                "truncated":false,
                            })
                    );
                }
                let payload = "PROFILE_WRITE_é雪\0END";
                let reply = client
                    .call(
                        "ssh_write_file",
                        json!({
                            "host":"allowed","path":file,"content":payload,"overwrite":true,
                        }),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":payload.len()}));
                ensure!(
                    fs::read(&file)? == payload.as_bytes(),
                    "allowed write lost bytes"
                );
                let reply = client
                    .call("ssh_read_file", json!({"host":"locked","path":file}))
                    .await?;
                ensure!(
                    succeeded(&reply)?["content"] == payload,
                    "read-only target did not see the real allowed SFTP write"
                );
                ensure!(
                    !masters(&client.log)?.is_empty(),
                    "successful file calls started no master"
                );
                ensure!(
                    fixture.authentications() > initial_auth,
                    "successful file calls did not authenticate to sshd"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_write_file() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let preserved = fixture.root.path().join("write-invalid-preserved");
            fs::write(&preserved, b"KEEP_INVALID_WRITE")?;
            for (content, encoding, code) in [
                ("x".repeat(1_048_577), "utf8", "invalid_argument"),
                ("YR==".to_owned(), "base64", "invalid_encoding"),
            ] {
                let reply = client.call("ssh_write_file", json!({
                    "host":"plain","path":preserved,"content":content,"encoding":encoding,"overwrite":true,
                })).await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&preserved)? == b"KEEP_INVALID_WRITE");
                ensure!(masters(&client.log)?.is_empty(), "invalid write acquired SSH");
            }
            fixture.await_authentications(2).await?;
            succeeded(&exec(&client, "printf WRITE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let root = fixture.root.path();
            let payload = "WRITE_PRIVATE_é雪\0END";
            let cap = "x".repeat(1_048_576);
            for (name, content, encoding, expected) in [
                ("write-unicode", payload, "utf8", payload.as_bytes()),
                ("write-empty", "", "utf8", b"".as_slice()),
                ("write-exact-cap", cap.as_str(), "utf8", cap.as_bytes()),
                ("write-binary", "AP+AQQ==", "base64", b"\0\xff\x80A".as_slice()),
                ("write-'\";~$*\n$(printf EVALUATED)", "LITERAL_WRITE", "utf8", b"LITERAL_WRITE".as_slice()),
            ] {
                let path = root.join(name);
                let reply = client.call("ssh_write_file", json!({
                    "host":"plain","path":path,"content":content,"encoding":encoding
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":expected.len()}), "{name}: {reply}");
                ensure!(fs::read(&path)? == expected, "{name}: native bytes differ");
            }
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
                .context("native prerequisite: current account")?;
            let home = fs::canonicalize(user.dir)?;
            let mut relative = PathBuf::new();
            for component in home.components() {
                if matches!(component, std::path::Component::Normal(_)) {
                    relative.push("..");
                }
            }
            relative.push(root.strip_prefix("/")?);
            relative.push("write-relative");
            let reply = client.call("ssh_write_file", json!({
                "host":"plain","path":relative,"content":"RELATIVE_WRITE"
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":14}));
            ensure!(fs::read(root.join("write-relative"))? == b"RELATIVE_WRITE");

            let existing = root.join("write-existing");
            fs::write(&existing, b"KEEP_OLD_TAIL")?;
            let link = root.join("write-existing-link");
            symlink(&existing, &link)?;
            let dangling = root.join("write-dangling-link");
            let absent = root.join("write-dangling-target");
            symlink(&absent, &dangling)?;
            for path in [&existing, &link, &dangling] {
                let reply = client.call("ssh_write_file", json!({
                    "host":"plain","path":path,"content":"MUST_NOT_REPLACE"
                })).await?;
                failed(&reply, "already_exists")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&existing)? == b"KEEP_OLD_TAIL");
                ensure!(fs::read_link(&link)? == existing);
                ensure!(fs::read_link(&dangling)? == absent && !absent.exists());
            }
            let reply = client.call("ssh_write_file", json!({
                "host":"plain","path":existing,"content":"short","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":5}));
            ensure!(fs::read(&existing)? == b"short", "overwrite retained old tail");
            let reply = client.call("ssh_write_file", json!({
                "host":"plain","path":link,"content":"L","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":1}));
            ensure!(fs::read(&existing)? == b"L" && fs::read_link(&link)? == existing);
            let reply = client.call("ssh_write_file", json!({
                "host":"plain","path":dangling,"content":"NEW","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":3}));
            ensure!(fs::read(&absent)? == b"NEW" && fs::read_link(&dangling)? == absent);

            let parent = root.join("write-missing-parent");
            let reply = client.call("ssh_write_file", json!({
                "host":"plain","path":parent.join("child"),"content":"NO_MKDIR"
            })).await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(!parent.exists(), "write created an implicit parent");
            let denied = root.join("write-denied");
            fs::write(&denied, b"DENIED_OLD_BYTES")?;
            fs::set_permissions(&denied, fs::Permissions::from_mode(0o400))?;
            let attempted = client.call("ssh_write_file", json!({
                "host":"plain","path":denied,"content":"DENIED_NEW_BYTES","overwrite":true
            })).await;
            let restored = fs::set_permissions(&denied, fs::Permissions::from_mode(0o600));
            let reply = attempted?;
            restored?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::read(&denied)? == b"DENIED_OLD_BYTES");

            let reply = client.call("ssh_read_file", json!({"host":"plain","path":existing})).await?;
            ensure!(succeeded(&reply)?["content"] == "L");
            let reply = client.call("ssh_stat", json!({"host":"plain","path":existing})).await?;
            ensure!(succeeded(&reply)? == &native_stat_data(&existing, false)?);
            ensure!(live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "exec/read/stat/write did not share the ordinary master");

            let unsupported = root.join("write-no-subsystem");
            let reply = client.call("ssh_write_file", json!({
                "host":"nosftp","path":unsupported,"content":"NO_FALLBACK"
            })).await?;
            ensure!(matches!(reply["error"]["code"].as_str(), Some("unsupported" | "io_error" | "connection_lost")));
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(!unsupported.exists(), "missing subsystem ran a write fallback");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client.call("ssh_exec", json!({
                "host":"nosftp","command":"printf WRITE_MASTER_HEALTHY"
            })).await?;
            ensure!(succeeded(&reply)?["stdout"] == "WRITE_MASTER_HEALTHY");
            ensure!(masters(&client.log)? == before);
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        for secret in ["WRITE_PRIVATE_", "LITERAL_WRITE", "DENIED_NEW_BYTES", "write-existing",
            "write-dangling", "write-no-subsystem"] {
            ensure!(!log.text().contains(secret), "write audit disclosed path or content");
        }
        let records = log.final_records()?;
        let writes: Vec<_> = records.iter().filter(|record| record["tool"] == "ssh_write_file").collect();
        ensure!(!writes.is_empty());
        for record in writes {
            ensure!(record["identity_role"] == "ordinary");
            for field in ["path", "content", "payload"] {
                ensure!(record.get(field).is_none(), "write audit disclosed {field}");
            }
        }
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_write_close_and_write_failures() -> Result<()> {
    let server = Fixture::sftp_server()?;
    for (request, expected, code) in [
        ("close", b"NEW".as_slice(), "permission_denied"),
        ("write", b"".as_slice(), "permission_denied"),
    ] {
        // The actual OpenSSH server denies this protocol request; no emulator
        // can accidentally acknowledge a write or close that never happened.
        let subsystem = format!("{} -P {request}", server.display());
        let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
        let scenario = async {
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                succeeded(&exec(&client, "printf WRITE_FAULT_MASTER").await?)?;
                let owned = observed_masters(&client.log, 1).await?;
                let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
                let path = fixture.root.path().join(format!("write-fault-{request}"));
                fs::write(&path, b"OLD_BYTES_LONGER_THAN_NEW")?;
                let reply = client
                    .call(
                        "ssh_write_file",
                        json!({
                            "host":"plain","path":path,"content":"NEW","overwrite":true
                        }),
                    )
                    .await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(
                    fs::read(&path)? == expected,
                    "{request}: incorrect post-mutation filesystem state"
                );
                let audit = await_audit(&client.log, "finish", code).await?;
                ensure!(
                    audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary"
                );
                ensure!(
                    live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                    "{request} failure discarded the healthy ordinary master"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let owned = masters(&client.log);
            let stopped = client.stop().await;
            let gone = match owned {
                Ok(owned) => assert_masters_gone(&owned).await,
                Err(error) => Err(error),
            };
            cases?;
            stopped?;
            gone
        }
        .await;
        let cleanup = fixture.stop().await;
        scenario?;
        cleanup?;
    }
    Ok(())
}

// Keep the applet basename: find_program canonicalizes Nix multicall symlinks,
// whereas the remote exec must invoke printf/id/sleep, not bare coreutils.
fn binding_program(name: &str) -> Result<PathBuf> {
    let resolved = support::find_program(name)?;
    ensure!(
        resolved.starts_with("/nix/store"),
        "{name} must be Nix-provided"
    );
    let program = resolved
        .parent()
        .context("coreutils executable directory")?
        .join(name);
    let metadata = fs::metadata(&program)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "missing executable coreutils applet {name}"
    );
    Ok(program)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_named_bindings() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let printf = binding_program("printf")?;
        let id = binding_program("id")?;
        let sleeper = binding_program("sleep")?;
        let identity = support::run(&mut Command::new(&id)).await?;
        ensure!(identity.status.success() && identity.stderr.is_empty());
        let identity = String::from_utf8(identity.stdout)?;
        let config = fixture.root.path().join("named-bindings.toml");
        let ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?;
        let printf_path = serde_json::to_string(&printf.to_string_lossy())?;
        let id_path = serde_json::to_string(&id.to_string_lossy())?;
        let sleep_path = serde_json::to_string(&sleeper.to_string_lossy())?;
        fs::write(&config, formatdoc! {r#"
            profile = "actions-only"
            enabled_tools = ["literal_values", "ordinary_identity", "missing_account", "bounded_pause"]
            [ssh]
            config_file = {ssh_config}
            [limits]
            operation_timeout_secs = 10
            max_timeout_secs = 15
            max_output_bytes = 1024
            [targets.plain]
            ssh_host = "plain"
            [targets.plain.sudo]
            mode = "same-account"
            users = ["root"]
            programs = [{id_path}]
            [targets.denied]
            ssh_host = "must-never-connect"
            [targets.locked]
            ssh_host = "must-never-connect"
            profile = "read-only-files"
            [tools.literal_values]
            description = "Emit bounded literal data with a fixed format."
            revision = "literal-r1"
            targets = ["plain", "locked"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{ kind = "native_argv", program = {printf_path}, argv = ["--", '%s\000%s\000%s', {{input="text"}}, {{input="number"}}, {{input="flag"}}] }}
            input_schema = {{ type="object", additionalProperties=false, required=["text","number","flag"], properties={{ text={{type="string",maxLength=256}}, number={{type="integer",minimum=-9,maximum=9}}, flag={{type="boolean"}} }} }}
            result = {{kind="command"}}
            [tools.ordinary_identity]
            description = "Observe the ordinary account without caller-selected options."
            revision = "identity-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={id_path},argv=["--"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            [tools.missing_account]
            description = "Observe a fixed invalid empty account."
            revision = "missing-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={id_path},argv=["--",""]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            [tools.bounded_pause]
            description = "A finite fixed native sleep; cancellation is uncertain."
            revision = "pause-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["availability"]
            execution = {{kind="native_argv",program={sleep_path},argv=["--","3"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            limits = {{timeout_secs=5,max_output_bytes=128}}
        "#})?;
        let client = Client::start(&config).await?;
        let cases = async {
            let listed = timeout(Duration::from_secs(5), client.service.list_tools(None)).await??;
            let mut names: Vec<_> = listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
            names.sort_unstable();
            ensure!(names == [
                "bounded_pause", "literal_values", "missing_account",
                "ordinary_identity", "ssh_targets",
            ], "actions-only exposed an unexpected tool: {names:?}");
            let initial_auth = fixture.authentications();
            let valid = json!({"host":"plain","text":"VALID","number":1,"flag":true});
            // Shape errors cannot override operator authority or fixed layout.
            for extra in ["program","argv","cwd","stdin","user","role","authority","shell"] {
                let mut args = valid.clone();
                args[extra] = json!("BINDING_FORBIDDEN_OVERRIDE");
                let result = timeout(
                    Duration::from_secs(5),
                    client.service.call_tool(params("literal_values", args)),
                ).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("binding accepted {extra}: {other:?}"),
                }
            }
            for (name,args) in [
                ("ssh_exec",json!({"host":"plain","command":"printf NEVER"})),
                ("ssh_run",json!({"host":"plain","argv":[id]})),
                ("ssh_sudo",json!({"host":"plain","argv":[id]})),
            ] {
                let result = timeout(Duration::from_secs(5),client.service.call_tool(params(name,args))).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("actions-only raw route remained reachable: {other:?}"),
                }
            }
            for (field, value) in [("number",json!("1")),("flag",json!(1)),("text",json!(false))] {
                let mut args = valid.clone();
                args[field] = value;
                let result = timeout(
                    Duration::from_secs(5),
                    client.service.call_tool(params("literal_values", args)),
                ).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("binding accepted wrong {field} type: {other:?}"),
                }
            }
            for (field, value, code) in [
                ("host",json!("denied"),"policy_denied"),
                ("host",json!("unknown-target"),"policy_denied"),
                ("host",json!("locked"),"policy_denied"),
                ("text",json!("x".repeat(257)),"invalid_argument"),
                ("text",json!("BINDING_NUL_SECRET\0"),"invalid_argument"),
                ("number",json!(-10),"invalid_argument"),
                ("number",json!(10),"invalid_argument"),
            ] {
                let mut args = valid.clone();
                args[field] = value;
                let reply = client.call("literal_values", args).await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client.call("bounded_pause",json!({"host":"plain","timeout_secs":6})).await?;
            failed(&reply,"invalid_argument")?;
            ensure!(masters(&client.log)?.is_empty(), "rejection acquired a master");
            ensure!(fixture.authentications() == initial_auth, "rejection authenticated");
            let injected = fixture.root.path().join("binding-injected");
            let injection = format!("$(touch {}); `touch {}`",quote(&injected.to_string_lossy()),quote(&injected.to_string_lossy()));
            let max_text = "雪".repeat(256);
            let payloads = [
                "", "--help", "-n", "BINDING_PAYLOAD_SECRET_09d2",
                "single' double\" \\ $HOME ; & | < > * ? [ ] { }",
                "日本語 🦀", "control:\n\r\t\u{1b}\u{7f}", &injection, &max_text,
            ];
            for (index, text) in payloads.into_iter().enumerate() {
                let number = if index % 2 == 0 { -9 } else { 9 };
                let flag = index % 2 == 0;
                let reply = client.call("literal_values",json!({
                    "host":"plain","text":text,"number":number,"flag":flag,
                })).await?;
                let data = succeeded(&reply)?;
                ensure!(data["stdout"] == format!("{text}\0{number}\0{flag}"), "literal conversion lost data: {reply}");
                ensure!(data["stderr"] == "" && data["exit_code"] == 0);
                ensure!(data["termination"] == "exited" && data["remote_may_still_be_running"] == false);
                ensure!(data["stdout_lossy"] == false && data["stderr_lossy"] == false);
                ensure!(!injected.exists(), "input interpolated into remote shell syntax");
            }
            let reply = client.call("ordinary_identity",json!({"host":"plain"})).await?;
            ensure!(succeeded(&reply)?["stdout"] == identity, "binding changed account identity");
            let reply = client.call("missing_account",json!({"host":"plain"})).await?;
            failed(&reply,"command_failed")?;
            ensure!(reply["data"]["stdout"] == "" && reply["data"]["exit_code"] == 1);
            ensure!(!reply["data"]["stderr"].as_str().context("id stderr")?.is_empty());
            ensure!(reply["data"]["termination"] == "exited");
            ensure!(reply["error"]["remote_state_unknown"] == false);
            let owned = observed_masters(&client.log,1).await?;
            fixture.await_authentications(initial_auth + 1).await?;
            let timed = client.call("bounded_pause",json!({"host":"plain","timeout_secs":1})).await?;
            failed(&timed,"timeout")?;
            ensure!(timed["data"]["termination"] == "timeout" && timed["data"]["exit_code"].is_null());
            ensure!(timed["data"]["remote_may_still_be_running"] == true);
            ensure!(timed["error"]["remote_state_unknown"] == true);
            let session_count = || fixture.listeners[0].log.text().lines()
                .filter(|line| line.contains("Starting session: command")).count();
            let before = session_count();
            let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
                "bounded_pause",json!({"host":"plain"}),
            )));
            let handle = timeout(Duration::from_secs(5),client.service.send_cancellable_request(
                request,PeerRequestOptions::default(),
            )).await??;
            // Observe real sshd dispatch before cancellation, not a fabricated reply.
            let dispatched = timeout(Duration::from_secs(5),async {
                while session_count() <= before { sleep(Duration::from_millis(20)).await; }
            }).await;
            let cancelled = timeout(Duration::from_secs(5),handle.cancel(Some("named native cancellation".into()))).await;
            dispatched.context("bound sleep was not dispatched")?;
            cancelled??;
            let audit = await_audit(&client.log,"finish","cancelled").await?;
            ensure!(audit["tool"] == "bounded_pause" && audit["exit_code"].is_null());
            ensure!(audit["remote_state_unknown"] == true);
            // A later ordinary binding must still use the original transport.
            let reply = client.call("ordinary_identity",json!({"host":"plain"})).await?;
            ensure!(succeeded(&reply)?["stdout"] == identity);
            let check = support::run(Command::new(&fixture.ssh)
                .arg("-F").arg(&fixture.ssh_config).arg("-S").arg(&owned[0].1)
                .args(["-O","check","plain"])).await?;
            ensure!(check.status.success());
            ensure!(String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={})",owned[0].0)));
            ensure!(masters(&client.log)? == owned, "binding replaced its healthy master");
            fixture.await_authentications(initial_auth + 1).await?;
            Ok::<_,anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        // Fixed sleep is finite. Give dispatched work its bounded settling window
        // even on assertion failure; neither channel teardown nor this wait proves
        // remote termination, and there is no remote process-kill claim.
        sleep(Duration::from_secs(4)).await;
        cases?;
        let log = stopped?;
        gone?;
        let text = log.text();
        for secret in ["BINDING_PAYLOAD_SECRET_09d2","BINDING_NUL_SECRET","BINDING_FORBIDDEN_OVERRIDE"] {
            ensure!(!text.contains(secret), "binding audit leaked caller payload");
        }
        for program in [&printf,&id,&sleeper] {
            ensure!(!text.contains(program.to_string_lossy().as_ref()), "audit leaked fixed executable");
        }
        let records = log.final_records()?;
        for (name,revision) in [
            ("literal_values","literal-r1"),("ordinary_identity","identity-r1"),
            ("missing_account","missing-r1"),("bounded_pause","pause-r1"),
        ] {
            let events: Vec<_> = records.iter().filter(|record| record["tool"] == name
                && ["start","finish"].contains(&record["event"].as_str().unwrap_or(""))).collect();
            ensure!(events.iter().any(|record| record["event"] == "start"));
            ensure!(events.iter().any(|record| record["event"] == "finish"));
            for record in events {
                ensure!(record["identity_role"] == "ordinary");
                ensure!(record["binding_revision"] == revision && record["executor"] == "native_argv");
                for forbidden in ["program","argv","command","stdin","stdout","stderr","user","text","number","flag"] {
                    ensure!(record.get(forbidden).is_none(), "binding audit exposed {forbidden}");
                }
            }
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

// The source and trusted interpreter live on the actual loopback sshd's
// filesystem. Neither is installed/uploaded by the server under test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_remote_scripts() -> Result<()> {
    let mut fixture = Fixture::start().await?;
    let root = fixture.root.path().to_path_buf();
    let ready = root.join("script-interpreter-ready");
    let release = root.join("script-interpreter-release");
    let barrier_done = root.join("script-interpreter-done");
    let interrupted_started = root.join("script-interrupted-started");
    let interrupted_release = root.join("script-interrupted-release");
    let interrupted_done = root.join("script-interrupted-done");
    let effects = root.join("script-interrupted-effects");
    let injected = root.join("script-injected");
    let forbidden_effect = root.join("script-forbidden-effect");
    let wrapper = root.join("trusted-script-interpreter");
    let sleeper = binding_program("sleep")?;
    fs::write(
        &wrapper,
        formatdoc! {r#"
        #!/bin/sh
        trap '' HUP
        printf ready > {ready}
        i=0
        while [ ! -f {release} ] && [ "$i" -lt 80 ]; do
            {sleeper} 0.1
            i=$((i + 1))
        done
        printf done > {done}
        [ -f {release} ] || exit 90
        exec /bin/sh "$@"
        "#,
            ready = quote(&ready.to_string_lossy()),
            release = quote(&release.to_string_lossy()),
            done = quote(&barrier_done.to_string_lossy()),
            sleeper = quote(&sleeper.to_string_lossy()),
        },
    )?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
    let literal = indoc! {r#"
        # SCRIPT_SOURCE_SECRET_672a
        printf '%s\000' "$1"
    "#}
    .as_bytes()
    .to_vec();
    let race_source = b"printf VERIFIED_OLD_BYTES\n".to_vec();
    let replacement = format!(
        "printf REPLACEMENT_MUST_NOT_EXECUTE; printf effect > {}\n",
        quote(&forbidden_effect.to_string_lossy())
    );
    let interrupted = formatdoc! {r#"
        trap '' HUP PIPE
        printf effect >> {effects}
        printf SCRIPT_PARTIAL
        printf SCRIPT_PARTIAL_ERR >&2
        printf started > {started}
        i=0
        while [ ! -f {release} ] && [ "$i" -lt 80 ]; do
            {sleeper} 0.1
            i=$((i + 1))
        done
        printf done > {done}
        "#,
        effects = quote(&effects.to_string_lossy()),
        started = quote(&interrupted_started.to_string_lossy()),
        release = quote(&interrupted_release.to_string_lossy()),
        sleeper = quote(&sleeper.to_string_lossy()),
        done = quote(&interrupted_done.to_string_lossy()),
    };
    let capture = indoc! {r#"
        i=0
        while [ "$i" -lt 2048 ]; do
            printf O
            printf E >&2
            i=$((i + 1))
        done
        exit 7
    "#}
    .as_bytes()
    .to_vec();
    let mut exact = b"printf EXACT_BOUND\n#".to_vec();
    exact.resize(128, b'x');
    let source = root.join("script-source-secret-path");
    let race_path = root.join("script-race-source");
    let mismatch_path = root.join("script-mismatch-source");
    let missing_path = root.join("script-missing-source");
    let unreadable_path = root.join("script-unreadable-source");
    let directory_path = root.join("script-directory-source");
    fs::create_dir(&directory_path)?;
    let missing_interpreter = root.join("script-missing-interpreter");
    // name, source path, pinned bytes, read ceiling, fixed interpreter.
    let cases = [
        (
            "script_literal",
            source.clone(),
            literal.clone(),
            None,
            PathBuf::from("/bin/sh"),
        ),
        (
            "script_race",
            race_path.clone(),
            race_source.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_mismatch",
            mismatch_path.clone(),
            race_source.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_missing",
            missing_path.clone(),
            literal.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_unreadable",
            unreadable_path.clone(),
            literal.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_directory",
            directory_path.clone(),
            literal.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_exact",
            root.join("script-exact"),
            exact,
            Some(128),
            PathBuf::from("/bin/sh"),
        ),
        (
            "script_oversize",
            root.join("script-oversize"),
            vec![b'#'; 129],
            Some(128),
            wrapper.clone(),
        ),
        (
            "script_utf8",
            root.join("script-utf8"),
            vec![0xff, 0xfe],
            Some(128),
            wrapper.clone(),
        ),
        (
            "script_nul",
            root.join("script-nul"),
            b"# invalid\0source\n".to_vec(),
            Some(128),
            wrapper.clone(),
        ),
        (
            "script_empty",
            root.join("script-empty"),
            Vec::new(),
            Some(128),
            PathBuf::from("/bin/sh"),
        ),
        (
            "script_no_interpreter",
            root.join("script-valid-no-interpreter"),
            literal.clone(),
            Some(1024),
            missing_interpreter.clone(),
        ),
        (
            "script_fifo",
            root.join("script-fifo"),
            literal.clone(),
            Some(1024),
            wrapper.clone(),
        ),
        (
            "script_capture",
            root.join("script-capture"),
            capture,
            Some(1024),
            PathBuf::from("/bin/sh"),
        ),
        (
            "script_interrupted",
            root.join("script-interrupted"),
            interrupted.into_bytes(),
            Some(4096),
            PathBuf::from("/bin/sh"),
        ),
        (
            "script_cwd",
            root.join("script-cwd"),
            b"pwd -P\n".to_vec(),
            Some(128),
            PathBuf::from("/bin/sh"),
        ),
    ];
    let scenario = async {
        let ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?;
        let names = serde_json::to_string(&cases.iter().map(|case| case.0).collect::<Vec<_>>())?;
        let mut config = formatdoc! {r#"
            profile = "actions-only"
            enabled_tools = {names}
            [ssh]
            config_file = {ssh_config}
            [limits]
            operation_timeout_secs = 10
            max_timeout_secs = 15
            max_output_bytes = 1024
            [targets.plain]
            ssh_host = "plain"
            [targets.nosftp]
            ssh_host = "nosftp"
        "#};
        for (name, path, bytes, cap, interpreter) in &cases {
            if *name == "script_fifo" {
                let created = support::run(Command::new(binding_program("mkfifo")?).arg(path)).await?;
                ensure!(created.status.success(), "could not create test-owned script FIFO");
            } else if path != &directory_path && path != &missing_path {
                fs::write(path, bytes)?;
            }
            let path_json = serde_json::to_string(&path.to_string_lossy())?;
            let program = serde_json::to_string(&interpreter.to_string_lossy())?;
            let digest = hex::encode(Sha256::digest(bytes));
            let cap = cap.map(|cap| format!(",max_bytes={cap}")).unwrap_or_default();
            let cwd = if *name == "script_cwd" {
                format!(",cwd={}", serde_json::to_string(&root.to_string_lossy())?)
            } else {
                String::new()
            };
            config.push_str(&formatdoc! {r#"
                [tools.{name}]
                description = "Reviewed ordinary script acceptance"
                revision = "script-r1"
                targets = ["plain","nosftp"]
                authority = "ordinary"
                effects = ["read"]
                execution = {{kind="remote_script",source={{path={path_json},content_sha256="{digest}"{cap}}},interpreter={{program={program},argv=["-s","--"]}},argv=[{{input="text"}}]{cwd}}}
                input_schema = {{type="object",additionalProperties=false,required=["text"],properties={{text={{type="string",maxLength=512}}}}}}
                result = {{kind="command"}}
            "#});
        }
        fs::write(&mismatch_path, &replacement)?;
        fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o000))?;
        let config_path = root.join("remote-scripts.toml");
        fs::write(&config_path, config)?;
        let mut server = WireServer::start(&config_path)?;
        let mut id = 10;
        let work = async {
            server.initialize().await?;
            let initial_auth = fixture.authentications();
            let payload_injection = format!("$(touch {}); `touch {}`",
                quote(&injected.to_string_lossy()), quote(&injected.to_string_lossy()));
            for text in [
                "", "--help", "-n", "SCRIPT_INPUT_SECRET_47ad",
                "single' double\" \\ $HOME ; & | < > * ? [ ] { }",
                "日本語 🦀", "controls:\n\r\t\u{1b}\u{7f}", &payload_injection,
            ] {
                id += 1;
                let reply = script_wire_call(&mut server, id, "script_literal",
                    json!({"host":"plain","text":text})).await?;
                let data = succeeded(&reply)?;
                ensure!(data["stdout"] == format!("{text}\0"), "script argv was not literal: {reply}");
                ensure!(data["stderr"] == "" && data["exit_code"] == 0);
                ensure!(data["termination"] == "exited" && data["remote_may_still_be_running"] == false);
                ensure!(data["stdout_lossy"] == false && data["stderr_lossy"] == false);
                ensure!(!injected.exists(), "script input became shell syntax");
            }
            let owned = observed_masters(&server.log, 1).await?;
            fixture.await_authentications(initial_auth + 1).await?;
            for (name, code) in [
                ("script_mismatch", "checksum_mismatch"),
                ("script_missing", "not_found"),
                ("script_unreadable", "permission_denied"),
                ("script_directory", "unsupported"),
                ("script_oversize", "resource_limit"),
                ("script_utf8", "invalid_encoding"),
                ("script_nul", "invalid_encoding"),
            ] {
                id += 1;
                let reply = script_wire_call(&mut server, id, name,
                    json!({"host":"plain","text":""})).await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                    "pre-read rejection claimed dispatch: {reply}");
                ensure!(!ready.exists() && !forbidden_effect.exists(),
                    "source rejection dispatched the interpreter");
                let serialized = serde_json::to_string(&reply)?;
                for (_, path, bytes, _, _) in &cases {
                    ensure!(!serialized.contains(path.to_string_lossy().as_ref()));
                    ensure!(!serialized.contains(&hex::encode(Sha256::digest(bytes))));
                }
                ensure!(!serialized.contains("REPLACEMENT_MUST_NOT_EXECUTE"));
            }
            id += 1;
            let source_timeout = script_wire_call(&mut server, id, "script_fifo",
                json!({"host":"plain","text":"","timeout_secs":2})).await?;
            failed(&source_timeout, "timeout")?;
            ensure!(source_timeout["data"].is_null() && source_timeout["error"]["remote_state_unknown"] == false,
                "blocked source read acquired interpreter uncertainty");
            ensure!(!ready.exists(), "FIFO source dispatched interpreter");
            id += 1;
            let unsupported = script_wire_call(&mut server, id, "script_literal",
                json!({"host":"nosftp","text":""})).await?;
            ensure!(unsupported["data"].is_null());
            ensure!(unsupported["error"]["remote_state_unknown"] == false);
            ensure!(["unsupported","io_error","connection_lost"].contains(
                &unsupported["error"]["code"].as_str().context("missing SFTP error")?));
            id += 1;
            let exact_reply = script_wire_call(&mut server, id, "script_exact",
                json!({"host":"plain","text":""})).await?;
            ensure!(succeeded(&exact_reply)?["stdout"] == "EXACT_BOUND");
            id += 1;
            let empty = script_wire_call(&mut server, id, "script_empty",
                json!({"host":"plain","text":""})).await?;
            ensure!(succeeded(&empty)?["stdout"] == "" && empty["data"]["exit_code"] == 0);
            id += 1;
            let cwd = script_wire_call(&mut server, id, "script_cwd",
                json!({"host":"plain","text":""})).await?;
            ensure!(succeeded(&cwd)?["stdout"] == format!("{}\n", fs::canonicalize(&root)?.display()));
            id += 1;
            let missing = script_wire_call(&mut server, id, "script_no_interpreter",
                json!({"host":"plain","text":""})).await?;
            failed(&missing, "command_failed")?;
            ensure!(missing["data"]["exit_code"] == 127);
            ensure!(missing["data"]["termination"] == "exited");
            ensure!(missing["error"]["remote_state_unknown"] == false);
            id += 1;
            let captured = script_wire_call(&mut server, id, "script_capture",
                json!({"host":"plain","text":""})).await?;
            failed(&captured, "command_failed")?;
            ensure!(captured["data"]["exit_code"] == 7 && captured["data"]["termination"] == "exited");
            for (stream, byte) in [("stdout", 'O'), ("stderr", 'E')] {
                let retained = captured["data"][stream].as_str().context("script capture")?;
                ensure!(retained.len() == 1024 && retained.chars().all(|value| value == byte));
                ensure!(captured["data"][format!("{stream}_truncated")] == true);
                ensure!(captured["data"][format!("{stream}_lossy")] == false);
            }
            ensure!(captured["error"]["remote_state_unknown"] == false);
            // The trusted wrapper signals only after the source was checked and
            // the interpreter dispatched. Replace the pathname, not the open inode.
            id += 1;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"script_race","arguments":{"host":"plain","text":""}}})).await?;
            fixture.eventual_markers.push(barrier_done.clone());
            Fixture::await_file(&ready).await?;
            let next_source = root.join("script-replacement");
            fs::write(&next_source, &replacement)?;
            fs::rename(&next_source, &race_path)?;
            fs::write(&release, b"release")?;
            let race = server.receive(json!(id)).await?.0;
            ensure!(succeeded(&race["result"]["structuredContent"])?["stdout"] == "VERIFIED_OLD_BYTES");
            ensure!(!forbidden_effect.exists(), "interpreter reread changed source path");
            fs::remove_file(&ready)?;
            id += 1;
            let changed = script_wire_call(&mut server, id, "script_race",
                json!({"host":"plain","text":""})).await?;
            failed(&changed, "checksum_mismatch")?;
            ensure!(changed["data"].is_null() && changed["error"]["remote_state_unknown"] == false);
            ensure!(!ready.exists() && !forbidden_effect.exists(), "changed source executed on next call");
            // Both interruption modes begin from a real script marker. Release
            // all dispatched work explicitly; do not infer termination from EOF.
            for cancel in [false, true] {
                if interrupted_started.exists() {
                    fs::remove_file(&interrupted_started)?;
                    fs::remove_file(&interrupted_done)?;
                    fs::remove_file(&interrupted_release)?;
                }
                id += 1;
                server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                    "params":{"name":"script_interrupted","arguments":{
                        "host":"plain","text":"","timeout_secs":if cancel { 10 } else { 2 }
                    }}})).await?;
                if !fixture.eventual_markers.contains(&interrupted_done) {
                    fixture.eventual_markers.push(interrupted_done.clone());
                }
                Fixture::await_file(&interrupted_started).await?;
                if cancel {
                    server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                        "params":{"requestId":id,"reason":"script acceptance cancellation"}})).await?;
                    // RMCP suppresses the cancelled response; the owned command
                    // task must nevertheless finish cleanup and its audit.
                    let audit = await_audit(&server.log, "finish", "cancelled").await?;
                    ensure!(audit["tool"] == "script_interrupted");
                    ensure!(audit["exit_code"].is_null() && audit["remote_state_unknown"] == true);
                } else {
                    let response = server.receive(json!(id)).await?.0;
                    let reply = &response["result"]["structuredContent"];
                    failed(reply, "timeout")?;
                    ensure!(reply["data"]["stdout"] == "SCRIPT_PARTIAL");
                    ensure!(reply["data"]["stderr"] == "SCRIPT_PARTIAL_ERR");
                    ensure!(reply["data"]["termination"] == "timeout" && reply["data"]["exit_code"].is_null());
                    ensure!(reply["error"]["remote_state_unknown"] == true);
                    ensure!(reply["data"]["remote_may_still_be_running"] == true);
                }
                ensure!(!interrupted_done.exists(), "interruption waited for remote completion");
                fs::write(&interrupted_release, b"release")?;
                Fixture::await_file(&interrupted_done).await?;
                ensure!(fs::read(&effects)? == if cancel { b"effecteffect".as_slice() } else { b"effect".as_slice() },
                    "interrupted script was replayed");
            }
            id += 1;
            let healthy = script_wire_call(&mut server, id, "script_literal",
                json!({"host":"plain","text":"ORIGINAL_MASTER_HEALTHY"})).await?;
            ensure!(succeeded(&healthy)?["stdout"] == "ORIGINAL_MASTER_HEALTHY\0");
            let check = support::run(Command::new(&fixture.ssh)
                .arg("-F").arg(&fixture.ssh_config).arg("-S").arg(&owned[0].1)
                .args(["-O","check","plain"])).await?;
            ensure!(check.status.success() && String::from_utf8_lossy(&check.stderr)
                .contains(&format!("(pid={})", owned[0].0)));
            let all_owned = observed_masters(&server.log, 2).await?;
            ensure!(all_owned[0] == owned[0], "source failure replaced the healthy master");
            fixture.await_authentications(initial_auth + 2).await?;
            ensure!(fs::read(&effects)? == b"effecteffect", "health probe replayed script");
            Ok::<_, anyhow::Error>(())
        }.await;
        // Always unblock the finite trusted interpreter and interrupted script,
        // even when a protocol/assertion failure aborts the scenario.
        let release_barrier = fs::write(&release, b"release");
        let release_script = fs::write(&interrupted_release, b"release");
        let restore_permissions = fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o600));
        let owned = masters(&server.log);
        let stopped = server.stop(false).await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        work?;
        release_barrier?;
        release_script?;
        restore_permissions?;
        let log = stopped?;
        gone?;
        let text = log.text();
        for secret in [
            "SCRIPT_SOURCE_SECRET_672a", "SCRIPT_INPUT_SECRET_47ad",
            "REPLACEMENT_MUST_NOT_EXECUTE", "SCRIPT_PARTIAL", "SCRIPT_PARTIAL_ERR",
        ] {
            ensure!(!text.contains(secret), "script audit leaked private data");
        }
        for (_, path, bytes, _, interpreter) in &cases {
            ensure!(!text.contains(path.to_string_lossy().as_ref()), "audit leaked source path");
            ensure!(!text.contains(&hex::encode(Sha256::digest(bytes))), "audit leaked source digest");
            if interpreter != Path::new("/bin/sh") {
                ensure!(!text.contains(interpreter.to_string_lossy().as_ref()), "audit leaked interpreter");
            }
        }
        let records = log.final_records()?;
        for (name, _, _, _, _) in &cases {
            let events: Vec<_> = records.iter().filter(|record| record["tool"] == *name
                && ["start","finish"].contains(&record["event"].as_str().unwrap_or(""))).collect();
            ensure!(events.iter().any(|record| record["event"] == "start"), "missing start for {name}");
            ensure!(events.iter().any(|record| record["event"] == "finish"), "missing finish for {name}");
            for record in events {
                ensure!(record["executor"] == "remote_script" && record["identity_role"] == "ordinary");
                ensure!(record["binding_revision"] == "script-r1");
                for field in ["source","path","content_sha256","program","argv","stdin","stdout","stderr","text"] {
                    ensure!(record.get(field).is_none(), "script audit exposed {field}");
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

async fn script_wire_call(
    server: &mut WireServer,
    id: u64,
    name: &str,
    args: Value,
) -> Result<Value> {
    let mut frame = server
        .request(id, "tools/call", json!({"name":name,"arguments":args}))
        .await?;
    let result = &frame["result"];
    let reply = &result["structuredContent"];
    ensure!(reply.is_object(), "missing script envelope: {frame}");
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("script text result")?,
    )?;
    ensure!(text == *reply, "script text and structured result disagree");
    ensure!(result["isError"].as_bool().unwrap_or(false) == !reply["error"].is_null());
    Ok(frame["result"]["structuredContent"].take())
}
