//! Real native command and SFTP acceptance; isolated sudo remains separate.
#[path = "support/replace_relay.rs"]
mod replace_relay;
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
use nix::sys::signal::Signal;
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
        "ssh_read_output",
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
    for target in succeeded(&targets)?["targets"]
        .as_array()
        .context("configured targets")?
    {
        let operations = target["permitted_operations"]
            .as_array()
            .context("target operations")?;
        ensure!(
            !operations.contains(&json!("ssh_read_output")),
            "hostless read listed per target"
        );
    }
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
        "ESTUS_MISSING_EXECUTABLE_8f19=value",
        "if",
        "-ESTUS_MISSING_EXECUTABLE_8f19",
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
        if !matches!(
            record["tool"].as_str(),
            Some("ssh_targets" | "ssh_read_output")
        ) {
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
    let stopped = server.stop(sigterm.then_some(Signal::SIGTERM)).await;
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
    for index in 0..8 {
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
            json!({"host":format!("slots-{}", index % 4),"command":command,"timeout_secs":15}),
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
async fn ssh_master_eviction_across_twenty_targets_and_immediate_reacquire() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut targets = String::new();
        for i in 0..20 {
            targets.push_str(&format!("[targets.sweep{i:02}]\nssh_host = 'plain'\n"));
        }
        let config = fixture.root.path().join("sweep20.toml");
        fs::write(
            &config,
            formatdoc! {r#"
                profile = "baseline"
                [ssh]
                config_file = {ssh_config}
                [limits]
                connect_timeout_secs = 3
                operation_timeout_secs = 5
                max_timeout_secs = 10
                max_output_bytes = 4096
                max_file_bytes = 4096
                {targets}
            "#,
                ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
            },
        )?;
        let client = Client::start(&config).await?;
        let run = async {
            for i in 0..20 {
                let target = format!("sweep{i:02}");
                let reply = client
                    .call(
                        "ssh_exec",
                        json!({"host": target, "command": format!("printf %s {target}")}),
                    )
                    .await?;
                ensure!(
                    succeeded(&reply)?["stdout"] == target,
                    "target {target} failed: {reply}"
                );
            }
            // At least 4 masters had to be evicted to fit 20 targets under MAX_MASTERS = 16.
            let finishes = client
                .log
                .records()?
                .into_iter()
                .filter(|record| record["event"] == "master_finish")
                .count();
            ensure!(
                finishes >= 4,
                "expected at least 4 evicted masters, saw {finishes}"
            );

            // Immediately close the last active master and re-acquire without connection_lost.
            let last = masters(&client.log)?.pop().context("last master")?;
            let closed = support::run(
                Command::new(&fixture.ssh)
                    .arg("-F")
                    .arg(&fixture.ssh_config)
                    .arg("-S")
                    .arg(&last.1)
                    .args(["-O", "exit", "plain"]),
            )
            .await?;
            ensure!(closed.status.success(), "failed to exit test master");
            let reacquired = client
                .call(
                    "ssh_exec",
                    json!({"host": "sweep19", "command": "printf REACQUIRED"}),
                )
                .await?;
            ensure!(
                succeeded(&reacquired)?["stdout"] == "REACQUIRED",
                "immediate re-acquire failed: {reacquired}"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        run?;
        stopped?;
        assert_masters_gone(&owned?).await?;
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
        let stopped = server.stop(None).await;
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
            "[ \"$ESTUS\" = 1 ] && ",
            "[ \"${{ESTUS_H04_HOST+x}}\" != x ] && ",
            "[ \"${{ESTUS_H04_MATCH+x}}\" != x ] && ",
            "[ \"${{ESTUS_H04_INCLUDE+x}}\" != x ] || exit 93; exec {}"
        ),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&guard));
    let fixture = Fixture::start_with_sftp_subsystem(
        indoc! {"
        AcceptEnv ESTUS ESTUS_H04_HOST ESTUS_H04_MATCH ESTUS_H04_INCLUDE
    "},
        &subsystem,
    )
    .await?;
    let scenario = async {
        let controls = [
            (
                "plain",
                "ESTUS_H04_HOST",
                "h04-host-secret",
                "operator-host",
            ),
            (
                "viajump",
                "ESTUS_H04_MATCH",
                "h04-match-secret",
                "operator-match",
            ),
            (
                "nosftp",
                "ESTUS_H04_INCLUDE",
                "h04-include-secret",
                "operator-include",
            ),
        ];
        let inherited = fixture.root.path().join("inherited-env.conf");
        fs::write(
            &inherited,
            indoc! {"
            Host nosftp
                SetEnv ESTUS_H04_INCLUDE=h04-include-secret ESTUS=operator-include
            Host *
        "},
        )?;
        let original = fs::read_to_string(&fixture.ssh_config)?;
        fs::write(
            &fixture.ssh_config,
            formatdoc! {"
            Host plain
                SetEnv ESTUS_H04_HOST=h04-host-secret ESTUS=operator-host
            Match originalhost viajump
                SetEnv ESTUS_H04_MATCH=h04-match-secret ESTUS=operator-match
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
            let command = format!("printf '%s:%s' \"${variable}\" \"$ESTUS\"");
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
            printf '%s:%s:%s:%s' "$ESTUS" \
                "${ESTUS_H04_HOST+x}" \
                "${ESTUS_H04_MATCH+x}" \
                "${ESTUS_H04_INCLUDE+x}"
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
                    let stopped = server.stop(sigterm.then_some(Signal::SIGTERM)).await;
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
                    }).await.with_context(|| format!(
                        "MCP fixture connections did not disconnect: phase={phase}, SIGTERM={sigterm}, baseline={baseline:?}, current={:?}, sshd_log={}",
                        connection_activity(&fixture), fixture.listeners[0].log.text(),
                    ));
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

fn directory_token(data: &Value) -> Result<String> {
    let token = data["continuation"]
        .as_str()
        .context("directory continuation")?;
    ensure!(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    ensure!(data["truncated"] == true);
    ensure!(
        data["expires_in_secs"]
            .as_u64()
            .is_some_and(|seconds| (1..=300).contains(&seconds))
    );
    Ok(token.to_owned())
}

async fn drain_directory(
    client: &Client,
    host: &str,
    path: &Path,
    mut data: Value,
    page_size: usize,
) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    let mut tokens = std::collections::HashSet::new();
    loop {
        let page = data["entries"]
            .as_array()
            .context("directory page entries")?;
        ensure!(
            !page.is_empty() || data["truncated"] == false,
            "nonterminal page made no progress"
        );
        ensure!(page.len() <= page_size);
        ensure!(
            serde_json::to_vec(page)?.len() <= 1_048_576,
            "directory page exceeded byte cap"
        );
        entries.extend(page.iter().cloned());
        if data["truncated"] == false {
            ensure!(data.get("continuation").is_none() && data.get("expires_in_secs").is_none());
            break;
        }
        let token = directory_token(&data)?;
        ensure!(
            tokens.insert(token.clone()),
            "directory token did not rotate"
        );
        let reply = client
            .call(
                "ssh_list_directory",
                json!({
                    "host":host,"path":path,"max_entries":page_size,"continuation":token
                }),
            )
            .await?;
        data = succeeded(&reply)?.clone();
        let stale = client
            .call(
                "ssh_list_directory",
                json!({
                    "host":host,"path":path,"max_entries":page_size,"continuation":token
                }),
            )
            .await?;
        failed(&stale, "not_found")?;
    }
    let mut names = std::collections::HashSet::new();
    for entry in &entries {
        let raw = STANDARD.decode(
            entry["name_base64"]
                .as_str()
                .context("raw directory name")?,
        )?;
        ensure!(names.insert(raw), "stable listing duplicated an entry");
    }
    Ok(entries)
}

fn directory_log_count(path: &Path, needle: &str) -> Result<usize> {
    match fs::read_to_string(path) {
        Ok(log) => Ok(log.lines().filter(|line| line.contains(needle)).count()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

async fn await_directory_log(path: &Path, needle: &str, count: usize) -> Result<()> {
    timeout(Duration::from_secs(10), async {
        loop {
            if directory_log_count(path, needle)? >= count {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("real SFTP lifecycle evidence did not arrive")??;
    ensure!(
        directory_log_count(path, needle)? == count,
        "unexpected SFTP replay/lifecycle count"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_directory_cursor_lifecycle() -> Result<()> {
    let work = tempfile::tempdir()?;
    let launches = work.path().join("launches");
    let closed = work.path().join("closed");
    let requests = work.path().join("requests");
    let script = format!(
        "trap '' HUP; exec 3<&0; {} <&3 -e -l VERBOSE 2>> {} & child=$!; echo launched >> {}; wait $child; echo closed >> {}",
        Fixture::sftp_server()?.display(),
        requests.display(),
        launches.display(),
        closed.display(),
    );
    let fixture =
        Fixture::start_with_sftp_subsystem("", &format!("/bin/sh -c {}", quote(&script))).await?;
    let scenario = async {
        let directory = fixture.root.path().join("cursor-directory");
        fs::create_dir(&directory)?;
        for i in 0..3201 {
            fs::write(directory.join(format!("entry-{i:05}")), b"")?;
        }
        #[cfg(target_os = "linux")]
        fs::write(directory.join(std::ffi::OsString::from_vec(b"raw-\xff\xfe".to_vec())), b"")?;
        let expected: std::collections::BTreeSet<_> = fs::read_dir(&directory)?
            .map(|entry| Ok(entry?.file_name().as_bytes().to_vec()))
            .collect::<Result<_>>()?;
        let client = Client::start(&fixture.config).await?;
        let mut private_tokens = Vec::new();
        let cases = async {
            let first = client.call("ssh_list_directory", json!({"host":"plain","path":directory,"max_entries":1})).await?;
            let token = directory_token(succeeded(&first)?)?;
            private_tokens.push(token.clone());
            for args in [
                json!({"host":"resource","path":directory,"continuation":token}),
                json!({"host":"plain","path":directory.join("."),"continuation":token}),
            ] {
                failed(&client.call("ssh_list_directory", args).await?, "invalid_argument")?;
            }
            let foreign = Client::start(&fixture.config).await?;
            let denied = foreign.call("ssh_list_directory", json!({"host":"plain","path":directory,"continuation":token})).await;
            let stopped = foreign.stop().await;
            failed(&denied?, "not_found")?;
            stopped?;
            ensure!(succeeded(&exec(&client, "printf CURSOR_PEER").await?)?["stdout"] == "CURSOR_PEER");
            let stat = client.call("ssh_stat", json!({"host":"plain","path":directory})).await?;
            succeeded(&stat)?;
            let next = client.call("ssh_list_directory", json!({
                "host":"plain","path":directory,"max_entries":127,"timeout_secs":5,"continuation":token
            })).await?;
            failed(&client.call("ssh_list_directory", json!({"host":"plain","path":directory,"continuation":token})).await?, "not_found")?;
            let mut all = succeeded(&first)?["entries"].as_array().context("initial entries")?.clone();
            all.extend(drain_directory(&client, "plain", &directory, succeeded(&next)?.clone(), 127).await?);
            let mut actual = std::collections::BTreeSet::new();
            for entry in &all {
                ensure!(actual.insert(STANDARD.decode(entry["name_base64"].as_str().context("raw name")?)?), "duplicate across first page");
            }
            ensure!(actual == expected, "stable continuation lost raw entries");
            await_directory_log(&closed, "closed", 2).await?; // listing + native stat
            ensure!(directory_log_count(&requests, "opendir \"")? == 1, "pages reopened directory");
            ensure!(directory_log_count(&launches, "")? == 2, "invalid/foreign handles launched a subsystem");

            // Mutation has no snapshot promise. Finish this same stream, bounding
            // progress, but deliberately do not compare it to either filesystem set.
            let first = client.call("ssh_list_directory", json!({"host":"plain","path":directory,"max_entries":1000})).await?;
            fs::remove_file(directory.join("entry-03200"))?;
            fs::write(directory.join("churn-new"), b"")?;
            let mut page = succeeded(&first)?.clone();
            let mut seen_tokens = std::collections::HashSet::new();
            for _ in 0..10 {
                if page["truncated"] == false { break; }
                let token = directory_token(&page)?;
                ensure!(seen_tokens.insert(token.clone()), "churn reused token");
                let reply = client.call("ssh_list_directory", json!({"host":"plain","path":directory,"max_entries":1000,"continuation":token})).await?;
                page = succeeded(&reply)?.clone();
                ensure!(page["entries"].as_array().context("churn entries")?.len() <= 1000);
            }
            ensure!(page["truncated"] == false, "churn made no bounded progress");
            await_directory_log(&closed, "closed", 3).await?;
            ensure!(directory_log_count(&requests, "opendir \"")? == 2, "churn silently restarted");

            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        cases?;
        let stopped = stopped?;
        let diagnostics = stopped.text();
        ensure!(!diagnostics.contains(directory.to_str().context("directory path")?));
        for token in private_tokens {
            ensure!(!diagnostics.contains(&token), "directory token leaked into audit");
        }
        assert_masters_gone(&owned?).await?;
        let capacity = Client::start(&fixture.config).await?;
        let capacity_cases = async {
            let empty = fixture.root.path().join("cursor-empty");
            fs::create_dir(&empty)?;
            for (index, host) in ["plain", "resource", "slots-0", "slots-1"].into_iter().enumerate() {
                for _ in 0..2 {
                    let reply = capacity.call("ssh_list_directory", json!({"host":host,"path":directory,"max_entries":1})).await?;
                    directory_token(succeeded(&reply)?)?;
                }
                if index == 0 {
                    let denied = capacity.call("ssh_list_directory", json!({"host":host,"path":directory,"max_entries":1})).await?;
                    failed(&denied, "resource_limit")?;
                    let one_shot = capacity.call("ssh_list_directory", json!({"host":host,"path":empty,"max_entries":1})).await?;
                    ensure!(succeeded(&one_shot)? == &json!({"entries":[],"truncated":false}));
                    let (command, read) = tokio::join!(
                        exec(&capacity, "printf IDLE_CURSORS_ALLOW_NATIVE_WORK"),
                        capacity.call("ssh_read_file", json!({"host":"plain","path":directory.join("entry-00000"),"max_bytes":1}))
                    );
                    ensure!(succeeded(&command?)?["stdout"] == "IDLE_CURSORS_ALLOW_NATIVE_WORK");
                    succeeded(&read?)?;
                }
            }
            let denied = capacity.call("ssh_list_directory", json!({"host":"slots-2","path":directory,"max_entries":1})).await?;
            failed(&denied, "resource_limit")?;
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&capacity.log);
        let stopped = capacity.stop().await;
        capacity_cases?;
        stopped?;
        assert_masters_gone(&owned?).await?;
        await_directory_log(&closed, "closed", directory_log_count(&launches, "")?).await?;


        // A one-credit, one-second store proves global exhaustion, timer-owned
        // cleanup and EOF cleanup using remote channel/session completion.
        let config = fixture.root.path().join("directory-limits.toml");
        fs::write(&config, format!("{}\n[directory]\nmax_cursors=1\nidle_timeout_secs=1\n", fs::read_to_string(&fixture.config)?))?;
        let mut wire = WireServer::start(&config)?;
        let cases = async {
            wire.initialize().await?;
            script_wire_call(&mut wire, 10, "ssh_exec", json!({"host":"resource","command":"printf WARM_CURSOR_PEER"})).await
                .and_then(|reply| succeeded(&reply).map(|_| ()))?;
            let first = script_wire_call(&mut wire, 2, "ssh_list_directory", json!({"host":"plain","path":directory,"max_entries":1})).await?;
            let expired = directory_token(succeeded(&first)?)?;
            ensure!(succeeded(&first)?["expires_in_secs"] == 1);
            let denied = script_wire_call(&mut wire, 3, "ssh_list_directory", json!({"host":"resource","path":directory,"max_entries":1})).await?;
            failed(&denied, "resource_limit")?;
            let launched = directory_log_count(&launches, "")?;
            await_directory_log(&closed, "closed", launched).await?;
            let stale = script_wire_call(&mut wire, 4, "ssh_list_directory", json!({"host":"plain","path":directory,"continuation":expired})).await?;
            failed(&stale, "not_found")?;
            let next = script_wire_call(&mut wire, 5, "ssh_list_directory", json!({"host":"plain","path":directory,"max_entries":1})).await?;
            directory_token(succeeded(&next)?)?;
            // Leave this retained cursor open: EOF below must close its channel
            // and reap the owned master, independently of idle expiry.
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&wire.log);
        let stopped = wire.stop(None).await;
        cases?;
        stopped?;
        await_directory_log(&closed, "closed", directory_log_count(&launches, "")?).await?;
        assert_masters_gone(&owned?).await
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup?;
    work.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_directory_cursor_controlled_fault_cleanup() -> Result<()> {
    for cancel in [false, true] {
        let work = tempfile::tempdir()?;
        let first_session = work.path().join("first-session");
        let normal_launches = work.path().join("normal-launches");
        let requests = work.path().join("requests");
        let server = Fixture::sftp_server()?;
        let fault = if cancel {
            replace_relay::Fault::DirectoryPageAck
        } else {
            replace_relay::Fault::None
        };
        let mut relay = replace_relay::Relay::start(&server, fault, None).await?;
        // Exactly one genuine subsystem uses the relay. Explicit new listings
        // use the ordinary real server, never a test-created protocol response.
        let script = format!(
            "if mkdir {} 2>/dev/null; then {}; else echo launched >> {}; exec {} -e -l VERBOSE 2>> {}; fi",
            quote(&first_session.to_string_lossy()),
            relay.subsystem,
            quote(&normal_launches.to_string_lossy()),
            quote(&server.to_string_lossy()),
            quote(&requests.to_string_lossy()),
        );
        let launcher = work.path().join("sftp-route");
        fs::write(&launcher, format!("#!/bin/sh\n{script}\n"))?;
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700))?;
        let fixture =
            match Fixture::start_with_sftp_subsystem("", launcher.to_str().context("route path")?)
                .await
            {
                Ok(fixture) => fixture,
                Err(error) => {
                    let _ = relay.stop().await;
                    return Err(error);
                }
            };
        let scenario = async {
            let directory = fixture.root.path().join("controlled-cursor-private");
            fs::create_dir(&directory)?;
            for index in 0..3201 {
                fs::write(directory.join(format!("entry-{index:05}")), b"")?;
            }
            let peer = fixture.root.path().join("cursor-peer");
            fs::write(&peer, b"CURSOR_NATIVE_PEER")?;
            let config = fixture.root.path().join("controlled-directory.toml");
            fs::write(
                &config,
                format!(
                    "{}\n[directory]\nmax_cursors=1\nidle_timeout_secs=300\n",
                    fs::read_to_string(&fixture.config)?,
                ),
            )?;
            let client = Client::start(&config).await?;
            let mut private_tokens = Vec::new();
            let cases = async {
                ensure!(
                    succeeded(&exec(&client, "printf CONTROLLED_CURSOR_MASTER").await?)?["stdout"]
                        == "CONTROLLED_CURSOR_MASTER"
                );
                let owned = observed_masters(&client.log, 1).await?;
                let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
                let first = client
                    .call(
                        "ssh_list_directory",
                        json!({
                            "host":"plain","path":directory,"max_entries":1
                        }),
                    )
                    .await?;
                let dead = directory_token(succeeded(&first).context("initial controlled page")?)?;
                private_tokens.push(dead.clone());
                if cancel {
                    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
                        "ssh_list_directory",
                        json!({"host":"plain","path":directory,"max_entries":1000,
                            "continuation":dead,"timeout_secs":10}),
                    )));
                    let handle = timeout(
                        Duration::from_secs(5),
                        client
                            .service
                            .send_cancellable_request(request, PeerRequestOptions::default()),
                    )
                    .await??;
                    timeout(Duration::from_secs(5), async {
                        loop {
                            let withheld = {
                                let seen = relay
                                    .evidence
                                    .lock()
                                    .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                                seen.dropped_directory_page
                            };
                            if withheld {
                                return Ok::<_, anyhow::Error>(());
                            }
                            sleep(Duration::from_millis(20)).await;
                        }
                    })
                    .await
                    .context("real second READDIR response was not withheld")??;
                    let started = timeout(Duration::from_secs(5), async {
                        loop {
                            if let Some(record) = client
                                .log
                                .records()?
                                .into_iter()
                                .filter(|record| {
                                    record["event"] == "start"
                                        && record["tool"] == "ssh_list_directory"
                                })
                                .nth(1)
                            {
                                return Ok::<_, anyhow::Error>(record);
                            }
                            sleep(Duration::from_millis(20)).await;
                        }
                    })
                    .await
                    .context("continued page start audit did not arrive")??;
                    timeout(
                        Duration::from_secs(5),
                        handle.cancel(Some("directory acceptance cancellation".into())),
                    )
                    .await??;
                    let finished = await_audit(&client.log, "finish", "cancelled").await?;
                    ensure!(
                        finished["tool"] == "ssh_list_directory"
                            && finished["request_id"] == started["request_id"]
                            && !finished["request_id"].is_null(),
                        "cancellation audit was not correlated to the blocked page"
                    );
                    // No helper teardown/kill precedes this observation: actual
                    // cancellation must close the relay input and real server.
                    relay.wait_server_exit().await?;
                } else {
                    relay.disconnect_server().await?;
                    // Production emits this only after registry and credits
                    // are released; process death alone is not that barrier.
                    await_audit(&client.log, "directory_cursor_error", "connection_lost").await?;
                }
                let (command, read) = tokio::join!(
                    exec(&client, "printf CONTROLLED_CURSOR_PEER"),
                    client.call("ssh_read_file", json!({"host":"plain","path":peer}))
                );
                ensure!(succeeded(&command?)?["stdout"] == "CONTROLLED_CURSOR_PEER");
                ensure!(succeeded(&read?)?["content"] == "CURSOR_NATIVE_PEER");
                ensure!(
                    live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                    "directory failure replaced the healthy ordinary master"
                );
                // Crucially acquire replacement credit BEFORE presenting dead.
                let replacement = client
                    .call(
                        "ssh_list_directory",
                        json!({
                            "host":"plain","path":directory,"max_entries":1000
                        }),
                    )
                    .await?;
                private_tokens.push(directory_token(
                    succeeded(&replacement).context("replacement page")?,
                )?);
                let before_stale = directory_log_count(&normal_launches, "launched")?;
                for _ in 0..2 {
                    failed(
                        &client
                            .call(
                                "ssh_list_directory",
                                json!({
                                    "host":"plain","path":directory,"continuation":dead
                                }),
                            )
                            .await?,
                        "not_found",
                    )?;
                }
                ensure!(
                    directory_log_count(&normal_launches, "launched")? == before_stale,
                    "dead cursor launched a replacement subsystem"
                );
                let entries = drain_directory(
                    &client,
                    "plain",
                    &directory,
                    succeeded(&replacement)?.clone(),
                    1000,
                )
                .await?;
                ensure!(
                    entries.len() == 3201,
                    "replacement did not exhaust the real directory"
                );
                // Exhaustion must return the sole credit as well.
                let again = client
                    .call(
                        "ssh_list_directory",
                        json!({
                            "host":"plain","path":directory,"max_entries":1000
                        }),
                    )
                    .await?;
                private_tokens.push(directory_token(
                    succeeded(&again).context("page after exhaustion")?,
                )?);
                ensure!(
                    drain_directory(
                        &client,
                        "plain",
                        &directory,
                        succeeded(&again)?.clone(),
                        1000
                    )
                    .await?
                    .len()
                        == 3201
                );
                await_directory_log(&requests, "opendir \"", 2).await?;
                let seen = relay
                    .evidence
                    .lock()
                    .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                ensure!(
                    seen.requests.iter().filter(|kind| **kind == 11).count() == 1,
                    "failed cursor reopened its directory"
                );
                if cancel {
                    ensure!(
                        seen.dropped_directory_page
                            && seen.readdirs >= 2
                            && seen.readdir_ids.len() == seen.readdirs
                    );
                }
                ensure!(
                    fs::read_to_string(&relay.launches)?.lines().count() == 1,
                    "controlled session was replayed"
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
            let log = stopped?;
            let diagnostics = log.text();
            ensure!(!diagnostics.contains(directory.to_str().context("directory path")?));
            for token in private_tokens {
                ensure!(
                    !diagnostics.contains(&token),
                    "directory token leaked into audit"
                );
            }
            for record in log.final_records()?.iter().filter(|record| {
                record["tool"] == "ssh_list_directory"
                    || record["event"] == "directory_cursor_error"
            }) {
                for field in ["path", "filename", "continuation", "target", "content"] {
                    ensure!(
                        record.get(field).is_none(),
                        "directory audit disclosed {field}"
                    );
                }
            }
            gone
        }
        .await;
        let relayed = relay.stop().await;
        let cleanup = fixture.stop().await;
        scenario
            .with_context(|| format!("controlled cursor cancel={cancel}; relay={relayed:?}"))?;
        relayed?;
        cleanup?;
        work.close()?;
    }
    Ok(())
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
        let data = succeeded(&reply)?;
        ensure!(
            data["entries"] == json!(&expected[..count]) && data["truncated"] == truncated,
            "listing lost bytes, reordered entries, fabricated metadata or misreported lookahead"
        );
        let all = drain_directory(
            client,
            "plain",
            &directory,
            data.clone(),
            limit.unwrap_or(200),
        )
        .await?;
        ensure!(all == expected);
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
    let all = drain_directory(client, "plain", &directory, data.clone(), 1000).await?;
    let actual: std::collections::BTreeSet<_> = all
        .iter()
        .map(|entry| {
            STANDARD
                .decode(entry["name_base64"].as_str().context("listed raw name")?)
                .map_err(Into::into)
        })
        .collect::<Result<_>>()?;
    let expected: std::collections::BTreeSet<_> = fs::read_dir(&directory)?
        .map(|entry| Ok(entry?.file_name().as_bytes().to_vec()))
        .collect::<Result<_>>()?;
    ensure!(
        actual == expected,
        "paged listing lost or invented raw filenames"
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
            for field in ["path", "name", "name_base64", "metadata", "entries", "continuation", "expires_in_secs"] {
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
        let stopped = wire.stop(None).await;
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
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_directory_cursor_byte_budget() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let directory = fixture.root.path().join("directory-byte-budget");
        fs::create_dir(&directory)?;
        for index in 0..1505 {
            let name = format!("entry-{index:04}-{}", "a".repeat(229));
            ensure!(name.len() == 240);
            fs::write(directory.join(name), b"")?;
        }
        let expected: std::collections::BTreeSet<_> = fs::read_dir(&directory)?
            .map(|entry| Ok(entry?.file_name().as_bytes().to_vec()))
            .collect::<Result<_>>()?;
        ensure!(expected.len() == 1505);
        let mut wire = WireServer::start(&fixture.config)?;
        let cases = async {
            wire.initialize().await?;
            let mut continuation = None;
            let mut tokens = std::collections::HashSet::new();
            let mut actual = std::collections::BTreeSet::new();
            let mut exhausted = false;
            for page in 0..16 {
                let mut args = json!({"host":"plain","path":directory,"max_entries":1000});
                if let Some(token) = &continuation {
                    args["continuation"] = json!(token);
                }
                let id = json!(page + 10);
                let (frame, size) = wire
                    .request_with_size(
                        id.clone(),
                        "tools/call",
                        json!({"name":"ssh_list_directory","arguments":args}),
                    )
                    .await?;
                ensure!(
                    frame["id"] == id && frame.get("error").is_none(),
                    "unexpected JSON-RPC directory response"
                );
                ensure!(
                    size <= 1_048_576 + 2048,
                    "actual directory reply exceeded byte budget: {size}"
                );
                let result = &frame["result"];
                let reply = &result["structuredContent"];
                ensure!(
                    serde_json::from_str::<Value>(
                        result["content"][0]["text"]
                            .as_str()
                            .context("directory compatibility text")?,
                    )? == *reply,
                    "directory result representations disagree"
                );
                ensure!(!result["isError"].as_bool().unwrap_or(false));
                let data = succeeded(reply)?;
                let entries = data["entries"].as_array().context("byte-budget entries")?;
                ensure!(
                    !entries.is_empty() && entries.len() <= 1000,
                    "byte-budget page made no bounded progress"
                );
                if page == 0 {
                    ensure!(
                        entries.len() < 1000 && data["truncated"] == true,
                        "first page did not exercise byte rather than entry-count limit"
                    );
                }
                for entry in entries {
                    let raw = STANDARD.decode(
                        entry["name_base64"]
                            .as_str()
                            .context("byte-budget raw filename")?,
                    )?;
                    ensure!(actual.insert(raw), "byte lookahead duplicated a filename");
                }
                if data["truncated"] == false {
                    ensure!(
                        data.get("continuation").is_none() && data.get("expires_in_secs").is_none()
                    );
                    exhausted = true;
                    break;
                }
                let token = directory_token(data)?;
                ensure!(
                    tokens.insert(token.clone()),
                    "byte-budget token did not rotate"
                );
                continuation = Some(token);
            }
            ensure!(exhausted, "byte-budget listing did not reach EOF");
            ensure!(
                actual == expected,
                "byte lookahead lost or invented raw filenames"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&wire.log);
        let stopped = wire.stop(None).await;
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
                            "ssh_mkdir",
                            "ssh_read_file",
                            "ssh_read_output",
                            "ssh_remove_directory",
                            "ssh_remove_file",
                            "ssh_rename",
                            "ssh_replace_file",
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
                let reply = client.call("ssh_replace_file", json!({
                    "host":"locked","path":file,"content":"MUST_NOT_REPLACE","overwrite":true,
                })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&file)? == b"abc");
                let denied_directory = directory.join("mkdir-policy-denied");
                let reply = client
                    .call(
                        "ssh_mkdir",
                        json!({
                            "host":"locked","path":denied_directory,
                        }),
                    )
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    !denied_directory.exists(),
                    "read-only target created a directory"
                );
                let denied_rename = directory.join("rename-policy-denied");
                let reply = client.call("ssh_rename", json!({
                    "host":"locked","source":file,"destination":denied_rename,"overwrite":true
                })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&file)? == b"abc" && !denied_rename.exists());
                let reply = client
                    .call(
                        "ssh_remove_file",
                        json!({
                            "host":"locked","path":file
                        }),
                    )
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    fs::read(&file)? == b"abc",
                    "read-only target unlinked an entry"
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
                let created_directory = directory.join("mkdir-allowed");
                let reply = client
                    .call(
                        "ssh_mkdir",
                        json!({
                            "host":"allowed","path":created_directory,
                        }),
                    )
                    .await?;
                succeeded(&reply)?;
                ensure!(
                    fs::symlink_metadata(&created_directory)?
                        .file_type()
                        .is_dir(),
                    "files-only profile did not create the actual allowed directory"
                );
                ensure!(fs::read_dir(&created_directory)?.next().is_none());
                ensure!(fs::read(&file)? == b"abc", "mkdir changed its sibling file");
                let created_inode = fs::symlink_metadata(&created_directory)?.ino();
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"locked","path":created_directory}))
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::symlink_metadata(&created_directory)?.ino() == created_inode);
                ensure!(fs::read_dir(&created_directory)?.next().is_none());
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"allowed","path":created_directory}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    matches!(fs::symlink_metadata(&created_directory), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "files-only profile did not remove the actual allowed empty directory"
                );
                ensure!(fs::read(&file)? == b"abc", "rmdir changed its sibling file");
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
                let previous_inode = fs::metadata(&file)?.ino();
                let reply = client.call("ssh_replace_file", json!({
                    "host":"allowed","path":file,"content":payload,"overwrite":true,
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":payload.len()}));
                ensure!(fs::read(&file)? == payload.as_bytes());
                ensure!(fs::metadata(&file)?.ino() != previous_inode);
                ensure!(fs::metadata(&file)?.mode() & 0o7777 == 0o600);
                let reply = client.call("ssh_read_file", json!({"host":"locked","path":file})).await?;
                ensure!(succeeded(&reply)?["content"] == payload);
                let renamed = directory.join("renamed");
                let before = fs::symlink_metadata(&file)?.ino();
                let reply = client
                    .call(
                        "ssh_rename",
                        json!({
                            "host":"allowed","source":file,"destination":renamed,"overwrite":true
                        }),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(!file.exists() && fs::symlink_metadata(&renamed)?.ino() == before);
                ensure!(fs::read(&renamed)? == payload.as_bytes());
                let reply = client
                    .call("ssh_read_file", json!({"host":"locked","path":renamed}))
                    .await?;
                ensure!(succeeded(&reply)?["content"] == payload);
                let reply = client
                    .call("ssh_remove_file", json!({"host":"locked","path":renamed}))
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::symlink_metadata(&renamed)?.ino() == before);
                ensure!(fs::read(&renamed)? == payload.as_bytes());
                let reply = client
                    .call("ssh_remove_file", json!({"host":"allowed","path":renamed}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    fs::symlink_metadata(&renamed).is_err(),
                    "files-only profile did not unlink the actual allowed entry"
                );
                ensure!(fs::read_dir(&directory)?.next().is_none());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_mkdir() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.mkdir-locked]\nssh_host = 'plain'\nprofile = 'read-only-files'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("mkdir-private");
        fs::create_dir(&directory)?;
        let sibling = directory.join("preserved-file");
        fs::write(&sibling, b"MKDIR_KEEP_SIBLING")?;
        let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"mkdir\0invalid"}),
                json!({"host":"plain","path":directory.join("zero"),"timeout_secs":0}),
                json!({"host":"plain","path":directory.join("over-limit"),"timeout_secs":16}),
            ] {
                let reply = client.call("ssh_mkdir", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let denied = directory.join("policy-denied");
            let reply = client
                .call(
                    "ssh_mkdir",
                    json!({
                        "host":"mkdir-locked","path":denied
                    }),
                )
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(
                masters(&client.log)?.is_empty(),
                "invalid or denied mkdir acquired SSH"
            );
            ensure!(
                fixture.authentications() == initial_auth,
                "invalid or denied mkdir authenticated"
            );
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "rejected mkdir changed directory entries"
            );

            succeeded(&exec(&client, "printf MKDIR_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let names = [
                "ordinary",
                "  é雪 directory  ",
                "'\";~$*\n$(printf EVALUATED)",
            ];
            for name in names {
                let path = directory.join(name);
                let reply = client
                    .call("ssh_mkdir", json!({"host":"plain","path":path}))
                    .await?;
                succeeded(&reply)?;
                ensure!(
                    fs::symlink_metadata(&path)?.file_type().is_dir(),
                    "{name:?}: no actual directory"
                );
                ensure!(
                    fs::read_dir(&path)?.next().is_none(),
                    "{name:?}: directory not empty"
                );
                let reply = client
                    .call("ssh_stat", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(succeeded(&reply)? == &native_stat_data(&path, false)?);
            }
            let existing = directory.join("ordinary");
            let child = existing.join("keep-child");
            fs::write(&child, b"KEEP_DIRECTORY_CHILD")?;
            let live = directory.join("live-link");
            symlink(&existing, &live)?;
            let dangling = directory.join("dangling-link");
            let absent = directory.join("absent-target");
            symlink(&absent, &dangling)?;
            for path in [&existing, &sibling, &live, &dangling] {
                let before = fs::symlink_metadata(path)?;
                let reply = client
                    .call("ssh_mkdir", json!({"host":"plain","path":path}))
                    .await?;
                failed(&reply, "already_exists")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                let after = fs::symlink_metadata(path)?;
                ensure!(
                    after.ino() == before.ino() && after.file_type() == before.file_type(),
                    "{}: existing entry replaced",
                    path.display()
                );
                ensure!(fs::read(&child)? == b"KEEP_DIRECTORY_CHILD");
                ensure!(fs::read(&sibling)? == b"MKDIR_KEEP_SIBLING");
                ensure!(fs::read_link(&live)? == existing);
                ensure!(fs::read_link(&dangling)? == absent && !absent.exists());
            }
            let missing = directory.join("missing-parent");
            let reply = client
                .call(
                    "ssh_mkdir",
                    json!({
                        "host":"plain","path":missing.join("child")
                    }),
                )
                .await?;
            ensure!(
                matches!(
                    reply["error"]["code"].as_str(),
                    Some("not_found" | "permission_denied" | "io_error")
                ),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                !missing.exists(),
                "mkdir recursively created a missing parent"
            );
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = names
                .iter()
                .map(|name| std::ffi::OsString::from(*name))
                .collect::<Vec<_>>();
            expected.extend(
                ["preserved-file", "live-link", "dangling-link"].map(std::ffi::OsString::from),
            );
            expected.sort();
            ensure!(
                entries == expected,
                "mkdir changed sibling entries or expanded a literal path"
            );
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"MKDIR_KEEP_SIBLING");
            let reply = client
                .call("ssh_read_file", json!({"host":"plain","path":sibling}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "MKDIR_KEEP_SIBLING");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "mkdir discarded the shared healthy master"
            );

            let unsupported = directory.join("no-subsystem");
            let reply = client
                .call("ssh_mkdir", json!({"host":"nosftp","path":unsupported}))
                .await?;
            ensure!(
                matches!(
                    reply["error"]["code"].as_str(),
                    Some("unsupported" | "io_error" | "connection_lost")
                ),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(
                !unsupported.exists(),
                "unavailable SFTP ran a mkdir fallback"
            );
            let before = observed_masters(&client.log, 2).await?;
            let reply = client
                .call(
                    "ssh_exec",
                    json!({
                        "host":"nosftp","command":"printf MKDIR_NO_SUBSYSTEM_HEALTHY"
                    }),
                )
                .await?;
            ensure!(succeeded(&reply)?["stdout"] == "MKDIR_NO_SUBSYSTEM_HEALTHY");
            ensure!(
                masters(&client.log)? == before,
                "unavailable SFTP replaced a healthy master"
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
            !log.text().contains("mkdir-private"),
            "mkdir audit disclosed a private path"
        );
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_mkdir_dispatch_failure() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    // This is the real SFTP server's policy denial, not a simulated reply.
    // Its own refusal log counts requests, including retries within one channel.
    let script = format!(
        "echo launch >> {}; exec {} -P mkdir -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MKDIR_FAULT_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("mkdir-fault");
            fs::create_dir(&directory)?;
            let sibling = directory.join("sibling");
            fs::write(&sibling, b"KEEP_FAULT_SIBLING")?;
            let path = directory.join("denied");
            let reply = client
                .call("ssh_mkdir", json!({"host":"plain","path":path}))
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(!path.exists(), "SFTP denial caused a shell fallback");
            ensure!(fs::read(&sibling)? == b"KEEP_FAULT_SIBLING");
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "SFTP denial changed sibling entries"
            );
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "SFTP mkdir denial discarded a healthy master"
            );
            ensure!(
                fs::read_to_string(&launches)?.lines().count() == 1,
                "mkdir denial replayed the SFTP session"
            );
            let log = fs::read_to_string(&requests)?;
            ensure!(
                log.lines()
                    .filter(|line| line.contains("Refusing") && line.contains("mkdir request"))
                    .count()
                    == 1,
                "expected exactly one actual MKDIR refusal, without replay: {log}"
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
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_mkdir_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let server = Fixture::sftp_server()?;
    // Delay only the handshake; the finite guard is awaited even on assertion
    // failure, before its private filesystem is removed.
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {}",
        started.display(),
        done.display(),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MKDIR_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("mkdir-delay");
            fs::create_dir(&directory)?;
            let sibling = directory.join("sibling");
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let path = directory.join("never-dispatched");
            let reply = client
                .call(
                    "ssh_mkdir",
                    json!({
                        "host":"plain","path":path,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake interruption discarded a healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "handshake timeout replayed SFTP"
            );
            ensure!(!path.exists(), "handshake timeout ran a mkdir fallback");
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "handshake timeout changed sibling entries"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // Await the finite remote guard even when the request assertion failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
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
                "ordinary_identity", "ssh_read_output", "ssh_targets",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_rename_moves_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.rename-locked]\nssh_host = 'plain'\nprofile = 'read-only-files'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("rename-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let destination = directory.join("destination");
        fs::write(&source, b"RENAME_SOURCE_BYTES")?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","source":"","destination":destination,"overwrite":true}),
                json!({"host":"plain","source":source,"destination":"","overwrite":true}),
                json!({"host":"plain","source":"source\0invalid","destination":destination,"overwrite":true}),
                json!({"host":"plain","source":source,"destination":"destination\0invalid","overwrite":true}),
                json!({"host":"plain","source":source,"destination":destination,"overwrite":true,"timeout_secs":0}),
                json!({"host":"plain","source":source,"destination":destination,"overwrite":true,"timeout_secs":16}),
            ] {
                let reply = client.call("ssh_rename", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call(
                    "ssh_rename",
                    json!({"host":"rename-locked","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected rename acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected rename authenticated");
            ensure!(fs::read(&source)? == b"RENAME_SOURCE_BYTES");
            ensure!(!destination.exists() && fs::read_dir(&directory)?.count() == 1);

            succeeded(&exec(&client, "printf RENAME_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let inode = fs::symlink_metadata(&source)?.ino();
            let reply = client
                .call(
                    "ssh_rename",
                    json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&source).is_err(), "source survived successful rename");
            ensure!(fs::symlink_metadata(&destination)?.ino() == inode);
            ensure!(fs::read(&destination)? == b"RENAME_SOURCE_BYTES");

            let replacement = directory.join("replacement");
            let retained = directory.join("old-destination-hardlink");
            fs::hard_link(&destination, &retained)?;
            fs::write(&replacement, b"EXPLICIT_OVERWRITE_BYTES")?;
            let replacement_inode = fs::symlink_metadata(&replacement)?.ino();
            let reply = client
                .call(
                    "ssh_rename",
                    json!({"host":"plain","source":replacement,"destination":destination,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&replacement).is_err());
            ensure!(fs::symlink_metadata(&destination)?.ino() == replacement_inode);
            ensure!(fs::read(&destination)? == b"EXPLICIT_OVERWRITE_BYTES");
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::read(&retained)? == b"RENAME_SOURCE_BYTES");

            let tree = directory.join("tree");
            let moved_tree = directory.join("moved-tree");
            fs::create_dir(&tree)?;
            fs::write(tree.join("child"), b"TREE_CHILD")?;
            let tree_inode = fs::symlink_metadata(&tree)?.ino();
            let child_inode = fs::symlink_metadata(tree.join("child"))?.ino();
            let reply = client
                .call(
                    "ssh_rename",
                    json!({"host":"plain","source":tree,"destination":moved_tree,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&tree).is_err());
            ensure!(fs::symlink_metadata(&moved_tree)?.ino() == tree_inode);
            ensure!(fs::symlink_metadata(moved_tree.join("child"))?.ino() == child_inode);
            ensure!(fs::read(moved_tree.join("child"))? == b"TREE_CHILD");

            let missing_link_target = directory.join("missing-link-target");
            for (index, target) in [&destination, &missing_link_target]
                .into_iter()
                .enumerate()
            {
                let link = directory.join(format!("link-{index}"));
                let moved_link = directory.join(format!("moved-link-{index}"));
                symlink(target, &link)?;
                let link_inode = fs::symlink_metadata(&link)?.ino();
                let reply = client
                    .call(
                        "ssh_rename",
                        json!({"host":"plain","source":link,"destination":moved_link,"overwrite":true}),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(fs::symlink_metadata(&link).is_err());
                let metadata = fs::symlink_metadata(&moved_link)?;
                ensure!(metadata.file_type().is_symlink() && metadata.ino() == link_inode);
                ensure!(fs::read_link(&moved_link)? == *target);
            }
            ensure!(fs::read(&destination)? == b"EXPLICIT_OVERWRITE_BYTES");
            ensure!(fs::symlink_metadata(&missing_link_target).is_err());

            let literal_names = [
                ("  é雪 source  ", "  雪é destination  "),
                ("'\";~$*\n$(printf EVALUATED)", "${HOME} {{rename}}\n'\";*"),
            ];
            for (from, to) in literal_names {
                let source = directory.join(from);
                let destination = directory.join(to);
                fs::write(&source, b"LITERAL_RENAME_BYTES")?;
                let inode = fs::symlink_metadata(&source)?.ino();
                let reply = client
                    .call(
                        "ssh_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(fs::symlink_metadata(&source).is_err(), "{from:?}: source survived");
                ensure!(fs::symlink_metadata(&destination)?.ino() == inode, "{to:?}: inode changed");
                ensure!(fs::read(&destination)? == b"LITERAL_RENAME_BYTES");
            }
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "destination", "old-destination-hardlink", "moved-tree",
                "moved-link-0", "moved-link-1", "  雪é destination  ",
                "${HOME} {{rename}}\n'\";*",
            ]
            .map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "rename expanded a literal name or changed siblings");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "rename replaced the shared healthy master"
            );
            let reply = client
                .call("ssh_read_file", json!({"host":"plain","path":retained}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "RENAME_SOURCE_BYTES");
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
        ensure!(!log.text().contains("rename-private"), "rename audit disclosed private paths");
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_no_overwrite_preserves_entries() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "exec {} -e -l VERBOSE 2>> {}",
        server.display(),
        requests.display()
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let directory = fixture.root.path().join("protected-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let existing = directory.join("existing");
        let tree = directory.join("tree");
        let live = directory.join("live");
        let dangling = directory.join("dangling");
        let absent = directory.join("absent");
        let missing_target = directory.join("missing-target");
        fs::write(&source, b"KEEP_SOURCE")?;
        fs::write(&existing, b"KEEP_DESTINATION")?;
        fs::create_dir(&tree)?;
        fs::write(tree.join("child"), b"KEEP_CHILD")?;
        symlink(&existing, &live)?;
        symlink(&missing_target, &dangling)?;
        let entries = [&source, &existing, &tree, &live, &dangling];
        let inodes = entries
            .iter()
            .map(|path| fs::symlink_metadata(path).map(|metadata| metadata.ino()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf PROTECTED_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            // Existing files, directories, live/dangling links and absent names
            // all require the same conservative pre-dispatch rejection.
            for (source, destination) in [
                (&source, &existing),
                (&source, &tree),
                (&source, &live),
                (&source, &dangling),
                (&source, &absent),
                (&tree, &absent),
                (&live, &absent),
                (&dangling, &absent),
            ] {
                let omitted_err = client
                    .service
                    .call_tool(params(
                        "ssh_rename",
                        json!({"host":"plain","source":source,"destination":destination}),
                    ))
                    .await
                    .unwrap_err();
                ensure!(
                    format!("{omitted_err:?}").contains("-32602")
                        || matches!(omitted_err, rmcp::ServiceError::McpError(_))
                );
                let reply = client
                    .call(
                        "ssh_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":false}),
                    )
                    .await?;
                failed(&reply, "unsupported")?;
                    ensure!(
                        reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false
                    );
                    for (path, inode) in entries.iter().zip(&inodes) {
                        ensure!(
                            fs::symlink_metadata(path)?.ino() == *inode,
                            "{} changed",
                            path.display()
                        );
                    }
                    ensure!(fs::read(directory.join("source"))? == b"KEEP_SOURCE");
                    ensure!(fs::read(&existing)? == b"KEEP_DESTINATION");
                    ensure!(fs::read(tree.join("child"))? == b"KEEP_CHILD");
                    ensure!(fs::read_link(&live)? == existing);
                    ensure!(fs::read_link(&dangling)? == missing_target);
                    ensure!(fs::symlink_metadata(&absent).is_err());
                    ensure!(fs::symlink_metadata(&missing_target).is_err());
                    ensure!(fs::read_dir(&directory)?.count() == 5);
            }
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "unsupported rename discarded a healthy master"
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
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("protected-private"),
            "rename audit disclosed private paths"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.contains("session opened") && log.contains("session closed"),
            "{log}"
        );
        for mutation in [
            "rename old ",
            "open \"",
            "mkdir ",
            "remove name ",
            "rmdir name ",
            "symlink old ",
            "hardlink old ",
            "setstat name ",
            "fsetstat ",
        ] {
            ensure!(
                !log.contains(mutation),
                "unsupported rename dispatched {mutation:?}: {log}"
            );
        }
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_without_posix_extension_preserves_entries() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let server = Fixture::sftp_server()?;
    // OpenSSH suppresses the advertised extension for a denied request.
    let script = format!(
        "exec {} -P posix-rename -e -l VERBOSE 2>> {}",
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let directory = fixture.root.path().join("extension-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let existing = directory.join("existing");
        let live = directory.join("live");
        let dangling = directory.join("dangling");
        let absent = directory.join("absent");
        let missing_target = directory.join("missing-target");
        fs::write(&source, b"KEEP_EXTENSION_SOURCE")?;
        fs::write(&existing, b"KEEP_EXTENSION_DESTINATION")?;
        symlink(&existing, &live)?;
        symlink(&missing_target, &dangling)?;
        let entries = [&source, &existing, &live, &dangling];
        let inodes = entries
            .iter()
            .map(|path| fs::symlink_metadata(path).map(|metadata| metadata.ino()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf EXTENSION_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            for destination in [&existing, &live, &dangling, &absent] {
                let reply = client
                    .call(
                        "ssh_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                    )
                    .await?;
                failed(&reply, "unsupported")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                for (path, inode) in entries.iter().zip(&inodes) {
                    ensure!(fs::symlink_metadata(path)?.ino() == *inode, "{} changed", path.display());
                }
                ensure!(fs::read(&source)? == b"KEEP_EXTENSION_SOURCE");
                ensure!(fs::read(&existing)? == b"KEEP_EXTENSION_DESTINATION");
                ensure!(fs::read_link(&live)? == existing);
                ensure!(fs::read_link(&dangling)? == missing_target);
                ensure!(fs::symlink_metadata(&absent).is_err());
                ensure!(fs::symlink_metadata(&missing_target).is_err());
                ensure!(fs::read_dir(&directory)?.count() == 4);
            }
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "missing extension discarded a healthy master"
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
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("extension-private"), "rename audit disclosed private paths");
        let log = fs::read_to_string(&requests)?;
        ensure!(log.contains("session opened") && log.contains("session closed"), "{log}");
        for mutation in [
            "rename old ", "open \"", "mkdir ", "remove name ", "rmdir name ",
            "symlink old ", "hardlink old ", "setstat name ", "fsetstat ",
        ] {
            ensure!(!log.contains(mutation), "missing extension dispatched {mutation:?}: {log}");
        }
        // OpenSSH logs one refusal while filtering each VERSION advertisement.
        // Any additional refusal would mean a rename reached request dispatch.
        ensure!(
            log.lines().filter(|line| line.contains("Refusing denylisted posix-rename request")).count() == 4,
            "expected only the four advertisement refusals: {log}"
        );
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_missing_source_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "echo launch >> {}; exec {} -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MISSING_SOURCE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("dispatch-private");
            fs::create_dir(&directory)?;
            let source = directory.join("missing-source");
            let destination = directory.join("destination");
            fs::write(&destination, b"KEEP_DISPATCH_DESTINATION")?;
            let inode = fs::symlink_metadata(&destination)?.ino();
            let reply = client
                .call(
                    "ssh_rename",
                    json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::symlink_metadata(&source).is_err());
            ensure!(fs::symlink_metadata(&destination)?.ino() == inode);
            ensure!(fs::read(&destination)? == b"KEEP_DISPATCH_DESTINATION");
            ensure!(fs::read_dir(&directory)?.count() == 1);
            let audit = await_audit(&client.log, "finish", "not_found").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "dispatched rename failure discarded the healthy sibling master"
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
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("dispatch-private"), "rename audit disclosed private paths");
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "missing-source failure replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines().filter(|line| line.contains("posix-rename old ")).count() == 1,
            "expected exactly one real POSIX rename request: {log}"
        );
        ensure!(
            !log.lines().any(|line| line.contains("rename old ") && !line.contains("posix-rename old ")),
            "missing source caused standard rename fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_remove_file_entries_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.remove-locked]\nssh_host = 'plain'\nprofile = 'read-only-files'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("remove-private");
        fs::create_dir(&directory)?;
        let file = directory.join("ordinary");
        let retained = directory.join("retained-hardlink");
        fs::write(&file, b"REMOVE_KEEP_INODE_BYTES")?;
        fs::hard_link(&file, &retained)?;
        let inode = fs::symlink_metadata(&file)?.ino();
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"remove\0invalid"}),
                json!({"host":"plain","path":file,"timeout_secs":0}),
                json!({"host":"plain","path":file,"timeout_secs":16}),
            ] {
                let reply = client.call("ssh_remove_file", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call("ssh_remove_file", json!({"host":"remove-locked","path":file}))
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected unlink acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected unlink authenticated");
            ensure!(fs::symlink_metadata(&file)?.ino() == inode);
            ensure!(fs::read(&file)? == b"REMOVE_KEEP_INODE_BYTES");
            ensure!(fs::read_dir(&directory)?.count() == 2);

            succeeded(&exec(&client, "printf REMOVE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let reply = client
                .call("ssh_remove_file", json!({"host":"plain","path":file}))
                .await?;
            ensure!(succeeded(&reply)? == &json!({"removed":true}));
            ensure!(
                matches!(fs::symlink_metadata(&file), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "successful unlink retained its entry"
            );
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::symlink_metadata(&retained)?.nlink() == 1);
            ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");

            let empty = directory.join("empty-directory");
            let tree = directory.join("tree");
            let child = tree.join("child");
            fs::create_dir(&empty)?;
            fs::create_dir(&tree)?;
            fs::write(&child, b"KEEP_TREE_CHILD")?;
            let empty_inode = fs::symlink_metadata(&empty)?.ino();
            let tree_inode = fs::symlink_metadata(&tree)?.ino();
            let child_inode = fs::symlink_metadata(&child)?.ino();
            let absent = directory.join("absent-target");
            for (index, target) in [&retained, &tree, &absent].into_iter().enumerate() {
                let link = directory.join(format!("final-link-{index}"));
                symlink(target, &link)?;
                let reply = client
                    .call("ssh_remove_file", json!({"host":"plain","path":link}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    matches!(fs::symlink_metadata(&link), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "final symlink {index} survived unlink"
                );
                ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
                ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_TREE_CHILD");
                ensure!(fs::symlink_metadata(&absent).is_err());
            }

            let wildcard_sibling = directory.join("wildcard-KEEP");
            fs::write(&wildcard_sibling, b"KEEP_LITERAL_SIBLING")?;
            let sibling_inode = fs::symlink_metadata(&wildcard_sibling)?.ino();
            for name in [
                "  é雪 entry  ",
                "wildcard-*",
                "'\";~$*\n$(printf EVALUATED)",
                "${HOME} {{remove}}\n'\";*",
            ] {
                let literal = directory.join(name);
                fs::write(&literal, b"REMOVE_LITERAL_ONLY")?;
                let reply = client
                    .call("ssh_remove_file", json!({"host":"plain","path":literal}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}), "{name:?}: {reply}");
                ensure!(fs::symlink_metadata(&literal).is_err(), "{name:?}: entry survived");
                ensure!(fs::symlink_metadata(&wildcard_sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&wildcard_sibling)? == b"KEEP_LITERAL_SIBLING");
            }

            // A real REMOVE must reject both directories, not walk or use RMDIR.
            for path in [&empty, &tree] {
                let reply = client
                    .call("ssh_remove_file", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("permission_denied" | "io_error")),
                    "directory unlink did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
                ensure!(fs::read_dir(&empty)?.next().is_none());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_TREE_CHILD");
                ensure!(fs::read_dir(&tree)?.count() == 1);
            }
            // Missing is an acknowledged backend failure, never missing_ok.
            let reply = client
                .call("ssh_remove_file", json!({"host":"plain","path":file}))
                .await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "retained-hardlink", "empty-directory", "tree", "wildcard-KEEP",
            ].map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "unlink expanded literal paths or changed siblings");
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            let reply = client
                .call("ssh_read_file", json!({"host":"plain","path":retained}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "REMOVE_KEEP_INODE_BYTES");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "unlink discarded the shared healthy master"
            );

            let reply = client
                .call("ssh_remove_file", json!({"host":"nosftp","path":retained}))
                .await?;
            ensure!(
                matches!(reply["error"]["code"].as_str(), Some("unsupported" | "io_error" | "connection_lost")),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client.call("ssh_exec", json!({
                "host":"nosftp","command":"printf REMOVE_NO_SUBSYSTEM_HEALTHY"
            })).await?;
            ensure!(succeeded(&reply)?["stdout"] == "REMOVE_NO_SUBSYSTEM_HEALTHY");
            ensure!(masters(&client.log)? == before, "unavailable SFTP replaced a healthy master");
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
        gone?;
        ensure!(!log.text().contains("remove-private"), "unlink audit disclosed private paths");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_file_dispatch_refusal_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    // -P refuses the actual standard REMOVE, without hiding an extension.
    let script = format!(
        "echo launch >> {}; exec {} -P remove -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf REMOVE_REFUSAL_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("remove-refusal-private");
            fs::create_dir(&directory)?;
            let file = directory.join("denied");
            let sibling = directory.join("sibling");
            fs::write(&file, b"KEEP_REFUSED_ENTRY")?;
            fs::write(&sibling, b"KEEP_REFUSAL_SIBLING")?;
            let inode = fs::symlink_metadata(&file)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call("ssh_remove_file", json!({"host":"plain","path":file}))
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                fs::symlink_metadata(&file)?.ino() == inode,
                "refusal caused fallback unlink"
            );
            ensure!(fs::read(&file)? == b"KEEP_REFUSED_ENTRY");
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_REFUSAL_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "refused unlink discarded a healthy shared master"
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
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("remove-refusal-private"),
            "unlink audit disclosed private paths"
        );
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "refused unlink replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines()
                .filter(|line| line.contains("Refusing") && line.contains("remove request"))
                .count()
                == 1,
            "expected exactly one actual REMOVE refusal, without retry: {log}"
        );
        ensure!(
            !log.lines().any(|line| {
                [
                    "lstat name ",
                    "stat name ",
                    "readlink ",
                    "opendir ",
                    "rmdir name ",
                ]
                .iter()
                .any(|operation| line.contains(operation))
            }),
            "unlink performed a preflight or recursive fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_file_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {}",
        started.display(),
        done.display(),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf REMOVE_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("remove-delay-private");
            fs::create_dir(&directory)?;
            let file = directory.join("never-dispatched");
            let sibling = directory.join("sibling");
            fs::write(&file, b"KEEP_UNDISPATCHED_ENTRY")?;
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let inode = fs::symlink_metadata(&file)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call(
                    "ssh_remove_file",
                    json!({
                        "host":"plain","path":file,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake timeout discarded the healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "timeout replayed SFTP"
            );
            ensure!(fs::symlink_metadata(&file)?.ino() == inode);
            ensure!(fs::read(&file)? == b"KEEP_UNDISPATCHED_ENTRY");
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // The finite guard must finish even if an assertion above failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        completed?;
        gone?;
        ensure!(
            !log.text().contains("remove-delay-private"),
            "unlink audit disclosed private paths"
        );
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_remove_directory_entries_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.rmdir-locked]\nssh_host = 'plain'\nprofile = 'read-only-files'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("rmdir-private");
        fs::create_dir(&directory)?;
        let empty = directory.join("empty");
        let tree = directory.join("tree");
        let nested = tree.join("nested");
        let child = nested.join("child");
        let sibling = directory.join("wildcard-KEEP");
        fs::create_dir(&empty)?;
        fs::create_dir_all(&nested)?;
        fs::write(&child, b"KEEP_NESTED_CHILD\0BYTES")?;
        fs::write(&sibling, b"KEEP_LITERAL_SIBLING")?;
        let empty_inode = fs::symlink_metadata(&empty)?.ino();
        let tree_inode = fs::symlink_metadata(&tree)?.ino();
        let nested_inode = fs::symlink_metadata(&nested)?.ino();
        let child_inode = fs::symlink_metadata(&child)?.ino();
        let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
        let missing = directory.join("missing");
        let mut links = Vec::new();
        for (index, target) in [&empty, &tree, &sibling, &missing].into_iter().enumerate() {
            let link = directory.join(format!("final-link-{index}"));
            symlink(target, &link)?;
            let inode = fs::symlink_metadata(&link)?.ino();
            links.push((link, target, inode));
        }
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"rmdir\0invalid"}),
                json!({"host":"plain","path":empty,"timeout_secs":0}),
                json!({"host":"plain","path":empty,"timeout_secs":16}),
            ] {
                let reply = client.call("ssh_remove_directory", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call("ssh_remove_directory", json!({"host":"rmdir-locked","path":empty}))
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected rmdir acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected rmdir authenticated");
            ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
            ensure!(fs::read_dir(&empty)?.next().is_none());

            succeeded(&exec(&client, "printf RMDIR_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            // Plain final links must fail RMDIR, never fall back to REMOVE.
            // OpenSSH also maps ENOTDIR (file/final-link operands) to NO_SUCH_FILE.
            for (link, target, inode) in &links {
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"plain","path":link}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("not_found" | "permission_denied" | "io_error")),
                    "final symlink rmdir did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                let metadata = fs::symlink_metadata(link)?;
                ensure!(metadata.file_type().is_symlink() && metadata.ino() == *inode);
                ensure!(fs::read_link(link)? == **target);
                ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
                ensure!(fs::read_dir(&empty)?.next().is_none());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&nested)?.ino() == nested_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_NESTED_CHILD\0BYTES");
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
                ensure!(fs::symlink_metadata(&missing).is_err());
            }
            for path in [&tree, &nested, &sibling] {
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("not_found" | "permission_denied" | "io_error")),
                    "nonempty directory/file rmdir did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(fs::symlink_metadata(&tree)?.is_dir());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&nested)?.is_dir());
                ensure!(fs::symlink_metadata(&nested)?.ino() == nested_inode);
                ensure!(fs::symlink_metadata(&child)?.is_file());
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_NESTED_CHILD\0BYTES");
                ensure!(fs::read_dir(&tree)?.count() == 1);
                ensure!(fs::read_dir(&nested)?.count() == 1);
                ensure!(fs::symlink_metadata(&sibling)?.is_file());
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
            }
            for name in [
                "  é雪 entry  ",
                "wildcard-*",
                "'\";~$*\n$(printf EVALUATED)",
                "${HOME} {{rmdir}}\n'\";*",
            ] {
                let literal = directory.join(name);
                fs::create_dir(&literal)?;
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"plain","path":literal}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}), "{name:?}: {reply}");
                ensure!(
                    matches!(fs::symlink_metadata(&literal), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "{name:?}: empty directory survived"
                );
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
            }
            let reply = client
                .call("ssh_remove_directory", json!({"host":"plain","path":empty}))
                .await?;
            ensure!(succeeded(&reply)? == &json!({"removed":true}));
            ensure!(
                matches!(fs::symlink_metadata(&empty), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "successful rmdir retained its entry"
            );
            // Neither a missing entry nor a repeated deletion is missing_ok.
            for path in [&empty, &missing] {
                let reply = client
                    .call("ssh_remove_directory", json!({"host":"plain","path":path}))
                    .await?;
                failed(&reply, "not_found")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            }
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "tree", "wildcard-KEEP", "final-link-0", "final-link-1",
                "final-link-2", "final-link-3",
            ].map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "rmdir expanded literal paths or removed siblings");
            let reply = client
                .call("ssh_read_file", json!({"host":"plain","path":sibling}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "KEEP_LITERAL_SIBLING");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "rmdir discarded the shared healthy master"
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
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("rmdir-private"), "rmdir audit disclosed private paths");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_directory_dispatch_refusal_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "echo launch >> {}; exec {} -P rmdir -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf RMDIR_REFUSAL_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("rmdir-refusal-private");
            fs::create_dir(&directory)?;
            let empty = directory.join("denied");
            let sibling = directory.join("sibling");
            fs::create_dir(&empty)?;
            fs::write(&sibling, b"KEEP_REFUSAL_SIBLING")?;
            let inode = fs::symlink_metadata(&empty)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call("ssh_remove_directory", json!({"host":"plain","path":empty}))
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::symlink_metadata(&empty)?.is_dir());
            ensure!(
                fs::symlink_metadata(&empty)?.ino() == inode,
                "refusal caused fallback rmdir"
            );
            ensure!(fs::read_dir(&empty)?.next().is_none());
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_REFUSAL_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "refused rmdir discarded a healthy shared master"
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
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("rmdir-refusal-private"),
            "rmdir audit disclosed private paths"
        );
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "refused rmdir replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines()
                .filter(|line| line.contains("Refusing") && line.contains("rmdir request"))
                .count()
                == 1,
            "expected exactly one actual RMDIR refusal, without retry: {log}"
        );
        ensure!(
            !log.lines().any(|line| {
                [
                    "lstat name ",
                    "stat name ",
                    "readlink ",
                    "opendir ",
                    "readdir ",
                    "remove name ",
                    "Refusing remove request",
                    "mkdir name ",
                    "rename old ",
                    "open \"",
                    "setstat name ",
                ]
                .iter()
                .any(|operation| line.contains(operation))
            }),
            "rmdir performed a preflight or mutation fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
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
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_directory_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let requests = work.path().join("sftp-requests");
    fs::write(&requests, b"")?;
    let server = Fixture::sftp_server()?;
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {} -e -l VERBOSE 2>> {}",
        started.display(),
        done.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf RMDIR_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("rmdir-delay-private");
            fs::create_dir(&directory)?;
            let empty = directory.join("never-dispatched");
            let sibling = directory.join("sibling");
            fs::create_dir(&empty)?;
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let inode = fs::symlink_metadata(&empty)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call(
                    "ssh_remove_directory",
                    json!({
                        "host":"plain","path":empty,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake timeout discarded the healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "timeout replayed SFTP"
            );
            ensure!(fs::symlink_metadata(&empty)?.is_dir());
            ensure!(fs::symlink_metadata(&empty)?.ino() == inode);
            ensure!(fs::read_dir(&empty)?.next().is_none());
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // Await the finite remote guard even when an assertion failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        completed?;
        gone?;
        ensure!(
            !log.text().contains("rmdir-delay-private"),
            "rmdir audit disclosed private paths"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let log = fs::read_to_string(&requests);
    let removed = work.close();
    scenario?;
    cleanup?;
    let log = log?;
    ensure!(
        !log.contains("rmdir name ") && !log.contains("remove name "),
        "handshake timeout dispatched a mutation: {log}"
    );
    removed?;
    Ok(())
}

// All replacement observations below use the real server's shared filesystem,
// independently of the MCP response and of the SFTP client's buffers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_atomic_visibility_and_lost_ack() -> Result<()> {
    // Each relay owns exactly one real SFTP session, including for empty payloads.
    for (drop_ack, new_len) in [(false, 0), (false, 786_432), (true, 786_432)] {
        let work = tempfile::tempdir()?;
        let destination = work.path().join("destination");
        let hardlink = work.path().join("old-hardlink");
        let old = vec![b'O'; 262_144];
        let new = vec![b'N'; new_len];
        fs::write(&destination, &old)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))?;
        fs::hard_link(&destination, &hardlink)?;
        let before = fs::metadata(&destination)?;
        let fault = if drop_ack {
            replace_relay::Fault::RenameAck
        } else {
            replace_relay::Fault::None
        };
        let relay = replace_relay::Relay::start(
            &Fixture::sftp_server()?,
            fault,
            Some(replace_relay::Oracle {
                destination: destination.clone(),
                hardlink: hardlink.clone(),
                old: old.clone(),
                inode: before.ino(),
                new_len: new.len(),
            }),
        )
        .await?;
        let evidence = relay.evidence.clone();
        let setup = Fixture::start_with_sftp_subsystem("", &relay.subsystem).await;
        let fixture = match setup {
            Ok(fixture) => fixture,
            Err(error) => {
                let _ = relay.stop().await;
                return Err(error);
            }
        };
        let scenario = async {
            let configured = fs::read_to_string(&fixture.config)?
                .replace("[limits]", "[limits]\nmax_file_bytes = 1048576");
            fs::write(&fixture.config, configured)?;
            // Explicitly configured above the 64KiB write boundary.
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                let observed_path = destination.clone();
                let observed_old = old.clone();
                let observed_new = new.clone();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
                let mut observer = tokio::spawn(async move {
                    let mut ready = Some(ready_tx);
                    let mut old_reads = 0usize;
                    let mut new_reads = 0usize;
                    timeout(Duration::from_secs(15), async {
                        loop {
                            let bytes = fs::read(&observed_path)?;
                            if bytes == observed_old { old_reads += 1; }
                            else if bytes == observed_new { new_reads += 1; }
                            else { anyhow::bail!("ordinary reader observed missing/partial/mixed replacement bytes"); }
                            if let Some(ready) = ready.take() { let _ = ready.send(()); }
                            if stop_rx.try_recv().is_ok() {
                                ensure!(fs::read(&observed_path)? == observed_new, "final independent publication observation");
                                new_reads += 1;
                                ensure!(old_reads > 0 && new_reads > 0, "observer missed old/new visibility");
                                return Ok::<_, anyhow::Error>(());
                            }
                            tokio::task::yield_now().await;
                        }
                    }).await.context("bounded visibility observer")?
                });
                let operation = async {
                    timeout(Duration::from_secs(5), ready_rx).await??;
                    let reply = client.call("ssh_replace_file", json!({
                        "host":"plain","path":destination,"content":String::from_utf8(new.clone())?,
                        "overwrite":true,"timeout_secs":3,
                    })).await?;
                    if drop_ack {
                        failed(&reply, "timeout")?;
                        ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                    } else {
                        ensure!(succeeded(&reply)? == &json!({"bytes_written":new.len()}));
                    }
                    ensure!(fs::read(&destination)? == new, "real server did not publish new bytes");
                    ensure!(fs::read(&hardlink)? == old);
                    let after = fs::metadata(&destination)?;
                    ensure!(after.ino() != before.ino());
                    ensure!(after.mode() & 0o7777 == 0o600);
                    ensure!(after.uid() == nix::unistd::Uid::current().as_raw());
                    ensure!(after.gid() == fs::metadata(work.path())?.gid());
                    ensure!(fs::metadata(&hardlink)?.ino() == before.ino());
                    ensure!(fs::metadata(&hardlink)?.mode() & 0o7777 == 0o644);
                    ensure!(fs::read_dir(work.path())?.count() == 2, "successful rename left a stage");
                    let seen = evidence.lock().map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                    seen.assert_private_stage_opens(1)?;
                    ensure!(!seen.requests.iter().any(|kind| matches!(*kind, 13 | 18)),
                        "replacement deleted an entry or used standard rename: {seen:?}");
                    ensure!(seen.renames == 1, "rename replayed: {seen:?}");
                    ensure!(seen.dropped_success == drop_ack, "lost ack was not a genuine successful STATUS");
                    if new.is_empty() {
                        ensure!(seen.writes == 0 && !seen.staged_partial, "empty replacement issued a write: {seen:?}");
                    } else {
                        ensure!(seen.writes > 1 && seen.staged_partial, "did not observe real multi-write staging");
                    }
                    let rename = seen.rename_index.context("POSIX rename request")?;
                    ensure!(seen.requests[rename + 1..].iter().all(|kind| !matches!(*kind, 3 | 6 | 13 | 18 | 200)),
                        "mutation/replay/cleanup after rename: {seen:?}");
                    Ok::<_, anyhow::Error>(())
                }.await;
                // Always stop and join the owned independent reader, including failed calls/assertions.
                let _ = stop_tx.send(());
                let observed = match timeout(Duration::from_secs(5), &mut observer).await {
                    Ok(result) => result.context("visibility observer panic").and_then(|result| result),
                    Err(error) => {
                        observer.abort();
                        let _ = observer.await;
                        Err(error.into())
                    }
                };
                operation?;
                observed
            }.await;
            let owned = masters(&client.log);
            let stopped = client.stop().await;
            let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
            cases?;
            stopped?;
            gone?;
            ensure!(fs::read_to_string(&relay.launches)?.lines().count() == 1, "replacement replayed the subsystem");
            Ok::<_, anyhow::Error>(())
        }.await;
        let observed_state = format!(
            "drop_ack={drop_ack}; new_len={new_len}; evidence={:?}; destination={:?}",
            evidence.lock(),
            fs::metadata(&destination).map(|metadata| (metadata.ino(), metadata.len()))
        );
        let relayed = relay.stop().await;
        let cleanup = fixture.stop().await;
        let removed = work.close();
        scenario.with_context(|| format!("{observed_state}; relay cleanup={relayed:?}"))?;
        relayed?;
        cleanup?;
        removed?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_replace_file_metadata_symlinks_and_literal_bytes() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let directory = fixture.root.path().join("replace-private-é雪 space-'\"\n${HOME}$(printf NEVER)");
            fs::create_dir(&directory)?;
            for (name, content, encoding, expected) in [
                ("é雪 space-'\"\n${HOME}$(printf NEVER)", "UTF8_é雪\0END", "utf8", "UTF8_é雪\0END".as_bytes()),
                ("binary", "AP+AQQ==", "base64", b"\0\xff\x80A".as_slice()),
                ("empty", "", "utf8", b"".as_slice()),
            ] {
                let path = directory.join(name);
                let reply = client.call("ssh_replace_file", json!({
                    "host":"plain","path":path,"content":content,"encoding":encoding,"overwrite":true,
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":expected.len()}));
                ensure!(fs::read(&path)? == expected);
                ensure!(fs::metadata(&path)?.mode() & 0o7777 == 0o600);
            }
            let target = directory.join("target");
            let link = directory.join("final-link");
            fs::write(&target, b"SYMLINK_TARGET_UNCHANGED")?;
            let target_inode = fs::metadata(&target)?.ino();
            symlink(&target, &link)?;
            let reply = client.call("ssh_replace_file", json!({
                "host":"plain","path":link,"content":"LINK_ENTRY_REPLACED","overwrite":true,
            })).await?;
            succeeded(&reply)?;
            ensure!(fs::symlink_metadata(&link)?.file_type().is_file());
            ensure!(fs::read(&link)? == b"LINK_ENTRY_REPLACED");
            ensure!(fs::read(&target)? == b"SYMLINK_TARGET_UNCHANGED");
            ensure!(fs::metadata(&target)?.ino() == target_inode);
            let missing_target = directory.join("missing-target");
            let dangling = directory.join("dangling");
            symlink(&missing_target, &dangling)?;
            succeeded(&client.call("ssh_replace_file", json!({
                "host":"plain","path":dangling,"content":"NEW_ENTRY","overwrite":true,
            })).await?)?;
            ensure!(fs::read(&dangling)? == b"NEW_ENTRY" && !missing_target.exists());
            // Raw repeated slashes and intermediate symlinks keep server pathname semantics.
            let parent_link = fixture.root.path().join("replace-parent-link");
            symlink(&directory, &parent_link)?;
            let raw = format!("{}//through-parent", parent_link.display());
            succeeded(&client.call("ssh_replace_file", json!({
                "host":"plain","path":raw,"content":"RAW_PARENT","overwrite":true,
            })).await?)?;
            ensure!(fs::read(directory.join("through-parent"))? == b"RAW_PARENT");
            let tree = directory.join("tree");
            fs::create_dir(&tree)?;
            fs::write(tree.join("child"), b"TREE_UNCHANGED")?;
            let tree_inode = fs::metadata(&tree)?.ino();
            let reply = client.call("ssh_replace_file", json!({
                "host":"plain","path":tree,"content":"NO_DIRECTORY_REPLACE","overwrite":true,
            })).await?;
            ensure!(reply["error"].is_object() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::metadata(&tree)?.ino() == tree_inode);
            ensure!(fs::read(tree.join("child"))? == b"TREE_UNCHANGED");
            let stages = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
            let stages: Vec<_> = stages.iter().filter(|entry| entry.file_name().as_bytes().starts_with(b".estus-replace-")).collect();
            ensure!(stages.len() == 1, "rename-attempt failure must not clean its stage");
            ensure!(fs::read(stages[0].path())? == b"NO_DIRECTORY_REPLACE");
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        let log = stopped?;
        ensure!(!log.text().contains("replace-private") && !log.text().contains("LINK_ENTRY_REPLACED"));
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_capability_and_owned_stage_failures() -> Result<()> {
    let server = Fixture::sftp_server()?;
    for request in ["posix-rename", "open", "write", "fsetstat", "close"] {
        let work = tempfile::tempdir()?;
        let requests = work.path().join("requests.log");
        let relay = replace_relay::Relay::start_denied(&server, request, &requests).await?;
        let fixture = match Fixture::start_with_sftp_subsystem("", &relay.subsystem).await {
            Ok(fixture) => fixture,
            Err(error) => {
                let _ = relay.stop().await;
                return Err(error);
            }
        };
        let scenario = async {
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                let directory = fixture.root.path().join("replace-fault");
                fs::create_dir(&directory)?;
                let path = directory.join("destination");
                fs::write(&path, b"PRESERVED_DESTINATION")?;
                let inode = fs::metadata(&path)?.ino();
                let reply = client.call("ssh_replace_file", json!({
                    "host":"plain","path":path,"content":"MUST_NOT_PUBLISH","overwrite":true,
                })).await?;
                failed(
                    &reply,
                    if request == "posix-rename" {
                        "unsupported"
                    } else {
                        "permission_denied"
                    },
                )?;
                ensure!(reply["data"].is_null());
                ensure!(reply["error"]["remote_state_unknown"] == (request != "posix-rename"));
                ensure!(fs::read(&path)? == b"PRESERVED_DESTINATION");
                ensure!(fs::metadata(&path)?.ino() == inode);
                ensure!(
                    fs::read_dir(&directory)?.count() == 1,
                    "failed OPEN created a stage or acknowledged pre-rename stage not removed"
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
            gone?;
            let log = fs::read_to_string(&requests)?;
            let seen = relay
                .evidence
                .lock()
                .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
            if request == "open" {
                ensure!(seen.opens.len() == 1, "failed OPEN replayed: {seen:?}");
                let open = &seen.opens[0];
                ensure!(
                    open.pflags == (0x02 | 0x08 | 0x20)
                        && open.attr_flags == 0x04
                        && open.permissions == 0o600
                        && open.initial_mode.is_none()
                        && open.initial_len.is_none(),
                    "failed OPEN flags/attrs or fabricated HANDLE: {seen:?}"
                );
            } else {
                seen.assert_private_stage_opens(usize::from(request != "posix-rename"))?;
            }
            if request == "posix-rename" {
                for mutation in [
                    "open \"",
                    "remove name ",
                    "setstat name ",
                    "fsetstat ",
                    "rename old ",
                    "mkdir ",
                    "rmdir name ",
                ] {
                    ensure!(
                        !log.contains(mutation),
                        "unsupported extension mutated filesystem: {log}"
                    );
                }
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("Refusing denylisted posix-rename request"))
                        .count()
                        == 1
                );
            } else if request == "open" {
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("Refusing denylisted open request"))
                        .count()
                        == 1,
                    "expected one genuine rejected OPEN: {log}"
                );
                for mutation in ["remove name ", "write \"", "fsetstat ", "rename old "] {
                    ensure!(
                        !log.contains(mutation),
                        "failed OPEN claimed/mutated a stage: {log}"
                    );
                }
            } else {
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("remove name "))
                        .count()
                        == 1,
                    "expected one owned-stage REMOVE: {log}"
                );
                ensure!(
                    !log.contains("rename old "),
                    "pre-rename failure attempted publication: {log}"
                );
                if request == "fsetstat" {
                    ensure!(
                        !log.contains("write \""),
                        "content was written before successful chmod: {log}"
                    );
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let cleanup = fixture.stop().await;
        let relayed = relay.stop().await;
        let removed = work.close();
        scenario?;
        cleanup?;
        relayed?;
        removed?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_unacknowledged_open_does_not_claim_stage() -> Result<()> {
    let relay = replace_relay::Relay::start(
        &Fixture::sftp_server()?,
        replace_relay::Fault::OpenAck,
        None,
    )
    .await?;
    let setup = Fixture::start_with_sftp_subsystem("", &relay.subsystem).await;
    let fixture = match setup {
        Ok(fixture) => fixture,
        Err(error) => {
            let _ = relay.stop().await;
            return Err(error);
        }
    };
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let directory = fixture.root.path().join("replace-unacknowledged");
            fs::create_dir(&directory)?;
            let path = directory.join("destination");
            fs::write(&path, b"UNACKNOWLEDGED_OLD")?;
            let inode = fs::metadata(&path)?.ino();
            let reply = client.call("ssh_replace_file", json!({
                "host":"plain","path":path,"content":"NEVER_WRITE_UNOWNED","overwrite":true,"timeout_secs":2,
            })).await?;
            failed(&reply, "timeout")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::metadata(&path)?.ino() == inode && fs::read(&path)? == b"UNACKNOWLEDGED_OLD");
            let entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
            let stages: Vec<_> = entries.iter().filter(|entry| entry.file_name().as_bytes().starts_with(b".estus-replace-")).collect();
            ensure!(stages.len() == 1 && fs::metadata(stages[0].path())?.len() == 0,
                "uncertain OPEN must leave the real empty stage, never claim/delete it");
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        stopped?;
        gone?;
        let seen = relay.evidence.lock().map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
        ensure!(seen.dropped_open && !seen.dropped_success && seen.renames == 0 && seen.writes == 0);
        seen.assert_private_stage_opens(1)?;
        ensure!(seen.requests.iter().filter(|kind| **kind == 3).count() == 1, "uncertain OPEN replayed");
        let open = seen.requests.iter().position(|kind| *kind == 3).context("real OPEN request")?;
        ensure!(!seen.requests[open + 1..].iter().any(|kind| matches!(*kind, 6 | 13 | 18 | 9 | 10 | 200)),
            "uncertain OPEN triggered write/chmod/cleanup/rename: {seen:?}");
        ensure!(fs::read_to_string(&relay.launches)?.lines().count() == 1);
        Ok::<_, anyhow::Error>(())
    }.await;
    let relayed = relay.stop().await;
    let cleanup = fixture.stop().await;
    scenario?;
    relayed?;
    cleanup
}

// Output artifacts are observed only through public receipts/reads and the
// test-owned TMPDIR, never through an implementation-specific pathname.
fn output_entries(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?)
}

fn output_handle(data: &Value) -> Result<String> {
    let receipt = &data["output"];
    ensure!(receipt["status"] == "ready", "retention receipt: {receipt}");
    let handle = receipt["handle"].as_str().context("output handle")?;
    ensure!(
        handle.len() == 32
            && handle
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "handle is not an opaque lowercase capability"
    );
    Ok(handle.to_owned())
}

async fn output_range(
    server: &mut WireServer,
    id: u64,
    handle: &str,
    stream: &str,
    (offset, limit): (u64, u64),
    (bytes, eof): (&[u8], bool),
    encoding: &str,
) -> Result<()> {
    let reply = script_wire_call(
        server,
        id,
        "ssh_read_output",
        json!({
            "handle":handle,"stream":stream,"offset":offset,"max_bytes":limit,"encoding":encoding,
        }),
    )
    .await?;
    let content = if encoding == "base64" {
        STANDARD.encode(bytes)
    } else {
        std::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":content,"encoding":encoding,"bytes_read":bytes.len(),
                "next_offset":offset + bytes.len() as u64,"eof":eof,
                "content_sha256":hex::encode(Sha256::digest(bytes)),
            }),
        "retained range mismatch: {reply}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_exact_ranges_permissions_and_local_reads() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let artifacts = fixture.root.path().join("output-tmp");
        let runtime = fixture.root.path().join("output-runtime");
        fs::create_dir(&artifacts)?;
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        let config = fixture.root.path().join("output.toml");
        fs::write(&config, format!(
            "profile = 'baseline'\n[ssh]\nconfig_file = {}\n[limits]\nmax_output_bytes = 4\n[output]\nper_stream_bytes = 64\ntotal_bytes = 128\nmax_handles = 1\n[targets.plain]\nssh_host = 'plain'\n",
            serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
        ))?;
        let mut command = support::server_command(&config)?;
        command.env("TMPDIR", &artifacts).env("XDG_RUNTIME_DIR", &runtime);
        let mut server = WireServer::start_command(command)?;
        let cases = async {
            server.initialize().await?;
            let reply = script_wire_call(&mut server, 2, "ssh_exec",
                json!({"host":"plain","command":"printf abc"})).await?;
            ensure!(succeeded(&reply)?.get("output").is_none());
            ensure!(output_entries(&artifacts)?.is_empty(), "default call created artifacts");
            let reply = script_wire_call(&mut server, 3, "ssh_exec", json!({
                "host":"plain","command":"printf 'abc\\000\\303\\251\\377Z'; printf 'err\\000\\376' >&2",
                "retain_output":true,
            })).await?;
            let data = succeeded(&reply)?;
            let handle = output_handle(data)?;
            ensure!(data["stdout"] == "abc\0" && data["stderr"] == "err\0");
            ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
            ensure!(data["output"]["stdout"] == json!({"bytes_retained":8,"total_bytes":8,"truncated":false}));
            ensure!(data["output"]["stderr"] == json!({"bytes_retained":5,"total_bytes":5,"truncated":false}));
            let directories = output_entries(&artifacts)?;
            ensure!(directories.len() == 1, "expected one private artifact owner: {directories:?}");
            ensure!(fs::metadata(&directories[0])?.permissions().mode() & 0o777 == 0o700);
            let files = output_entries(&directories[0])?;
            ensure!(files.len() == 2);
            let mut payloads = Vec::new();
            for path in &files {
                ensure!(fs::metadata(path)?.permissions().mode() & 0o777 == 0o600);
                payloads.push(fs::read(path)?);
            }
            ensure!(payloads.contains(&b"abc\0\xc3\xa9\xffZ".to_vec()));
            ensure!(payloads.contains(&b"err\0\xfe".to_vec()));
            let before_masters = masters(&server.log)?;
            let before_auth = fixture.authentications();
            output_range(&mut server, 4, &handle, "stdout", (0, 8), (b"abc\0\xc3\xa9\xffZ", true), "base64").await?;
            output_range(&mut server, 5, &handle, "stderr", (0, 5), (b"err\0\xfe", true), "base64").await?;
            output_range(&mut server, 6, &handle, "stdout", (0, 3), (b"abc", false), "utf8").await?;
            output_range(&mut server, 7, &handle, "stdout", (4, 2), ("é".as_bytes(), false), "utf8").await?;
            output_range(&mut server, 8, &handle, "stdout", (8, 1), (b"", true), "utf8").await?;
            output_range(&mut server, 9, &handle, "stderr", (99, 1), (b"", true), "base64").await?;
            for (id, offset, count) in [(10, 4, 1), (11, 5, 1), (12, 6, 1)] {
                let reply = script_wire_call(&mut server, id, "ssh_read_output", json!({
                    "handle":handle,"stream":"stdout","offset":offset,"max_bytes":count,
                })).await?;
                failed(&reply, "invalid_encoding")?;
                ensure!(reply["error"]["remote_state_unknown"] == false && reply["data"].is_null());
            }
            // A second, real server has no authority over the first server's handle.
            let mut foreign = WireServer::start(&config)?;
            let foreign_case = async {
                foreign.initialize().await?;
                let reply = script_wire_call(&mut foreign, 2, "ssh_read_output",
                    json!({"handle":handle,"stream":"stdout"})).await?;
                failed(&reply, "not_found")?;
                ensure!(masters(&foreign.log)?.is_empty());
                Ok::<_, anyhow::Error>(())
            }.await;
            let foreign_stop = foreign.stop(None).await;
            foreign_case?;
            foreign_stop?;
            ensure!(masters(&server.log)? == before_masters);
            ensure!(fixture.authentications() == before_auth, "local reads opened SSH");
            Ok::<_, anyhow::Error>(handle)
        }.await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        let handle = cases?;
        let log = stopped?;
        gone?;
        ensure!(output_entries(&artifacts)?.is_empty(), "shutdown retained private files");
        ensure!(!log.text().contains(&handle), "capability leaked into audit");
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_prefix_quota_disabled_storage_failure_and_expiry() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        for mode in ["quota", "disabled", "storage", "expiry"] {
            let temporary = fixture.root.path().join(format!("output-{mode}"));
            let runtime = fixture.root.path().join(format!("runtime-{mode}"));
            fs::create_dir(&runtime)?;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
            if mode == "storage" { fs::write(&temporary, b"not a directory")?; }
            else { fs::create_dir(&temporary)?; }
            let config = fixture.root.path().join(format!("output-{mode}.toml"));
            fs::write(&config, format!(
                "profile = 'baseline'\n[ssh]\nconfig_file = {}\n[limits]\nmax_output_bytes = 4\n[output]\nenabled = {}\nper_stream_bytes = 8\ntotal_bytes = 16\nmax_handles = 1\nttl_secs = {}\n[targets.plain]\nssh_host = 'plain'\n",
                serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
                mode != "disabled", if mode == "expiry" { 1 } else { 300 },
            ))?;
            let mut command = support::server_command(&config)?;
            command.env("TMPDIR", &temporary).env("XDG_RUNTIME_DIR", &runtime);
            let mut server = WireServer::start_command(command)?;
            let cases = async {
                server.initialize().await?;
                let reply = script_wire_call(&mut server, 2, "ssh_exec", json!({
                    "host":"plain","command":"printf 0123456789; printf abcdefghij >&2","retain_output":true,
                })).await?;
                let data = succeeded(&reply)?;
                if matches!(mode, "quota" | "expiry") {
                    let handle = output_handle(data)?;
                    for stream in ["stdout", "stderr"] {
                        ensure!(data["output"][stream] == json!({"bytes_retained":8,"total_bytes":10,"truncated":true}));
                    }
                    output_range(&mut server, 3, &handle, "stdout", (0, 8), (b"01234567", true), "utf8").await?;
                    output_range(&mut server, 4, &handle, "stderr", (0, 8), (b"abcdefgh", true), "utf8").await?;
                    if mode == "expiry" {
                        timeout(Duration::from_secs(5), async {
                            while !output_entries(&temporary)?.is_empty() { sleep(Duration::from_millis(10)).await; }
                            Ok::<_, anyhow::Error>(())
                        }).await??;
                        let reply = script_wire_call(&mut server, 5, "ssh_read_output",
                            json!({"handle":handle,"stream":"stdout"})).await?;
                        failed(&reply, "not_found")?;
                        return Ok::<_, anyhow::Error>(());
                    }
                } else {
                    ensure!(data["output"] == json!({"status":"unavailable","reason":if mode == "disabled" {"retention_disabled"} else {"io_error"}}));
                }
                // More than pipe capacity on both streams, followed by a real
                // observed nonzero exit: failed retention must keep draining.
                let reply = script_wire_call(&mut server, 6, "ssh_exec", json!({
                    "host":"plain","retain_output":true,
                    "command":"x=oooooooooooooooo; y=eeeeeeeeeeeeeeee; i=0; while [ \"$i\" -lt 14 ]; do x=$x$x; y=$y$y; i=$((i+1)); done; printf '%s' \"$x\"; printf '%s' \"$y\" >&2; exit 23",
                })).await?;
                failed(&reply, "command_failed")?;
                let data = &reply["data"];
                ensure!(data["exit_code"] == 23 && data["termination"] == "exited");
                ensure!(data["stdout"] == "oooo" && data["stderr"] == "eeee");
                ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
                ensure!(data["output"] == json!({"status":"unavailable","reason":match mode {
                    "quota" => "resource_limit", "disabled" => "retention_disabled", _ => "io_error",
                }}), "retention changed execution failure: {reply}");
                if mode == "disabled" { ensure!(output_entries(&temporary)?.is_empty()); }
                if mode == "storage" { ensure!(fs::read(&temporary)? == b"not a directory"); }
                let finished = fixture.root.path().join(format!("output-timeout-{mode}-done"));
                let sleeper = binding_program("sleep")?;
                let timed = script_wire_call(&mut server, 7, "ssh_exec", json!({
                    "host":"plain","retain_output":true,"timeout_secs":1,
                    "command":format!("trap '' HUP; printf TIME; printf WAIT >&2; {} 2; printf done > {}",
                        quote(&sleeper.to_string_lossy()), quote(&finished.to_string_lossy())),
                })).await;
                // Observe the finite synchronous remote command's completion
                // even if its channel-deadline response is wrong.
                Fixture::await_file(&finished).await?;
                let timed = timed?;
                failed(&timed, "timeout")?;
                ensure!(timed["data"]["termination"] == "timeout");
                ensure!(timed["data"]["exit_code"].is_null());
                ensure!(timed["data"]["remote_may_still_be_running"] == true);
                ensure!(timed["error"]["remote_state_unknown"] == true);
                ensure!(timed["data"]["output"] == json!({"status":"unavailable","reason":match mode {
                    "quota" => "resource_limit", "disabled" => "retention_disabled", _ => "io_error",
                }}));
                Ok::<_, anyhow::Error>(())
            }.await;
            let owned = masters(&server.log);
            let stopped = server.stop(None).await;
            let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
            cases.with_context(|| mode)?;
            stopped?;
            gone?;
            if mode != "storage" { ensure!(output_entries(&temporary)?.is_empty()); }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_argv_and_named_native() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let printf = binding_program("printf")?;
        let config = fixture.root.path().join("output-bindings.toml");
        fs::write(&config, formatdoc! {r#"
            profile = "baseline"
            enabled_tools = ["retained_native"]
            [ssh]
            config_file = {ssh_config}
            [limits]
            max_output_bytes = 4
            [output]
            per_stream_bytes = 64
            total_bytes = 512
            max_handles = 4
            [targets.plain]
            ssh_host = "plain"
            [tools.retained_native]
            description = "Emit fixed native output."
            revision = "output-1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={printf},argv=["--",'%s\000%s',"native","é"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
        "#,
            ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
            printf = serde_json::to_string(&printf.to_string_lossy())?,
        })?;
        let mut server = WireServer::start(&config)?;
        let cases = async {
            server.initialize().await?;
            let mut id = 2;
            for (name, args, stdout, stderr) in [
                ("ssh_run", json!({"host":"plain","argv":["/bin/sh","-c","printf 'native\\000\\303\\251'; printf 'error\\000\\377' >&2"],"retain_output":true}), &b"native\0\xc3\xa9"[..], &b"error\0\xff"[..]),
                ("retained_native", json!({"host":"plain","retain_output":true}), &b"native\0\xc3\xa9"[..], &b""[..]),
            ] {
                let reply = script_wire_call(&mut server, id, name, args).await?;
                id += 1;
                let data = succeeded(&reply)?;
                ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
                let handle = output_handle(data)?;
                ensure!(data["stdout"] == "nati" && data["stdout_truncated"] == true);
                for (stream, bytes) in [("stdout", stdout), ("stderr", stderr)] {
                    ensure!(data["output"][stream] == json!({
                        "bytes_retained":bytes.len(),"total_bytes":bytes.len(),"truncated":false,
                    }));
                    output_range(&mut server, id, &handle, stream, (0, 64), (bytes, true), "base64").await?;
                    id += 1;
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        stopped?;
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}
