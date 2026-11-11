//! Real native command and read-only SFTP acceptance; isolated sudo remains separate.
mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use indoc::{formatdoc, indoc};
use rmcp::{
    model::{CallToolRequest, ClientRequest},
    service::PeerRequestOptions,
};
use serde_json::{Value, json};
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
    for name in ["ssh_targets", "ssh_exec", "ssh_sudo", "ssh_read_file"] {
        let tool = listed
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .with_context(|| format!("missing {name}"))?;
        ensure!(tool.output_schema.is_some(), "{name} missing outputSchema");
    }
    for name in ["ssh_write_file", "ssh_stat", "ssh_list_directory"] {
        ensure!(
            !listed.tools.iter().any(|tool| tool.name == name),
            "file milestone must not advertise unfinished {name}"
        );
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
    let secret = "SYNTHETIC_STDIN_PAYLOAD_77c940";
    let reply = client.call("ssh_exec", json!({"host":"plain","command":"printf SYNTHETIC_COMMAND_MARKER_07b9; printf SYNTHETIC_STDERR_MARKER_319a >&2; cat","stdin":secret})).await?;
    let data = succeeded(&reply)?;
    ensure!(
        data["stdout"] == format!("SYNTHETIC_COMMAND_MARKER_07b9{secret}")
            && data["stderr"] == "SYNTHETIC_STDERR_MARKER_319a"
    );
    // POSIX printf octal escapes generate invalid UTF-8 on both streams.
    let reply = exec(client, "printf '\\377'; printf '\\376' >&2").await?;
    let data = succeeded(&reply)?;
    ensure!(
        data["stdout_lossy"] == true && data["stderr_lossy"] == true,
        "binary output must disclose lossy decoding"
    );
    ensure!(data["stdout"] == "\u{fffd}" && data["stderr"] == "\u{fffd}");
    let reply = client.call("ssh_exec", json!({"host":"plain","command":"i=0; while [ \"$i\" -lt 4096 ]; do printf x; printf y >&2; i=$((i+1)); done; cat; exit 7","stdin":"z".repeat(8192)})).await?;
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
        "printf started > {}; printf partial; printf error >&2; sleep 3; printf done > {}",
        quote(&timeout_started.to_string_lossy()),
        quote(&timeout_done.to_string_lossy())
    );
    let (timed, unaffected) = tokio::join!(
        client.call(
            "ssh_exec",
            json!({"host":"plain","command":command,"timeout_secs":1})
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
        "printf started > {}; printf cancel-partial; sleep 3; printf done > {}",
        quote(&cancel_started.to_string_lossy()),
        quote(&cancel_done.to_string_lossy())
    );
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
        "ssh_exec",
        json!({"host":"plain","command":command,"timeout_secs":10}),
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
    let request = client.call("ssh_exec", json!({"host":"resource","command":command}));
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
                let reply = exec(&client, &quiet).await?;
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

async fn read_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let root = fixture.root.path();
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
        let reply = client.call("ssh_read_file", args).await?;
        ensure!(
            succeeded(&reply)?
                == &json!({
                    "content":content,"encoding":"utf8","bytes_read":content.len(),
                    "next_offset":next,"eof":eof
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
    let binary = root.join("read-binary");
    fs::write(&binary, [0, 255, 128, 65])?;
    let reply = client
        .call(
            "ssh_read_file",
            json!({"host":"plain","path":binary,"encoding":"base64"}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":"AP+AQQ==","encoding":"base64","bytes_read":4,"next_offset":4,"eof":true
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
                "next_offset":65_536,"eof":false
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
