//! Explicit packaged SSH, SFTP and sudo acceptance against the exact Nix-built image.
//! Runs require SSH_MCP_TEST_FIXTURE, explicit DOCKER_HOST and the Nix-provided Docker CLI.
//! Containers select the artifact's exact config digest; execution is not network-isolated.
#[path = "support/baseline_commands.rs"]
mod baseline_commands;
#[path = "support/baseline_files.rs"]
mod baseline_files;
#[path = "support/isolated.rs"]
mod isolated;
#[allow(dead_code, unused_imports)]
// Shared native-only fixture helpers are not this test's backend.
mod support;

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use anyhow::{Context, Result, ensure};
use rmcp::{
    model::{CallToolRequest, ClientRequest, ServerResult},
    service::PeerRequestOptions,
};
use serde_json::{Value, json};
use support::{Client, assert_masters_gone, masters};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    task::JoinHandle,
    time::{Duration, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

/// One disposable opaque SSH relay, not an SSH/SFTP implementation.
/// A 1 MiB upload needs over three minutes at this rate (compression is disabled).
struct WriteRelay {
    port: u16,
    connections: Arc<AtomicUsize>,
    forwarded: Arc<AtomicUsize>,
    throttled: Arc<AtomicBool>,
    cancel: CancellationToken,
    task: JoinHandle<Result<()>>,
}

impl WriteRelay {
    async fn start(endpoint: (String, u16)) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let connections = Arc::new(AtomicUsize::new(0));
        let forwarded = Arc::new(AtomicUsize::new(0));
        let throttled = Arc::new(AtomicBool::new(true));
        let cancel = CancellationToken::new();
        let task = tokio::spawn({
            let connections = Arc::clone(&connections);
            let forwarded = Arc::clone(&forwarded);
            let throttled = Arc::clone(&throttled);
            let cancel = cancel.clone();
            async move {
                let relay = async {
                    let (mut downstream, _) = listener.accept().await?;
                    connections.fetch_add(1, Ordering::SeqCst);
                    let mut upstream = TcpStream::connect(endpoint).await?;
                    let connection = async move {
                        let (mut client_read, mut client_write) = downstream.split();
                        let (mut server_read, mut server_write) = upstream.split();
                        let upload = async {
                            let mut buffer = [0_u8; 1024];
                            loop {
                                let count = client_read.read(&mut buffer).await?;
                                if count == 0 {
                                    return server_write.shutdown().await;
                                }
                                // Deliberate bandwidth fault, never readiness evidence.
                                if throttled.load(Ordering::Relaxed) {
                                    sleep(Duration::from_millis(200)).await;
                                }
                                server_write.write_all(&buffer[..count]).await?;
                                forwarded.fetch_add(count, Ordering::SeqCst);
                            }
                        };
                        let download = tokio::io::copy(&mut server_read, &mut client_write);
                        // Either EOF/reset closes both sockets immediately; do not
                        // wait for the throttled upload after the container dies.
                        tokio::select! {
                            _ = upload => {}
                            _ = download => {}
                        }
                        Ok::<_, anyhow::Error>(())
                    };
                    tokio::pin!(connection);
                    let mut connected = true;
                    loop {
                        tokio::select! {
                            result = &mut connection, if connected => {
                                result?;
                                connected = false;
                            }
                            accepted = listener.accept() => {
                                let (socket, _) = accepted?;
                                connections.fetch_add(1, Ordering::SeqCst);
                                // Never forward a replay. Its attempt is still observable.
                                drop(socket);
                            }
                        }
                    }
                };
                tokio::select! {
                    () = cancel.cancelled() => Ok(()),
                    result = timeout(Duration::from_secs(90), relay) => {
                        result.context("write relay lifetime exceeded")?
                    }
                }
            }
        });
        Ok(Self {
            port,
            connections,
            forwarded,
            throttled,
            cancel,
            task,
        })
    }

    async fn stop(mut self) -> Result<()> {
        self.cancel.cancel();
        match timeout(Duration::from_secs(5), &mut self.task).await {
            Ok(result) => result.context("write relay task")?,
            Err(error) => {
                self.task.abort();
                let _ = (&mut self.task).await;
                Err(error).context("write relay cleanup deadline")
            }
        }
    }
}

impl Drop for WriteRelay {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn ordinary(client: &Client, command: &str) -> Result<Value> {
    let reply = client
        .call(
            "ssh_exec",
            json!({"host":"plain", "command":command, "timeout_secs":10}),
        )
        .await?;
    ensure!(
        reply["error"].is_null() && reply["data"]["exit_code"] == 0,
        "ordinary ssh_exec failed: {reply}"
    );
    Ok(reply["data"].clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_end_to_end() -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let client = match Client::start(&fixture.config).await {
        Ok(client) => client,
        Err(error) => {
            let cleanup = fixture.stop().await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("fixture cleanup also failed: {cleanup:#}")))
                }
            };
        }
    };
    let scenario = async {
        fixture.verify_identities().await?;
        // Readiness uses plain once and viajump twice on primary (jump and
        // forwarded login), with a separate login on the nosftp container.
        timeout(Duration::from_secs(5), async {
            loop {
                let count = fixture.authentication_count().await?;
                ensure!(count <= 3, "unexpected primary readiness authentications: {count}");
                if count == 3 { return Ok::<_, anyhow::Error>(()); }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("jump's extra public-key authentication was not observed")??;
        let first = ordinary(&client, "/usr/bin/id -u; /usr/bin/printf '%s\\n' 'literal ; $HOME $(id) *'; /usr/bin/printf '%s' \"$SSH_CONNECTION\"").await?;
        let stdout = first["stdout"].as_str().context("ordinary stdout")?;
        let transport = stdout.strip_prefix("1000\nliteral ; $HOME $(id) *\n").context("ordinary UID/literal command output mismatch")?;
        ensure!(transport.split_ascii_whitespace().count() == 4, "missing real SSH transport identity");
        let second = ordinary(&client, "/usr/bin/printf '%s' \"$SSH_CONNECTION\"").await?;
        ensure!(second["stdout"] == transport, "ordinary calls did not share the same SSH transport");
        let owned = timeout(Duration::from_secs(5), async {
            loop {
                let owned = masters(&client.log)?;
                ensure!(owned.len() <= 1, "ordinary calls created more than one master");
                if owned.len() == 1 { return Ok::<_, anyhow::Error>(owned); }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("ordinary master audit did not arrive")??;
        let check = support::run(Command::new(&fixture.ssh).arg("-F").arg(&fixture.ssh_config).arg("-S").arg(&owned[0].1).args(["-O", "check", "plain"])).await?;
        ensure!(check.status.success() && String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={})", owned[0].0)), "original ordinary master is not alive");
        timeout(Duration::from_secs(5), async {
            loop {
                let count = fixture.authentication_count().await?;
                ensure!(count <= 4, "ordinary operations authenticated more than once: {count}");
                if count == 4 { return Ok::<_, anyhow::Error>(()); }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("ordinary master authentication was not observed")??;
        fixture.reject_unknown_key().await?;
        fixture.verify_identities().await?;
        Ok::<_, anyhow::Error>(())
    }.await;
    // Collect all results before propagating any error: server/master cleanup
    // and both container removals are explicit on ordinary Result failures.
    let log = client.log.clone();
    let server_cleanup = client.stop().await.map(|_| ());
    let master_cleanup = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Err(anyhow::anyhow!("no ordinary master cleanup evidence")),
        Err(error) => Err(error),
    };
    let container_cleanup = fixture.stop().await;
    let errors = [
        ("scenario", scenario),
        ("server cleanup", server_cleanup),
        ("master cleanup", master_cleanup),
        ("container cleanup", container_cleanup),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
    .collect::<Vec<_>>();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(())
}

#[derive(Clone, Copy)]
enum WriteFault {
    Disconnect,
    Timeout,
    Cancel,
}

async fn isolated_write_fault(fault: WriteFault) -> Result<()> {
    let fixture = isolated::Fixture::start().await?;
    let relay = match async { WriteRelay::start(fixture.primary_endpoint().await?).await }.await {
        Ok(relay) => relay,
        Err(error) => {
            let cleanup = fixture.stop().await;
            return Err(error.context(format!("fixture cleanup: {cleanup:?}")));
        }
    };
    let client = match async {
        fixture.configure_write_relay(relay.port)?;
        Client::start(&fixture.config).await
    }
    .await
    {
        Ok(client) => client,
        Err(error) => {
            let relay_cleanup = relay.stop().await;
            let fixture_cleanup = fixture.stop().await;
            return Err(error.context(format!(
                "relay cleanup: {relay_cleanup:?}; fixture cleanup: {fixture_cleanup:?}"
            )));
        }
    };
    let scenario = async {
        // Privileged SDK exec only prepares/observes disposable fixture files.
        // The actual writer below authenticates as ordinary mcp (UID 1000).
        fixture.primary_exec(indoc::indoc! {"
            printf ORIGINAL > /tmp/f04-blocked
            chown mcp /tmp/f04-blocked
            chmod 600 /tmp/f04-blocked
            printf ROOT_ONLY > /tmp/f04-root-only
            chown root /tmp/f04-root-only
            chmod 600 /tmp/f04-root-only
        "}).await?;
        let denied = client.call("ssh_write_file", json!({
            "host":"plain", "path":"/tmp/f04-root-only",
            "content":"MUST_NOT_REPLACE", "overwrite":true
        })).await?;
        ensure!(
            denied["data"].is_null()
                && denied["error"]["code"] == "permission_denied"
                && denied["error"]["remote_state_unknown"] == true,
            "ordinary denied mutating OPEN did not report conservative uncertainty: {denied}"
        );
        ensure!(
            fixture.primary_exec("cat /tmp/f04-root-only; stat -c '%u' /tmp/f04-root-only").await?
                == b"ROOT_ONLY0\n",
            "ordinary write changed root-owned denied data/ownership"
        );
        let warm = client.call("ssh_exec", json!({
            "host":"slowwrite", "command":"/usr/bin/id -u; /usr/bin/printf '%s' \"$SSH_CONNECTION\"", "timeout_secs":15
        })).await?;
        ensure!(
            warm["error"].is_null() && warm["data"]["exit_code"] == 0,
            "relay did not authenticate the ordinary writer: {warm}"
        );
        let slow_transport = warm["data"]["stdout"].as_str()
            .and_then(|text| text.strip_prefix("1000\n"))
            .context("slow writer UID/transport")?;
        ensure!(slow_transport.split_ascii_whitespace().count() == 4);
        let sibling = client.call("ssh_exec", json!({
            "host":"nosftp", "command":"/usr/bin/printf '%s' \"$SSH_CONNECTION\""
        })).await?;
        ensure!(
            sibling["error"].is_null() && sibling["data"]["exit_code"] == 0,
            "independent sibling failed: {sibling}"
        );
        let transport = sibling["data"]["stdout"].as_str().context("sibling transport")?;
        ensure!(transport.split_ascii_whitespace().count() == 4, "missing sibling transport");
        let before = timeout(Duration::from_secs(5), async {
            loop {
                let owned = masters(&client.log)?;
                ensure!(owned.len() <= 3, "write setup created extra masters");
                if owned.len() == 3 { return Ok::<_, anyhow::Error>(owned); }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("write master audits did not arrive")??;
        let forwarded_before = relay.forwarded.load(Ordering::SeqCst);
        let arguments = json!({
            "host":"slowwrite", "path":"/tmp/f04-blocked",
            "content":"W".repeat(1024 * 1024), "overwrite":true,
            "timeout_secs": if matches!(fault, WriteFault::Timeout) { 8 } else { 30 },
        });
        let mut request = client.service.send_cancellable_request(
            ClientRequest::CallToolRequest(CallToolRequest::new(support::params("ssh_write_file", arguments))),
            PeerRequestOptions::default(),
        ).await?;
        let request_id = serde_json::to_value(&request.id)?;
        // This command observes the real file via independent container exec.
        // It cannot report READY from FIFO/ESPIPE, an unopened file or a completed upload.
        let truncated = timeout(Duration::from_secs(10), async {
            loop {
                let size = fixture.primary_exec("stat -c '%s' /tmp/f04-blocked").await?;
                if size == b"0\n" { return Ok::<_, anyhow::Error>(()); }
                ensure!(size == b"8\n", "upload wrote before the truncation barrier");
                sleep(Duration::from_millis(20)).await;
            }
        });
        tokio::pin!(truncated);
        tokio::select! {
            result = &mut request.rx => anyhow::bail!("write finished before observed truncation: {result:?}"),
            result = &mut truncated => result.context("mutating OPEN was not observed")??,
        }
        // Keep polling the real request while throttled bytes are in flight.
        tokio::select! {
            result = &mut request.rx => anyhow::bail!("write was not genuinely blocked: {result:?}"),
            () = sleep(Duration::from_secs(1)) => {}
        }
        ensure!(
            fixture.primary_exec("stat -c '%s:%u' /tmp/f04-blocked").await? == b"0:1000\n",
            "blocked overwrite must still be truncated and owned by mcp"
        );
        let forwarded = relay.forwarded.load(Ordering::SeqCst) - forwarded_before;
        ensure!(
            forwarded > 0 && forwarded < 1024 * 1024,
            "relay did not hold the actual upload in flight: {forwarded} bytes"
        );
        if matches!(fault, WriteFault::Disconnect) {
            fixture.kill_primary().await?;
        }
        let expected_code = if matches!(fault, WriteFault::Cancel) {
            timeout(Duration::from_secs(5), request.cancel(Some("isolated write cancellation".into()))).await??;
            "cancelled".to_owned()
        } else {
            let response = timeout(Duration::from_secs(12), request.await_response())
                .await.context("blocked write did not terminate within its fault deadline")??;
            let ServerResult::CallToolResult(result) = response else {
                anyhow::bail!("write returned a non-tool result");
            };
            let reply = support::envelope(result)?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true,
                "post-truncation fault was reported as success/known state: {reply}"
            );
            let code = reply["error"]["code"].as_str().context("write error code")?;
            if matches!(fault, WriteFault::Timeout) {
                ensure!(code == "timeout", "blocked write did not time out: {reply}");
            } else {
                ensure!(code == "connection_lost", "disconnect was misclassified: {reply}");
            }
            code.to_owned()
        };
        timeout(Duration::from_secs(5), async {
            loop {
                if let Some(record) = client.log.records()?.into_iter().find(|record|
                    record["event"] == "finish" && record["request_id"] == request_id)
                {
                    ensure!(record["error_code"] == expected_code && record["remote_state_unknown"] == true);
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("cancelled/failed write audit did not finish")??;
        if !matches!(fault, WriteFault::Disconnect) {
            // Remove the intentional bandwidth fault so new channel traffic is
            // not queued behind old encrypted bytes. This is not a replay.
            relay.throttled.store(false, Ordering::Relaxed);
            let healthy = client.call("ssh_exec", json!({
                "host":"slowwrite", "command":"/usr/bin/printf '%s' \"$SSH_CONNECTION\""
            })).await?;
            ensure!(
                healthy["error"].is_null() && healthy["data"]["stdout"] == slow_transport,
                "write cancellation replaced/damaged its healthy shared master: {healthy}"
            );
            fixture.kill_primary().await?;
        }
        let survivor = client.call("ssh_exec", json!({
            "host":"nosftp", "command":"/usr/bin/printf '%s' \"$SSH_CONNECTION\""
        })).await?;
        ensure!(
            survivor["error"].is_null()
                && survivor["data"]["exit_code"] == 0
                && survivor["data"]["stdout"] == transport,
            "write fault damaged the independent original sibling master: {survivor}"
        );
        ensure!(
            masters(&client.log)? == before
                && relay.connections.load(Ordering::SeqCst) == 1,
            "write failure automatically replayed or created another master"
        );
        Ok::<_, anyhow::Error>(())
    }.await;
    // Always close the packaged server, observe owned masters gone, abort/join
    // the relay, and explicitly remove both owned containers on Result failures.
    let log = client.log.clone();
    let server_cleanup = client.stop().await.map(|_| ());
    let master_cleanup = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    };
    let relay_cleanup = relay.stop().await;
    let container_cleanup = fixture.stop().await;
    let errors = [
        ("write fault", scenario),
        ("packaged server cleanup", server_cleanup),
        ("master cleanup", master_cleanup),
        ("relay cleanup", relay_cleanup),
        ("fixture cleanup", container_cleanup),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
    .collect::<Vec<_>>();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_write_interrupted_after_truncate() -> Result<()> {
    isolated_write_fault(WriteFault::Disconnect).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_write_timeout_after_truncate() -> Result<()> {
    isolated_write_fault(WriteFault::Timeout).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit dedicated Docker-compatible daemon"]
async fn ssh_write_cancel_after_truncate() -> Result<()> {
    isolated_write_fault(WriteFault::Cancel).await
}

fn command_succeeded(reply: &Value, stdout: &str) -> Result<()> {
    ensure!(
        reply["error"].is_null() && reply["data"]["exit_code"] == 0,
        "command did not succeed"
    );
    let data = &reply["data"];
    ensure!(
        data["stdout"] == stdout && data["stderr"] == "",
        "command output differs"
    );
    for field in [
        "stdout_truncated",
        "stderr_truncated",
        "stdout_lossy",
        "stderr_lossy",
    ] {
        ensure!(
            data[field] == false,
            "command output was truncated or decoded lossily"
        );
    }
    Ok(())
}

fn policy_rejected(reply: &Value) -> Result<()> {
    ensure!(reply["data"].is_null() && reply["error"]["code"] == "policy_denied");
    ensure!(reply["error"]["remote_state_unknown"] == false);
    Ok(())
}

fn private_boundary(text: &str, markers: &[String]) -> Result<()> {
    for marker in markers {
        ensure!(
            !text.contains(marker),
            "credential material reached the MCP transcript/audit"
        );
    }
    Ok(())
}

async fn fixture_fingerprints(
    fixture: &isolated::Fixture,
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut keys = std::collections::BTreeMap::new();
    for account in ["mcp", "mcp-sudo", "mcp-admin", "mcp-password", "mcp-tty"] {
        keys.insert(account.to_owned(), fixture.key_fingerprint(account).await?);
    }
    Ok(keys)
}

async fn observed_authentications(
    fixture: &isolated::Fixture,
    keys: &std::collections::BTreeMap<String, String>,
    expected: &[(&str, usize)],
) -> Result<()> {
    timeout(Duration::from_secs(5), async {
        loop {
            let accepted = fixture.authentication_keys().await?;
            for (account, fingerprint) in &accepted {
                ensure!(
                    keys.get(account) == Some(fingerprint)
                        && expected.iter().any(|(name, _)| *name == account.as_str()),
                    "SSH authenticated with a different account/key"
                );
            }
            let mut complete = true;
            for (account, limit) in expected {
                let count = accepted.iter().filter(|(name, _)| name == account).count();
                ensure!(
                    count <= *limit,
                    "unexpected extra SSH authentication for {account}"
                );
                complete &= count == *limit;
            }
            if complete {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("expected account/key authentication was not observed")?
}

async fn observed_master_count(
    log: &support::Log,
    count: usize,
) -> Result<Vec<(u32, std::path::PathBuf)>> {
    timeout(Duration::from_secs(5), async {
        loop {
            let owned = masters(log)?;
            ensure!(owned.len() <= count, "unexpected extra owned SSH master");
            if owned.len() == count {
                return Ok::<_, anyhow::Error>(owned);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("owned SSH master records did not arrive")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit Docker-compatible daemon"]
async fn ssh_sudo_authority() -> Result<()> {
    use std::io::Write as _;

    let fixture = isolated::Fixture::start().await?;
    // A second logical target for the same sudo-capable UID is deliberately NOT
    // isolation: disabling its structured tool cannot constrain arbitrary exec.
    let setup = (|| -> Result<_> {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&fixture.config)?
            .write_all(
                indoc::indoc! {"
                [targets.same-disabled]
                ssh_host = 'same'
            "}
                .as_bytes(),
            )?;
        fixture.credential_markers()
    })();
    let markers = match setup {
        Ok(markers) => markers,
        Err(error) => {
            let cleanup = fixture.stop().await;
            cleanup?;
            return Err(error);
        }
    };
    let client = match Client::start(&fixture.config).await {
        Ok(client) => client,
        Err(error) => {
            let cleanup = fixture.stop().await;
            cleanup?;
            return Err(error);
        }
    };
    let scenario = async {
        let keys = fixture_fingerprints(&fixture).await?;
        observed_authentications(
            &fixture,
            &keys,
            &[
                ("mcp", 3),
                ("mcp-sudo", 1),
                ("mcp-admin", 0),
                ("mcp-password", 0),
                ("mcp-tty", 0),
            ],
        )
        .await?;
        let out = fixture
            .primary_exec("/usr/bin/id -u mcp; /usr/bin/id -u mcp-sudo; /usr/bin/id -u mcp-admin")
            .await?;
        ensure!(
            out == b"1000\n1001\n1002\n",
            "fixture identities are not distinct UIDs"
        );

        for (tool, args) in [
            (
                "ssh_sudo",
                json!({"host":"same-disabled","argv":["/usr/bin/id","-u"]}),
            ),
            (
                "ssh_sudo",
                json!({"host":"split-admin","argv":["/usr/bin/id","-u"]}),
            ),
            (
                "ssh_exec",
                json!({"host":"split-admin","command":"/usr/bin/id -u"}),
            ),
        ] {
            policy_rejected(&client.call(tool, args).await?)?;
        }
        ensure!(
            masters(&client.log)?.is_empty(),
            "policy refusal dispatched SSH"
        );
        observed_authentications(
            &fixture,
            &keys,
            &[
                ("mcp", 3),
                ("mcp-sudo", 1),
                ("mcp-admin", 0),
                ("mcp-password", 0),
                ("mcp-tty", 0),
            ],
        )
        .await?;

        let ordinary = client
            .call(
                "ssh_exec",
                json!({"host":"split","command":"/usr/bin/id -u"}),
            )
            .await?;
        command_succeeded(&ordinary, "1000\n")?;
        let denied = client
            .call(
                "ssh_exec",
                json!({
                    "host":"split","command":"/usr/bin/sudo -n -k -u root -- /usr/bin/id -u"
                }),
            )
            .await?;
        ensure!(
            denied["error"]["code"] == "command_failed"
                && denied["error"]["remote_state_unknown"] == false
                && denied["data"]["exit_code"] == 1
                && denied["data"]["stdout"] == ""
        );
        let first = observed_master_count(&client.log, 1).await?;
        let root = client
            .call(
                "ssh_sudo",
                json!({"host":"split","argv":["/usr/bin/id","-u"]}),
            )
            .await?;
        command_succeeded(&root, "0\n")?;
        let split = observed_master_count(&client.log, 2).await?;
        ensure!(split[..1] == first);
        observed_authentications(
            &fixture,
            &keys,
            &[
                ("mcp", 4),
                ("mcp-sudo", 1),
                ("mcp-admin", 1),
                ("mcp-password", 0),
                ("mcp-tty", 0),
            ],
        )
        .await?;
        // A primed elevated master must not bypass per-request user/program policy.
        for args in [
            json!({"host":"split","user":"mcp","argv":["/usr/bin/id","-u"]}),
            json!({"host":"split","argv":["/bin/sh","-c","/usr/bin/id -u"]}),
        ] {
            policy_rejected(&client.call("ssh_sudo", args).await?)?;
        }
        command_succeeded(
            &client
                .call(
                    "ssh_exec",
                    json!({"host":"split","command":"/usr/bin/id -u"}),
                )
                .await?,
            "1000\n",
        )?;
        command_succeeded(
            &client
                .call(
                    "ssh_sudo",
                    json!({"host":"split","argv":["/usr/bin/id","-u"]}),
                )
                .await?,
            "0\n",
        )?;
        ensure!(
            masters(&client.log)? == split,
            "split roles did not reuse their two original masters"
        );

        command_succeeded(
            &client
                .call(
                    "ssh_exec",
                    json!({"host":"same","command":"/usr/bin/id -u"}),
                )
                .await?,
            "1001\n",
        )?;
        let same = observed_master_count(&client.log, 3).await?;
        command_succeeded(
            &client
                .call(
                    "ssh_sudo",
                    json!({"host":"same","argv":["/usr/bin/id","-u"]}),
                )
                .await?,
            "0\n",
        )?;
        ensure!(
            masters(&client.log)? == same,
            "same-account sudo created another identity/master"
        );
        // This succeeds despite the earlier structured sudo policy refusal.
        command_succeeded(&client.call("ssh_exec", json!({
            "host":"same-disabled","command":"/usr/bin/sudo -n -k -u root -- /usr/bin/id -u"
        })).await?, "0\n")?;
        let owned = observed_master_count(&client.log, 4).await?;
        for ((pid, socket), alias) in owned.iter().zip(["split", "split-admin", "same", "same"]) {
            let check = support::run(
                Command::new(&fixture.ssh)
                    .arg("-F")
                    .arg(&fixture.ssh_config)
                    .arg("-S")
                    .arg(socket)
                    .args(["-O", "check", alias]),
            )
            .await?;
            ensure!(
                check.status.success()
                    && String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={pid})")),
                "original authority master did not remain alive"
            );
        }
        observed_authentications(
            &fixture,
            &keys,
            &[
                ("mcp", 4),
                ("mcp-sudo", 3),
                ("mcp-admin", 1),
                ("mcp-password", 0),
                ("mcp-tty", 0),
            ],
        )
        .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let log = client.log.clone();
    let server = client.stop().await;
    let master_cleanup = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    };
    let container_cleanup = fixture.stop().await;
    let errors: Vec<_> = [
        ("authority", scenario),
        ("server cleanup", server.map(|_| ())),
        ("master cleanup", master_cleanup),
        ("container cleanup", container_cleanup),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
    .collect();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    private_boundary(&log.text(), &markers)?;
    let records = log.final_records()?;
    let roles: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "master_start")
        .map(|record| record["role"].as_str())
        .collect();
    ensure!(
        roles
            == [
                Some("ordinary"),
                Some("elevated"),
                Some("ordinary"),
                Some("ordinary")
            ]
    );
    for (host, role, mode) in [
        ("same", "ordinary", "same-account"),
        ("split", "elevated", "separate-identity"),
    ] {
        let completed: Vec<_> = records
            .iter()
            .filter(|record| {
                record["event"] == "finish"
                    && record["tool"] == "ssh_sudo"
                    && record["host"] == host
            })
            .collect();
        ensure!(
            !completed.is_empty(),
            "successful elevated audit is missing"
        );
        ensure!(
            completed
                .iter()
                .all(|record| record["identity_role"] == role
                    && record["sudo_mode"] == mode
                    && record["user"] == "root"
                    && record["program"] == "/usr/bin/id"
                    && record["exit_code"] == 0
                    && record["remote_state_unknown"] == false)
        );
    }
    Ok(())
}

async fn wire_tool(
    wire: &mut support::WireServer,
    id: u64,
    name: &str,
    arguments: Value,
    markers: &[String],
) -> Result<Value> {
    let mut frame = wire
        .request(id, "tools/call", json!({"name":name,"arguments":arguments}))
        .await?;
    private_boundary(&serde_json::to_string(&frame)?, markers)?;
    let result = frame
        .get_mut("result")
        .context("raw tool result missing")?
        .take();
    support::envelope(serde_json::from_value::<rmcp::model::CallToolResult>(
        result,
    )?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit Docker-compatible daemon"]
async fn ssh_sudo_fidelity_and_failures() -> Result<()> {
    const STDIN_SECRET: &str = "V02_STDIN_SECRET_NOT_FOR_REPLY";
    const REJECTED_SECRET: &str = "V02_REJECTED_ARG_NOT_FOR_REPLY";
    const ARGV_SECRET: &str = "V02_ARG_AUDIT_SECRET";

    let fixture = isolated::Fixture::start().await?;
    let setup = fixture.credential_markers();
    let mut markers = match setup {
        Ok(markers) => markers,
        Err(error) => {
            let cleanup = fixture.stop().await;
            cleanup?;
            return Err(error);
        }
    };
    markers.extend([STDIN_SECRET.to_owned(), REJECTED_SECRET.to_owned()]);
    let mut wire = match support::WireServer::start(&fixture.config) {
        Ok(wire) => wire,
        Err(error) => {
            let cleanup = fixture.stop().await;
            cleanup?;
            return Err(error);
        }
    };
    let scenario = async {
        wire.initialize().await?;
        let keys = fixture_fingerprints(&fixture).await?;
        let invalid = wire_tool(
            &mut wire,
            2,
            "ssh_sudo",
            json!({
                "host":"split","argv":["/usr/bin/printf",format!("{REJECTED_SECRET}\0")]
            }),
            &markers,
        )
        .await?;
        ensure!(
            invalid["data"].is_null()
                && invalid["error"]["code"] == "invalid_argument"
                && invalid["error"]["remote_state_unknown"] == false
        );
        ensure!(
            masters(&wire.log)?.is_empty(),
            "invalid elevated argv authenticated"
        );

        // Independent policy/TTY oracles distinguish real sudo constraints from
        // a missing executable, unauthorized command or broken fixture runtime.
        fixture
            .primary_exec("/usr/bin/sudo -n -l -U mcp-password -- /usr/bin/id -u")
            .await
            .context("password fixture policy does not permit the tested command")?;
        let tty = fixture
            .direct_tty(
                "requiretty",
                "/usr/bin/sudo -n -k -u root -- /usr/bin/id -u",
            )
            .await?;
        ensure!(
            tty.status.success() && std::str::from_utf8(&tty.stdout)?.trim() == "0",
            "requiretty command did not succeed with an independently allocated TTY"
        );

        let arguments = [
            "",
            " leading and trailing  ",
            "-n",
            "'\"\\$HOME `id` ! * ? [x] {a,b}; & | < >\n\t\r",
            "é雪",
            "$(/bin/touch /tmp/v02-argv-injected)",
            ARGV_SECRET,
        ];
        let mut argv = vec!["/usr/bin/printf", "%s\\0"];
        argv.extend(arguments);
        let mut expected = String::new();
        for argument in arguments {
            expected.push_str(argument);
            expected.push('\0');
        }
        for (id, host) in [(3, "same"), (4, "split")] {
            let reply = wire_tool(
                &mut wire,
                id,
                "ssh_sudo",
                json!({
                    "host":host,"user":"root","argv":argv,
                }),
                &markers,
            )
            .await?;
            command_succeeded(&reply, &expected)?;
        }
        fixture
            .primary_exec("test ! -e /tmp/v02-argv-injected")
            .await
            .context("literal elevated argv executed shell substitution")?;

        for (id, host) in [(5, "password"), (6, "requiretty")] {
            let reply = wire_tool(
                &mut wire,
                id,
                "ssh_sudo",
                json!({
                    "host":host,"argv":["/usr/bin/id","-u"],"timeout_secs":3,
                }),
                &markers,
            )
            .await?;
            ensure!(
                reply["error"]["code"] == "command_failed"
                    && reply["error"]["remote_state_unknown"] == false
                    && reply["data"]["exit_code"] == 1
                    && reply["data"]["stdout"] == "",
                "sudo failure did not preserve its known noninteractive command exit"
            );
            let direct = fixture
                .direct(host, "/usr/bin/sudo -n -k -u root -- /usr/bin/id -u")
                .await?;
            ensure!(direct.status.code() == Some(1) && direct.stdout.is_empty());
            ensure!(
                reply["data"]["stderr"] == std::str::from_utf8(&direct.stderr)?,
                "sudo command diagnostics differ from independent direct SSH"
            );
        }
        let consumed = wire_tool(
            &mut wire,
            7,
            "ssh_exec",
            json!({
                "host":"plain",
                "command":indoc::indoc! {"
                IFS= read -r hidden
                /usr/bin/printf 'STDIN_CONSUMED\\n'
            "},
                "stdin":format!("{STDIN_SECRET}\n"),
            }),
            &markers,
        )
        .await?;
        command_succeeded(&consumed, "STDIN_CONSUMED\n")?;
        observed_master_count(&wire.log, 5).await?;
        observed_authentications(
            &fixture,
            &keys,
            &[
                ("mcp", 4),
                ("mcp-sudo", 2),
                ("mcp-admin", 1),
                ("mcp-password", 2),
                ("mcp-tty", 3),
            ],
        )
        .await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let log = wire.log.clone();
    let server = wire.stop(false).await;
    let master_cleanup = match masters(&log) {
        Ok(owned) if !owned.is_empty() => assert_masters_gone(&owned).await,
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    };
    let container_cleanup = fixture.stop().await;
    let errors: Vec<_> = [
        ("fidelity", scenario),
        ("server cleanup", server.map(|_| ())),
        ("master cleanup", master_cleanup),
        ("container cleanup", container_cleanup),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
    .collect();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    // Literal printf output is intentionally public in the reply, never audit.
    markers.push(ARGV_SECRET.to_owned());
    private_boundary(&log.text(), &markers)?;
    let records = log.final_records()?;
    for record in records
        .iter()
        .filter(|record| record["tool"] == "ssh_sudo" || record["tool"] == "ssh_exec")
    {
        for field in [
            "argv",
            "stdin",
            "command",
            "stdout",
            "stderr",
            "password",
            "private_key",
        ] {
            ensure!(
                record.get(field).is_none(),
                "audit retained a payload/credential field"
            );
        }
    }
    for host in ["password", "requiretty"] {
        let failed = records
            .iter()
            .find(|record| record["event"] == "finish" && record["host"] == host)
            .context("sudo failure audit")?;
        ensure!(
            failed["identity_role"] == "ordinary"
                && failed["sudo_mode"] == "same-account"
                && failed["error_code"] == "command_failed"
                && failed["exit_code"] == 1
                && failed["remote_state_unknown"] == false
        );
    }
    Ok(())
}
