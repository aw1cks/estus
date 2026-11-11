//! Explicit packaged ordinary-SSH acceptance against the exact Nix-built image.
//! Local runs require SSH_MCP_TEST_FIXTURE, explicit DOCKER_HOST and the Nix CLI.
//! They check artifact/running-image identity, but upstream testcontainers 0.28
//! can still pull on create-404. Required CI must retain the image and deny
//! registry egress; that external enforcement belongs to V03.
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
