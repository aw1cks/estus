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

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use support::{Client, assert_masters_gone, masters};
use tokio::{
    process::Command,
    time::{Duration, sleep, timeout},
};

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
