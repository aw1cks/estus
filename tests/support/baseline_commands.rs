//! Packaged included-config, strict-trust, environment and diagnostic acceptance.
use crate::{command_succeeded, isolated, private_boundary, support};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use support::{Client, Log, assert_masters_gone, masters};
use tokio::time::{sleep, timeout};
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
