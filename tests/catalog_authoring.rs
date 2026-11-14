#![allow(dead_code)]
#[path = "support/catalog.rs"]
mod catalog;
mod support;

use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

async fn command(base: &Path, arguments: &[&std::ffi::OsStr]) -> Result<()> {
    let mut child = support::server_command(base)?;
    child
        .arg("catalog")
        .arg("--root")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("examples"))
        .args(arguments);
    let output = support::run(&mut child).await?;
    ensure!(
        output.status.success(),
        "catalog authoring command failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn site(guest: &catalog::Guest, root: &Path) -> Result<toml::Value> {
    let mut site: toml::Value = toml::from_str(&std::fs::read_to_string(&guest.config)?)?;
    let runtime = std::env::var("ESTUS_TEST_ANSIBLE_RUNTIME").context("pinned runtime")?;
    let workspace = root.join("workspace");
    std::fs::DirBuilder::new().mode(0o700).create(&workspace)?;
    let automation = site
        .get_mut("automation")
        .and_then(toml::Value::as_table_mut)
        .context("automation")?;
    automation.insert("runtime".into(), runtime.into());
    automation.insert(
        "workspace_root".into(),
        workspace.to_str().context("workspace path")?.into(),
    );
    automation.insert(
        "targets".into(),
        toml::Value::try_from(
            json!({"plain":{"destination":"plain","python":"/usr/bin/python3"}}),
        )?,
    );
    Ok(site)
}

async fn use_prepared(config: &Path, tool: &str) -> Result<serde_json::Value> {
    let client = support::Client::start(config).await?;
    let result = client
        .call(tool, json!({"host":"plain","inputs":{},"timeout_secs":20}))
        .await;
    let stop = client.stop().await;
    let value = result?;
    stop?;
    Ok(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real catalog EFI guest and pinned Runner runtime"]
async fn prepare_pinned_presets_and_named_runtime_then_call_real_tools() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let temporary = tempfile::tempdir()?;
        let export = temporary.path().join("health-export");
        command(
            &guest.config,
            &[
                "export".as_ref(),
                "--preset".as_ref(),
                "linux-health".as_ref(),
                "--output".as_ref(),
                export.as_os_str(),
            ],
        )
        .await?;
        let root = temporary.path().join("health-site");
        std::fs::create_dir(&root)?;
        let mut health = site(&guest, &root)?;
        let alias = temporary.path().join("site-alias");
        std::fs::create_dir(&alias)?;
        let ssh_source = health["ssh"]["config_file"]
            .as_str()
            .context("site SSH config")?;
        std::fs::copy(ssh_source, alias.join("identity.conf"))?;
        health["ssh"]["config_file"] = "identity.conf".into();
        health.as_table_mut().context("site table")?.insert(
            "tool_presets".into(),
            toml::Value::try_from(json!(["linux-health"]))?,
        );
        health.as_table_mut().context("site table")?.insert(
            "disabled_tools".into(),
            toml::Value::try_from(json!(["memory_stats"]))?,
        );
        health["targets"]["plain"]
            .as_table_mut()
            .context("target")?
            .insert(
                "enabled_tools".into(),
                toml::Value::try_from(json!(["pressure_get"]))?,
            );
        let site_path = root.join("site.toml");
        std::fs::write(&site_path, toml::to_string(&health)?)?;
        std::os::unix::fs::symlink(&site_path, alias.join("site.toml"))?;
        let site_path = alias.join("site.toml");
        let prepared = temporary.path().join("health-reviewed");
        command(
            &guest.config,
            &[
                "prepare".as_ref(),
                "--site".as_ref(),
                site_path.as_os_str(),
                "--definitions".as_ref(),
                export.join("tools.toml").as_os_str(),
                "--target".as_ref(),
                "plain".as_ref(),
                "--output".as_ref(),
                prepared.as_os_str(),
            ],
        )
        .await?;
        let config = prepared.join("estus.toml");
        let reply = use_prepared(&config, "pressure_get").await?;
        let observed = catalog::projection(&reply)?;
        ensure!(
            observed["pressure"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|r| r["resource"] == "memory" && r["status"] == "available")),
            "prepared PSI did not observe the real guest"
        );
        let client = support::Client::start(&config).await?;
        let rejected = client
            .call("cpu_stats", json!({"host":"plain","inputs":{}}))
            .await;
        let stopped = client.stop().await;
        ensure!(rejected.is_err(), "per-target exclusion was only cosmetic");
        stopped?;
        let client = support::Client::start(&config).await?;
        let rejected = client
            .call("memory_stats", json!({"host":"plain","inputs":{}}))
            .await;
        let stopped = client.stop().await;
        ensure!(rejected.is_err(), "global disable was bypassed");
        stopped?;

        // A valid named runtime must not consult this deliberately broken global runtime.
        let export = temporary.path().join("named-export");
        command(
            &guest.config,
            &[
                "export".as_ref(),
                "--tool".as_ref(),
                "journal_usage_get".as_ref(),
                "--output".as_ref(),
                export.as_os_str(),
            ],
        )
        .await?;
        let root = temporary.path().join("named-site");
        std::fs::create_dir(&root)?;
        let mut named = site(&guest, &root)?;
        let runtime = named["automation"]["runtime"].clone();
        named["automation"]["runtime"] = "/unavailable/global/runtime".into();
        named["automation"]["authorities"]["catalog"]
            .as_table_mut()
            .context("catalog authority")?
            .insert("runtime".into(), runtime);
        let site_path = root.join("site.toml");
        std::fs::write(&site_path, toml::to_string(&named)?)?;
        let prepared = temporary.path().join("named-reviewed");
        command(
            &guest.config,
            &[
                "prepare".as_ref(),
                "--site".as_ref(),
                site_path.as_os_str(),
                "--definitions".as_ref(),
                export.join("tools.toml").as_os_str(),
                "--target".as_ref(),
                "plain".as_ref(),
                "--output".as_ref(),
                prepared.as_os_str(),
            ],
        )
        .await?;
        let reply = use_prepared(&prepared.join("estus.toml"), "journal_usage_get").await?;
        let observed = catalog::projection(&reply)?;
        ensure!(
            observed["disk_usage_text"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "named-runtime prepared binding did not read actual journal state"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real catalog EFI guest and pinned Runner runtime"]
async fn extracted_baseline_collectors_preserve_real_kernel_identity_and_units() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let boot = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(boot.status.success(), "independent boot identity");
        let boot = std::str::from_utf8(&boot.stdout)?.trim();
        let host = guest.binding("host_summary", json!({})).await?;
        let reply = host.call(json!({})).await?;
        ensure!(
            catalog::projection(&reply)?["boot_id"] == boot,
            "extracted summary lost actual kernel identity"
        );
        let cpu = guest.binding("cpu_stats", json!({})).await?;
        let reply = cpu.call(json!({"limit":1,"sample_ms":0})).await?;
        let p = catalog::projection(&reply)?;
        ensure!(
            p["boot_id"] == boot
                && p["clock_ticks_per_second"].as_u64().is_some_and(|n| n > 0)
                && p["counters"]["idle"].as_u64().is_some(),
            "extracted CPU collector lost identity, units or counters"
        );
        let memory = guest.binding("memory_stats", json!({})).await?;
        let reply = memory.call(json!({})).await?;
        let p = catalog::projection(&reply)?;
        let oracle = guest.shell("cat /proc/meminfo").await?;
        ensure!(oracle.status.success(), "independent memory observation");
        let text = std::str::from_utf8(&oracle.stdout)?;
        let total = text
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .context("MemTotal")?
            .split_whitespace()
            .nth(1)
            .context("memory KiB")?
            .parse::<u64>()?
            * 1024;
        ensure!(
            p["boot_id"] == boot && p["memory_bytes"]["mem_total_bytes"] == total,
            "extracted memory collector changed byte units or identity"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
