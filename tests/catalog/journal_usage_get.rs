use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn journal_usage_get_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("journal_usage_get", json!({})).await?;
        binding.reject(json!({"vacuum_size":0})).await?;
        let prep = guest.shell("mkdir -p /etc/systemd/journald.conf.d; printf '[Journal]\nMaxRetentionSec=1234s\n' > /etc/systemd/journald.conf.d/90-estus-catalog.conf").await?;
        ensure!(prep.status.success(), "retention fixture creation failed");
        let independent = guest.shell("LC_ALL=C /usr/bin/journalctl --disk-usage --no-pager").await?;
        ensure!(independent.status.success(), "usage oracle failed");
        let reply = binding.call(json!({})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["disk_usage_text"].as_str().context("usage")?.contains("journals take up"), "usage not actual journalctl observation");
        // The running daemon is not reloaded; source assignment is not falsely claimed as effective runtime policy.
        ensure!(value["runtime_retention_known"] == false, "runtime policy fabricated");
        ensure!(value["retention_assignments"].as_array().context("retention assignments")?.iter().any(|v| v["path"] == "/etc/systemd/journald.conf.d/90-estus-catalog.conf" && v["key"] == "MaxRetentionSec" && v["value"] == "1234s"), "selected retention source missing");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
