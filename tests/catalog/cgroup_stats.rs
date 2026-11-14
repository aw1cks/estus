use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn cgroup_stats_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("cgroup_stats", json!({})).await?;
        binding.reject(json!({"approved_root":"/"})).await?;
        let independent = guest.shell("cat /proc/sys/kernel/random/boot_id; stat -c '%d:%i' /sys/fs/cgroup/system.slice/estus-fixture.service").await?;
        ensure!(independent.status.success(), "cgroup identity oracle failed");
        let oracle = String::from_utf8(independent.stdout)?;
        let mut lines = oracle.lines();
        let boot = lines.next().context("boot")?;
        let identity = lines.next().context("inode")?;
        let reply = binding.call(json!({})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["boot_id"] == boot && value["identity"] == identity, "cgroup identity differs from independent source");
        ensure!(value["root"] == "/system.slice/estus-fixture.service", "subtree escaped");
        ensure!(value["ancestors"].as_array().context("ancestors")?.iter().any(|a| a["path"] == "/system.slice"), "slice ancestor omitted");

        let reference = guest.shell("cat /sys/fs/cgroup/system.slice/estus-fixture.service/memory.max").await?;
        ensure!(reference.status.success(), "memory limit oracle failed");
        let expected = String::from_utf8(reference.stdout)?;
        let file = value["files"].as_array().context("files")?.iter().find(|v| v["name"] == "memory.max").context("memory.max unavailable")?;
        ensure!(file["text"] == expected.trim() && file["kind"] == "limit", "memory limit mismatch");
        let cpu = value["files"].as_array().context("files")?.iter().find(|v| v["name"] == "cpu.stat").context("cpu.stat unavailable")?;
        ensure!(cpu["kind"] == "cumulative", "CPU counter mislabeled");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
