use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn cgroup_tree_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("cgroup_tree", json!({})).await?;
        binding.reject(json!({"approved_root":"/"})).await?;
        let independent = guest.shell("cat /proc/sys/kernel/random/boot_id; stat -c '%d:%i' /sys/fs/cgroup/system.slice/estus-fixture.service").await?;
        ensure!(independent.status.success(), "cgroup identity oracle failed");
        let oracle = String::from_utf8(independent.stdout)?;
        let mut lines = oracle.lines();
        let boot = lines.next().context("boot")?;
        let identity = lines.next().context("inode")?;
        let reply = binding.call(json!({"depth":2,"limit":8})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["boot_id"] == boot && value["identity"] == identity, "cgroup identity differs from independent source");
        ensure!(value["root"] == "/system.slice/estus-fixture.service", "subtree escaped");
        ensure!(value["ancestors"].as_array().context("ancestors")?.iter().any(|a| a["path"] == "/system.slice"), "slice ancestor omitted");

        ensure!(value["nodes"].as_array().context("nodes")?.iter().any(|v| v["path"] == "/system.slice/estus-fixture.service" && v["systemd_component"] == "estus-fixture.service" && v["identity"] == identity), "approved service node missing");
        ensure!(value["nodes"].as_array().context("nodes")?.iter().all(|v| v["path"].as_str().is_some_and(|p| p.starts_with("/system.slice/estus-fixture.service"))), "unapproved sibling enumerated");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
