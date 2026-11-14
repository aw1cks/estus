use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn nic_rings_set() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"set -e; /usr/bin/ip link set tune0 down; /usr/bin/ethtool -G tune0 rx 32"#).await?;
        ensure!(prepared.status.success(), "independent capability/baseline preparation failed: {:?}", prepared);
        let before = guest.shell(r#"set -e; /usr/bin/ethtool -g tune0"#).await?;
        ensure!(before.status.success(), "independent baseline query failed: {:?}", before);
        let binding = guest.binding("nic_rings_set", json!({})).await?;
        binding.reject(json!({"interface": "tune0", "rx": 0})).await?;
        binding.reject(json!({"interface": "tune0", "rx": 64, "operator_policy": {"allow_runtime_tuning": true}})).await?;
        binding.reject(json!({"interface": "management0", "rx": 64})).await?;
        let reply = binding.call(json!({"interface": "tune0", "rx": 64})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["verified"] == true, "setter must perform a meaningful verified mutation: {value}");
        ensure!(value["before"] != value["after"], "setter only reported a no-op");
        ensure!(value["before"]["rx"] == 32 && value["after"]["rx"] == 64, "observed baseline outside request enum must retain a typed receipt");
        let after = guest.shell(r#"set -e; /usr/bin/ethtool -g tune0"#).await?;
        ensure!(after.status.success(), "independent postcondition query failed");
        ensure!(String::from_utf8_lossy(&after.stdout).split("Current hardware settings:").nth(1).is_some_and(|section| section.lines().any(|line| line.split_whitespace().collect::<Vec<_>>() == ["RX:", "64"])), "independent postcondition mismatch: {:?}", after);
        ensure!(before.stdout != after.stdout, "independent driver setting did not change");
        let noop = binding.call(json!({"interface": "tune0", "rx": 64})).await?;
        ensure!(catalog::projection(&noop)?["changed"] == false, "already-current request must be unchanged");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
