use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn nic_pause_set() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"set -e; /usr/bin/ip link set pause0 down; /usr/bin/ethtool -A pause0 autoneg off rx on tx on"#).await?;
        ensure!(prepared.status.success(), "independent capability/baseline preparation failed: {:?}", prepared);
        let before = guest.shell(r#"set -e; /usr/bin/ethtool -a pause0"#).await?;
        ensure!(before.status.success(), "independent baseline query failed: {:?}", before);
        let binding = guest.binding("nic_pause_set", json!({})).await?;
        binding.reject(json!({"interface": "pause0", "rx": "off", "tx": false})).await?;
        binding.reject(json!({"interface": "pause0", "rx": false, "tx": false, "operator_policy": {"allow_runtime_tuning": true}})).await?;
        binding.reject(json!({"interface": "management0", "rx": false, "tx": false})).await?;
        let reply = binding.call(json!({"interface": "pause0", "rx": false, "tx": false})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["verified"] == true, "setter must perform a meaningful verified mutation: {value}");
        ensure!(value["before"] != value["after"], "setter only reported a no-op");
        let after = guest.shell(r#"set -e; /usr/bin/ethtool -a pause0"#).await?;
        ensure!(after.status.success(), "independent postcondition query failed");
        ensure!(["Autonegotiate:", "RX:", "TX:"].iter().all(|label| String::from_utf8_lossy(&after.stdout).lines().any(|line| line.split_whitespace().collect::<Vec<_>>() == [*label, "off"])), "independent postcondition mismatch: {:?}", after);
        ensure!(before.stdout != after.stdout, "independent driver setting did not change");
        let noop = binding.call(json!({"interface": "pause0", "rx": false, "tx": false})).await?;
        ensure!(catalog::projection(&noop)?["changed"] == false, "already-current request must be unchanged");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
