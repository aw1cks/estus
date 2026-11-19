use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn observe_nic_pause() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell("set -e; /usr/bin/ip link set pause0 down; /usr/bin/ethtool -A pause0 autoneg off rx on tx off").await?;
        ensure!(prepared.status.success(), "independent pause preparation failed: {:?}", prepared);
        let binding = guest.binding("observe_nic_pause", json!({})).await?;
        binding.reject(json!({"interface":"management0"})).await?;
        binding.reject(json!({"interface":"pause0", "rx":false})).await?;
        let reply = binding.call(json!({"interface":"pause0"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["autoneg"] == false && value["rx"] == true && value["tx"] == false, "actual selected pause state mismatch: {value}");
        let oracle = guest.shell("/usr/bin/ethtool -a pause0").await?;
        ensure!(oracle.status.success(), "independent pause observation failed");
        let text = String::from_utf8_lossy(&oracle.stdout);
        ensure!(text.lines().any(|line| line.split_whitespace().collect::<Vec<_>>() == ["RX:","on"]), "independent RX state missing");
        ensure!(text.lines().any(|line| line.split_whitespace().collect::<Vec<_>>() == ["TX:","off"]), "independent TX state missing");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
