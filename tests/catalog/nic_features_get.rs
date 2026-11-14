use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn nic_features_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("nic_features_get", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"interface":"bad;selector"})).await?;
        let envelope = binding.call(json!({"interface":"eth0"})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("ethtool -k eth0").await?;
        ensure!(observed.status.success(), "offload oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let rx = text
            .lines()
            .find_map(|l| l.strip_prefix("rx-checksumming: "))
            .ok_or_else(|| anyhow::anyhow!("missing checksum observation"))?;
        ensure!(
            value["features"]["rx_checksumming"] == rx.trim(),
            "offload state differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
