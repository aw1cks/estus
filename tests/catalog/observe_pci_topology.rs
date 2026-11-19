use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_pci_topology() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_pci_topology", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest
            .shell("readlink -f /sys/bus/pci/devices/0000:00:00.0")
            .await?;
        ensure!(observed.status.success(), "topology oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let chain: Vec<&str> = text
            .trim()
            .split('/')
            .filter(|p| p.len() == 12 && p.contains(':'))
            .collect();
        let node = value["nodes"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["address"] == "0000:00:00.0"))
            .ok_or_else(|| anyhow::anyhow!("missing topology node"))?;
        ensure!(
            node["ancestors"] == json!(&chain[..chain.len() - 1]),
            "ancestry differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
