use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_pci_devices() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_pci_devices", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest
            .shell("cat /sys/bus/pci/devices/0000:00:00.0/vendor")
            .await?;
        ensure!(observed.status.success(), "PCI oracle failed");
        let device = value["devices"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["address"] == "0000:00:00.0"))
            .ok_or_else(|| anyhow::anyhow!("missing host bridge"))?;
        ensure!(
            device["vendor"] == String::from_utf8(observed.stdout)?.trim(),
            "vendor differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
