use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_pci_aspects() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_pci", json!({})).await?;
        binding.reject(json!({"unexpected": true})).await?;
        binding.reject(json!({"address": "bad;selector"})).await?;
        binding
            .reject(json!({"address": "0000:00:00.0", "aspect": "reset"}))
            .await?;
        let absent = binding
            .call(json!({"address": "0000:ff:1f.7", "aspect": "identity"}))
            .await?;
        ensure!(
            absent["error"]["reason"] == "target_not_found"
                && absent["error"]["remote_state_unknown"] == false,
            "absent PCI device not reported as target_not_found: {absent}"
        );

        let envelope = binding
            .call(json!({"address": "0000:00:00.0", "aspect": "identity"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["pci"]["aspect"] == "identity" && value["pci"]["identity"].is_object(),
            "identity aspect did not publish its block"
        );
        let observed = guest
            .shell("cat /sys/bus/pci/devices/0000:00:00.0/vendor")
            .await?;
        ensure!(observed.status.success(), "PCI oracle failed");
        ensure!(
            value["pci"]["identity"]["vendor"] == String::from_utf8(observed.stdout)?.trim(),
            "vendor differs"
        );
        ensure!(
            value["pci"].get("binding").is_none() && value["pci"].get("iommu").is_none(),
            "identity aspect leaked an unrelated block"
        );

        let envelope = binding
            .call(json!({"address": "0000:00:00.0", "aspect": "driver"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["pci"]["aspect"] == "driver"
                && value["pci"]["binding"]["address"] == "0000:00:00.0",
            "driver aspect did not publish its block"
        );
        ensure!(
            value["pci"]["binding"].get("bound").is_some(),
            "driver aspect omitted the bound flag"
        );

        let envelope = binding
            .call(json!({"address": "0000:00:00.0", "aspect": "iommu"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["pci"]["aspect"] == "iommu"
                && value["pci"]["iommu"]["address"] == "0000:00:00.0"
                && value["pci"]["iommu"]["available"].is_boolean(),
            "iommu aspect did not publish its block"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
