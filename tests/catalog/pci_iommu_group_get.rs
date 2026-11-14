use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn pci_iommu_group_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let observed = guest.shell("for p in /sys/bus/pci/devices/*; do if test -L \"$p/iommu_group\"; then basename \"$p\"; basename \"$(readlink -f \"$p/iommu_group\")\"; ls \"$p/iommu_group/devices\"; break; fi; done").await?;
        ensure!(observed.status.success(), "IOMMU oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let mut lines = text.lines();
        let address = lines.next().ok_or_else(|| anyhow::anyhow!("fixture requires an actual IOMMU group"))?;
        let group: u64 = lines.next().ok_or_else(|| anyhow::anyhow!("missing group number"))?.parse()?;
        let members: Vec<&str> = lines.collect();
        let binding = guest.binding("pci_iommu_group_get", json!({"address":address})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"address":"bad;selector"})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        ensure!(value["iommu"]["available"] == true && value["iommu"]["group"] == group, "IOMMU group differs");
        ensure!(value["iommu"]["members"] == json!(members), "IOMMU members differ");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
