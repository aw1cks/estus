use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_pci_driver_binding() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let observed = guest.shell("for p in /sys/bus/pci/devices/*; do if test -L \"$p/driver\"; then basename \"$p\"; basename \"$(readlink -f \"$p/driver\")\"; break; fi; done").await?;
        ensure!(observed.status.success(), "binding oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let mut lines = text.lines();
        let address = lines.next().ok_or_else(|| anyhow::anyhow!("fixture has no bound PCI device"))?;
        let driver = lines.next().ok_or_else(|| anyhow::anyhow!("fixture has no PCI driver"))?;
        let binding = guest.binding("observe_pci_driver_binding", json!({"address":address})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"address":"bad;selector"})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        ensure!(value["binding"]["bound"] == true && value["binding"]["driver"] == driver, "binding state differs");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
