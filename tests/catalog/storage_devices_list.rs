use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn storage_devices_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("storage_devices_list", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("cat /sys/class/block/vda/size").await?;
        ensure!(observed.status.success(), "block oracle failed");
        let disk = value["devices"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["name"] == "vda"))
            .ok_or_else(|| anyhow::anyhow!("missing virtio disk"))?;
        ensure!(
            disk["sectors"] == String::from_utf8(observed.stdout)?.trim(),
            "sector count differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
