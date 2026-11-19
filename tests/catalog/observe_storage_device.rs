use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_storage_device() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_storage_device", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"device":"bad;selector"})).await?;
        let envelope = binding.call(json!({"device":"vda"})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("cat /sys/class/block/vda/size").await?;
        ensure!(observed.status.success(), "block oracle failed");
        let disk = &value["device"];
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
