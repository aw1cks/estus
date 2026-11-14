use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn storage_mounts_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("storage_mounts_list", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("findmnt -n -o FSTYPE /").await?;
        ensure!(observed.status.success(), "mount oracle failed");
        let root = value["mounts"]
            .as_array()
            .and_then(|a| a.iter().find(|m| m["mount"] == "/"))
            .ok_or_else(|| anyhow::anyhow!("missing root mount"))?;
        ensure!(
            root["fstype"] == String::from_utf8(observed.stdout)?.trim(),
            "root mount differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
