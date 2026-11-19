use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_hardware_memory() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_hardware_memory", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("dmidecode --type 17").await?;
        ensure!(observed.status.success(), "firmware oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let records = value["records"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("firmware records missing"))?;
        ensure!(!records.is_empty(), "positive SMBIOS type17 required");
        for record in records {
            let handle = record["handle"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("handle missing"))?;
            ensure!(
                text.to_lowercase()
                    .contains(&format!("handle {handle}, dmi type 17")),
                "firmware handle differs"
            );
            let key = "locator";
            let field = record[key]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("useful firmware field missing"))?;
            ensure!(text.contains(field), "firmware location differs");
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
