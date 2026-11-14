use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn hardware_system_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("hardware_system_get", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("cat /sys/class/dmi/id/sys_vendor").await?;
        ensure!(observed.status.success(), "firmware oracle failed");
        ensure!(
            value["values"]["system_vendor"]
                .as_str()
                .map(str::to_lowercase)
                == Some(String::from_utf8(observed.stdout)?.trim().to_lowercase()),
            "firmware value differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
