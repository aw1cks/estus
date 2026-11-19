use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn inspect_hardware_identifiers() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest
            .binding("inspect_hardware_identifiers", json!({}))
            .await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        // The real fixture provisions a type1 serial, not a product UUID.
        // Qualify an actual sensitive identity rather than requiring firmware
        // to fabricate a UUID for a machine that does not report one.
        let observed = guest.shell("cat /sys/class/dmi/id/product_serial").await?;
        ensure!(observed.status.success(), "firmware serial oracle failed");
        ensure!(
            value["values"]["product_serial"].as_str()
                == Some(String::from_utf8(observed.stdout)?.trim()),
            "firmware serial differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
