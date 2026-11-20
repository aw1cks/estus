use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_nic_aspects() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_nic", json!({})).await?;
        binding
            .reject(json!({"interface": "catalog0", "aspect": "fec"}))
            .await?;
        binding.reject(json!({"aspect": "link"})).await?;
        binding
            .reject(json!({"interface": "eth-none", "aspect": "link"}))
            .await?;

        for aspect in ["link", "rings", "channels", "coalesce"] {
            let envelope = binding
                .call(json!({"interface": "catalog0", "aspect": aspect}))
                .await?;
            let value = catalog::projection(&envelope)?;
            ensure!(
                value["interface"] == "catalog0" && value["aspect"] == aspect,
                "aspect {aspect} reported the wrong identity"
            );
            let block = &value[aspect];
            ensure!(
                block["supported"].is_boolean() && block.get("values").is_some(),
                "aspect {aspect} did not publish supported/values"
            );
            for other in ["channels", "coalesce", "link", "rings"] {
                ensure!(
                    other == aspect || value.get(other).is_none(),
                    "aspect {aspect} leaked the {other} block"
                );
            }
        }

        // Link speed is driver text, so it stays a string when reported.
        let envelope = binding
            .call(json!({"interface": "catalog0", "aspect": "link"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        if let Some(speed) = value["link"]["values"].get("speed") {
            ensure!(
                speed.is_string(),
                "link speed must stay driver-reported text"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
