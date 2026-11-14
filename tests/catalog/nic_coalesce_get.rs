use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn nic_coalesce_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("nic_coalesce_get", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"interface":"bad;selector"})).await?;
        let envelope = binding.call(json!({"interface":"eth0"})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("ethtool -c eth0").await?;
        ensure!(
            observed.status.success(),
            "positive driver capability required"
        );
        let text = String::from_utf8(observed.stdout)?;
        let field = text
            .lines()
            .filter_map(|l| l.trim().split_once(':'))
            .rfind(|(k, _)| k.to_lowercase().replace([' ', '-'], "_") == "rx_usecs")
            .map(|(_, v)| v.trim())
            .ok_or_else(|| anyhow::anyhow!("missing independent field"))?;
        ensure!(
            value["supported"] == true && value["values"]["rx_usecs"] == field,
            "driver value differs"
        );
        let absent = binding.call(json!({"interface":"lo"})).await?;
        let absent = catalog::projection(&absent)?;
        ensure!(
            absent["supported"] == false
                || absent["values"].as_object().is_some_and(|v| !v.is_empty()),
            "loopback capability must be explicit"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
