use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_nic_stats() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_nic_stats", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"interface":"bad;selector"})).await?;
        let envelope = binding.call(json!({"interface":"eth0"})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("ethtool -S eth0").await?;
        ensure!(observed.status.success(), "statistics oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let counters = value["counters"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("missing counters"))?;
        ensure!(!counters.is_empty(), "positive driver counters required");
        for c in counters {
            let name = c["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("counter name"))?;
            let actual = text
                .lines()
                .find_map(|line| {
                    let (key, value) = line.trim().split_once(':')?;
                    (key == name)
                        .then(|| value.trim().parse::<u64>().ok())
                        .flatten()
                })
                .ok_or_else(|| anyhow::anyhow!("counter not independently observed"))?;
            let projected = c["value"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("counter value missing"))?;
            ensure!(
                projected <= actual,
                "cumulative driver counter exceeds later independent observation"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
