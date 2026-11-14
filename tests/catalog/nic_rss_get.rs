use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn nic_rss_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("nic_rss_get", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"interface":"bad;selector"})).await?;
        let envelope = binding.call(json!({"interface":"eth0"})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest.shell("ethtool -x eth0").await?;
        ensure!(
            observed.status.success(),
            "positive RSS capability required"
        );
        let text = String::from_utf8(observed.stdout)?;
        let expected: Vec<u64> = text
            .lines()
            .filter_map(|l| l.trim().split_once(':'))
            .filter(|(k, _)| k.parse::<usize>().is_ok())
            .flat_map(|(_, v)| v.split_whitespace().filter_map(|c| c.parse::<u64>().ok()))
            .collect();
        ensure!(
            !expected.is_empty() && value["indirection"] == json!(expected),
            "RSS indirection differs"
        );
        ensure!(value.get("hash_key").is_none(), "hash key must not leak");
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
