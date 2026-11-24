use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_nic_rss() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_nic_rss", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        binding.reject(json!({"interface":"bad;selector"})).await?;
        let mut indirection = Vec::new();
        let mut offset = 0;
        let value = loop {
            let envelope = binding.call(json!({"interface":"eth0","offset":offset})).await?;
            let value = catalog::projection(&envelope)?.clone();
            indirection.extend(value["indirection"].as_array().context("indirection")?.iter().cloned());
            match value.get("next_offset") {
                Some(next) => offset = next.as_u64().context("next_offset")?,
                None => break value,
            }
        };
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
            !expected.is_empty() && json!(indirection) == json!(expected),
            "RSS indirection differs"
        );
        ensure!(
            value["indirection_size"] == json!(expected.len()),
            "RSS indirection size differs"
        );
        ensure!(value.get("hash_key").is_none(), "hash key must not leak");
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
