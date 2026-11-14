use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn pressure_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("pressure_get", json!({})).await?;
        binding.reject(json!({"path":"/proc/meminfo"})).await?;
        let oracle = guest.shell("cat /proc/pressure/memory").await?;
        ensure!(
            oracle.status.success(),
            "guest must enable CONFIG_PSI for qualification"
        );
        let text = std::str::from_utf8(&oracle.stdout)?;
        let before: u64 = text
            .lines()
            .find(|line| line.starts_with("some "))
            .context("PSI some line")?
            .split_whitespace()
            .find_map(|part| part.strip_prefix("total="))
            .context("PSI total")?
            .parse()?;
        let reply = binding.call(json!({})).await?;
        let value = catalog::projection(&reply)?;
        let memory = value["pressure"]
            .as_array()
            .context("pressure array")?
            .iter()
            .find(|entry| entry["resource"] == "memory")
            .context("memory PSI")?;
        ensure!(
            memory["status"] == "available",
            "real PSI must be available"
        );
        ensure!(
            memory["some"]["total_microseconds"]
                .as_u64()
                .context("cumulative microseconds")?
                >= before,
            "cumulative PSI cannot precede independent earlier read"
        );
        for field in ["avg10_percent", "avg60_percent", "avg300_percent"] {
            let average = memory["some"][field].as_f64().context("PSI average")?;
            ensure!(
                (0.0..=100.0).contains(&average),
                "actual percent units required"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
