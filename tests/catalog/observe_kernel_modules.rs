use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_kernel_modules() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_kernel_modules", json!({})).await?;
        binding.reject(json!({"path":"/proc/modules"})).await?;
        binding.reject(json!({"offset":513})).await?;
        let mut offset = 0_u64;
        let mut rows = Vec::new();
        loop {
            let envelope = binding.call(json!({"offset":offset})).await?;
            let page = catalog::projection(&envelope)?;
            rows.extend(
                page["modules"]
                    .as_array()
                    .context("missing module page")?
                    .iter()
                    .cloned(),
            );
            let Some(next) = page.get("next_offset") else {
                break;
            };
            let next = next.as_u64().context("non-integer next page")?;
            ensure!(next > offset && next <= 512, "invalid paging progress");
            offset = next;
        }
        let oracle = guest.shell("cat /proc/modules").await?;
        ensure!(oracle.status.success(), "module oracle failed");
        let output = String::from_utf8(oracle.stdout)?;
        let dummy = output
            .lines()
            .find(|line| line.starts_with("dummy "))
            .context("dummy not loaded")?;
        let fields: Vec<_> = dummy.split_whitespace().collect();
        let observed = rows
            .iter()
            .find(|m| m["name"] == "dummy")
            .context("missing actual dummy")?;
        ensure!(
            observed["size_bytes"].as_u64() == Some(fields[1].parse()?),
            "module size mismatch"
        );
        ensure!(observed["state"] == fields[4], "module state mismatch");
        ensure!(observed["holders"].is_array(), "holders missing");
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
