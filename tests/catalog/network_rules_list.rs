use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_rules_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("network_rules_list", json!({})).await?;
        binding.reject(json!({"limit": 0})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j -4 rule show"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"family": "inet"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["scope"] == "current_network_namespace" && value["truncated"] == false,
            "list scope or completeness metadata missing"
        );
        let limited = binding.call(json!({"limit":1})).await?;
        let limited = catalog::projection(&limited)?;
        ensure!(
            limited["entries"]
                .as_array()
                .context("bounded entries")?
                .len()
                == 1
                && limited["truncated"] == true,
            "omitted records must report truncation"
        );
        ensure!(
            value["entries"]
                .as_array()
                .context("rules")?
                .iter()
                .any(|r| r["priority"] == 0 && r["table"] == "local"),
            "kernel local routing rule missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
