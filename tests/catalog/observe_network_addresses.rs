use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_network_addresses() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest
            .binding("observe_network_addresses", json!({}))
            .await?;
        binding.reject(json!({"family": "--flush"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j address show dev lo"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding
            .call(json!({"interface": "lo", "family": "inet", "scope": "host"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["scope"] == "approved_interfaces" && value["truncated"] == false,
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
                .context("addresses")?
                .iter()
                .any(|r| r["address"] == "127.0.0.1" && r["prefix_length"] == 8),
            "loopback address missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
