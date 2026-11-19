use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_network_links() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_network_links", json!({})).await?;
        binding.reject(json!({"interface": "eth0"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j link show dev lo"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"interface": "lo"})).await?;
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
        let rows = value["entries"].as_array().context("link entries")?;
        ensure!(
            rows.iter()
                .any(|r| r["interface"] == "lo" && r["mtu"] == 65536),
            "real loopback link missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
