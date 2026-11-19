use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_network_routes() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up"#).await?;
        ensure!(
            prepared.status.success(),
            "independent fixture preparation failed: {:?}",
            prepared
        );
        let binding = guest.binding("observe_network_routes", json!({})).await?;
        binding.reject(json!({"limit": 129})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest
            .shell(r#"/usr/bin/ip -j route show table 254 exact 192.0.2.0/24"#)
            .await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding
            .call(json!({"family": "inet", "table": 254, "destination": "192.0.2.0/24"}))
            .await?;
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
                .context("routes")?
                .iter()
                .any(|r| r["destination"] == "192.0.2.0/24" && r["interface"] == "catalog0"),
            "real connected route missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
