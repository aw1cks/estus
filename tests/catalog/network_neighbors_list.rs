use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_neighbors_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up; /usr/bin/ip neighbor replace 192.0.2.2 lladdr 02:00:00:00:00:02 nud permanent dev catalog0"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("network_neighbors_list", json!({})).await?;
        binding.reject(json!({"interface": "--flush"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j neighbor show dev catalog0"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"interface": "catalog0", "family": "inet"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["scope"] == "approved_interfaces" && value["truncated"] == false, "list scope or completeness metadata missing");
        ensure!(value["entries"].as_array().context("neighbors")?.iter().any(|r| r["destination"] == "192.0.2.2" && r["address"] == "02:00:00:00:00:02"), "real neighbor missing");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
