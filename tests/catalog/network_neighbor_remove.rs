use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_neighbor_remove() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up; /usr/bin/ip neighbor replace 192.0.2.2 lladdr 02:00:00:00:00:02 nud permanent dev catalog0"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("network_neighbor_remove", json!({})).await?;
        binding.reject(json!({"interface": "catalog0", "destination": "10.0.2.2"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let mutation: Result<()> = async {
            let oracle = guest.shell(r#"/usr/bin/ip -j neighbor show dev catalog0"#).await?;
            ensure!(oracle.status.success(), "independent network oracle failed");
            let reply = binding.call(json!({"interface": "catalog0", "destination": "192.0.2.2"})).await?;
            let value = catalog::projection(&reply)?;
            ensure!(value["verified"] == true && value["persistence"] == "runtime_only", "mutation receipt missing");
            let after = guest.shell(r#"/usr/bin/ip -j neighbor show dev catalog0"#).await?;
            ensure!(after.status.success(), "independent postcondition oracle failed");
            let rows: serde_json::Value = serde_json::from_slice(&after.stdout)?;
            ensure!(!rows.as_array().context("neighbors")?.iter().any(|r| r["dst"] == "192.0.2.2"), "neighbor was not removed");
            Ok(())
        }.await;
        let recovery = guest.shell(r#"/usr/bin/ip neighbor replace 192.0.2.2 lladdr 02:00:00:00:00:02 nud permanent dev catalog0"#).await?;
        ensure!(recovery.status.success(), "independent root-control recovery failed: {:?}", recovery);
        mutation?;
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
