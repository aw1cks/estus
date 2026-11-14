use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_link_up() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 down"#).await?;
        ensure!(
            prepared.status.success(),
            "independent fixture preparation failed: {:?}",
            prepared
        );
        let binding = guest.binding("network_link_up", json!({})).await?;
        binding.reject(json!({"interface": "lo"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let mutation: Result<()> = async {
            let oracle = guest
                .shell(r#"/usr/bin/ip -j link show dev catalog0"#)
                .await?;
            ensure!(oracle.status.success(), "independent network oracle failed");
            let reply = binding.call(json!({"interface": "catalog0"})).await?;
            let value = catalog::projection(&reply)?;
            ensure!(
                value["verified"] == true && value["persistence"] == "runtime_only",
                "mutation receipt missing"
            );
            let after = guest
                .shell(r#"/usr/bin/ip -j link show dev catalog0"#)
                .await?;
            ensure!(
                after.status.success(),
                "independent postcondition oracle failed"
            );
            let rows: serde_json::Value = serde_json::from_slice(&after.stdout)?;
            let up = rows[0]["flags"]
                .as_array()
                .context("flags")?
                .iter()
                .any(|f| f == "UP");
            ensure!(up, "link state did not change");
            Ok(())
        }
        .await;
        let recovery = guest.shell(r#"/usr/bin/ip link set catalog0 down"#).await?;
        ensure!(
            recovery.status.success(),
            "independent root-control recovery failed: {:?}",
            recovery
        );
        mutation?;
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
