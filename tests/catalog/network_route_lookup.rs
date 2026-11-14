use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_route_lookup() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("network_route_lookup", json!({})).await?;
        binding.reject(json!({"destination": "8.8.8.8"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest
            .shell(r#"/usr/bin/ip -j route get 127.0.0.1 from 127.0.0.1"#)
            .await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding
            .call(json!({"destination": "127.0.0.1", "source": "127.0.0.1"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["scope"] == "current_network_namespace" && value["truncated"] == false,
            "list scope or completeness metadata missing"
        );
        ensure!(
            value["entries"][0]["interface"] == "lo",
            "local route selection missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
