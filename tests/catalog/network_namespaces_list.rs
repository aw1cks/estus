use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_namespaces_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip netns add catalogns"#).await?;
        ensure!(
            prepared.status.success(),
            "independent fixture preparation failed: {:?}",
            prepared
        );
        let binding = guest.binding("network_namespaces_list", json!({})).await?;
        binding.reject(json!({"namespace": "catalogns"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j netns list"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["scope"] == "approved_named_namespaces" && value["truncated"] == false,
            "list scope or completeness metadata missing"
        );
        ensure!(
            value["entries"]
                .as_array()
                .context("namespaces")?
                .iter()
                .any(|r| r["name"] == "catalogns"),
            "approved real namespace missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
