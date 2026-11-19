use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn inspect_network_path_probe() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest
            .binding("inspect_network_path_probe", json!({}))
            .await?;
        binding
            .reject(json!({"destination": "127.0.0.1", "max_hops": 255, "deadline": 5}))
            .await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest.shell(r#"/usr/bin/ip -j route get 127.0.0.1"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding
            .call(json!({"destination": "127.0.0.1", "max_hops": 2, "deadline": 5}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["reached"] == true && value["hops"][0]["addresses"][0] == "127.0.0.1",
            "real loopback path missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
