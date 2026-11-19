use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn inspect_icmp_probe() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("inspect_icmp_probe", json!({})).await?;
        binding
            .reject(json!({"destination": "127.0.0.1", "count": 4, "deadline": 2}))
            .await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest
            .shell(r#"/usr/bin/ping -n -c 1 -w 2 -s 16 127.0.0.1"#)
            .await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding
            .call(json!({"destination": "127.0.0.1", "count": 1, "deadline": 2}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["received"] == 1 && value["transmitted"] == 1 && value["reachable"] == true,
            "real loopback ICMP reply missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
