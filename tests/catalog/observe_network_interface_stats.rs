use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_network_interface_stats() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest
            .shell(r#"/usr/bin/ping -n -c 1 -w 2 127.0.0.1"#)
            .await?;
        ensure!(
            prepared.status.success(),
            "independent fixture preparation failed: {:?}",
            prepared
        );
        let binding = guest
            .binding("observe_network_interface_stats", json!({}))
            .await?;
        binding.reject(json!({"interface": "../../etc"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let oracle = guest
            .shell(r#"cat /sys/class/net/lo/statistics/rx_packets"#)
            .await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"interface": "lo"})).await?;
        let value = catalog::projection(&reply)?;
        let before: u64 = String::from_utf8(oracle.stdout)?.trim().parse()?;
        ensure!(
            value["counters"]["rx_packets"]
                .as_u64()
                .context("rx packets")?
                >= before
                && before > 0,
            "real cumulative loopback traffic missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
