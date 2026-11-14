use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn device_attributes_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("device_attributes_get", json!({})).await?;
        binding
            .reject(json!({"device":"../../devices","attributes":["mtu"]}))
            .await?;
        binding
            .reject(json!({"device":"loopback","attributes":["reset"]}))
            .await?;
        let oracle = guest.shell("cat /sys/class/net/lo/mtu").await?;
        ensure!(oracle.status.success(), "independent sysfs oracle");
        let expected = std::str::from_utf8(&oracle.stdout)?.trim();
        let reply = binding
            .call(json!({"device":"loopback","attributes":["mtu","operstate"]}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["name"] == "lo" && value["class"] == "net",
            "logical alias must resolve to reviewed net device"
        );
        ensure!(
            value["attributes"][0]["value"] == expected
                && value["attributes"][0]["status"] == "available",
            "real approved attribute"
        );
        let after = guest.shell("cat /sys/class/net/lo/mtu").await?;
        ensure!(
            after.status.success() && after.stdout == oracle.stdout,
            "inspection must not change device"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
