use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn kernel_module_load() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("kernel_module_load", json!({})).await?;
        for invalid in [json!({"name":"dummy","parameters":{"numdummies":5}}),json!({"name":"dummy","parameters":{"force":1}}),json!({"name":"/tmp/dummy.ko","parameters":{}})] {
            binding.reject(invalid).await?;
        }
        let remove = guest.shell("set -eu; /usr/bin/ip link delete catalog0; /usr/bin/modprobe --remove dummy; test ! -d /sys/module/dummy").await?;
        ensure!(remove.status.success(), "dummy unload preparation failed");
        let envelope = binding.call(json!({"name":"dummy","parameters":{"numdummies":1}})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["outcome"] == "verified" && p["postcondition_verified"] == true, "load postcondition missing");
        ensure!(p["loaded_before"] == false && p["loaded_after"] == true, "no real load transition");
        ensure!(p["added_modules"].as_array().context("module delta absent")?.iter().any(|v| v == "dummy"), "dummy dependency delta absent");
        let oracle = guest.shell("set -eu; test -d /sys/module/dummy; test -d /sys/class/net/dummy0; test ! -d /sys/class/net/dummy1").await?;
        ensure!(oracle.status.success(), "real loaded module/typed parameter effect absent");
        ensure!(envelope["data"]["changed"] == true, "actual insertion reported no change");
        let repeated = binding.call(json!({"name":"dummy","parameters":{}})).await?;
        let p = catalog::projection(&repeated)?;
        ensure!(p["outcome"] == "verified" && p["loaded_before"] == true && p["loaded_after"] == true, "already-loaded observation incorrect");
        ensure!(repeated["data"]["changed"] == false, "already-loaded no-effect request falsely reported a change");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
