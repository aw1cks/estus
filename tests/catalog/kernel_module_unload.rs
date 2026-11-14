use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn kernel_module_unload() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("kernel_module_unload", json!({})).await?;
        binding.reject(json!({"name":"dummy","force":true})).await?;
        let prepare = guest
            .shell("/usr/bin/ip link delete catalog0; test -d /sys/module/dummy")
            .await?;
        ensure!(prepare.status.success(), "dummy module not loaded");
        let envelope = binding.call(json!({"name":"dummy"})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(
            p["outcome"] == "verified" && p["loaded_before"] == true && p["loaded_after"] == false,
            "no actual unload transition"
        );
        ensure!(
            p["removed_modules"]
                .as_array()
                .context("removed delta absent")?
                .iter()
                .any(|v| v == "dummy"),
            "removed dummy not tracked"
        );
        let oracle = guest
            .shell("test ! -d /sys/module/dummy; ! grep -q '^dummy ' /proc/modules")
            .await?;
        ensure!(oracle.status.success(), "module remains loaded");
        ensure!(
            envelope["data"]["changed"] == true,
            "actual removal reported no change"
        );
        let repeated = binding.call(json!({"name":"dummy"})).await?;
        let p = catalog::projection(&repeated)?;
        ensure!(
            p["outcome"] == "verified" && p["loaded_before"] == false && p["loaded_after"] == false,
            "already-absent observation incorrect"
        );
        ensure!(
            repeated["data"]["changed"] == false,
            "already-absent no-effect request falsely reported a change"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
