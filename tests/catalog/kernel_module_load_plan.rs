use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn kernel_module_load_plan() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("kernel_module_load_plan", json!({})).await?;
        binding.reject(json!({"name":"dummy","flags":"--force"})).await?;
        let remove = guest.shell("set -eu; /usr/bin/ip link delete catalog0; /usr/bin/modprobe --remove dummy; test ! -d /sys/module/dummy").await?;
        ensure!(remove.status.success(), "dummy unload preparation failed");
        let envelope = binding.call(json!({"name":"dummy"})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["permission_granted"] == false && p["loaded"] == false, "preview grants authority or inserts module");
        let path = guest.shell("/usr/bin/modinfo -F filename dummy").await?;
        ensure!(path.status.success(), "installed module oracle failed");
        let path = String::from_utf8(path.stdout)?.trim().to_owned();
        ensure!(p["plan"].as_array().context("missing plan")?.iter().any(|v| v.as_str().is_some_and(|s| s.contains(&path))), "plan lacks installed dummy insertion");
        let still_absent = guest.shell("test ! -d /sys/module/dummy").await?;
        ensure!(still_absent.status.success(), "dry run inserted module");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
