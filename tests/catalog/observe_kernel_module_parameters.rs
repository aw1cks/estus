use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_kernel_module_parameters() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest
            .binding("observe_kernel_module_parameters", json!({}))
            .await?;
        binding
            .reject(json!({"name":"dummy","parameter":"../../etc/passwd"}))
            .await?;
        let envelope = binding.call(json!({"name":"estus_catalog"})).await?;
        let p = catalog::projection(&envelope)?;
        let oracle = guest
            .shell("cat /sys/module/estus_catalog/parameters/value")
            .await?;
        ensure!(oracle.status.success(), "parameter oracle failed");
        let parameter = &p["parameters"][0];
        ensure!(
            parameter["parameter"] == "value" && parameter["supported"] == true,
            "approved parameter absent"
        );
        ensure!(
            parameter["value"] == String::from_utf8(oracle.stdout)?.trim(),
            "current parameter mismatch"
        );
        ensure!(
            parameter["writable"] == true,
            "actual compatible parameter not writable"
        );
        let oracle = guest
            .shell("test ! -e /sys/module/dummy/parameters/numdummies")
            .await?;
        ensure!(
            oracle.status.success(),
            "dummy parameter unexpectedly exported by this kernel"
        );
        let absent = binding.call(json!({"name":"dummy"})).await?;
        let absent = catalog::projection(&absent)?;
        ensure!(
            absent["parameters"][0]["supported"] == false
                && absent["parameters"][0].get("value").is_none(),
            "unexported load-only parameter invented a current value"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
