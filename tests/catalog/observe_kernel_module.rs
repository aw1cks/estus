use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_kernel_module() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_kernel_module", json!({})).await?;
        binding.reject(json!({"name":"/tmp/evil.ko"})).await?;
        let envelope = binding.call(json!({"name":"dummy"})).await?;
        let p = catalog::projection(&envelope)?;
        let oracle = guest.shell("/usr/bin/modinfo -F filename dummy").await?;
        ensure!(oracle.status.success(), "modinfo oracle failed");
        ensure!(
            p["metadata"]["filename"][0] == String::from_utf8(oracle.stdout)?.trim(),
            "installed module path mismatch"
        );
        ensure!(
            p["loaded"] == true && p["signer_is_trust_proof"] == false,
            "loaded/trust semantics wrong"
        );
        ensure!(
            p["metadata"]["parm"]
                .as_array()
                .context("declared parameters absent")?
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s.starts_with("numdummies:"))),
            "declared dummy parameter missing"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
