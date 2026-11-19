use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_kernel_state() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_kernel_state", json!({})).await?;
        binding.reject(json!({"clear_taint":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let p = catalog::projection(&envelope)?;
        let oracle = guest
            .shell("cat /proc/sys/kernel/tainted; uname -r")
            .await?;
        ensure!(oracle.status.success(), "kernel state oracle failed");
        let output = String::from_utf8(oracle.stdout)?;
        let mut lines = output.lines();
        ensure!(
            p["taint"].as_u64() == Some(lines.next().context("missing taint")?.parse()?),
            "taint mismatch"
        );
        ensure!(
            p["kernel_release"] == lines.next().context("missing release")?,
            "release mismatch"
        );
        for field in ["lockdown", "signature_enforce", "modules_disabled"] {
            ensure!(
                p.get(field).is_some()
                    || p["unavailable"]
                        .as_array()
                        .context("missing unavailable")?
                        .iter()
                        .any(|v| v == field),
                "policy observation silently absent"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
