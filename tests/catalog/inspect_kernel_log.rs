use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn kernel_log_read_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("inspect_kernel_log", json!({})).await?;
        binding.reject(json!({"boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"unit":"ssh.service"})).await?;
        binding.reject(json!({"boot_id":"current","since":0,"until":4102444800_u64,"priority":8,"limit":4})).await?;
        let observed = guest.shell("/usr/bin/journalctl -b --no-pager -o json -n 8 _TRANSPORT=kernel").await?;
        ensure!(observed.status.success(), "kernel oracle failed");
        let reference: Vec<Value> = String::from_utf8(observed.stdout)?.lines().map(serde_json::from_str).collect::<std::result::Result<_,_>>()?;
        ensure!(!reference.is_empty(), "fixture kernel journal missing");
        let reply = binding.call(json!({"boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4})).await?;
        let value = catalog::projection(&reply)?;
        let records = value["records"].as_array().context("kernel records")?;
        ensure!(!records.is_empty(), "kernel records omitted");
        for r in records {
            ensure!(r["transport"] == "kernel", "non-kernel journal leaked");
            ensure!(reference.iter().any(|v| v["__CURSOR"] == r["cursor"] && v["_BOOT_ID"] == r["boot_id"]), "kernel record not independently retained");
        }
        let cursor = value["continuation_cursor"].as_str().context("kernel continuation cursor")?;
        let continuation = binding.call(json!({"boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"cursor":cursor})).await.context("kernel cursor continuation call")?;
        let continued = catalog::projection(&continuation).context("kernel cursor continuation projection")?;
        ensure!(continued["records"].as_array().context("kernel continued records")?.iter().all(|r| r["transport"] == "kernel" && r["cursor"] != cursor), "kernel continuation escaped scope or replayed cursor");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
