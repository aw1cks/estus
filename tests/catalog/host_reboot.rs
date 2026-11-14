use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn host_reboot() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("host_reboot", json!({})).await?;
        binding.reject(json!({"force":true})).await?;
        let before = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(before.status.success(), "boot ID oracle failed");
        let before = String::from_utf8(before.stdout)?.trim().to_owned();
        let request = binding.call(json!({})).await;
        // Always reconcile independently even if transport loss prevents a receipt.
        let after = guest.wait_for_reboot(&before).await?;
        ensure!(after != before, "actual reboot was not confirmed");
        if let Ok(envelope) = request
            && let Ok(p) = catalog::projection(&envelope)
        {
            ensure!(
                p["boot_id"] == before,
                "receipt did not record previous boot"
            );
            ensure!(
                p["outcome"] == "scheduled" && p["reboot_confirmed"] == false,
                "scheduling receipt falsely confirmed reboot"
            );
        }
        let healthy = guest
            .shell("/usr/bin/systemctl is-active estus-fixture.service")
            .await?;
        ensure!(
            healthy.status.success(),
            "separate post-reboot fixture health check failed"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
