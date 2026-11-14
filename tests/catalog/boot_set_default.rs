use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn boot_set_default() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("boot_set_default", json!({})).await?;
        binding.reject(json!({"entry_id":"@current","reboot":true})).await?;
        let before = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(before.status.success(), "boot ID oracle failed");
        let before = String::from_utf8(before.stdout)?.trim().to_owned();
        let envelope = binding.call(json!({"entry_id":"estus-alternate.conf"})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["outcome"] == "verified" && p["postcondition_verified"] == true, "selection readback not verified");
        ensure!(p["reboot_requested"] == false, "selection silently requests reboot");
        let unchanged = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(String::from_utf8(unchanged.stdout)?.trim() == before, "selection rebooted guest");
        let schedule = guest.shell("/usr/bin/systemd-run --unit=estus-test-reboot --on-active=2s --timer-property=AccuracySec=1s /usr/bin/systemctl reboot").await?;
        ensure!(schedule.status.success(), "independent reboot scheduling failed");
        let after = guest.wait_for_reboot(&before).await?;
        ensure!(after != before, "reboot not independently confirmed");
        let selected = guest.shell("/usr/bin/python3 -c \"from pathlib import Path;print(Path('/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f').read_bytes()[4:].decode('utf-16-le').rstrip(chr(0)))\"").await?;
        ensure!(selected.status.success(), "selected entry oracle failed");
        ensure!(String::from_utf8(selected.stdout)?.trim() == "estus-alternate.conf", "actual next-boot entry differs");
        let before = after;
        let schedule = guest.shell("/usr/bin/systemd-run --unit=estus-test-reboot --on-active=2s --timer-property=AccuracySec=1s /usr/bin/systemctl reboot").await?;
        ensure!(schedule.status.success(), "independent reboot scheduling failed");
        let after = guest.wait_for_reboot(&before).await?;
        ensure!(after != before, "reboot not independently confirmed");
        let selected = guest.shell("/usr/bin/python3 -c \"from pathlib import Path;print(Path('/sys/firmware/efi/efivars/LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f').read_bytes()[4:].decode('utf-16-le').rstrip(chr(0)))\"").await?;
        ensure!(selected.status.success() && String::from_utf8(selected.stdout)?.trim() == "estus-alternate.conf", "persistent default did not survive second reboot");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
