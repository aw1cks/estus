use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn sysctl_set_runtime_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_sysctl_runtime", json!({})).await?;
        binding.reject(json!({"key":"kernel.sysrq","value":1})).await?;
        binding.reject(json!({"key":"kernel.printk_ratelimit","value":"7;id"})).await?;
        binding.reject(json!({"key":"kernel.printk_ratelimit","value":61})).await?;
        binding.reject(json!({"key":"kernel.printk_ratelimit","value":7,"reload_all":true})).await?;
        let prep = guest.shell("mkdir -p /etc/sysctl.d; printf 'kernel.printk_ratelimit_burst = 123\n' > /etc/sysctl.d/99-estus-unrelated.conf; /usr/bin/sysctl -w kernel.printk_ratelimit_burst=17").await?;
        ensure!(prep.status.success(), "sysctl fixture failed");
        let before = guest.shell("cat /proc/sys/kernel/printk_ratelimit").await?;
        ensure!(before.status.success(), "sysctl oracle failed");
        let old: u64 = String::from_utf8(before.stdout)?.trim().parse()?;
        let desired = if old == 7 { 6 } else { 7 };
        let reply = binding.call(json!({"key":"kernel.printk_ratelimit","value":desired})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["before"] == old && value["value"] == desired && value["verified"] == true, "sysctl readback receipt wrong");
        ensure!(value["atomic_compare_exchange"] == false && value["rollback_guaranteed"] == false, "false atomicity guarantee");
        let after = guest.shell("cat /proc/sys/kernel/printk_ratelimit; cat /proc/sys/kernel/printk_ratelimit_burst").await?;
        ensure!(after.status.success(), "sysctl independent readback failed");
        let observed = String::from_utf8(after.stdout)?;
        let mut lines = observed.lines();
        ensure!(lines.next().context("sysctl value")?.parse::<u64>()? == desired, "actual runtime setting unchanged");
        ensure!(lines.next() == Some("17"), "unrelated config was reloaded");

        let absent = guest.shell("test ! -e /etc/sysctl.d/90-estus-catalog-kernel_printk__ratelimit.conf").await?;
        ensure!(absent.status.success() && value["persistent"] == false, "runtime setting persisted unexpectedly");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
