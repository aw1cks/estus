use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn journal_boots_list_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_journal_boots", json!({})).await?;
        binding.reject(json!({"limit":33})).await?;
        binding.reject(json!({"limit":1,"vacuum":true})).await?;
        let observed = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(observed.status.success(), "boot oracle failed");
        let boot = String::from_utf8(observed.stdout)?.trim().replace('-', "");
        let reply = binding.call(json!({"limit":8})).await?;
        let value = catalog::projection(&reply)?;
        let boots = value["boots"].as_array().context("boots")?;
        ensure!(
            boots
                .iter()
                .any(|b| b["boot_id"] == boot && b["index"] == 0),
            "current retained boot missing"
        );
        let independent = guest
            .shell("/usr/bin/journalctl --list-boots --no-pager --quiet")
            .await?;
        ensure!(independent.status.success(), "boots oracle failed");
        let lines = String::from_utf8(independent.stdout)?;
        for item in boots {
            ensure!(
                lines.contains(item["boot_id"].as_str().context("boot id")?),
                "invented retained boot"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
