use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn journal_read_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("inspect_journal", json!({})).await?;
        let inputs = json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4});
        binding.reject(json!({"unit":"ssh.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4})).await?;
        binding.reject(json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"follow":true})).await?;
        let sync = guest.shell("/usr/bin/journalctl --sync").await?;
        ensure!(sync.status.success(), "journal sync failed");
        let oracle = guest.shell("/usr/bin/journalctl -b --no-pager -o json _SYSTEMD_UNIT=estus-fixture.service").await?;
        ensure!(oracle.status.success(), "independent journal read failed");
        let reference: Vec<Value> = String::from_utf8(oracle.stdout)?.lines().map(serde_json::from_str).collect::<std::result::Result<_,_>>()?;
        let marker = reference.iter().find(|r| r["MESSAGE"].as_str().is_some_and(|v| v.contains("ESTUS_CATALOG_JOURNAL_MARKER"))).context("fixture marker missing from unit journal")?;
        let envelope = binding.call(inputs.clone()).await.context("inspect_journal selected-record call")?;
        let value = catalog::projection(&envelope).context("inspect_journal selected-record projection")?;
        let records = value["records"].as_array().context("records")?;
        ensure!(records.iter().any(|r| r["cursor"] == marker["__CURSOR"] && r["message"] == marker["MESSAGE"] && r["boot_id"] == marker["_BOOT_ID"]), "selected real marker missing");
        ensure!(records.iter().all(|r| r["unit"] == "estus-fixture.service"), "unit filter escaped");
        ensure!(value["incomplete"] == true, "retention incompleteness hidden");
        let dashed = guest.shell("cat /proc/sys/kernel/random/boot_id").await?;
        ensure!(dashed.status.success(), "boot_id oracle failed");
        let dashed = String::from_utf8(dashed.stdout)?.trim().to_owned();
        let mut by_dashed = inputs.clone();
        by_dashed["boot_id"] = json!(dashed);
        let by_dashed = binding.call(by_dashed).await.context("inspect_journal dashed boot_id call")?;
        let by_dashed = catalog::projection(&by_dashed).context("inspect_journal dashed boot_id projection")?;
        ensure!(by_dashed["boot_id"] == value["boot_id"] && by_dashed["boot_id"] == json!(dashed.replace('-', "")), "dashed boot_id not normalized to the journald form");
        let mut continuation = inputs.clone();
        continuation["cursor"] = value["continuation_cursor"].clone();
        continuation["direction"] = json!("backward");
        let next = binding.call(continuation).await.context("inspect_journal continuation call")?;
        let next = catalog::projection(&next).context("inspect_journal continuation projection")?;
        let boundary_cursor = value["records"].as_array().and_then(|r| r.last()).and_then(|r| r["cursor"].as_str()).context("boundary cursor")?;
        ensure!(next["records"].as_array().context("continuation records")?.iter().all(|r| r["cursor"] != boundary_cursor), "cursor replayed");
        let filtered = binding.call(json!({"boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":50,"contains":"ESTUS_CATALOG_JOURNAL_MARKER","direction":"forward"})).await.context("inspect_journal system-wide substring call")?;
        let filtered = catalog::projection(&filtered)?;
        ensure!(filtered["scope"] == "system_journal");
        ensure!(filtered["records"].as_array().context("filtered records")?.iter().any(|r| r["cursor"] == marker["__CURSOR"]));
        let missing_cursor = "s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=1;t=1;x=1";
        let expired = binding.call(json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"cursor":missing_cursor})).await.context("inspect_journal expired-cursor call")?;
        let expired = catalog::projection(&expired).context("inspect_journal expired-cursor projection")?;
        ensure!(expired["status"] == "cursor_unavailable" && expired["records"].as_array().context("expired records")?.is_empty() && expired["incomplete"] == true, "missing cursor silently treated as retained history");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
