use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn journal_read_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("journal_read", json!({})).await?;
        let inputs = json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4});
        binding.reject(json!({"unit":"ssh.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4})).await?;
        binding.reject(json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"follow":true})).await?;
        let sync = guest.shell("/usr/bin/journalctl --sync").await?;
        ensure!(sync.status.success(), "journal sync failed");
        let oracle = guest.shell("/usr/bin/journalctl -b --no-pager -o json _SYSTEMD_UNIT=estus-fixture.service").await?;
        ensure!(oracle.status.success(), "independent journal read failed");
        let reference: Vec<Value> = String::from_utf8(oracle.stdout)?.lines().map(serde_json::from_str).collect::<std::result::Result<_,_>>()?;
        let marker = reference.iter().find(|r| r["MESSAGE"].as_str().is_some_and(|v| v.contains("ESTUS_CATALOG_JOURNAL_MARKER"))).context("fixture marker missing from unit journal")?;
        let envelope = binding.call(inputs.clone()).await.context("journal_read selected-record call")?;
        let value = catalog::projection(&envelope).context("journal_read selected-record projection")?;
        let records = value["records"].as_array().context("records")?;
        ensure!(records.iter().any(|r| r["cursor"] == marker["__CURSOR"] && r["message"] == marker["MESSAGE"] && r["boot_id"] == marker["_BOOT_ID"]), "selected real marker missing");
        ensure!(records.iter().all(|r| r["unit"] == "estus-fixture.service"), "unit filter escaped");
        ensure!(value["incomplete"] == true, "retention incompleteness hidden");
        let mut continuation = inputs;
        continuation["cursor"] = value["continuation_cursor"].clone();
        let next = binding.call(continuation).await.context("journal_read continuation call")?;
        let next = catalog::projection(&next).context("journal_read continuation projection")?;
        ensure!(next["records"].as_array().context("continuation records")?.iter().all(|r| r["cursor"] != value["continuation_cursor"]), "cursor replayed");
        let missing_cursor = "s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=1;t=1;x=1";
        let expired = binding.call(json!({"unit":"estus-fixture.service","boot_id":"current","since":0,"until":4102444800_u64,"priority":7,"limit":4,"cursor":missing_cursor})).await.context("journal_read expired-cursor call")?;
        let expired = catalog::projection(&expired).context("journal_read expired-cursor projection")?;
        ensure!(expired["status"] == "cursor_unavailable" && expired["records"].as_array().context("expired records")?.is_empty() && expired["incomplete"] == true, "missing cursor silently treated as retained history");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
