use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_timers_list_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_timers_list", json!({})).await?;
        binding.reject(json!({"flags": ["--now"]})).await?;
        let prep = guest.shell("systemctl start estus-fixture.timer").await?;
        ensure!(prep.status.success(), "timer preparation failed");
        let reply = binding.call(json!({})).await?;
        let timer = catalog::projection(&reply)?["timers"]
            .as_array()
            .context("timers")?
            .iter()
            .find(|t| t["Id"] == "estus-fixture.timer")
            .context("fixture timer absent")?;
        let oracle = guest
            .shell("systemctl show estus-fixture.timer -p Triggers --value")
            .await?;
        ensure!(
            oracle.status.success()
                && timer["Triggers"].as_str() == Some(String::from_utf8(oracle.stdout)?.trim()),
            "timer activation target disagrees"
        );
        ensure!(
            timer.get("NextElapseUSecMonotonic").is_some()
                && timer.get("LastTriggerUSec").is_some(),
            "actual activation times omitted"
        );
        let oracle = guest
            .shell("systemctl show estus-fixture.timer -p NextElapseUSecMonotonic --value")
            .await?;
        ensure!(
            oracle.status.success()
                && timer["NextElapseUSecMonotonic"].as_str()
                    == Some(String::from_utf8(oracle.stdout)?.trim()),
            "timer next activation differs from actual clock property"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
