use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_reset_failed_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_reset_failed", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let prep = guest.shell("systemctl start estus-fixture-fail.service >/dev/null 2>&1; systemctl is-failed --quiet estus-fixture-fail.service").await?;
        ensure!(prep.status.success(), "failed-state preparation failed");
        let reply = binding.call(json!({"unit":"estus-fixture-fail.service"})).await?;
        ensure!(catalog::projection(&reply)?["operation_completed"] == true, "reset-failed did not complete");
        let oracle = guest.shell("test \"$(systemctl show estus-fixture-fail.service -p ActiveState --value)\" = inactive && test \"$(systemctl show estus-fixture-fail.service -p MainPID --value)\" = 0").await?;
        ensure!(oracle.status.success(), "failure state was not cleared independently of service start");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
