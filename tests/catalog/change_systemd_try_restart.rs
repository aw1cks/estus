use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_try_restart_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_try_restart", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let before = guest.shell("systemctl show estus-fixture.service -p MainPID --value").await?;
        ensure!(before.status.success(), "PID oracle failed");
        let reply = binding.call(json!({"unit":"estus-fixture.service"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["operation_completed"] == true && value["health"] == "not_checked", "completion/health distinction missing");
        let after = guest.shell("systemctl show estus-fixture.service -p MainPID --value; systemctl is-active --quiet estus-fixture.service").await?;
        ensure!(after.status.success() && before.stdout != after.stdout && after.stdout != b"0\n", "active unit was not actually restarted");
        let inactive = binding.call(json!({"unit":"estus-fixture-idle.service"})).await?;
        ensure!(catalog::projection(&inactive)?["properties"]["ActiveState"] == "inactive", "try-restart started inactive service");
        let oracle = guest.shell("test \"$(systemctl show estus-fixture-idle.service -p MainPID --value)\" = 0").await?;
        ensure!(oracle.status.success(), "try-restart spawned inactive service");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
