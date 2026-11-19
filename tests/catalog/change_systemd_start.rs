use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_start_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_start", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let prep = guest.shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl stop estus-fixture-idle.service; systemctl disable estus-fixture-idle.service").await?;
        ensure!(prep.status.success(), "start preparation failed");
        let reply = binding.call(json!({"unit":"estus-fixture-idle.service"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["operation_completed"] == true && value["health"] == "not_checked", "effect completion conflated with health");
        let oracle = guest.shell("set -eu; systemctl is-active --quiet estus-fixture-idle.service && test \"$(systemctl is-enabled estus-fixture-idle.service)\" = disabled").await?;
        ensure!(oracle.status.success(), "start effect or separation invariant failed: {}", String::from_utf8_lossy(&oracle.stderr));
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
