use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_enable_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_enable", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let prep = guest.shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl stop estus-fixture-idle.service; systemctl disable estus-fixture-idle.service").await?;
        ensure!(prep.status.success(), "enable preparation failed");
        let pending = guest.shell(r#"set -eu
printf '[Unit]\nDescription=unit-file-before-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service
systemctl daemon-reload
systemctl start estus-fixture-manager.service
test "$(systemctl show estus-fixture-manager.service -p Description --value)" = unit-file-before-reload
printf '[Unit]\nDescription=unit-file-after-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service"#).await?;
        ensure!(pending.status.success(), "pending unrelated unit definition preparation failed");
        let reply = binding.call(json!({"unit":"estus-fixture-idle.service"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["operation_completed"] == true && value["health"] == "not_checked", "effect completion conflated with health");
        ensure!(value["manager_reload_performed"] == false && value["manager_reload_required"] == true && value["properties"]["UnitFileState"] == "enabled", "unit-file disk state or deferred activation receipt is incorrect");
        let oracle = guest.shell("set -eu; systemctl is-enabled --quiet estus-fixture-idle.service && test \"$(systemctl show estus-fixture-idle.service -p ActiveState --value)\" = inactive").await?;
        ensure!(oracle.status.success(), "enable effect or separation invariant failed: {}", String::from_utf8_lossy(&oracle.stderr));
        let unchanged = guest.shell("test \"$(systemctl show estus-fixture-manager.service -p Description --value)\" = unit-file-before-reload").await?;
        ensure!(unchanged.status.success(), "unit-file operation implicitly reloaded unrelated manager configuration");
        let manager = guest.binding("systemd_manager_reload", json!({})).await?;
        let reloaded = manager.call(json!({})).await?;
        ensure!(catalog::projection(&reloaded)?["operation_completed"] == true, "separately approved manager reload failed");
        let changed = guest.shell("test \"$(systemctl show estus-fixture-manager.service -p Description --value)\" = unit-file-after-reload").await?;
        ensure!(changed.status.success(), "pending unrelated definition was not applied by explicitly approved manager reload");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
