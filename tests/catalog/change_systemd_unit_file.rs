use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

const PENDING_RELOAD: &str = r#"set -eu
printf '[Unit]\nDescription=unit-file-before-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service
systemctl daemon-reload
systemctl start estus-fixture-manager.service
test "$(systemctl show estus-fixture-manager.service -p Description --value)" = unit-file-before-reload
printf '[Unit]\nDescription=unit-file-after-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_file_operations_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_unit_file", json!({})).await?;
        binding
            .reject(json!({"unit": "estus-fixture.service", "operation": "enable", "flags": ["--now"]}))
            .await?;
        binding
            .reject(json!({"unit": "ssh.service", "operation": "enable"}))
            .await?;
        binding
            .reject(json!({"unit": "estus-fixture.service", "operation": "start"}))
            .await?;

        // enable
        let prep = guest
            .shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl stop estus-fixture-idle.service; systemctl disable estus-fixture-idle.service")
            .await?;
        ensure!(prep.status.success(), "enable preparation failed");
        let pending = guest.shell(PENDING_RELOAD).await?;
        ensure!(pending.status.success(), "pending unit definition preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"enable"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "enable"
                && value["operation_completed"] == true
                && value["health"] == "not_checked",
            "effect completion conflated with health or lost its operation"
        );
        ensure!(
            value["manager_reload_performed"] == false
                && value["manager_reload_required"] == true
                && value["properties"]["UnitFileState"] == "enabled",
            "unit-file disk state or deferred activation receipt is incorrect"
        );
        let oracle = guest
            .shell("set -eu; systemctl is-enabled --quiet estus-fixture-idle.service && test \"$(systemctl show estus-fixture-idle.service -p ActiveState --value)\" = inactive")
            .await?;
        ensure!(
            oracle.status.success(),
            "enable effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );
        let unchanged = guest
            .shell("test \"$(systemctl show estus-fixture-manager.service -p Description --value)\" = unit-file-before-reload")
            .await?;
        ensure!(
            unchanged.status.success(),
            "unit-file operation implicitly reloaded unrelated manager configuration"
        );

        // disable
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"disable"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "disable"
                && value["manager_reload_required"] == true
                && value["properties"]["UnitFileState"] == "disabled",
            "disable left the wrong unit-file state"
        );
        let oracle = guest
            .shell("set -eu; test \"$(systemctl is-enabled estus-fixture-idle.service)\" = disabled && systemctl is-active --quiet estus-fixture-idle.service")
            .await?;
        ensure!(
            oracle.status.success(),
            "disable effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );

        // mask
        let prep = guest
            .shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl stop estus-fixture-idle.service; systemctl unmask estus-fixture-idle.service")
            .await?;
        ensure!(prep.status.success(), "mask preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"mask"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "mask" && value["properties"]["UnitFileState"] == "masked",
            "mask readback is not masked"
        );
        let oracle = guest
            .shell("set -eu; test \"$(readlink /etc/systemd/system/estus-fixture-idle.service)\" = /dev/null && test \"$(systemctl is-enabled estus-fixture-idle.service)\" = masked")
            .await?;
        ensure!(
            oracle.status.success(),
            "mask effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );

        // unmask
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"unmask"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "unmask" && value["properties"]["UnitFileState"] == "disabled",
            "unmask readback is not disabled"
        );
        let oracle = guest
            .shell("set -eu; test ! -e /etc/systemd/system/estus-fixture-idle.service && test \"$(systemctl is-enabled estus-fixture-idle.service)\" = disabled && test \"$(systemctl show estus-fixture-idle.service -p ActiveState --value)\" = inactive")
            .await?;
        ensure!(
            oracle.status.success(),
            "unmask effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );

        // Only the separately approved manager reload applies pending definitions.
        let manager = guest.binding("change_systemd_manager_reload", json!({})).await?;
        let reloaded = manager.call(json!({})).await?;
        ensure!(
            catalog::projection(&reloaded)?["operation_completed"] == true,
            "separately approved manager reload failed"
        );
        let changed = guest
            .shell("test \"$(systemctl show estus-fixture-manager.service -p Description --value)\" = unit-file-after-reload")
            .await?;
        ensure!(
            changed.status.success(),
            "pending unrelated definition was not applied by explicitly approved manager reload"
        );
        let activated = guest
            .shell("systemctl start estus-fixture-idle.service && systemctl is-active --quiet estus-fixture-idle.service")
            .await?;
        ensure!(
            activated.status.success(),
            "explicit manager reload did not activate unmasked unit configuration"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
