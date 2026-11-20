use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_runtime_operations_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_unit", json!({})).await?;
        binding
            .reject(json!({"unit": "estus-fixture.service", "operation": "start", "flags": ["--now"]}))
            .await?;
        binding
            .reject(json!({"unit": "ssh.service", "operation": "start"}))
            .await?;
        // An operation outside the merged enum is rejected before any systemctl call.
        binding
            .reject(json!({"unit": "estus-fixture.service", "operation": "isolate"}))
            .await?;

        // start
        let prep = guest
            .shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl stop estus-fixture-idle.service; systemctl disable estus-fixture-idle.service")
            .await?;
        ensure!(prep.status.success(), "start preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"start"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "start"
                && value["operation_completed"] == true
                && value["health"] == "not_checked",
            "start effect completion conflated with health or lost its operation"
        );
        let oracle = guest
            .shell("set -eu; systemctl is-active --quiet estus-fixture-idle.service && test \"$(systemctl is-enabled estus-fixture-idle.service)\" = disabled")
            .await?;
        ensure!(
            oracle.status.success(),
            "start effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );

        // restart
        let before = guest
            .shell("systemctl show estus-fixture.service -p MainPID --value")
            .await?;
        ensure!(before.status.success(), "PID oracle failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture.service","operation":"restart"}))
            .await?;
        ensure!(
            catalog::projection(&reply)?["operation"] == "restart",
            "restart reported the wrong operation"
        );
        let after = guest
            .shell("systemctl show estus-fixture.service -p MainPID --value; systemctl is-active --quiet estus-fixture.service")
            .await?;
        ensure!(
            after.status.success() && before.stdout != after.stdout && after.stdout != b"0\n",
            "restart did not replace the MainPID"
        );

        // try_restart leaves an inactive unit inactive
        let reply = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"try_restart"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "try_restart"
                && value["properties"]["ActiveState"] == "inactive",
            "try-restart started an inactive service"
        );

        // reload invokes ExecReload without replacing the MainPID
        let before = guest
            .shell("systemctl show estus-fixture.service -p MainPID --value; rm -f /var/lib/estus-catalog/reload-marker")
            .await?;
        ensure!(before.status.success(), "reload preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture.service","operation":"reload"}))
            .await?;
        ensure!(
            catalog::projection(&reply)?["health"] == "not_checked",
            "reload claimed application health"
        );
        let after = guest
            .shell("test -f /var/lib/estus-catalog/reload-marker && systemctl show estus-fixture.service -p MainPID --value")
            .await?;
        ensure!(
            after.status.success() && before.stdout == after.stdout,
            "reload did not invoke ExecReload or replaced MainPID"
        );
        let failed = binding
            .call(json!({"unit":"estus-fixture-idle.service","operation":"reload"}))
            .await?;
        ensure!(
            catalog::projection(&failed).is_err(),
            "reload unexpectedly succeeded on an inactive service"
        );

        // reset_failed clears failure state without starting the unit
        let prep = guest
            .shell("systemctl start estus-fixture-fail.service >/dev/null 2>&1; systemctl is-failed --quiet estus-fixture-fail.service")
            .await?;
        ensure!(prep.status.success(), "failed-state preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture-fail.service","operation":"reset_failed"}))
            .await?;
        ensure!(
            catalog::projection(&reply)?["operation"] == "reset_failed",
            "reset-failed did not complete"
        );
        let oracle = guest
            .shell("test \"$(systemctl show estus-fixture-fail.service -p ActiveState --value)\" = inactive")
            .await?;
        ensure!(
            oracle.status.success(),
            "failure state was not cleared independently of service start"
        );

        // stop
        let prep = guest
            .shell("set -eu; systemctl stop estus-fixture.timer estus-fixture.socket; systemctl start estus-fixture.service")
            .await?;
        ensure!(prep.status.success(), "stop preparation failed");
        let reply = binding
            .call(json!({"unit":"estus-fixture.service","operation":"stop"}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["operation"] == "stop"
                && value["operation_completed"] == true
                && value["health"] == "not_checked",
            "stop effect completion conflated with health"
        );
        let oracle = guest
            .shell("set -eu; test \"$(systemctl show estus-fixture.service -p ActiveState --value)\" = inactive")
            .await?;
        ensure!(
            oracle.status.success(),
            "stop effect or separation invariant failed: {}",
            String::from_utf8_lossy(&oracle.stderr)
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
