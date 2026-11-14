use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_reload_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_reload", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let before = guest.shell("systemctl show estus-fixture.service -p MainPID --value; rm -f /var/lib/estus-catalog/reload-marker").await?;
        ensure!(before.status.success(), "reload preparation failed");
        let reply = binding.call(json!({"unit":"estus-fixture.service"})).await?;
        ensure!(catalog::projection(&reply)?["health"] == "not_checked", "reload claimed application health");
        let after = guest.shell("test -f /var/lib/estus-catalog/reload-marker && systemctl show estus-fixture.service -p MainPID --value").await?;
        ensure!(after.status.success() && before.stdout == after.stdout, "reload did not invoke ExecReload or replaced MainPID: before={} after={} stderr={}", String::from_utf8_lossy(&before.stdout), String::from_utf8_lossy(&after.stdout), String::from_utf8_lossy(&after.stderr));
        let failed = binding.call(json!({"unit":"estus-fixture-idle.service"})).await?;
        ensure!(catalog::projection(&failed).is_err(), "reload-only unexpectedly succeeded on inactive service");
        let oracle = guest.shell("test \"$(systemctl show estus-fixture-idle.service -p ActiveState --value)\" = inactive && test \"$(systemctl show estus-fixture-idle.service -p MainPID --value)\" = 0").await?;
        ensure!(oracle.status.success(), "reload-only started inactive service");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
