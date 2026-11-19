use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_manager_reload_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_manager_reload", json!({})).await?;
        binding.reject(json!({"flags": ["--now"]})).await?;
        let prep = guest.shell(r#"set -eu
printf '[Unit]\nDescription=before-manager-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service
systemctl daemon-reload
systemctl start estus-fixture-manager.service
test "$(systemctl show estus-fixture-manager.service -p Description --value)" = before-manager-reload
printf '[Unit]\nDescription=after-manager-reload\n[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture-manager.service"#).await?;
        ensure!(prep.status.success(), "manager reload preparation failed");
        let before = guest.shell("systemctl show estus-fixture-manager.service -p MainPID --value").await?;
        ensure!(before.status.success() && before.stdout != b"0\n", "manager oracle unit is not running");
        let reply = binding.call(json!({})).await?;
        ensure!(catalog::projection(&reply)?["operation_completed"] == true, "manager reload did not complete");
        let oracle = guest.shell("test \"$(systemctl show estus-fixture-manager.service -p Description --value)\" = after-manager-reload && systemctl is-active --quiet estus-fixture-manager.service && systemctl show estus-fixture-manager.service -p MainPID --value").await?;
        ensure!(oracle.status.success() && oracle.stdout == before.stdout, "manager did not reread the retained unit definition or changed its running process");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
