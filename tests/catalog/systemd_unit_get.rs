use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_get_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_get", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let before = guest.shell("systemctl show estus-fixture.service -p MainPID --value").await?;
        let before_pid = String::from_utf8(before.stdout)?;
        let reply = binding.call(json!({"unit":"estus-fixture.service"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["properties"]["ActiveState"] == "active", "active unit status missing");
        ensure!(value["properties"]["MainPID"].as_str() == Some(before_pid.trim()), "getter PID differs from independent oracle");
        ensure!(value["properties"].get("Environment").is_none(), "secret environment leaked");
        let inactive = binding.call(json!({"unit":"estus-fixture-idle.service"})).await?;
        ensure!(catalog::projection(&inactive)?["properties"]["ActiveState"] == "inactive", "inactive observation was treated as failure or started service");
        let prep = guest.shell("systemctl start estus-fixture-fail.service >/dev/null 2>&1; systemctl is-failed --quiet estus-fixture-fail.service").await?;
        ensure!(prep.status.success(), "failed-unit preparation failed");
        let failed = binding.call(json!({"unit":"estus-fixture-fail.service"})).await?;
        ensure!(catalog::projection(&failed)?["properties"]["ActiveState"] == "failed", "failed state is not observation data");
        let after = guest.shell("systemctl show estus-fixture.service -p MainPID --value; systemctl is-active estus-fixture-idle.service").await?;
        let after_text = String::from_utf8(after.stdout)?;
        ensure!(after_text.lines().next() == Some(before_pid.trim()) && after_text.ends_with("inactive\n"), "query changed active or inactive state");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
