use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_config_read_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_config_read", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service"})).await?;
        let prep = guest.shell(r#"set -eu
mkdir -p /run/systemd/system/estus-fixture.service.d
printf '[Service]\nEnvironment=ESTUS_CONFIG_SECRET=separate-sensitive-approval\n' > /run/systemd/system/estus-fixture.service.d/sensitive.conf
systemctl daemon-reload"#).await?;
        ensure!(prep.status.success(), "sensitive drop-in preparation failed");
        let reply = binding.call(json!({"unit":"estus-fixture.service"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["sensitive"] == true, "sensitive read annotation missing");
        let files = value["files"].as_array().context("unit config files")?;
        ensure!(files.iter().any(|f| f["kind"] == "fragment" && f["content"].as_str().is_some_and(|s| s.contains("ExecStart="))), "real fragment content missing");
        let dropin = files.iter().find(|f| f["path"] == "/run/systemd/system/estus-fixture.service.d/sensitive.conf").context("actual drop-in missing")?;
        let oracle = guest.shell("cat /run/systemd/system/estus-fixture.service.d/sensitive.conf").await?;
        ensure!(oracle.status.success() && dropin["content"].as_str() == Some(String::from_utf8(oracle.stdout)?.as_str()), "drop-in content differs from independent source read");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
