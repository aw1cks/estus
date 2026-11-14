use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_dependencies_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_dependencies", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "direction": "forward", "depth": 1, "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service", "direction": "forward", "depth": 1})).await?;
        binding.reject(json!({"unit":"estus-fixture.service","direction":"forward","depth":4})).await?;
        let prep = guest.shell(r#"set -eu
mkdir -p /run/systemd/system/estus-fixture.service.d
printf '[Unit]\nWants=estus-fixture-idle.service\n' > /run/systemd/system/estus-fixture.service.d/relationships.conf
systemctl daemon-reload"#).await?;
        ensure!(prep.status.success(), "relationship preparation failed");
        let forward = binding.call(json!({"unit":"estus-fixture.service","direction":"forward","depth":1})).await?;
        ensure!(catalog::projection(&forward)?["relationships"].as_array().context("relationships")?.iter().any(|e| e["relation"] == "Wants" && e["target"] == "estus-fixture-idle.service"), "actual Wants relationship missing");
        let reverse = binding.call(json!({"unit":"estus-fixture-idle.service","direction":"reverse","depth":1})).await?;
        ensure!(catalog::projection(&reverse)?["relationships"].as_array().context("reverse relationships")?.iter().any(|e| e["relation"] == "WantedBy" && e["target"] == "estus-fixture.service"), "actual reverse relationship missing");
        let oracle = guest.shell("systemctl show estus-fixture.service -p Wants --value").await?;
        ensure!(oracle.status.success() && String::from_utf8(oracle.stdout)?.split_whitespace().any(|u| u == "estus-fixture-idle.service"), "relationship oracle disagrees");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
