use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_jobs_list_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_systemd_jobs", json!({})).await?;
        binding.reject(json!({"flags": ["--now"]})).await?;
        let prep = guest.shell(r#"set -eu
printf '[Service]\nType=oneshot\nExecStart=/usr/bin/sleep 240\nTimeoutStartSec=300\n' > /run/systemd/system/estus-fixture-block.service
systemctl daemon-reload
systemctl start --no-block estus-fixture-block.service
for i in $(seq 1 30); do
  test "$(systemctl show estus-fixture-block.service -p ActiveState --value)" != activating || exit 0
  sleep 0.1
done
exit 1"#).await?;
        ensure!(prep.status.success(), "pending-job preparation failed");
        let reply = binding.call(json!({})).await?;
        let value = catalog::projection(&reply)?;
        let job = value["jobs"].as_array().context("jobs")?.iter().find(|j| j["unit"] == "estus-fixture-block.service").context("real pending start job absent")?;
        ensure!(job["type"] == "start" && job["state"] == "running", "pending job semantics lost");
        let oracle = guest.shell("systemctl list-jobs --no-pager --no-legend").await?;
        ensure!(oracle.status.success() && String::from_utf8(oracle.stdout)?.contains("estus-fixture-block.service"), "job oracle disagrees");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
