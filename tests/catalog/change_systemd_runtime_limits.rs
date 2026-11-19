use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_set_runtime_limits_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_systemd_runtime_limits", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "limits": {"tasks_max": 32}, "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service", "limits": {"tasks_max": 32}})).await?;
        binding.reject(json!({"unit":"estus-fixture.service","limits":{"tasks_max":0}})).await?;
        let prep = guest.shell("test ! -e /etc/systemd/system.control/estus-fixture.service.d").await?;
        ensure!(prep.status.success(), "persistent control baseline is not clean");
        let reply = binding.call(json!({"unit":"estus-fixture.service","limits":{"memory_max_bytes":67108864,"tasks_max":32,"cpu_quota_percent":25}})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["persistent"] == false && value["health"] == "not_checked", "runtime or impact contract lost");
        ensure!(value["properties"]["MemoryMax"] == "67108864" && value["properties"]["TasksMax"] == "32", "actual limits readback missing");
        let oracle = guest.shell("set -eu; test \"$(systemctl show estus-fixture.service -p MemoryMax --value)\" = 67108864; test \"$(systemctl show estus-fixture.service -p TasksMax --value)\" = 32; test \"$(systemctl show estus-fixture.service -p CPUQuotaPerSecUSec --value)\" = 250ms; test ! -e /etc/systemd/system.control/estus-fixture.service.d; test -d /run/systemd/system.control/estus-fixture.service.d; systemctl is-active --quiet estus-fixture.service").await?;
        ensure!(oracle.status.success(), "runtime limits were not effective/nonpersistent");
        let reply = binding
            .call(json!({"unit":"estus-fixture.service","limits":{"tasks_max":8.0}}))
            .await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["requested_limits"]["tasks_max"].as_u64() == Some(8)
                && value["properties"]["TasksMax"] == "8",
            "integral float did not reach the collector as an integer"
        );
        let oracle = guest
            .shell("test \"$(systemctl show estus-fixture.service -p TasksMax --value)\" = 8; systemctl is-active --quiet estus-fixture.service")
            .await?;
        ensure!(oracle.status.success(), "TasksMax=8 was not effective");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
