use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn change_nic_channels() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"set -e; /usr/bin/ip link add queue0 address 52:54:00:12:34:59 numrxqueues 4 numtxqueues 4 type veth peer name queuepeer0 numrxqueues 4 numtxqueues 4; /usr/bin/ethtool -L queue0 rx 4 tx 4"#).await?;
        ensure!(prepared.status.success(), "independent capability/baseline preparation failed: {:?}", prepared);
        let before = guest.shell(r#"set -e; /usr/bin/ethtool -l queue0"#).await?;
        ensure!(before.status.success(), "independent baseline query failed: {:?}", before);
        let binding = guest.binding("change_nic_channels", json!({})).await?;
        binding.reject(json!({"interface": "queue0", "rx": 5})).await?;
        binding.reject(json!({"interface": "queue0", "rx": 2, "operator_policy": {"allow_runtime_tuning": true}})).await?;
        binding.reject(json!({"interface": "management0", "rx": 2})).await?;
        let reply = binding.call(json!({"interface": "queue0", "rx": 2})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["verified"] == true && reply["data"]["changed"] == true, "setter must perform a meaningful verified mutation: {reply}");
        ensure!(value["before"] != value["after"], "setter only reported a no-op");
        let after = guest.shell(r#"set -e; /usr/bin/ethtool -l queue0"#).await?;
        ensure!(after.status.success(), "independent postcondition query failed");
        ensure!(String::from_utf8_lossy(&after.stdout).split("Current hardware settings:").nth(1).is_some_and(|section| section.lines().any(|line| line.split_whitespace().collect::<Vec<_>>() == ["RX:", "2"])), "independent postcondition mismatch: {:?}", after);
        ensure!(before.stdout != after.stdout, "independent driver setting did not change");
        let noop = binding.call(json!({"interface": "queue0", "rx": 2})).await?;
        ensure!(catalog::projection(&noop)?["changed"] == false && noop["data"]["changed"] == false, "already-current request must be unchanged: {noop}");
        ensure!(value["before"]["rx"] == 4 && value["after"]["rx"] == 2 && value["after"]["tx"] == 4, "RX-only change must preserve actual TX channels");
        let queues = guest.shell("find /sys/class/net/queue0/queues -maxdepth 1 -name 'rx-*' | wc -l").await?;
        ensure!(queues.status.success() && String::from_utf8_lossy(&queues.stdout).trim() == "2", "kernel active RX queues did not change");
        let alive = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(alive.status.success() && alive.stdout == b"1000\nup\n",
            "ordinary management path lost after channel tuning: {alive:?}");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
