use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn nic_rss_set() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"set -e; /usr/bin/ip link set tune0 down; /usr/bin/ethtool -X tune0 hkey 6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:6a:42:b7:3b:be:ac:01:fa"#).await?;
        ensure!(prepared.status.success(), "independent capability/baseline preparation failed: {:?}", prepared);
        let before = guest.shell(r#"set -e; /usr/bin/ethtool -x tune0"#).await?;
        ensure!(before.status.success(), "independent baseline query failed: {:?}", before);
        let binding = guest.binding("nic_rss_set", json!({})).await?;
        binding.reject(json!({"interface": "tune0", "preset": "arbitrary"})).await?;
        binding.reject(json!({"interface": "tune0", "preset": "rotated", "operator_policy": {"allow_runtime_tuning": true}})).await?;
        binding.reject(json!({"interface": "management0", "preset": "rotated"})).await?;
        let reply = binding.call(json!({"interface": "tune0", "preset": "rotated"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["verified"] == true, "setter must perform a meaningful verified mutation: {value}");
        ensure!(value["before"] != value["after"], "setter only reported a no-op");
        let after = guest.shell(r#"set -e; /usr/bin/ethtool -x tune0"#).await?;
        ensure!(after.status.success(), "independent postcondition query failed");
        ensure!(String::from_utf8_lossy(&after.stdout).split("RSS hash key:").nth(1).and_then(|section| section.lines().find(|line| !line.trim().is_empty())).is_some_and(|line| line.trim() == "5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:6a:42:b7:3b:be:ac:01:fa:6d"), "independent postcondition mismatch: {:?}", after);
        ensure!(before.stdout != after.stdout, "independent driver setting did not change");
        let noop = binding.call(json!({"interface": "tune0", "preset": "rotated"})).await?;
        ensure!(catalog::projection(&noop)?["changed"] == false, "already-current request must be unchanged");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
