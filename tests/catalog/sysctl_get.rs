use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn sysctl_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("sysctl_get", json!({})).await?;
        binding.reject(json!({"keys":["vm.drop_caches"]})).await?;
        binding.reject(json!({"keys":["../../etc/passwd"]})).await?;
        let oracle = guest.shell("cat /proc/sys/vm/swappiness").await?;
        ensure!(oracle.status.success(), "independent sysctl read");
        let expected: u64 = std::str::from_utf8(&oracle.stdout)?.trim().parse()?;
        let reply = binding.call(json!({"keys":["vm.swappiness"]})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["values"][0]["status"] == "available" && value["values"][0]["value"] == expected,
            "real exact approved sysctl value"
        );
        let after = guest.shell("cat /proc/sys/vm/swappiness").await?;
        ensure!(
            after.status.success() && after.stdout == oracle.stdout,
            "read must not mutate sysctl"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
