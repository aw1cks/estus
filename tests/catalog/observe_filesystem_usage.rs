use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_filesystem_usage() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prep = guest.shell("mkdir -p /var/lib/estus-catalog/actual; ln -s actual /var/lib/estus-catalog/usage-link").await?;
        ensure!(prep.status.success(), "prepare configured-path symlink resolution");
        let binding = guest.binding("observe_filesystem_usage", json!({"configured_paths":{"data":"/var/lib/estus-catalog/usage-link"}})).await?;
        binding.reject(json!({"path_id":"/etc/shadow"})).await?;
        let oracle = guest.shell("python3 -c 'import os,json; p=\"/var/lib/estus-catalog/actual\"; s=os.statvfs(p); print(json.dumps({\"total_bytes\":s.f_blocks*s.f_frsize,\"inodes_total\":s.f_files,\"device_id\":os.stat(p).st_dev}))'").await?;
        ensure!(oracle.status.success(), "independent statvfs oracle");
        let expected: Value = serde_json::from_slice(&oracle.stdout)?;
        let reply = binding.call(json!({"path_id":"data"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["status"] == "available" && value["resolved_path"] == "/var/lib/estus-catalog/actual", "resolve configured non-mount path");
        for field in ["total_bytes","inodes_total","device_id"] { ensure!(value[field] == expected[field], "independent capacity/inode observation {field}"); }
        ensure!(value["available_bytes"].as_u64().context("available bytes")? <= value["free_bytes"].as_u64().context("free bytes")?, "reserved capacity semantics");
        let missing = guest.binding("observe_filesystem_usage", json!({"configured_paths":{"data":"/var/lib/estus-catalog/missing"}})).await?;
        let reply = missing.call(json!({"path_id":"data"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["status"] == "missing" && value.get("total_bytes").is_none(), "missing path is not fabricated zero capacity");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
