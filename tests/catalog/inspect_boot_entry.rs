use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn inspect_boot_entry() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("inspect_boot_entry", json!({})).await?;
        for id in ["@current", "*.conf", "../estus-current.conf"] {
            binding.reject(json!({"entry_id":id})).await?;
        }
        let envelope = binding
            .call(json!({"entry_id":"estus-current.conf"}))
            .await?;
        let p = catalog::projection(&envelope)?;
        let oracle = guest
            .shell("/usr/bin/bootctl --json=short --no-pager list")
            .await?;
        ensure!(oracle.status.success(), "bootctl oracle failed");
        let entries: Value = serde_json::from_slice(&oracle.stdout)?;
        let expected = entries
            .as_array()
            .context("oracle entries")?
            .iter()
            .find(|e| e["id"] == "estus-current.conf")
            .context("missing current")?;
        ensure!(p["entry"]["entry_id"] == expected["id"], "entry mismatch");
        ensure!(
            p["entry"]["command_line_sensitive"] == true,
            "missing sensitivity marker"
        );
        ensure!(
            p["entry"].get("command_line") == expected.get("options"),
            "commandline does not match actual loader entry"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
