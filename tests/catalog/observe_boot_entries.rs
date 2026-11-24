use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_boot_entries() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_boot_entries", json!({})).await?;
        binding.reject(json!({"flags":"--all"})).await?;
        let mut actual = Vec::new();
        let mut offset = 0_u64;
        loop {
            let envelope = binding.call(json!({"offset": offset})).await?;
            let page = catalog::projection(&envelope)?;
            actual.extend(
                page["entries"]
                    .as_array()
                    .context("missing entries")?
                    .iter()
                    .cloned(),
            );
            let Some(next) = page.get("next_offset") else {
                break;
            };
            offset = next.as_u64().context("non-integer next page")?;
        }
        let oracle = guest
            .shell("/usr/bin/bootctl --json=short --no-pager list")
            .await?;
        ensure!(oracle.status.success(), "bootctl oracle failed");
        let entries: Value = serde_json::from_slice(&oracle.stdout)?;
        ensure!(
            actual.len() == entries.as_array().context("oracle entries")?.len(),
            "paged boot entries lost entries"
        );
        for id in ["estus-current.conf", "estus-alternate.conf"] {
            let expected = entries
                .as_array()
                .context("oracle entries")?
                .iter()
                .find(|e| e["id"] == id)
                .context("missing real entry")?;
            let observed = actual
                .iter()
                .find(|e| e["entry_id"] == id)
                .context("missing projected entry")?;
            ensure!(
                observed.get("linux") == expected.get("linux"),
                "kernel association mismatch"
            );
            ensure!(
                observed.get("initrd") == expected.get("initrd"),
                "initrd association mismatch"
            );
            ensure!(
                observed["command_line_sensitive"] == true
                    && observed.get("command_line").is_none(),
                "sensitive command line leaked"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
