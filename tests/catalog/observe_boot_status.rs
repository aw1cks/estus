use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_boot_status() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_boot_status", json!({})).await?;
        binding.reject(json!({"firmware":"efi"})).await?;
        let envelope = binding.call(json!({})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["firmware_mode"] == "efi", "actual EFI firmware not observed");
        let oracle = guest.shell("cat /proc/sys/kernel/random/boot_id; /usr/bin/python3 -c \"from pathlib import Path;print(Path('/sys/firmware/efi/efivars/LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f').read_bytes()[4:].decode('utf-16-le').rstrip(chr(0)))\"").await?;
        ensure!(oracle.status.success(), "boot oracle failed");
        let output = String::from_utf8(oracle.stdout)?;
        let mut lines = output.lines();
        ensure!(p["boot_id"] == lines.next().context("missing boot ID")?, "boot ID mismatch");
        ensure!(p["loader"] == lines.next().context("missing loader")?, "actual loader mismatch");
        ensure!(p["current_entry"] == "estus-current.conf", "wrong selected entry");
        ensure!(p["security_source"] == "UEFI global variables", "missing security provenance");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
