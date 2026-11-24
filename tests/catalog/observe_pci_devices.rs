use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_pci_devices() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_pci_devices", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let mut devices = Vec::new();
        let mut offset = 0;
        let value = loop {
            let envelope = binding.call(json!({"offset": offset})).await?;
            let value = catalog::projection(&envelope)?.clone();
            devices.extend(
                value["devices"]
                    .as_array()
                    .context("devices")?
                    .iter()
                    .cloned(),
            );
            match value.get("next_offset") {
                Some(next) => offset = next.as_u64().context("next_offset")?,
                None => break value,
            }
        };
        let listed = guest.shell("ls /sys/bus/pci/devices").await?;
        ensure!(listed.status.success(), "PCI listing oracle failed");
        let expected = String::from_utf8(listed.stdout)?.split_whitespace().count();
        ensure!(
            devices.len() == expected && value["device_count"] == json!(expected),
            "paged PCI inventory lost devices"
        );
        let observed = guest
            .shell("cat /sys/bus/pci/devices/0000:00:00.0/vendor")
            .await?;
        ensure!(observed.status.success(), "PCI oracle failed");
        let device = devices
            .iter()
            .find(|d| d["address"] == "0000:00:00.0")
            .ok_or_else(|| anyhow::anyhow!("missing host bridge"))?;
        ensure!(
            device["vendor"] == String::from_utf8(observed.stdout)?.trim(),
            "vendor differs"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
