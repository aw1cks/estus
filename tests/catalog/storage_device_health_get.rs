use crate::payload;

use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

fn counter(value: &Value) -> Result<u128> {
    if let Some(text) = value.as_str() {
        return Ok(text.parse()?);
    }
    Ok(u128::from(
        value.as_u64().context("invalid independent NVMe counter")?,
    ))
}

async fn capture_smart(guest: &catalog::Guest, phase: &str) -> Result<()> {
    let raw = guest.shell("/usr/bin/nvme smart-log /dev/nvme0 --raw-binary | /usr/bin/python3 -c 'import sys; data=sys.stdin.buffer.read(513); print(data.hex()) if len(data)==512 else sys.exit(1)'").await?;
    ensure!(
        raw.status.success() && raw.stdout.len() == 1025,
        "bounded SMART capture failed"
    );
    eprintln!(
        "NVME_{phase}_CAPTURE={}",
        String::from_utf8(raw.stdout)?.trim()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn storage_device_health_get() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let ordinary = guest.ordinary("/usr/bin/nvme smart-log /dev/nvme0 --raw-binary").await?;
        ensure!(!ordinary.status.success() && ordinary.stdout.is_empty(), "ordinary principal unexpectedly accessed privileged controller SMART ioctl");
        let binding = guest.binding("storage_device_health_get", json!({})).await?;
        binding.reject(json!({"device":"/dev/vda"})).await?;
        binding.reject(json!({"device":"/dev/nvme0n1"})).await?;
        binding.reject(json!({"device":"/dev/nvme0", "self_test":true})).await?;
        let before = binding.call(json!({"device":"/dev/nvme0"})).await?;
        let before = catalog::projection(&before).context("initial virtual controller projection")?;
        ensure!(before["scope"] == "virtual_reported_controller" && before["model"] == "QEMU NVMe Ctrl", "incorrect health scope");
        capture_smart(&guest, "BEFORE").await?;
        eprintln!("NVME_BEFORE_PROJECTION={before}");
        let io = guest.shell("dd if=/dev/zero of=/dev/nvme0n1 bs=4096 count=256 oflag=direct conv=fsync && dd if=/dev/nvme0n1 of=/dev/null bs=4096 count=256 iflag=direct").await?;
        ensure!(io.status.success(), "approved guest-only NVMe preparation IO failed: {}", String::from_utf8_lossy(&io.stderr));
        let after = binding.call(json!({"device":"/dev/nvme0"})).await?;
        let after = catalog::projection(&after).context("post-IO virtual controller projection")?;
        let oracle = guest.shell("/usr/bin/nvme smart-log /dev/nvme0 --output-format=json").await?;
        ensure!(oracle.status.success(), "independent nvme-cli SMART query failed");
        let oracle: Value = serde_json::from_slice(&oracle.stdout)?;
        capture_smart(&guest, "AFTER").await?;
        eprintln!("NVME_AFTER_PROJECTION={after}");
        eprintln!("NVME_JSON_ORACLE={oracle}");
        for name in ["host_read_commands", "host_write_commands", "data_units_read", "data_units_written"] {
            let old = counter(&before["counters"][name])?;
            let new = counter(&after["counters"][name])?;
            ensure!(new > old, "virtual controller did not report real {name} change: {old} -> {new}");
            ensure!(new == counter(&oracle[name])?, "independent reported {name} disagrees");
        }
        ensure!(after["critical_warning"] == oracle["critical_warning"], "reported warning mismatch");
        if let Some(temperature) = after.get("temperature_kelvin") {
            ensure!(temperature == &oracle["temperature"], "reported temperature mismatch");
        } else {
            ensure!(after["unavailable"] == json!(["temperature_kelvin"]), "unknown temperature was not preserved");
        }
        let state = guest.shell("cat /sys/class/nvme/nvme0/state").await?;
        ensure!(state.status.success(), "controller state oracle failed");
        ensure!(after["controller_state"].as_str() == Some(String::from_utf8_lossy(&state.stdout).trim()), "reported controller state mismatch");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn captured_smart_logs_use_the_production_parser() -> Result<()> {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/catalog/fixtures/storage_device_health_get");
    for phase in ["before", "after"] {
        for variant in ["captured", "truncated"] {
            let hex = std::fs::read_to_string(fixtures.join(format!("{phase}.hex")))?;
            let mut data = hex
                .trim()
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
                .collect::<Result<Vec<_>>>()?;
            if variant == "truncated" {
                data.pop();
            }
            let result = payload::call(
                "storage_device_health_get",
                "parse_smart_log",
                json!([payload::bytes(&data)]),
            )?;
            if variant == "truncated" {
                ensure!(
                    result["error"] == "ValueError",
                    "truncated real SMART capture accepted"
                );
                continue;
            }
            let actual = result.get("ok").context("captured SMART parser failed")?;
            let expected: Value = serde_json::from_slice(&std::fs::read(
                fixtures.join(format!("{phase}.expected.json")),
            )?)?;
            ensure!(
                actual == &expected,
                "{phase} captured SMART state changed: {actual}"
            );
        }
    }
    Ok(())
}
