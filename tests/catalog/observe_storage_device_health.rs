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

async fn health(client: &crate::support::Client) -> Result<Value> {
    client
        .call(
            "observe_storage_device_health",
            json!({
                "host":"plain", "inputs":{"device":"/dev/nvme0"}, "timeout_secs":30
            }),
        )
        .await
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
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn observe_storage_device_health() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let ordinary = guest.ordinary("/usr/bin/nvme smart-log /dev/nvme0 --raw-binary").await?;
        ensure!(!ordinary.status.success() && ordinary.stdout.is_empty(), "ordinary principal unexpectedly accessed privileged controller SMART ioctl");
        let binding = guest.binding("observe_storage_device_health", json!({})).await?;
        binding.reject(json!({"device":"/dev/vda"})).await?;
        binding.reject(json!({"device":"/dev/nvme0n1"})).await?;
        binding.reject(json!({"device":"/dev/nvme0", "self_test":true})).await?;
        let hidden = guest.shell(r#"set -eu
mkdir -m700 /run/estus-storage-nvme
mv /usr/bin/nvme /run/estus-storage-nvme/original
test ! -e /usr/bin/nvme
"#).await?;
        ensure!(hidden.status.success(), "NVMe prerequisite fixture failed");
        let client = crate::support::Client::start(&binding.config).await?;
        let observations: Result<()> = async {
        let missing = health(&client).await?;
        ensure!(missing["error"]["code"] == "discovery_failed"
            && missing["error"]["remote_state_unknown"] == false
            && missing["data"]["status"] == "not_started"
            && missing["data"]["complete"] == false,
            "missing nvme-cli reached payload execution: {missing}");
        let restored = guest.shell(
            "ln -s /run/estus-storage-nvme/original /usr/bin/nvme",
        ).await?;
        ensure!(restored.status.success(), "NVMe prerequisite restoration failed");
        let before = health(&client).await?;
        ensure!(before["data"]["changed"] == false, "read-only SMART observation claimed change");
        let before = catalog::projection(&before).context("initial virtual controller projection")?;
        ensure!(before["scope"] == "virtual_reported_controller" && before["model"] == "QEMU NVMe Ctrl", "incorrect health scope");
        ensure!(before.get("serial").is_none() && !serde_json::to_string(before)?.contains("ESTUS-LAB-NVME"),
            "fixed identity constraint leaked into published device telemetry");
        capture_smart(&guest, "BEFORE").await?;
        eprintln!("NVME_BEFORE_PROJECTION={before}");
        let io = guest.shell("dd if=/dev/zero of=/dev/nvme0n1 bs=4096 count=256 oflag=direct conv=fsync && dd if=/dev/nvme0n1 of=/dev/null bs=4096 count=256 iflag=direct").await?;
        ensure!(io.status.success(), "approved guest-only NVMe preparation IO failed: {}", String::from_utf8_lossy(&io.stderr));
        let after = health(&client).await?;
        ensure!(after["data"]["changed"] == false, "fresh read-only SMART observation claimed change");
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
        let alive = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(alive.status.success() && alive.stdout == b"1000\nup\n",
            "ordinary management path or identity changed during SMART observation");
        Ok(())
        }.await;
        let stopped = client.stop().await;
        let recovery = guest.shell(r#"set -eu
rm -f /usr/bin/nvme
mv /run/estus-storage-nvme/original /usr/bin/nvme
rmdir /run/estus-storage-nvme
"#).await?;
        ensure!(recovery.status.success(), "NVMe utility recovery failed");
        stopped?;
        observations
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn captured_smart_logs_use_the_production_parser() -> Result<()> {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/catalog/captures/storage_device_health_get");
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
                "observe_storage_device_health",
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
