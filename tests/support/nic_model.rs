//! Hardware-free tests of real kernel callbacks and the pinned native decoder.
use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::process::Output;

async fn command(guest: &catalog::Guest, script: &str) -> Result<Vec<u8>> {
    let output = guest.shell(script).await?;
    ensure!(
        output.status.success(),
        "native command failed: {script}: {output:?}"
    );
    Ok(output.stdout)
}

// Arguments here are test-owned constants or bounded integers, never caller input.
async fn ethtool(guest: &catalog::Guest, args: &str) -> Result<Output> {
    guest
        .shell(&format!("/usr/bin/timeout 6 /usr/bin/ethtool {args}"))
        .await
}

async fn ethtool_ok(guest: &catalog::Guest, args: &str) -> Result<Vec<u8>> {
    let output = ethtool(guest, args).await?;
    ensure!(
        output.status.success(),
        "native ethtool failed: {args}: {output:?}"
    );
    Ok(output.stdout)
}

fn singleton(bytes: &[u8]) -> Result<Value> {
    let mut values: Vec<Value> = serde_json::from_slice(bytes).context("native ethtool JSON")?;
    ensure!(values.len() == 1, "expected one native result");
    Ok(values.remove(0))
}

async fn eee(guest: &catalog::Guest) -> Result<Value> {
    let value = singleton(&ethtool_ok(guest, "--json --show-eee model0").await?)?;
    ensure!(
        value["ifname"] == "model0",
        "wrong native EEE interface: {value}"
    );
    Ok(value)
}

async fn parameter(guest: &catalog::Guest, name: &str, value: i64) -> Result<()> {
    command(
        guest,
        &format!("/usr/bin/printf '%s' {value} > /sys/module/estus_nic_model/parameters/{name}"),
    )
    .await?;
    Ok(())
}

async fn parameter_read(guest: &catalog::Guest, name: &str) -> Result<i64> {
    let bytes = command(
        guest,
        &format!("/usr/bin/cat /sys/module/estus_nic_model/parameters/{name}"),
    )
    .await?;
    Ok(std::str::from_utf8(&bytes)?.trim().parse()?)
}

async fn set_timer(guest: &catalog::Guest, timer: u32) -> Result<Output> {
    ethtool(
        guest,
        &format!("--set-eee model0 eee on tx-lpi on tx-timer {timer}"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned native ethtool"]
async fn nic_model_native_eee_callbacks() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let mac = command(&guest, "/usr/bin/cat /sys/class/net/model0/address").await?;
        ensure!(
            std::str::from_utf8(&mac)?.trim() == "52:54:00:12:34:5a",
            "wrong model MAC"
        );
        let driver = command(
            &guest,
            "/usr/bin/readlink -f /sys/class/net/model0/device/driver",
        )
        .await?;
        ensure!(
            std::str::from_utf8(&driver)?
                .trim()
                .ends_with("/estus_nic_model"),
            "wrong platform driver"
        );
        let info = ethtool_ok(&guest, "-i model0").await?;
        ensure!(
            std::str::from_utf8(&info)?.contains("driver: estus_nic_model"),
            "wrong ethtool driver"
        );
        let addresses = command(&guest, "/usr/bin/ip --json address show dev model0").await?;
        ensure!(
            singleton(&addresses)?["addr_info"] == json!([]),
            "model must have no addresses"
        );
        ensure!(
            command(&guest, "/usr/bin/ip route show dev model0")
                .await?
                .is_empty(),
            "model must have no routes"
        );
        let value = eee(&guest).await?;
        ensure!(
            value["status"] == "disabled" && value["tx-lpi"] == 100,
            "wrong initial EEE state: {value}"
        );
        for field in ["supported-eee-link-modes", "advertised-eee-link-modes"] {
            let modes = value[field].as_array().context("EEE mode array")?;
            ensure!(
                modes.len() == 2
                    && modes.contains(&json!("100baseT/Full"))
                    && modes.contains(&json!("1000baseT/Full")),
                "wrong initial modes: {value}"
            );
        }
        ensure!(
            value["link-partner-advertised-eee-link-modes"] == json!([]),
            "model has no peer: {value}"
        );
        let enabled = set_timer(&guest, 321).await?;
        ensure!(
            enabled.status.success(),
            "native enable failed: {enabled:?}"
        );
        let value = eee(&guest).await?;
        ensure!(
            value["status"] == "inactive" && value["tx-lpi"] == 321,
            "enabled is not negotiated active: {value}"
        );
        ethtool_ok(&guest, "--set-eee model0 tx-lpi off").await?;
        ensure!(
            eee(&guest).await?.get("tx-lpi").is_none(),
            "disabled LPI timer must be absent"
        );
        let legacy = ethtool_ok(&guest, "--disable-netlink --show-eee model0").await?;
        ensure!(
            std::str::from_utf8(&legacy)?.contains("enabled - inactive"),
            "legacy EEE state disagrees"
        );
        ethtool_ok(
            &guest,
            "--disable-netlink --set-eee model0 eee off tx-lpi on tx-timer 100",
        )
        .await?;
        let value = eee(&guest).await?;
        ensure!(
            value["status"] == "disabled" && value["tx-lpi"] == 100,
            "legacy setter not reflected in netlink: {value}"
        );
        ethtool_ok(&guest, "--disable-netlink --set-eee model0 advertise 0x8").await?;
        ensure!(
            eee(&guest).await?["advertised-eee-link-modes"] == json!(["100baseT/Full"]),
            "valid advertised subset not stored"
        );
        ethtool_ok(&guest, "--disable-netlink --set-eee model0 advertise 0x28").await?;
        for timer in [0, 1_000_000, 100] {
            ethtool_ok(&guest, &format!("--set-eee model0 tx-timer {timer}")).await?;
            ensure!(
                eee(&guest).await?["tx-lpi"] == timer,
                "timer boundary not stored: {timer}"
            );
        }
        for script in [
            "/usr/bin/ethtool --set-eee model0 eee on tx-lpi on tx-timer 432",
            "echo 1 > /sys/module/estus_nic_model/parameters/eee_write_fault",
        ] {
            let denied = guest.ordinary(script).await?;
            ensure!(
                !denied.status.success(),
                "ordinary root-only API access succeeded: {script}: {denied:?}"
            );
        }
        let ordinary = guest
            .ordinary("/usr/bin/ethtool --json --show-eee model0")
            .await?;
        ensure!(
            ordinary.status.success(),
            "ordinary EEE read denied: {ordinary:?}"
        );
        ensure!(
            singleton(&ordinary.stdout)? == eee(&guest).await?,
            "ordinary EEE read differs"
        );
        let before = eee(&guest).await?;
        for fault in [1, 2] {
            parameter(&guest, "eee_read_fault", fault).await?;
            let failed = ethtool(&guest, "--json --show-eee model0").await?;
            ensure!(
                !failed.status.success(),
                "EEE read fault became success: {fault}: {failed:?}"
            );
        }
        parameter(&guest, "eee_read_fault", 0).await?;
        ensure!(eee(&guest).await? == before, "read faults altered state");
        for (fault, success, timer) in [(1, false, 401), (2, true, 402), (3, false, 403)] {
            let before = eee(&guest).await?;
            let writes = parameter_read(&guest, "eee_writes").await?;
            parameter(&guest, "eee_write_fault", fault).await?;
            let output = set_timer(&guest, timer).await?;
            ensure!(
                output.status.success() == success,
                "wrong injected setter result: {fault}: {output:?}"
            );
            ensure!(
                parameter_read(&guest, "eee_writes").await? == writes + 1,
                "setter callback replayed or skipped: {fault}"
            );
            let after = eee(&guest).await?;
            if fault == 3 {
                ensure!(
                    after["status"] == "inactive" && after["tx-lpi"] == timer,
                    "partial effect missing: {after}"
                );
            } else {
                ensure!(
                    after == before,
                    "failure/ignored-write state changed: {fault}: {before}: {after}"
                );
            }
        }
        parameter(&guest, "eee_write_fault", 0).await?;
        let restored = set_timer(&guest, 404).await?;
        ensure!(
            restored.status.success() && eee(&guest).await?["tx-lpi"] == 404,
            "setter did not recover"
        );
        // Force ioctl so the driver, rather than netlink's mask filter, validates.
        for args in ["tx-timer 1000001", "advertise 0x8000"] {
            let before = eee(&guest).await?;
            let failed = ethtool(
                &guest,
                &format!("--disable-netlink --set-eee model0 {args}"),
            )
            .await?;
            ensure!(
                !failed.status.success() && eee(&guest).await? == before,
                "invalid EEE setting accepted: {args}: {failed:?}"
            );
        }
        for (name, invalid) in [
            ("delay_ms", 10001),
            ("eee_read_fault", 3),
            ("eee_write_fault", 4),
            ("module_fault", 4),
            ("temperature_raw", -32769),
            ("temperature_raw", 32768),
            ("voltage_raw", 65536),
        ] {
            let before = parameter_read(&guest, name).await?;
            let output = guest
                .shell(&format!(
                    "/usr/bin/printf '%s' {invalid} > /sys/module/estus_nic_model/parameters/{name}"
                ))
                .await?;
            ensure!(
                !output.status.success() && parameter_read(&guest, name).await? == before,
                "invalid parameter accepted: {name}={invalid}: {output:?}"
            );
        }
        command(
            &guest,
            "/usr/bin/timeout 6 /usr/bin/modprobe -r estus_nic_model",
        )
        .await?;
        let removed = guest.shell("/usr/bin/stat /sys/class/net/model0").await?;
        ensure!(!removed.status.success(), "netdev survived module removal");
        command(
            &guest,
            "/usr/bin/timeout 6 /usr/bin/modprobe estus_nic_model",
        )
        .await?;
        ensure!(
            parameter_read(&guest, "eee_writes").await? == 0,
            "counter not reset after reload"
        );
        let value = eee(&guest).await?;
        ensure!(
            value["status"] == "disabled" && value["tx-lpi"] == 100,
            "reload did not reset state: {value}"
        );
        let alive = guest.ordinary("/usr/bin/printf management-alive").await?;
        ensure!(
            alive.status.success() && alive.stdout == b"management-alive",
            "management SSH did not survive"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

async fn module(guest: &catalog::Guest) -> Result<Value> {
    singleton(&ethtool_ok(guest, "--json -m model0").await?)
}

async fn page(guest: &catalog::Guest, address: u8, offset: u16, length: u16) -> Result<Vec<u8>> {
    ethtool_ok(
        guest,
        &format!("-m model0 raw on page 0 i2c {address} offset {offset} length {length}"),
    )
    .await
}

fn check_module(value: &Value, temperature: f64, voltage: f64) -> Result<()> {
    ensure!(
        value["vendor_name"] == "ESTUS TEST" && value["vendor_pn"] == "SIM-SFP-1",
        "wrong synthetic identity: {value}"
    );
    for (field, expected) in [
        ("module_temperature_measurement", temperature),
        ("module_voltage_measurement", voltage),
        ("laser_tx_bias_current", 4.0),
        ("transmit_avg_optical_power", 1.0),
    ] {
        ensure!(
            value[field].as_f64() == Some(expected),
            "wrong decoded {field}: {value}"
        );
    }
    ensure!(
        value["rx_power"]["value"].as_f64() == Some(0.5),
        "wrong decoded RX power: {value}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned native ethtool"]
async fn nic_model_native_module_callbacks() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        for script in [
            "/usr/bin/ethtool --json -m model0",
            "/usr/bin/ethtool --disable-netlink -m model0 raw on",
        ] {
            let denied = guest.ordinary(script).await?;
            ensure!(
                !denied.status.success(),
                "ordinary EEPROM read succeeded: {script}: {denied:?}"
            );
        }
        check_module(&module(&guest).await?, 25.25, 3.3)?;
        let legacy = ethtool_ok(&guest, "--disable-netlink -m model0 raw on").await?;
        ensure!(
            legacy.len() == 512,
            "wrong legacy EEPROM size: {}",
            legacy.len()
        );
        ensure!(legacy[..3] == [3, 4, 7], "wrong SFP/LC identifiers");
        for (start, end) in [(0, 63), (64, 95), (256, 351)] {
            let sum = legacy[start..end]
                .iter()
                .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
            ensure!(legacy[end] == sum, "invalid EEPROM checksum at {end}");
        }
        ensure!(
            legacy[348] == 0 && legacy[92] == 0x68,
            "wrong calibration/diagnostic bits"
        );
        ensure!(
            legacy[352..362] == [0x19, 0x40, 0x80, 0xe8, 0x07, 0xd0, 0x27, 0x10, 0x13, 0x88],
            "wrong diagnostic bytes"
        );
        for (address, base) in [(0x50, 0usize), (0x51, 256)] {
            for (offset, length) in [(0, 128), (128, 128), (96, 10), (255, 1)] {
                let bytes = page(&guest, address, offset, length).await?;
                let start = base + usize::from(offset);
                ensure!(
                    bytes == legacy[start..start + usize::from(length)],
                    "page differs from legacy EEPROM: {address:#x}, {offset}, {length}"
                );
            }
        }
        for args in [
            "page 1 i2c 0x50",
            "bank 1 i2c 0x50",
            "i2c 0x52",
            "page 0 offset 127 length 2",
            "page 0 offset 255 length 2",
            "page 0 offset 256 length 1",
        ] {
            let failed = ethtool(&guest, &format!("-m model0 raw on {args}")).await?;
            ensure!(
                !failed.status.success(),
                "invalid module page returned success: {args}: {failed:?}"
            );
        }
        parameter(&guest, "temperature_raw", -2560).await?;
        parameter(&guest, "voltage_raw", 30000).await?;
        check_module(&module(&guest).await?, -10.0, 3.0)?;
        ensure!(
            page(&guest, 0x51, 96, 4).await? == [0xf6, 0, 0x75, 0x30],
            "dynamic sensors not reflected in EEPROM"
        );
        for fault in [1, 2] {
            parameter(&guest, "module_fault", fault).await?;
            for args in [
                "--json -m model0",
                "--disable-netlink -m model0 raw on",
                "-m model0 raw on page 0 i2c 0x51",
            ] {
                let failed = ethtool(&guest, args).await?;
                ensure!(
                    !failed.status.success(),
                    "module fault returned success: {fault}: {args}: {failed:?}"
                );
            }
        }
        parameter(&guest, "module_fault", 3).await?;
        ensure!(
            page(&guest, 0x50, 0, 1).await? == [0xff],
            "malformed identifier not injected"
        );
        // Native ethtool can successfully hex-dump an unknown ID, not decode it.
        let malformed = ethtool(&guest, "--json -m model0").await?;
        if let Ok(value) = serde_json::from_slice::<Value>(&malformed.stdout)
            && let Some(values) = value.as_array()
        {
            ensure!(
                values.iter().all(|item| item.get("vendor_name").is_none()
                    || item.get("module_temperature_measurement").is_none()),
                "unknown module unexpectedly produced selected decoded data: {value}"
            );
        }
        parameter(&guest, "module_fault", 0).await?;
        check_module(&module(&guest).await?, -10.0, 3.0)?;
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
