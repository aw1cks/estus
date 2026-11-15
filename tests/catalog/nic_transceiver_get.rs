use crate::{catalog, payload};
use anyhow::{Result, ensure};
use serde_json::{Value, json};

async fn native_module(guest: &catalog::Guest) -> Result<Value> {
    let output = guest.shell("/usr/bin/ethtool --json -m model0").await?;
    ensure!(
        output.status.success(),
        "independent real module decoder failed: {output:?}"
    );
    let mut decoded: Vec<Value> = serde_json::from_slice(&output.stdout)?;
    ensure!(decoded.len() == 1, "expected one native decoded SFP");
    Ok(decoded.remove(0))
}

fn agrees_with_native(
    selected: &Value,
    native: &Value,
    temperature: f64,
    voltage: f64,
) -> Result<()> {
    ensure!(
        selected
            .as_object()
            .is_some_and(|fields| fields.len() == 11),
        "nonselected fields leaked: {selected}"
    );
    ensure!(
        selected["interface"] == "model0"
            && selected["driver"] == "estus_nic_model"
            && selected["scope"] == "software_model",
        "model identity missing"
    );
    ensure!(
        selected["vendor"] == "ESTUS TEST" && selected["part"] == "SIM-SFP-1",
        "synthetic module identity mismatch"
    );
    for (field, decoded) in [
        ("vendor", &native["vendor_name"]),
        ("part", &native["vendor_pn"]),
        ("temperature_c", &native["module_temperature_measurement"]),
        ("voltage_v", &native["module_voltage_measurement"]),
        ("tx_bias_ma", &native["laser_tx_bias_current"]),
        ("tx_power_mw", &native["transmit_avg_optical_power"]),
        ("rx_power_mw", &native["rx_power"]["value"]),
    ] {
        ensure!(
            &selected[field] == decoded,
            "selected {field} disagrees with independent real decoder"
        );
    }
    ensure!(
        selected["temperature_c"].as_f64() == Some(temperature)
            && selected["voltage_v"].as_f64() == Some(voltage),
        "updated sensors stale or wrong"
    );
    ensure!(
        selected["tx_bias_ma"] == 4.0
            && selected["tx_power_mw"] == 1.0
            && selected["rx_power_mw"] == 0.5,
        "sensor units incorrect"
    );
    ensure!(
        selected.get("vendor_sn").is_none()
            && selected.get("date_code").is_none()
            && selected.get("pages").is_none(),
        "serial/date/raw pages leaked"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn nic_transceiver_get() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let baseline = native_module(&guest).await?;
        let denied = guest.ordinary("/usr/bin/ethtool --json -m model0").await?;
        ensure!(!denied.status.success(), "ordinary module EEPROM read unexpectedly permitted");
        let binding = guest.binding("nic_transceiver_get", json!({})).await?;
        for invalid in [
            json!({}), json!({"interface":"management0"}), json!({"interface":"model0", "raw":true}),
            json!({"interface":"model0", "operator_policy":{}}), json!({"interface":"model0", "temperature_raw":0}),
        ] {
            binding.reject(invalid).await?;
        }
        let reply = binding.call(json!({"interface":"model0"})).await?;
        agrees_with_native(catalog::projection(&reply)?, &baseline, 25.25, 3.3)?;
        let updated = guest.shell("set -eu; printf '%s' -2560 > /sys/module/estus_nic_model/parameters/temperature_raw; printf '%s' 30000 > /sys/module/estus_nic_model/parameters/voltage_raw").await?;
        ensure!(updated.status.success(), "independent model sensor update failed: {updated:?}");
        let changed = native_module(&guest).await?;
        let reply = binding.call(json!({"interface":"model0"})).await?;
        agrees_with_native(catalog::projection(&reply)?, &changed, -10.0, 3.0)?;
        for fault in [1, 2, 3] {
            let injected = guest.shell(&format!("printf '%s' {fault} > /sys/module/estus_nic_model/parameters/module_fault")).await?;
            ensure!(injected.status.success(), "module fault injection failed");
            if let Ok(reply) = binding.call(json!({"interface":"model0"})).await {
                ensure!(catalog::projection(&reply).is_err(), "module fault {fault} returned successful placeholder data: {reply}");
            }
            let reset = guest.shell("printf '%s' 0 > /sys/module/estus_nic_model/parameters/module_fault").await?;
            ensure!(reset.status.success(), "module fault reset failed");
        }
        let recovered = native_module(&guest).await?;
        let reply = binding.call(json!({"interface":"model0"})).await?;
        agrees_with_native(catalog::projection(&reply)?, &recovered, -10.0, 3.0)?;
        let management = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(management.status.success() && management.stdout == b"1000\nup\n", "ordinary management SSH did not survive module observations");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

fn decoded_module() -> Value {
    json!([{
        "identifier":3, "extended_identifier":4, "optical_diagnostics_support":true,
        "vendor_name":"ESTUS TEST", "vendor_pn":"SIM-SFP-1", "vendor_sn":"SYNTHETIC-SECRET", "date_code":"TESTONLY",
        "module_temperature_measurement":25.25, "module_voltage_measurement":3.3,
        "laser_tx_bias_current":4.0, "transmit_avg_optical_power":1.0,
        "rx_power":{"value":0.5,"type":"Receiver signal average optical power"}
    }])
}

#[test]
fn module_parser_selects_nonserial_fields_and_decoded_units() -> Result<()> {
    for (temperature, voltage, tx_power, rx_power) in [
        (25.25, 3.3, 1.0, 0.5),
        (-10.0, 3.0, 1.0, 0.5),
        (-128.0, 0.0, 0.0, 0.0),
        (127.996, 6.5535, 6.5535, 6.5535),
    ] {
        let mut decoded = decoded_module();
        decoded[0]["module_temperature_measurement"] = json!(temperature);
        decoded[0]["module_voltage_measurement"] = json!(voltage);
        decoded[0]["transmit_avg_optical_power"] = json!(tx_power);
        decoded[0]["rx_power"]["value"] = json!(rx_power);
        assert_eq!(
            payload::call(
                "nic_transceiver_get",
                "parse_module",
                json!([decoded.to_string()])
            )?,
            json!({"ok":{
                "vendor":"ESTUS TEST", "part":"SIM-SFP-1", "temperature_c":temperature, "voltage_v":voltage,
                "tx_bias_ma":4.0, "tx_power_mw":tx_power, "rx_power_mw":rx_power
            }})
        );
    }
    Ok(())
}

#[test]
fn module_parser_rejects_unavailable_malformed_ambiguous_and_wrong_unit_data() -> Result<()> {
    let baseline = decoded_module();
    let mut cases = vec![
        "not json".to_owned(),
        "{}".to_owned(),
        "[]".to_owned(),
        "[{},{}]".to_owned(),
        "[null]".to_owned(),
        " ".repeat(65537),
        "[".repeat(1000),
    ];
    for field in [
        "identifier",
        "extended_identifier",
        "optical_diagnostics_support",
        "vendor_name",
        "vendor_pn",
        "module_temperature_measurement",
        "module_voltage_measurement",
        "laser_tx_bias_current",
        "transmit_avg_optical_power",
        "rx_power",
    ] {
        let mut decoded = baseline.clone();
        decoded[0].as_object_mut().unwrap().remove(field);
        cases.push(decoded.to_string());
    }
    for (field, bad) in [
        ("identifier", json!(12)),
        ("identifier", json!(3.0)),
        ("extended_identifier", json!(true)),
        ("optical_diagnostics_support", json!(false)),
        ("optical_diagnostics_support", json!(1)),
        ("vendor_name", json!("unknown")),
        ("vendor_name", json!("x".repeat(17))),
        ("vendor_pn", json!(null)),
        ("module_temperature_measurement", json!(true)),
        ("module_temperature_measurement", json!("25.25 C")),
        ("module_temperature_measurement", json!(-128.01)),
        ("module_temperature_measurement", json!(127.997)),
        ("module_voltage_measurement", json!(-0.1)),
        ("module_voltage_measurement", json!(6.5536)),
        ("laser_tx_bias_current", json!(131.071)),
        ("laser_tx_bias_current", json!(-1)),
        ("transmit_avg_optical_power", json!(6.5536)),
        ("transmit_avg_optical_power", json!(-1)),
        (
            "rx_power",
            json!({"value":0.5,"type":"Receiver signal OMA"}),
        ),
        (
            "rx_power",
            json!({"value":true,"type":"Receiver signal average optical power"}),
        ),
        (
            "rx_power",
            json!({"value":6.5536,"type":"Receiver signal average optical power"}),
        ),
        (
            "rx_power",
            json!({"type":"Receiver signal average optical power"}),
        ),
    ] {
        let mut decoded = baseline.clone();
        decoded[0][field] = bad;
        cases.push(decoded.to_string());
    }
    let text = baseline.to_string();
    for number in ["NaN", "Infinity", "-Infinity", "1e999"] {
        cases.push(text.replace("25.25", number));
    }
    cases.push(text.replacen("\"identifier\":3", "\"identifier\":3,\"identifier\":3", 1));
    cases.push(text.replacen("\"value\":0.5", "\"value\":0.5,\"value\":0.5", 1));
    let mut excessive = baseline.clone();
    excessive[0]["extra"] = json!(vec![0; 2048]);
    cases.push(excessive.to_string());
    excessive[0]["extra"] = json!([[[[[[[[[0]]]]]]]]]);
    cases.push(excessive.to_string());
    for text in cases {
        assert_eq!(
            payload::call("nic_transceiver_get", "parse_module", json!([text]))?,
            json!({"error":"ValueError"}),
            "input: {text:?}"
        );
    }
    Ok(())
}
