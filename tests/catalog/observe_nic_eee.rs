use crate::{catalog, payload};
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn observe_nic_eee() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell("/usr/bin/ethtool --set-eee model0 eee on tx-lpi on tx-timer 237").await?;
        ensure!(prepared.status.success(), "native EEE setup failed: {prepared:?}");
        let binding = guest.binding("observe_nic_eee", json!({})).await?;
        for input in [json!({"interface":"management0"}), json!({"interface":"model0","enabled":true}), json!({"interface":"model0","operator_policy":{}})] {
            binding.reject(input).await?;
        }
        let ordinary = guest.ordinary("/usr/bin/ethtool --json --show-eee model0").await?;
        ensure!(ordinary.status.success(), "EEE read must work without root: {ordinary:?}");
        let native: serde_json::Value = serde_json::from_slice(&ordinary.stdout)?;
        ensure!(native[0]["status"] == "inactive" && native[0]["tx-lpi"] == 237, "native configuration/active distinction: {native}");
        let reply = binding.call(json!({"interface":"model0"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value == &json!({"interface":"model0","driver":"estus_nic_model","scope":"software_model","enabled":true,"active":false,"tx_lpi_enabled":true,"tx_lpi_timer_us":237,"supported_modes":["100baseT/Full","1000baseT/Full"],"advertised_modes":["100baseT/Full","1000baseT/Full"],"peer_modes":[]}), "actual EEE projection: {value}");
        let changed = guest.shell("/usr/bin/ethtool --set-eee model0 eee off tx-lpi off tx-timer 913").await?;
        ensure!(changed.status.success(), "native LPI-off setup failed: {changed:?}");
        let reply = binding.call(json!({"interface":"model0"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["enabled"] == false && value["active"] == false && value["tx_lpi_enabled"] == false && value.get("tx_lpi_timer_us").is_none(), "hidden timer must remain unknown: {value}");
        let denied = guest.ordinary("printf 1 > /sys/module/estus_nic_model/parameters/eee_read_fault").await?;
        ensure!(!denied.status.success(), "fault control unexpectedly writable by ordinary account");
        for fault in [1, 2] {
            let control = guest.shell(&format!("printf {fault} > /sys/module/estus_nic_model/parameters/eee_read_fault")).await?;
            ensure!(control.status.success(), "root fault setup failed: {control:?}");
            let failed = binding.call(json!({"interface":"model0"})).await;
            if let Ok(envelope) = failed {
                ensure!(catalog::projection(&envelope).is_err(), "read failure became disabled success: {envelope}");
            }
            let reset = guest.shell("printf 0 > /sys/module/estus_nic_model/parameters/eee_read_fault").await?;
            ensure!(reset.status.success(), "fault reset failed");
        }
        let delay = guest.shell("printf 7000 > /sys/module/estus_nic_model/parameters/delay_ms").await?;
        ensure!(delay.status.success(), "bounded callback delay setup failed");
        let timed_out = binding.call(json!({"interface":"model0"})).await;
        let reset = guest.shell("printf 0 > /sys/module/estus_nic_model/parameters/delay_ms").await?;
        ensure!(reset.status.success(), "callback delay reset failed");
        if let Ok(envelope) = timed_out {
            ensure!(catalog::projection(&envelope).is_err(), "expired read returned cached or placeholder state: {envelope}");
        }
        let recovered = binding.call(json!({"interface":"model0"})).await?;
        let state = catalog::projection(&recovered)?;
        ensure!(state["enabled"] == false && state.get("tx_lpi_timer_us").is_none(), "post-timeout state or hidden timer changed: {state}");
        let alive = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(alive.status.success() && alive.stdout == b"1000\nup\n", "ordinary management path did not survive: {alive:?}");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn eee_parser_preserves_configuration_active_and_unknown_timer() -> Result<()> {
    for tool in ["observe_nic_eee", "change_nic_eee"] {
        for (status, enabled, active) in [
            ("disabled", false, false),
            ("inactive", true, false),
            ("active", true, true),
        ] {
            for timer in [None, Some(0), Some(237), Some(4294967295_u64)] {
                let mut row = json!({"ifname":"model0","status":status,"supported-eee-link-modes":["100baseT/Full","1000baseT/Full"],"advertised-eee-link-modes":["100baseT/Full"],"link-partner-advertised-eee-link-modes":[]});
                let mut expected = json!({"enabled":enabled,"active":active,"tx_lpi_enabled":timer.is_some(),"supported_modes":["100baseT/Full","1000baseT/Full"],"advertised_modes":["100baseT/Full"],"peer_modes":[]});
                if let Some(timer) = timer {
                    row["tx-lpi"] = json!(timer);
                    expected["tx_lpi_timer_us"] = json!(timer);
                }
                let text = json!([row]).to_string();
                assert_eq!(
                    payload::call(tool, "parse_eee", json!([text]))?,
                    json!({"ok":expected}),
                    "{tool} status={status}, timer={timer:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn eee_parsers_refuse_ambiguous_missing_nonfinite_and_unbounded_data() -> Result<()> {
    let baseline = json!({"ifname":"model0","status":"inactive","tx-lpi":100,"supported-eee-link-modes":["100baseT/Full"],"advertised-eee-link-modes":["100baseT/Full"],"link-partner-advertised-eee-link-modes":[]});
    let mut invalid = vec![
        "[]".to_owned(),
        "{}".to_owned(),
        "[null]".to_owned(),
        " ".repeat(65537),
        json!([baseline, baseline]).to_string(),
    ];
    for key in [
        "ifname",
        "status",
        "supported-eee-link-modes",
        "advertised-eee-link-modes",
        "link-partner-advertised-eee-link-modes",
    ] {
        let mut row = baseline.clone();
        row.as_object_mut().unwrap().remove(key);
        invalid.push(json!([row]).to_string());
    }
    for (key, value) in [
        ("ifname", json!("management0")),
        ("status", json!("not supported")),
        ("status", json!("enabled")),
        ("status", json!(true)),
        ("tx-lpi", json!(true)),
        ("tx-lpi", json!(-1)),
        ("tx-lpi", json!(1.5)),
        ("tx-lpi", json!(4294967296_u64)),
        ("supported-eee-link-modes", json!([])),
        ("advertised-eee-link-modes", json!(["1000baseT/Full"])),
        (
            "supported-eee-link-modes",
            json!(["100baseT/Full", "100baseT/Full"]),
        ),
        ("link-partner-advertised-eee-link-modes", json!([false])),
        (
            "link-partner-advertised-eee-link-modes",
            json!(["x".repeat(65)]),
        ),
        (
            "link-partner-advertised-eee-link-modes",
            json!((0..17).map(|i| format!("mode{i}")).collect::<Vec<_>>()),
        ),
        ("future", json!(null)),
    ] {
        let mut row = baseline.clone();
        row[key] = value;
        invalid.push(json!([row]).to_string());
    }
    let text = json!([baseline]).to_string();
    invalid.push(text.replace("\"tx-lpi\":100", "\"tx-lpi\":100,\"tx-lpi\":100"));
    for constant in ["NaN", "Infinity", "-Infinity"] {
        invalid.push(text.replace("\"tx-lpi\":100", &format!("\"tx-lpi\":{constant}")));
    }
    for tool in ["observe_nic_eee", "change_nic_eee"] {
        for text in &invalid {
            assert_eq!(
                payload::call(tool, "parse_eee", json!([text]))?,
                json!({"error":"ValueError"}),
                "{tool} input: {text:?}"
            );
        }
    }
    Ok(())
}
