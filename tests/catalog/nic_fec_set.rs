use crate::{catalog, payload};
use anyhow::{Result, ensure};
use serde_json::json;

async fn assert_native_fec(guest: &catalog::Guest, mode: &str) -> Result<()> {
    let output = guest.shell("/usr/bin/ethtool --show-fec fec0").await?;
    ensure!(
        output.status.success(),
        "independent FEC query failed: {output:?}"
    );
    let text = String::from_utf8(output.stdout)?;
    for label in ["Supported/Configured FEC encodings", "Active FEC encoding"] {
        let mut values = text.lines().filter_map(|line| {
            let (name, value) = line.trim().split_once(':')?;
            (name == label).then_some(value.trim())
        });
        ensure!(
            values.next() == Some(mode) && values.next().is_none(),
            "independent {label} mismatch: {text}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn nic_fec_set() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell("/usr/bin/ethtool --set-fec fec0 encoding off").await?;
        ensure!(prepared.status.success(), "independent FEC baseline preparation failed: {prepared:?}");
        assert_native_fec(&guest, "Off").await?;
        let binding = guest.binding("nic_fec_set", json!({})).await?;
        binding.reject(json!({"interface": "fec0", "mode": "auto"})).await?;
        binding.reject(json!({"interface": "fec0", "mode": "rs", "operator_policy": {"allow_runtime_tuning": true, "modes": ["rs"]}})).await?;
        binding.reject(json!({"interface": "management0", "mode": "rs"})).await?;
        let reply = binding.call(json!({"interface": "fec0", "mode": "rs"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value == &json!({
            "interface": "fec0", "driver": "netdevsim",
            "before": {"configured": ["off"], "active": "off"},
            "after": {"configured": ["rs"], "active": "rs"},
            "changed": true, "verified": true, "persistence": "runtime_only"
        }), "complete verified FEC mutation projection: {value}");
        assert_native_fec(&guest, "RS").await?;
        let ordinary = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(ordinary.status.success() && ordinary.stdout == b"1000\nup\n", "ordinary management SSH must survive FEC tuning: {ordinary:?}");
        let noop = binding.call(json!({"interface": "fec0", "mode": "rs"})).await?;
        let value = catalog::projection(&noop)?;
        ensure!(value == &json!({
            "interface": "fec0", "driver": "netdevsim",
            "before": {"configured": ["rs"], "active": "rs"},
            "after": {"configured": ["rs"], "active": "rs"},
            "changed": false, "verified": true, "persistence": "runtime_only"
        }), "already-current FEC request must be unchanged: {value}");
        assert_native_fec(&guest, "RS").await?;
        let reverse = binding.call(json!({"interface": "fec0", "mode": "off"})).await?;
        let value = catalog::projection(&reverse)?;
        ensure!(value == &json!({
            "interface": "fec0", "driver": "netdevsim",
            "before": {"configured": ["rs"], "active": "rs"},
            "after": {"configured": ["off"], "active": "off"},
            "changed": true, "verified": true, "persistence": "runtime_only"
        }), "explicit reverse operation must really restore off: {value}");
        assert_native_fec(&guest, "Off").await?;
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn fec_set_parser_normalizes_driver_encodings() -> Result<()> {
    for (text, expected) in [
        (
            "FEC parameters for fec0:\nSupported/Configured FEC encodings: RS\nActive FEC encoding: RS\n",
            json!({"configured": ["rs"], "active": "rs"}),
        ),
        (
            "Supported/Configured FEC encodings: Off\nActive FEC encoding: Off\n",
            json!({"configured": ["off"], "active": "off"}),
        ),
        (
            "Supported/Configured FEC encodings: None\nActive FEC encoding: None\n",
            json!({"configured": ["none"], "active": "none"}),
        ),
        (
            "Supported/Configured FEC encodings: Auto RS BaseR LLRS\nActive FEC encoding: BaseR\n",
            json!({"configured": ["auto", "rs", "baser", "llrs"], "active": "baser"}),
        ),
    ] {
        let actual = payload::call("nic_fec_set", "parse_fec", json!([text]))?;
        ensure!(
            actual == json!({"ok": expected}),
            "FEC parser normalization changed for {text:?}: {actual}"
        );
    }
    Ok(())
}

#[test]
fn fec_set_parser_refuses_incomplete_or_ambiguous_observations() -> Result<()> {
    let oversized = format!(
        "{}\nSupported/Configured FEC encodings: RS\nActive FEC encoding: RS\n",
        " ".repeat(65537)
    );
    for text in [
        "Supported/Configured FEC encodings: RS\n",
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: RS\nActive FEC encoding: Off\n",
        "Supported/Configured FEC encodings: RS\nSupported/Configured FEC encodings: Off\nActive FEC encoding: RS\n",
        "Supported/Configured FEC encodings: RS RS\nActive FEC encoding: RS\n",
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: RS Off\n",
        "Supported/Configured FEC encodings: Future\nActive FEC encoding: RS\n",
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: Future\n",
        "Supported/Configured FEC encodings: \nActive FEC encoding: RS\n",
        oversized.as_str(),
    ] {
        let actual = payload::call("nic_fec_set", "parse_fec", json!([text]))?;
        ensure!(
            actual == json!({"error": "ValueError"}),
            "unsafe FEC observation accepted ({} bytes): {actual}",
            text.len()
        );
    }
    Ok(())
}
