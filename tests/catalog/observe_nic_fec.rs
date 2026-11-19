use crate::{catalog, payload};
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn observe_nic_fec() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest
            .shell("/usr/bin/ethtool --set-fec fec0 encoding rs")
            .await?;
        ensure!(
            prepared.status.success(),
            "independent FEC preparation failed: {prepared:?}"
        );
        let binding = guest.binding("observe_nic_fec", json!({})).await?;
        binding.reject(json!({"interface":"management0"})).await?;
        binding
            .reject(json!({"interface":"fec0", "mode":"off"}))
            .await?;
        binding
            .reject(json!({"interface":"fec0", "operator_policy":{}}))
            .await?;
        let reply = binding.call(json!({"interface":"fec0"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["interface"] == "fec0"
                && value["driver"] == "netdevsim"
                && value["configured"] == json!(["rs"])
                && value["active"] == "rs",
            "actual selected FEC state mismatch: {value}"
        );
        let oracle = guest.shell("/usr/bin/ethtool --show-fec fec0").await?;
        ensure!(
            oracle.status.success(),
            "independent FEC observation failed"
        );
        let text = String::from_utf8_lossy(&oracle.stdout);
        ensure!(
            text.lines()
                .any(|line| line.trim() == "Supported/Configured FEC encodings: RS")
                && text
                    .lines()
                    .any(|line| line.trim() == "Active FEC encoding: RS"),
            "independent RS readback missing: {text}"
        );
        let changed = guest
            .shell("/usr/bin/ethtool --set-fec fec0 encoding off")
            .await?;
        ensure!(changed.status.success(), "independent FEC change failed");
        let reply = binding.call(json!({"interface":"fec0"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(
            value["configured"] == json!(["off"]) && value["active"] == "off",
            "FEC readback was cached or lost exact off encoding: {value}"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn fec_parser_preserves_reported_encodings_and_order() -> Result<()> {
    for (text, configured, active) in [
        (
            "FEC parameters for fec0:\nSupported/Configured FEC encodings: None\nActive FEC encoding: None\n",
            json!(["none"]),
            "none",
        ),
        (
            "FEC parameters for fec0:\nSupported/Configured FEC encodings: Off\nActive FEC encoding: Off\n",
            json!(["off"]),
            "off",
        ),
        (
            "FEC parameters for fec0:\nSupported/Configured FEC encodings: RS BaseR LLRS\nActive FEC encoding: BaseR\n",
            json!(["rs", "baser", "llrs"]),
            "baser",
        ),
        (
            "Supported/Configured FEC encodings: Auto\nActive FEC encoding: RS\n",
            json!(["auto"]),
            "rs",
        ),
    ] {
        assert_eq!(
            payload::call("observe_nic_fec", "parse_fec", json!([text]))?,
            json!({"ok":{"configured":configured,"active":active}}),
            "input: {text:?}"
        );
    }
    Ok(())
}

#[test]
fn fec_parser_refuses_missing_unknown_duplicate_and_ambiguous_state() -> Result<()> {
    for text in [
        "FEC parameters for fec0:\n".to_owned(),
        "Supported/Configured FEC encodings: RS\n".to_owned(),
        "Active FEC encoding: RS\n".to_owned(),
        "Supported/Configured FEC encodings:\nActive FEC encoding: RS\n".to_owned(),
        "Supported/Configured FEC encodings: RS\nActive FEC encoding:\n".to_owned(),
        "Supported/Configured FEC encodings: Future\nActive FEC encoding: RS\n".to_owned(),
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: Future\n".to_owned(),
        "Supported/Configured FEC encodings: RS RS\nActive FEC encoding: RS\n".to_owned(),
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: RS BaseR\n".to_owned(),
        "Supported/Configured FEC encodings: RS\nSupported/Configured FEC encodings: Off\nActive FEC encoding: RS\n".to_owned(),
        "Supported/Configured FEC encodings: RS\nActive FEC encoding: RS\nActive FEC encoding: RS\n".to_owned(),
        format!(
            "Supported/Configured FEC encodings: RS\nActive FEC encoding: RS\n{}",
            " ".repeat(65536)
        ),
    ] {
        assert_eq!(
            payload::call("observe_nic_fec", "parse_fec", json!([text]))?,
            json!({"error":"ValueError"}),
            "input: {text:?}"
        );
    }
    Ok(())
}
