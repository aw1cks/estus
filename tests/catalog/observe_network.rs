use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_network_aspects() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_network", json!({})).await?;
        binding.reject(json!({"aspect": "unexpected"})).await?;
        binding
            .reject(json!({"aspect": "links", "interface": "eth99"}))
            .await?;
        // Counters describe one interface, so the stats aspect cannot default it.
        binding.reject(json!({"aspect": "stats"})).await?;

        let envelope = binding
            .call(json!({"aspect": "links", "interface": "catalog0"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["aspect"] == "links"
                && value["links"]["scope"] == "approved_interfaces"
                && value["links"]["entries"][0]["interface"] == "catalog0",
            "links aspect did not publish its block"
        );
        ensure!(
            value.get("addresses").is_none()
                && value.get("neighbors").is_none()
                && value.get("stats").is_none(),
            "links aspect leaked an unrelated block"
        );
        let mtu = guest
            .shell("cat /sys/class/net/catalog0/mtu")
            .await?;
        ensure!(mtu.status.success(), "link oracle failed");
        ensure!(
            value["links"]["entries"][0]["mtu"]
                == String::from_utf8(mtu.stdout)?.trim().parse::<serde_json::Value>()?,
            "mtu differs from the kernel oracle"
        );

        let envelope = binding
            .call(json!({"aspect": "addresses", "interface": "catalog0", "family": "inet"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["aspect"] == "addresses"
                && value["addresses"]["entries"]
                    .as_array()
                    .is_some_and(|entries| entries
                        .iter()
                        .all(|entry| entry["family"] == "inet")),
            "addresses aspect published the wrong family"
        );

        let envelope = binding
            .call(json!({"aspect": "neighbors", "interface": "catalog0"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["aspect"] == "neighbors"
                && value["neighbors"]["entries"]
                    .as_array()
                    .is_some_and(|entries| entries
                        .iter()
                        .all(|entry| entry["interface"] == "catalog0")),
            "neighbors aspect published another interface"
        );

        let envelope = binding
            .call(json!({"aspect": "stats", "interface": "catalog0"}))
            .await?;
        let value = catalog::projection(&envelope)?;
        ensure!(
            value["aspect"] == "stats" && value["stats"]["interface"] == "catalog0",
            "stats aspect did not publish its block"
        );
        let counters = &value["stats"]["counters"];
        for key in ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"] {
            ensure!(
                counters[key].as_u64().is_some(),
                "counter {key} missing or negative"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
