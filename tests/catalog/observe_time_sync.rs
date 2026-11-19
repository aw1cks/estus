use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn observe_time_sync() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_time_sync", json!({})).await?;
        binding.reject(json!({"unexpected":true})).await?;
        let envelope = binding.call(json!({})).await?;
        let value = catalog::projection(&envelope)?;
        let observed = guest
            .shell("timedatectl show --property=NTPSynchronized --value")
            .await?;
        ensure!(observed.status.success(), "time oracle failed");
        let text = String::from_utf8(observed.stdout)?;
        let expected = match text.trim() {
            "yes" => "synchronized",
            "no" => "unsynchronized",
            _ => "unknown",
        };
        ensure!(
            value["status"]["synchronization"] == expected,
            "synchronization differs"
        );
        ensure!(
            value["unavailable"]
                .as_array()
                .is_some_and(|a| a.contains(&json!("offset_seconds"))),
            "unknown offset not explicit"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
