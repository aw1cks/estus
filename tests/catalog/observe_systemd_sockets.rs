use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_sockets_list_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_systemd_sockets", json!({})).await?;
        binding.reject(json!({"flags": ["--now"]})).await?;
        let prep = guest.shell("systemctl start estus-fixture.socket").await?;
        ensure!(prep.status.success(), "socket preparation failed");
        let reply = binding.call(json!({})).await?;
        let socket = catalog::projection(&reply)?["sockets"]
            .as_array()
            .context("sockets")?
            .iter()
            .find(|s| s["Id"] == "estus-fixture.socket")
            .context("fixture socket absent")?;
        let oracle = guest
            .shell("systemctl show estus-fixture.socket -p Listen --value")
            .await?;
        ensure!(
            oracle.status.success()
                && socket["Listen"].as_str() == Some(String::from_utf8(oracle.stdout)?.trim()),
            "socket endpoint differs from independent oracle"
        );
        ensure!(
            !socket["Listen"].as_str().context("endpoint")?.is_empty(),
            "socket endpoint is empty"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
