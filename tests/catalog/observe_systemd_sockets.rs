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
        let mut sockets = Vec::new();
        let mut offset = 0;
        loop {
            let reply = binding.call(json!({"offset": offset})).await?;
            let page = catalog::projection(&reply)?;
            sockets.extend(
                page["sockets"]
                    .as_array()
                    .context("sockets")?
                    .iter()
                    .cloned(),
            );
            match page.get("next_offset") {
                Some(next) => offset = next.as_u64().context("next_offset")?,
                None => break,
            }
        }
        let socket = sockets
            .iter()
            .find(|s| s["Id"] == "estus-fixture.socket")
            .context("fixture socket absent")?;
        let oracle = guest
            .shell("systemctl show estus-fixture.socket -p Listen --value")
            .await?;
        ensure!(oracle.status.success(), "socket oracle failed");
        let expected: Vec<String> = String::from_utf8(oracle.stdout)?
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        ensure!(
            !expected.is_empty() && socket["Listen"] == json!(expected),
            "socket endpoints differ from independent oracle"
        );
        let journald = sockets
            .iter()
            .find(|s| s["Id"] == "systemd-journald.socket")
            .context("journald socket absent")?;
        ensure!(
            journald["Listen"]
                .as_array()
                .context("journald endpoints")?
                .len()
                > 1,
            "multi-endpoint socket collapsed"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
