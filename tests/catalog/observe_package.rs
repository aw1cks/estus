use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn observe_package() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_package", json!({})).await?;
        binding.reject(json!({"package": "--help"})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        let reply=binding.call(json!({"package":"estus-catalog-base"})).await?;
        let value=catalog::projection(&reply)?;
        ensure!(value["ownership"]["owner"]=="estus-catalog-base", "missing genuine owner");
        ensure!(value["maintainer"].as_str().context("maintainer")?.contains("Estus Fixture"), "missing package metadata");
        ensure!(value["files"].as_array().context("files")?.iter().any(|v| v=="/usr/share/estus-catalog/estus-catalog-base"), "missing owned payload");
        let oracle=guest.shell("dpkg-query -S /usr/share/estus-catalog/estus-catalog-base; cat /usr/share/estus-catalog/estus-catalog-base").await?;
        ensure!(oracle.status.success() && String::from_utf8(oracle.stdout)?.contains("estus-catalog-base 1.0"), "ownership oracle disagrees");
        ensure!(catalog::projection(&binding.call(json!({"package":"estus-catalog-demo"})).await?).is_err(), "absent package reported installed");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
