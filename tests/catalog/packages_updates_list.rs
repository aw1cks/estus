use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn packages_updates_list() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("packages_updates_list", json!({})).await?;
        binding.reject(json!({"unexpected": true})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        let reply=binding.call(json!({})).await?;
        let value=catalog::projection(&reply)?;
        ensure!(value["cache"]["state"]=="unknown" && value["refreshed"]==false, "read fabricated freshness");
        ensure!(value["updates"].as_array().context("updates")?.iter().any(|p| p["package"]=="estus-catalog-base" && p["installed"]=="1.0" && p["candidate"]=="2.0"), "missing real cached update");
        let state=guest.shell("test ! -e /var/lib/apt/periodic/update-success-stamp; dpkg-query -W -f='${Version}' estus-catalog-base").await?;
        ensure!(state.status.success() && state.stdout==b"1.0", "read refreshed or installed");
        ensure!(guest.shell("mkdir -p /var/lib/apt/periodic; touch -d '3 days ago' /var/lib/apt/periodic/update-success-stamp").await?.status.success(), "stale setup");
        ensure!(catalog::projection(&binding.call(json!({})).await?)?["cache"]["state"]=="stale", "stale cache hidden");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
