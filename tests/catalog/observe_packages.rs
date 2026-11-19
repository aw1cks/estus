use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn observe_packages() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_packages", json!({})).await?;
        binding.reject(json!({"unexpected": true})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        binding.reject(json!({"offset":0,"limit":17})).await?;
        let reply=binding.call(json!({"offset":0,"limit":16})).await?;
        let value=catalog::projection(&reply)?;
        let packages=value["packages"].as_array().context("package array")?;
        ensure!(packages.iter().any(|p| p["name"]=="estus-catalog-base" && p["version"]=="1.0" && p["source"]=="apt"), "missing maintained baseline facts");
        ensure!(value["total"]==1 && value["truncated"]==false, "inventory coverage inaccurate");
        let empty=binding.call(json!({"offset":1,"limit":1})).await?;
        ensure!(catalog::projection(&empty)?["packages"].as_array().context("empty page")?.is_empty(), "pagination repeated package");
        let state=guest.shell("dpkg-query -W -f='${Version}' estus-catalog-base; test ! -e /var/lib/apt/periodic/update-success-stamp").await?;
        ensure!(state.status.success() && state.stdout==b"1.0", "inventory changed baseline/cache");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
