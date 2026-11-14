use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn package_repository_change() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("package_repository_change", json!({})).await?;
        binding.reject(json!({"repository": "https://unreviewed.invalid"})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        let reply=binding.call(json!({"repository":"alternate"})).await?;
        ensure!(catalog::projection(&reply)?["signature_required"]==true, "signature policy missing");
        let source=guest.shell("cat /etc/apt/sources.list.d/estus-catalog.list; test ! -e /var/lib/apt/periodic/update-success-stamp").await?;
        ensure!(source.status.success() && String::from_utf8(source.stdout)?.contains("repo-b"), "source replacement not real");
        let refresh=guest.binding("package_repository_refresh",json!({})).await?;
        catalog::projection(&refresh.call(json!({})).await?)?;
        let upgrade=guest.binding("packages_upgrade",json!({})).await?;
        catalog::projection(&upgrade.call(json!({"package":"estus-catalog-base","version":"3.0"})).await?)?;
        let oracle=guest.shell("dpkg-query -W -f='${Version}' estus-catalog-base; cat /usr/share/estus-catalog/estus-catalog-base").await?;
        ensure!(oracle.status.success() && String::from_utf8(oracle.stdout)?.contains("3.0estus-catalog-base 3.0"), "alternate repository had no actual effect");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
