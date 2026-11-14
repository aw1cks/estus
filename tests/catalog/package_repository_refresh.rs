use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn package_repository_refresh() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("package_repository_refresh", json!({})).await?;
        binding.reject(json!({"unexpected": true})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        let reply=binding.call(json!({})).await?;
        let value=catalog::projection(&reply)?;
        ensure!(value["refreshed"]==true && value["cache"]["state"]=="fresh", "explicit refresh not published");
        ensure!(guest.shell("test -f /var/lib/apt/periodic/update-success-stamp; dpkg-query -W -f='${Version}' estus-catalog-base").await?.stdout==b"1.0", "refresh installed packages");
        // The declarative repositories are immutable store-backed assets. Replace only this
        // disposable guest's symlink with a mutable copy before the authenticity attack.
        ensure!(guest.shell("set -eu; cp -aL /opt/estus-catalog /opt/estus-catalog-tamper; rm /opt/estus-catalog; mv /opt/estus-catalog-tamper /opt/estus-catalog; chmod -R u+w /opt/estus-catalog; sed -i 's/Origin: Estus/Origin: Forged/' /opt/estus-catalog/repo-a/InRelease; grep -q '^Origin: Forged' /opt/estus-catalog/repo-a/InRelease; test -x /run/current-system/sw/bin/gpgv; if /run/current-system/sw/bin/gpgv --keyring /usr/share/keyrings/estus-catalog.gpg /opt/estus-catalog/repo-a/InRelease >/dev/null 2>&1; then exit 1; fi; rm -f /var/lib/apt/periodic/update-success-stamp").await?.status.success(), "independent forged-signature setup failed");
        ensure!(catalog::projection(&binding.call(json!({})).await?).is_err(), "invalid signature accepted");
        ensure!(guest.shell("test ! -e /var/lib/apt/periodic/update-success-stamp").await?.status.success(), "failed refresh fabricated freshness");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
