use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn packages_upgrade() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("packages_upgrade", json!({})).await?;
        binding.reject(json!({"package": "--help", "version": "2.0"})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-base", "version": "99.0"})).await?).is_err(), "unavailable version accepted");
        ensure!(guest.shell("apt-mark hold estus-catalog-base").await?.status.success(), "hold setup");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-base", "version": "2.0"})).await?).is_err(), "held package changed");
        ensure!(guest.shell("apt-mark unhold estus-catalog-base").await?.status.success(), "hold cleanup");
        ensure!(guest.shell("python3 -c 'import fcntl,time; f=open(\"/var/lib/dpkg/lock-frontend\",\"w\"); fcntl.lockf(f,fcntl.LOCK_EX); open(\"/run/estus-package-lock-ready\",\"w\").close(); time.sleep(45)' >/dev/null 2>&1 & echo $! >/run/estus-package-lock-pid; while test ! -f /run/estus-package-lock-ready; do sleep .1; done").await?.status.success(), "lock setup");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-base", "version": "2.0"})).await?).is_err(), "locked database changed");
        ensure!(guest.shell("kill $(cat /run/estus-package-lock-pid)").await?.status.success(), "lock cleanup");
        let reply=binding.call(json!({"package": "estus-catalog-base", "version": "2.0"})).await?;
        ensure!(catalog::projection(&reply)?["verified"]==true, "postcondition absent");
        ensure!(guest.shell("test \"$(dpkg-query -W -f='${Version}' estus-catalog-base)\" = 2.0; grep -F 'estus-catalog-base 2.0 configured' /var/lib/estus-catalog/package-effects; grep -F 'estus-catalog-base 2.0' /usr/share/estus-catalog/estus-catalog-base").await?.status.success(), "actual dpkg/payload/maintainer postcondition failed");
        let before_repeat=guest.shell("cat /var/lib/dpkg/status /var/lib/estus-catalog/package-effects").await?;
        ensure!(before_repeat.status.success(), "repeat baseline oracle failed");
        let repeated=binding.call(json!({"package": "estus-catalog-base", "version": "2.0"})).await?;
        let receipt=catalog::projection(&repeated)?;
        ensure!(receipt["verified"]==true && receipt["changed"]==false && receipt["before"]==receipt["after"], "explicit desired-state repeat was not a verified no-op");
        let after_repeat=guest.shell("cat /var/lib/dpkg/status /var/lib/estus-catalog/package-effects").await?;
        ensure!(after_repeat.status.success() && before_repeat.stdout==after_repeat.stdout, "explicit repeat changed dpkg state or reran maintainer scripts");
        ensure!(guest.shell("apt-get -y --allow-downgrades install estus-catalog-base=1.0; printf '%s\\n' 'DPkg::Pre-Invoke { \"echo entered >> /var/lib/estus-catalog/interruption-attempts; sleep 90\"; };' > /etc/apt/apt.conf.d/99-interruption").await?.status.success(), "interruption setup");
        ensure!(catalog::projection(&binding.call(json!({"package":"estus-catalog-base","version":"2.0"})).await?).is_err(), "interrupted upgrade reported verified");
        ensure!(guest.shell("test \"$(wc -l < /var/lib/estus-catalog/interruption-attempts)\" = 1").await?.status.success(), "uncertain upgrade replayed");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
