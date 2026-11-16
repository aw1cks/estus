use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM with signed apt state and pinned Runner runtime"]
async fn packages_install() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        let binding = guest.binding("packages_install", json!({})).await?;
        binding.reject(json!({"package": "--help", "version": "2.0"})).await?;
        let sources=guest.shell("cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list").await?;
        ensure!(sources.status.success(), "source oracle failed");
        let sources=String::from_utf8(sources.stdout)?;
        ensure!(sources.lines().filter(|line| !line.trim().is_empty()).all(|line| line.starts_with("deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-")), "nonlocal or unreviewed source");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-demo", "version": "99.0"})).await?).is_err(), "unavailable version accepted");
        ensure!(guest.shell("apt-mark hold estus-catalog-base").await?.status.success(), "hold setup");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-base", "version": "2.0"})).await?).is_err(), "held package changed");
        ensure!(guest.shell("apt-mark unhold estus-catalog-base").await?.status.success(), "hold cleanup");
        ensure!(guest.shell("python3 -c 'import fcntl,time; f=open(\"/var/lib/dpkg/lock-frontend\",\"w\"); fcntl.lockf(f,fcntl.LOCK_EX); open(\"/run/estus-package-lock-ready\",\"w\").close(); time.sleep(45)' >/dev/null 2>&1 & echo $! >/run/estus-package-lock-pid; while test ! -f /run/estus-package-lock-ready; do sleep .1; done").await?.status.success(), "lock setup");
        ensure!(catalog::projection(&binding.call(json!({"package": "estus-catalog-demo", "version": "2.0"})).await?).is_err(), "locked database changed");
        ensure!(guest.shell("kill $(cat /run/estus-package-lock-pid)").await?.status.success(), "lock cleanup");
        let reply=binding.call(json!({"package": "estus-catalog-demo", "version": "2.0"})).await?;
        ensure!(catalog::projection(&reply)?["verified"]==true, "postcondition absent");
        ensure!(guest.shell("test \"$(dpkg-query -W -f='${Version}' estus-catalog-demo)\" = 2.0; grep -F 'estus-catalog-demo 2.0 configured' /var/lib/estus-catalog/package-effects; grep -F 'estus-catalog-demo 2.0' /usr/share/estus-catalog/estus-catalog-demo").await?.status.success(), "actual dpkg/payload/maintainer postcondition failed");
        let before_repeat=guest.shell("cat /var/lib/dpkg/status /var/lib/estus-catalog/package-effects").await?;
        ensure!(before_repeat.status.success(), "repeat baseline oracle failed");
        let repeated=binding.call(json!({"package": "estus-catalog-demo", "version": "2.0"})).await?;
        let receipt=catalog::projection(&repeated)?;
        ensure!(receipt["verified"]==true && receipt["changed"]==false && receipt["before"]==receipt["after"] && repeated["data"]["changed"]==false, "explicit desired-state repeat was not a verified no-op for the caller");
        let after_repeat=guest.shell("cat /var/lib/dpkg/status /var/lib/estus-catalog/package-effects").await?;
        ensure!(after_repeat.status.success() && before_repeat.stdout==after_repeat.stdout, "explicit repeat changed dpkg state or reran maintainer scripts");
        // Real apt failure after dpkg has already configured the package.
        ensure!(guest.shell("apt-get -y remove estus-catalog-demo; printf '%s\\n' 'DPkg::Post-Invoke { \"exit 42\"; };' > /etc/apt/apt.conf.d/99-partial-failure").await?.status.success(), "partial failure setup");
        let partial = binding.call(json!({"package":"estus-catalog-demo","version":"2.0"})).await?;
        ensure!(guest.shell("test \"$(dpkg-query -W -f='${Status} ${Version}' estus-catalog-demo)\" = 'install ok installed 2.0'; test \"$(cat /usr/share/estus-catalog/estus-catalog-demo)\" = 'estus-catalog-demo 2.0'").await?.status.success(), "failed apt did not actually install target");
        failed_mutation_receipt(&partial)?;
        ensure!(guest.shell("rm /etc/apt/apt.conf.d/99-partial-failure; apt-get -y remove estus-catalog-demo").await?.status.success(), "partial failure cleanup");
        // apt.conf values cannot contain backslashes or nested double quotes.
        // Keep the fault in a private script, not an incorrectly escaped hook.
        // The hook proves dpkg configured 2.0 before corrupting its recorded version.
        ensure!(guest.shell(r#"set -eu
cat > /run/estus-package-postcondition <<'SCRIPT'
set -eu
test "$(dpkg-query -W -f='${Status} ${Version}' estus-catalog-demo)" = 'install ok installed 2.0'
sed -i '/^Package: estus-catalog-demo$/,/^$/s/^Version: 2.0$/Version: 9.0/' /var/lib/dpkg/status
test "$(dpkg-query -W -f='${Version}' estus-catalog-demo)" = 9.0
printf 'configured-2.0-then-recorded-9.0\n' > /run/estus-package-postcondition-observed
SCRIPT
sh -n /run/estus-package-postcondition
printf '%s\n' 'DPkg::Post-Invoke { "sh /run/estus-package-postcondition"; };' > /etc/apt/apt.conf.d/99-postcondition-failure
apt-config dump >/dev/null"#).await?.status.success(), "postcondition failure setup");
        let postcondition = binding.call(json!({"package":"estus-catalog-demo","version":"2.0"})).await?;
        ensure!(guest.shell("set -eu; test \"$(cat /run/estus-package-postcondition-observed)\" = configured-2.0-then-recorded-9.0; test \"$(dpkg-query -W -f='${Status} ${Version}' estus-catalog-demo)\" = 'install ok installed 9.0'; test \"$(cat /usr/share/estus-catalog/estus-catalog-demo)\" = 'estus-catalog-demo 2.0'").await?.status.success(), "postcondition fault did not leave independently observable mutation");
        failed_mutation_receipt(&postcondition)?;
        ensure!(guest.shell("set -eu; rm /etc/apt/apt.conf.d/99-postcondition-failure /run/estus-package-postcondition /run/estus-package-postcondition-observed; apt-get -y remove estus-catalog-demo").await?.status.success(), "postcondition failure cleanup");
        ensure!(guest.shell("apt-get -y remove estus-catalog-demo; printf '%s\\n' 'DPkg::Pre-Invoke { \"echo entered >> /var/lib/estus-catalog/interruption-attempts; sleep 90\"; };' > /etc/apt/apt.conf.d/99-interruption").await?.status.success(), "interruption setup");
        let interrupted = binding.call(json!({"package":"estus-catalog-demo","version":"2.0"})).await?;
        ensure!(catalog::projection(&interrupted).is_err(), "interrupted install reported verified");
        ensure!(interrupted["data"]["changed"].is_null(), "unobserved interrupted mutation was reported unchanged: {interrupted}");
        ensure!(guest.shell("test \"$(wc -l < /var/lib/estus-catalog/interruption-attempts)\" = 1").await?.status.success(), "uncertain install replayed");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

fn failed_mutation_receipt(reply: &serde_json::Value) -> Result<()> {
    ensure!(
        reply["data"]["status"] == "failed"
            && reply["data"]["complete"] == true
            && reply["data"]["changed"] == true
            && reply["data"]["runner_rc"] == 1
            && reply["error"]["code"] == "payload_failed"
            && reply["data"]["projection"]["status"] == "unavailable",
        "failed package execution erased actual mutation or confused projection failure: {reply}"
    );
    Ok(())
}
