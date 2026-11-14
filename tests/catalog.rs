//! Real operational catalog acceptance against disposable, privately keyed EFI guests.
#![allow(dead_code)]
#[path = "support/catalog.rs"]
mod catalog;
mod support;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn catalog_guest_qualification() -> anyhow::Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: anyhow::Result<()> = async {
        let control = guest.shell("test -d /sys/firmware/efi && test -d /sys/fs/cgroup/system.slice && test -e /sys/module/estus_catalog/parameters/value && test -e /boot/loader/entries/estus-current.conf && test -e /boot/loader/entries/estus-alternate.conf && systemctl is-active estus-fixture.service && ip -j address show dev catalog0").await?;
        anyhow::ensure!(control.status.success(), "guest lacks required real boot/systemd/module/network evidence: {}", String::from_utf8_lossy(&control.stderr));
        anyhow::ensure!(String::from_utf8_lossy(&control.stdout).contains("192.0.2.1"), "guest fixture address missing");
        let ordinary = guest.ordinary("/usr/bin/id -u").await?;
        anyhow::ensure!(ordinary.status.success() && ordinary.stdout == b"1000\n", "ordinary key/principal is not usable: {}", String::from_utf8_lossy(&ordinary.stderr));
        let administrative = guest.administrative("/usr/bin/id -u; /usr/bin/sudo -H -n -k /usr/bin/id -u").await?;
        anyhow::ensure!(administrative.status.success() && administrative.stdout == b"1001\n0\n", "separate administrative identity/sudo is not usable: {}", String::from_utf8_lossy(&administrative.stderr));
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[path = "catalog"]
mod tools {
    mod device_attributes_get;
    mod filesystem_usage_get;
    mod pressure_get;
    mod process_fds_list;
    mod process_get;
}
