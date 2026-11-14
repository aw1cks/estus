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
        let mutable_units = guest.shell("test ! -L /etc/systemd/system && test ! -L /etc/systemd/system/multi-user.target.wants && touch /etc/systemd/system/.estus-write-probe /etc/systemd/system/multi-user.target.wants/.estus-write-probe && rm /etc/systemd/system/.estus-write-probe /etc/systemd/system/multi-user.target.wants/.estus-write-probe").await?;
        anyhow::ensure!(mutable_units.status.success(), "fixture unit-file directories are not writable: {}", String::from_utf8_lossy(&mutable_units.stderr));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn catalog_lab_qualification() -> anyhow::Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: anyhow::Result<()> = async {
        let observed = guest.shell("/usr/bin/ip link set tune0 up && /usr/bin/ip link set pause0 up && test -b /dev/vdb && test -b /dev/vdc && test -b /dev/nvme0n1 && test -r /proc/mdstat && /usr/bin/ethtool -i tune0 && /usr/bin/ethtool -i pause0 && /usr/bin/nvme id-ctrl /dev/nvme0 -o json").await?;
        anyhow::ensure!(observed.status.success(), "virtual tuning/storage lab prerequisites failed: {}", String::from_utf8_lossy(&observed.stderr));
        let text = String::from_utf8(observed.stdout)?;
        anyhow::ensure!(text.contains("virtio_net") && text.contains("e1000e") && text.contains("ESTUS-LAB-NVME"), "lab did not expose the real selected drivers/controller");
        let management = guest.ordinary("/usr/bin/id -u").await?;
        anyhow::ensure!(management.status.success() && management.stdout == b"1000\n", "lab devices displaced the independent management path");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[path = "catalog"]
mod tools {
    mod boot_clear_oneshot;
    mod boot_entries_list;
    mod boot_entry_get;
    mod boot_set_default;
    mod boot_set_oneshot;
    mod boot_status;
    mod cgroup_processes;
    mod cgroup_sample;
    mod cgroup_stats;
    mod cgroup_tree;
    mod device_attributes_get;
    mod dns_lookup;
    mod filesystem_usage_get;
    mod hardware_identifiers_get;
    mod hardware_memory_inventory;
    mod hardware_slots_list;
    mod hardware_system_get;
    mod host_reboot;
    mod icmp_probe;
    mod journal_boots_list;
    mod journal_read;
    mod journal_usage_get;
    mod kernel_log_read;
    mod kernel_module_get;
    mod kernel_module_load;
    mod kernel_module_load_plan;
    mod kernel_module_parameter_set;
    mod kernel_module_parameters_get;
    mod kernel_module_unload;
    mod kernel_modules_list;
    mod kernel_state_get;
    mod network_address_add;
    mod network_address_remove;
    mod network_addresses_list;
    mod network_device_get;
    mod network_interface_stats;
    mod network_link_down;
    mod network_link_up;
    mod network_links_list;
    mod network_namespaces_list;
    mod network_neighbor_remove;
    mod network_neighbors_list;
    mod network_path_probe;
    mod network_route_add;
    mod network_route_lookup;
    mod network_route_remove;
    mod network_routes_list;
    mod network_rules_list;
    mod network_sockets_list;
    mod nic_channels_get;
    mod nic_channels_set;
    mod nic_coalesce_get;
    mod nic_coalesce_set;
    mod nic_features_get;
    mod nic_link_get;
    mod nic_pause_get;
    mod nic_pause_set;
    mod nic_rings_get;
    mod nic_rss_get;
    mod nic_stats_get;
    mod package_get;
    mod package_repository_change;
    mod package_repository_refresh;
    mod packages_install;
    mod packages_list;
    mod packages_remove;
    mod packages_updates_list;
    mod packages_upgrade;
    mod pci_device_get;
    mod pci_devices_list;
    mod pci_driver_binding_get;
    mod pci_iommu_group_get;
    mod pci_topology_get;
    mod pressure_get;
    mod process_fds_list;
    mod process_get;
    mod processes_list;
    mod storage_device_get;
    mod storage_device_health_get;
    mod storage_devices_list;
    mod storage_mounts_list;
    mod storage_raid_status;
    mod sysctl_config_set;
    mod sysctl_get;
    mod sysctl_set_runtime;
    mod systemd_jobs_list;
    mod systemd_manager_reload;
    mod systemd_sockets_list;
    mod systemd_timers_list;
    mod systemd_unit_config_read;
    mod systemd_unit_dependencies;
    mod systemd_unit_disable;
    mod systemd_unit_enable;
    mod systemd_unit_get;
    mod systemd_unit_mask;
    mod systemd_unit_reload;
    mod systemd_unit_reset_failed;
    mod systemd_unit_restart;
    mod systemd_unit_set_runtime_limits;
    mod systemd_unit_signal;
    mod systemd_unit_start;
    mod systemd_unit_stop;
    mod systemd_unit_try_restart;
    mod systemd_unit_unmask;
    mod systemd_units_list;
    mod tcp_connect_probe;
    mod time_sync_status;
}
