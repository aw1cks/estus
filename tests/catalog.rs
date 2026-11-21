//! Real operational catalog acceptance against disposable, privately keyed EFI guests.
#![allow(dead_code)]
#[path = "support/catalog.rs"]
mod catalog;
#[path = "support/nic_model.rs"]
mod nic_model;
#[path = "support/payload.rs"]
mod payload;
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
    mod change_boot_clear_oneshot;
    mod change_boot_default;
    mod change_boot_oneshot;
    mod change_host_reboot;
    mod change_kernel_module_load;
    mod change_kernel_module_parameter;
    mod change_kernel_module_unload;
    mod change_network_address_add;
    mod change_network_address_remove;
    mod change_network_link_down;
    mod change_network_link_up;
    mod change_network_neighbor_remove;
    mod change_network_route_add;
    mod change_network_route_remove;
    mod change_nic_channels;
    mod change_nic_coalesce;
    mod change_nic_eee;
    mod change_nic_features;
    mod change_nic_fec;
    mod change_nic_pause;
    mod change_nic_rings;
    mod change_nic_rss;
    mod change_sysctl_config;
    mod change_sysctl_runtime;
    mod change_systemd_manager_reload;
    mod change_systemd_runtime_limits;
    mod change_systemd_signal;
    mod change_systemd_unit;
    mod change_systemd_unit_file;
    mod inspect_boot_entry;
    mod inspect_cgroup_processes;
    mod inspect_dns_lookup;
    mod inspect_hardware_identifiers;
    mod inspect_icmp_probe;
    mod inspect_journal;
    mod inspect_journal_record;
    mod inspect_kernel_log;
    mod inspect_network_path_probe;
    mod inspect_process;
    mod inspect_process_fds;
    mod inspect_processes;
    mod inspect_sockets;
    mod inspect_systemd_unit_config;
    mod inspect_tcp_connect_probe;
    mod observe_boot_entries;
    mod observe_boot_status;
    mod observe_cgroup_sample;
    mod observe_cgroup_stats;
    mod observe_cgroup_tree;
    mod observe_device_attributes;
    mod observe_filesystem_usage;
    mod observe_hardware_memory;
    mod observe_hardware_slots;
    mod observe_hardware_system;
    mod observe_journal_boots;
    mod observe_journal_usage;
    mod observe_kernel_module;
    mod observe_kernel_module_parameters;
    mod observe_kernel_modules;
    mod observe_kernel_state;
    mod observe_network;
    mod observe_network_device;
    mod observe_network_namespaces;
    mod observe_network_route_lookup;
    mod observe_network_routes;
    mod observe_network_rules;
    mod observe_nic;
    mod observe_nic_eee;
    mod observe_nic_stats;
    mod observe_nic_transceiver;
    mod observe_packages;
    mod observe_pci;
    mod observe_pci_devices;
    mod observe_pci_topology;
    mod observe_pressure;
    mod observe_storage_device;
    mod observe_storage_device_health;
    mod observe_storage_devices;
    mod observe_storage_mounts;
    mod observe_storage_raid;
    mod observe_sysctl;
    mod observe_systemd_jobs;
    mod observe_systemd_sockets;
    mod observe_systemd_timers;
    mod observe_systemd_unit;
    mod observe_systemd_unit_dependencies;
    mod observe_systemd_units;
    mod observe_time_sync;
    mod preview_kernel_module_load;
    mod preview_package;
    mod workflows;
}
