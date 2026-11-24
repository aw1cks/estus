# Catalog reference

> Generated. Do not edit. Regenerate with `python3 scripts/gen-catalog-reference.py`.

Use this reference to choose catalog tools and check what they need on the
target. See [the catalog guide](../catalog.md) for selection and site policy.

## Presets

| Preset | Tools |
| --- | --- |
| `linux-health` | `observe_cpu`, `observe_memory`, `observe_pressure` |
| `network-observe` | `observe_network`, `observe_network_device`, `observe_network_routes`, `observe_network_route_lookup`, `observe_network_rules`, `observe_network_namespaces` |
| `network-probes` | `inspect_dns_lookup`, `inspect_icmp_probe`, `inspect_tcp_connect_probe`, `inspect_network_path_probe` |
| `sensitive-observe` | `inspect_processes`, `inspect_process`, `inspect_process_fds`, `inspect_sockets`, `inspect_journal`, `inspect_kernel_log`, `inspect_journal_record` |
| `sre-core` | `observe_host_summary`, `observe_cpu`, `observe_memory`, `observe_pressure`, `observe_filesystem_usage`, `observe_systemd_units`, `observe_systemd_unit`, `observe_network`, `observe_network_routes`, `observe_nic`, `observe_storage_devices`, `observe_storage_mounts`, `observe_time_sync`, `observe_kernel_state`, `observe_packages`, `inspect_processes`, `inspect_sockets`, `inspect_journal`, `inspect_journal_record` |

Authorities and tiers are defined in [Concepts](../concepts.md). A qualification
marked **policy required** needs a site overlay. A preview pairing still requires
matching intent; see [Policy](../policy.md). The bundle sets the Python minimum
for [Ansible-backed tools](../ansible-bundles.md).

## Host and hardware

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_cpu` | `observe` | Read aggregate CPU tick counters and topology IDs, optionally sampling twice. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_device_attributes` | `observe` | Read reviewed sysfs attributes of an allowlisted net or block device. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `observe_hardware_memory` | `observe` | Read per-DIMM SMBIOS inventory without serials. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `dmidecode`; `linux` | — |
| `observe_hardware_slots` | `observe` | Read expansion-slot SMBIOS inventory without serials. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `dmidecode`; `linux` | — |
| `observe_hardware_system` | `observe` | Read selected DMI fields the firmware reports, such as vendor, product and BIOS version. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_host_summary` | `observe` | Read OS facts, boot ID and uptime through the ordinary SSH process view. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_memory` | `observe` | Read memory gauges in bytes and cumulative VM counters. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_pci` | `observe` | Read one PCI device's numeric identity, its bound driver/module, or its IOMMU group and members from sysfs. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_pci_devices` | `observe` | List every PCI device with its numeric address and identity fields from bounded sysfs reads. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_pci_topology` | `observe` | Read the PCI topology: root bridges, buses and the device tree beneath them. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_pressure` | `observe` | Read PSI some/full averages and cumulative stall time. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `inspect_hardware_identifiers` | `inspect` | Read selected firmware serial and asset identifiers. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `linux` | — |

## Systemd

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_systemd_jobs` | `observe` | List pending and running systemd jobs. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_systemd_sockets` | `observe` | List socket units' listen endpoints, activation links and counters. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_systemd_timers` | `observe` | List timer units' last and next trigger times and their service links. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_systemd_unit` | `observe` | Read one allowed unit's non-secret status properties. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_systemd_unit_dependencies` | `observe` | Read one unit's forward or reverse dependencies to a bounded depth. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_systemd_units` | `observe` | List loaded units or installed unit files and templates, one bounded page per call; pass next_offset as offset until it is absent. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `observe_time_sync` | `observe` | Read the manager's observed clock synchronization state. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemd`; `timedatectl` | — |
| `inspect_systemd_unit_config` | `inspect` | Read one allowed unit's fragment and drop-in configuration. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `preview_systemd_service` | `preview` | Preview a systemd unit transition (start, stop, restart, reload, enable, disable, mask, unmask) without mutating unit state; authorizes the matching change_systemd_unit or change_systemd_unit_file operation. | `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | `change_systemd_unit` (start, stop, restart or reload), `change_systemd_unit_file` |
| `change_systemd_manager_reload` | `change` | Reload the systemd manager so pending unit-file changes take effect. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `change_systemd_runtime_limits` | `change` | Set runtime memory, task or CPU-quota limits on one allowed unit and read them back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `change_systemd_signal` | `change` | Send one approved signal to the main process of an allowed unit and return the post-state. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | — |
| `change_systemd_unit` | `change` | Start, stop, restart, try-restart, reload or reset-failed one allowed unit, then return its post-state. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | `preview_systemd_service` (start, stop, restart or reload) |
| `change_systemd_unit_file` | `change` | Enable, disable, mask or unmask one allowed unit's unit file without reloading the manager, and return the on-disk state. | `persistent_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `systemctl`; `systemd` | `preview_systemd_service` |

## Network

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_network` | `observe` | Read links, addresses, neighbors or one interface's rx/tx counters through `ip`, restricted to the policy's interface allowlist. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `observe_network_device` | `observe` | Read a network interface's driver-reported device facts through a fixed ethtool query. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_network_namespaces` | `observe` | List the operator-approved named network namespaces and their IDs. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `observe_network_route_lookup` | `observe` | Resolve the route the kernel would use for one approved destination, optionally from a given source address. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `observe_network_routes` | `observe` | List the kernel routing table for one address family, optionally filtered by table or destination. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `observe_network_rules` | `observe` | Read the policy-routing rules that select routing tables before a lookup. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_address_add` | `change` | Add one approved address to an interface at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_address_remove` | `change` | Remove one approved address from an interface at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_link_down` | `change` | Bring one approved interface down at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_link_up` | `change` | Bring one approved interface up at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_neighbor_remove` | `change` | Delete one approved neighbor entry at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_route_add` | `change` | Add one approved route at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |
| `change_network_route_remove` | `change` | Remove one approved route at runtime and read the result back. | `runtime_write`, `availability`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `linux` | — |

## NIC

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_nic` | `observe` | Read one interface's link settings, ring sizes, channel counts or coalescing parameters through fixed read-only ethtool queries. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_nic_eee` | `observe` | Read a lab interface's synthetic EEE configuration and its active state from real ethtool output. | `read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.10; `estus_nic_model`; `ethtool`; `linux` | — |
| `observe_nic_features` | `observe` | Read an interface's offload feature flags with their fixed and requested annotations. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_nic_fec` | `observe` | Read the driver-reported FEC configuration and active encoding. | `read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.10; `ethtool`; `linux`; `netdevsim` | — |
| `observe_nic_pause` | `observe` | Read an interface's driver-reported pause and autonegotiation state. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_nic_rss` | `observe` | Read an interface's RSS hash algorithms, indirection table size and slots per queue, excluding the secret key; the table itself comes one bounded page per call (pass next_offset as offset). | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_nic_stats` | `observe` | Read an interface's driver-specific cumulative counters, optionally filtered by name. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `ethtool`; `linux` | — |
| `observe_nic_transceiver` | `observe` | Read nonserial identity and typed sensor fields from a lab-only synthetic SFP EEPROM via real ethtool. | `read` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.10; `estus_nic_model`; `ethtool`; `linux` | — |
| `change_nic_channels` | `change` | Set one interface's channel counts at runtime and read them back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `ethtool`; `linux`; `veth` | — |
| `change_nic_coalesce` | `change` | Set one interface's coalescing parameters at runtime and read them back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |
| `change_nic_eee` | `change` | Configure synthetic EEE state with a fixed Tx LPI timer and read it back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.10; `estus_nic_model`; `ethtool`; `linux` | — |
| `change_nic_features` | `change` | Enable or disable one offload feature at runtime and read the resulting flags back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |
| `change_nic_fec` | `change` | Set a virtual FEC mode and read the driver's view back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `ethtool`; `linux`; `netdevsim` | — |
| `change_nic_pause` | `change` | Set one interface's pause and autonegotiation parameters at runtime and read them back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |
| `change_nic_rings` | `change` | Set one interface's rx/tx ring sizes at runtime and read them back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |
| `change_nic_rss` | `change` | Apply one approved RSS indirection preset and read the queue map back. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `ethtool`; `linux` | — |

## Storage

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_filesystem_usage` | `observe` | Report capacity, available bytes and inode counts for one configured path's filesystem. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `observe_storage_device` | `observe` | Read one block device's geometry, partitions and holder relationships. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_storage_device_health` | `observe` | Read SMART log 02 and controller state of the reviewed lab NVMe device. | `read` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `linux`; `nvme`; `nvme-cli`; `qemu_nvme_estus_lab_nvme` | — |
| `observe_storage_devices` | `observe` | List block devices with geometry, partitions and holder relationships. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_storage_mounts` | `observe` | List current mounts, including overmount duplicates. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_storage_raid` | `observe` | Read the reviewed MD RAID1 array's state, degraded count, sync action and member errors from sysfs. | `read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.8; `linux`; `linux_md_raid1_md0_vdb_vdc` | — |

## Kernel

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_kernel_module` | `observe` | Read one approved module's metadata, dependencies and declared parameters. | `read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.8; `kmod`; `linux`; `modinfo`; `reviewed_dummy_or_estus_catalog_module` | — |
| `observe_kernel_module_parameters` | `observe` | Read the reviewed current values of one module's parameters, including whether sysfs exposes them writable. | `read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.8; `linux`; `reviewed_dummy_or_estus_catalog_module` | — |
| `observe_kernel_modules` | `observe` | List loaded modules with size, reference count, state and holders. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `observe_kernel_state` | `observe` | Read kernel taint, release, lockdown and module signature policy. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `preview_kernel_module_load` | `preview` | Preview one module's dependencies and effective modprobe hooks without loading it. | `read`, `sensitive_read` | `automation` | `laboratory_only`; **policy required** | Python ≥ 3.8; `kmod`; `linux`; `modinfo`; `modprobe`; `reviewed_dummy_or_estus_catalog_module` | `change_kernel_module_load` (no module parameters) |
| `change_kernel_module_load` | `change` | Load one approved installed module with typed parameters and report module-set and taint deltas. | `read`, `runtime_write`, `availability` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `ip`; `iproute2`; `kmod`; `linux`; `modinfo`; `modprobe`; `reviewed_dummy_or_estus_catalog_module` | `preview_kernel_module_load` (no module parameters) |
| `change_kernel_module_parameter` | `change` | Write one approved bounded integer to the reviewed estus_catalog sysfs parameter and read it back. | `read`, `runtime_write` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `estus_catalog`; `linux` | — |
| `change_kernel_module_unload` | `change` | Unload one approved module through normal modprobe removal, honouring configured hooks and unused dependencies. | `read`, `runtime_write`, `availability` | `automation:catalog` | `laboratory_only`; **policy required** | Python ≥ 3.8; `kmod`; `linux`; `modinfo`; `modprobe`; `reviewed_dummy_or_estus_catalog_module` | — |

## Boot

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_boot_entries` | `observe` | List bootctl entries with their IDs, kernels and initrds. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `bootctl`; `efi`; `linux`; `systemd-boot` | — |
| `observe_boot_status` | `observe` | Read the EFI loader identity, current/default/one-shot selections and Secure Boot state. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `efi`; `linux`; `systemd-boot` | — |
| `inspect_boot_entry` | `inspect` | Read one approved boot entry, including its command line and any unknown fields. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `bootctl`; `efi`; `linux`; `systemd-boot` | — |
| `change_boot_clear_oneshot` | `change` | Clear the systemd-boot next-boot override and confirm it is gone. | `read`, `runtime_write` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `bootctl`; `efi`; `linux`; `systemd-boot` | — |
| `change_boot_default` | `change` | Point the persistent systemd-boot default at one approved installed entry and read it back. | `read`, `persistent_write` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `bootctl`; `efi`; `linux`; `systemd-boot` | — |
| `change_boot_oneshot` | `change` | Boot one approved installed systemd-boot entry on the next boot only, then read the selection back. | `read`, `runtime_write` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `bootctl`; `efi`; `linux`; `systemd-boot` | — |
| `change_host_reboot` | `change` | Schedule a host reboot in five seconds and return a scheduling receipt. | `read`, `runtime_write`, `availability` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `linux`; `systemctl`; `systemd`; `systemd-run` | — |

## Packages

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_packages` | `observe` | List installed packages from the maintained apt inventory. | `read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `preview_apt` | `preview` | Preview an apt change in check mode, including a diff where apt supports one. | `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.apt`; `apt`; `linux` | `change_apt` |
| `preview_dnf` | `preview` | Preview a dnf/dnf5 change in check mode. | `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.dnf`; `dnf`; `linux` | `change_dnf` |
| `preview_package` | `preview` | Preview a package change in check mode via the target's package manager. | `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.package`; `linux` | `change_package` |
| `change_apt` | `change` | Install, upgrade or remove Debian/Ubuntu packages, optionally purging and allowing downgrades. | `persistent_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.apt`; `apt`; `linux` | `preview_apt` |
| `change_dnf` | `change` | Install, upgrade or remove packages with dnf/dnf5, including the repo and best-effort options. | `persistent_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.dnf`; `dnf`; `linux` | `preview_dnf` |
| `change_package` | `change` | Install, upgrade or remove packages through the target's own package manager and return the result. | `persistent_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python (bundle minimum); Ansible bundle: `ansible.builtin.package`; `linux` | `preview_package` |

## Journal and processes

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_journal_boots` | `observe` | List retained journal boots with their timestamps. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `journalctl`; `linux`; `systemd` | — |
| `observe_journal_usage` | `observe` | Report journal disk usage and the configured retention assignments. | `read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `journalctl`; `linux`; `systemd` | — |
| `inspect_journal` | `inspect` | Read bounded journal records filtered by unit, boot, time, priority or literal substring, with a continuation cursor. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `journalctl`; `linux`; `systemd` | — |
| `inspect_journal_record` | `inspect` | Read a bounded byte slice of one retained journal record by boot ID and cursor. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `journalctl`; `journald`; `linux`; `systemd` | — |
| `inspect_kernel_log` | `inspect` | Read bounded kernel-only journal records for one boot and time window. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `journalctl`; `linux`; `systemd` | — |
| `inspect_process` | `inspect` | Read one exact process identity: owner, state, CPU ticks, memory, limits and cgroup. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `inspect_process_fds` | `inspect` | List the file descriptors of one exact process identity. | `read`, `sensitive_read` | `automation:catalog` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `inspect_processes` | `inspect` | List processes by exact real UID and literal name substring, with boot ID and start ticks for identity. | `read`, `sensitive_read` | `automation` | `site_policy_template` | Python ≥ 3.8; `linux` | — |
| `inspect_sockets` | `inspect` | List sockets bound to operator-approved local ports, filtered by protocol, state, address or port. | `read`, `sensitive_read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `iproute2`; `linux`; `ss` | — |

## Cgroups

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_cgroup_sample` | `observe` | Sample one approved cgroup's cumulative CPU use over a real interval. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `observe_cgroup_stats` | `observe` | Read one approved cgroup's controller files, limits and pressure. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `observe_cgroup_tree` | `observe` | Walk one approved cgroup subtree to a bounded depth. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `inspect_cgroup_processes` | `inspect` | List the processes directly in one approved cgroup, without arguments. | `read`, `sensitive_read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |

## Sysctl

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `observe_sysctl` | `observe` | Read reviewed side-effect-free sysctl keys by name. | `read` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `preview_sysctl` | `preview` | Preview a sysctl parameter change without modifying runtime or persistent configuration. | `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | `change_sysctl_config` (`mode = "config"`), `change_sysctl_runtime` (`mode = "runtime"`) |
| `change_sysctl_config` | `change` | Persist one approved integer sysctl key to a dedicated sysctl.d file and apply exactly that file. | `persistent_write`, `runtime_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `procps`; `sysctl` | `preview_sysctl` (`mode = "config"`) |
| `change_sysctl_runtime` | `change` | Set one approved integer sysctl key in the live kernel and read it back. | `runtime_write`, `read` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `procps`; `sysctl` | `preview_sysctl` (`mode = "runtime"`) |

## Probes

| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inspect_dns_lookup` | `inspect` | Resolve one approved name through the configured resolver. | `probe` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
| `inspect_icmp_probe` | `inspect` | Send bounded ICMP probes to one approved destination and report loss and latency. | `probe` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `ping` | — |
| `inspect_network_path_probe` | `inspect` | Trace the path to one approved destination with bounded hop and time limits. | `probe` | `automation:catalog` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux`; `traceroute` | — |
| `inspect_tcp_connect_probe` | `inspect` | Attempt one bounded TCP connection to an approved destination and port. | `probe` | `automation` | `site_policy_template`; **policy required** | Python ≥ 3.8; `linux` | — |
