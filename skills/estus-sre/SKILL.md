---
name: estus-sre
description: Safe observation-first Linux triage, journal inspection, and change reconciliation over Estus MCP.
---

# Estus SRE Operating Method

## 1. Risk Tiers & Escalation
- **`observe_*`** (auto-allow eligible): read-only system telemetry. Always start here (`observe_targets`, `observe_host_summary`, `observe_cpu`, `observe_memory`, `observe_pressure`, `observe_systemd_units`, `observe_network_links`).
- **`inspect_*`** (ask): sensitive reads (files, directories, processes, sockets, journal logs) or active network probes. Narrow scope before calling.
- **`preview_*`** (ask): pre-change dependency and plan checks (`preview_kernel_module_load`, `preview_systemd_service`, `preview_sysctl`, `preview_package`, `preview_apt`, `preview_dnf`). Run before the matching mutation.
- **`change_*`** (ask): structured single-purpose mutations and `change_target_quarantine_clear`. Never automatically replayed.
- **`exec_*`** (ask): generic command/argv/sudo execution (`exec_command`, `exec_argv`, `exec_sudo`). Escalate only when structured tools cannot express the operation.

## 2. Uncertainty, Quarantine & No Replay
- Estus **never** retries or replays interrupted/timed-out operations automatically.
- Any mutating call whose acknowledgement or worker ownership is lost after dispatch sets `remote_state_unknown=true` and quarantines further writes on that logical host (`target_quarantined`).
- Read/observe tools stay open while quarantined. Inspect actual remote state first (`observe_stat`, `inspect_file`, `observe_systemd_unit`, `inspect_journal`), reconcile independently, and only then clear quarantine with `change_target_quarantine_clear` (`acknowledge_remote_state_reconciled=true`).

## 3. Continuation & Output Handles
- Paginated inspection tools use explicit single-use tokens or byte offsets:
  - `inspect_directory`: one bounded page per call, `max_entries` 1–1000 (default 200); `truncated=true` means more entries existed, so re-call the same `host`/`path` with a larger `max_entries` or accept the prefix. The result is not a snapshot.
  - `inspect_journal`: optional `unit`, literal `contains`, `limit` 1–500, `direction` (`backward` default or `forward`), direction-bound `continuation_cursor` packed within 131072 bytes.
  - `inspect_journal_record`: reconstruct long/truncated messages by `boot_id`, `cursor`, `offset`, and `max_bytes` (1–4096 base64 UTF-8 slices) until `eof=true`.
- Command and local-execution tools support `retain_output=true`, returning session-scoped handles readable via `inspect_output`.

## 4. Package Changes Across Distributions
- `change_package` is the cross-distro transition: the reviewed bundle routes it to the target-detected manager (apt, dnf/dnf5, apk, zypper) and it accepts `name`, `state`, optional `version` and `update_cache`. A version pin requires `state="present"` and exactly one package name; it is rewritten as `name=version` on apt and `name-version` on dnf/dnf5/zypper.
- `change_apt` and `change_dnf` are explicit escape hatches for manager-specific options (purge, allow_downgrade, enablerepo, disablerepo, allowerasing, nobest). Use them only when the generic tool cannot express the change.
- `preview_package`, `preview_apt` and `preview_dnf` are the qualified check-mode previews. A preview authorizes only the requested module and the reviewed options it was given: a `preview_package` run never authorizes `change_apt` or `change_dnf`, and neither does the reverse. Preview and change must select the same module with matching inputs/options; the package database detected at pre-state time is recorded independently, so a changed target manager invalidates reuse.
- Package prerequisites and repositories are preprovisioned by the operator. Estus installs no dependencies and performs no repository refresh unless that reviewed option is approved.
- Target-host Python bindings are prerequisites for the package tools: `preview_package`, `change_package`, `preview_apt` and `change_apt` need `python3-apt` (Debian/Ubuntu); `preview_dnf` and `change_dnf` need `python3-dnf` or `python3-libdnf5` (RHEL/Fedora). Estus never installs these (`auto_install_module_deps = false`): a missing binding fails closed with `dependency_unavailable` in check mode, and no check-mode run mutates the target. `observe_packages` is pure stdlib plus the shipped runtime helper and needs none of these bindings.

## 5. Preview Pairing Under `require_preview = true`
- `preview_sysctl` with `{name, value, state: "present"}` is the qualified preview for `change_sysctl_config` (persistent dedicated sysctl.d file + exact-file apply, then readback).
- `preview_sysctl` with `{name, value, state: "present", sysctl_set: true}` is the qualified preview for `change_sysctl_runtime` (single-key runtime write, no persistence).
- A preview authorizes only the change tool it was paired with and the exact inputs it was given; a sysctl preview never authorizes systemd, package, or any other mutation, and preview and change must agree on key, value, and persistence semantics.

## 6. MCP Guidance Surfaces
- **Prompts**: `triage_host`, `diagnose_service`, `safe_change`, `network_triage`.
- **Resources**: `estus://guides/systemd`, `estus://guides/linux-memory`, `estus://guides/networking`, `estus://guides/preview`, `estus://guides/uncertainty-reconciliation`, and `estus://targets/{host}/policy`.

## 7. Exact-Name Client Approval Policy (127 Published Tools)
Published tools are the 15 builtin names plus the 112 bundled catalog tools. Which catalog tools exist depends on the selected configuration and, in zero-config workstation mode, on the installed catalog and bundle. Configure exact tool names according to your MCP client's permission rules (prefix globs are optional because client support varies).

### Allow (`observe_*` — 61 tools)
```json
[
  "observe_boot_entries",
  "observe_boot_status",
  "observe_cgroup_sample",
  "observe_cgroup_stats",
  "observe_cgroup_tree",
  "observe_cpu",
  "observe_device_attributes",
  "observe_filesystem_usage",
  "observe_hardware_memory",
  "observe_hardware_slots",
  "observe_hardware_system",
  "observe_host_summary",
  "observe_journal_boots",
  "observe_journal_usage",
  "observe_kernel_module",
  "observe_kernel_module_parameters",
  "observe_kernel_modules",
  "observe_kernel_state",
  "observe_memory",
  "observe_network",
  "observe_network_device",
  "observe_network_namespaces",
  "observe_network_route_lookup",
  "observe_network_routes",
  "observe_network_rules",
  "observe_nic_channels",
  "observe_nic_coalesce",
  "observe_nic_eee",
  "observe_nic_features",
  "observe_nic_fec",
  "observe_nic_link",
  "observe_nic_pause",
  "observe_nic_rings",
  "observe_nic_rss",
  "observe_nic_stats",
  "observe_nic_transceiver",
  "observe_packages",
  "observe_pci",
  "observe_pci_devices",
  "observe_pci_topology",
  "observe_pressure",
  "observe_stat",
  "observe_storage_device",
  "observe_storage_device_health",
  "observe_storage_devices",
  "observe_storage_mounts",
  "observe_storage_raid",
  "observe_sysctl",
  "observe_systemd_jobs",
  "observe_systemd_sockets",
  "observe_systemd_timers",
  "observe_systemd_unit",
  "observe_systemd_unit_dependencies",
  "observe_systemd_units",
  "observe_targets",
  "observe_time_sync"
]
```

### Ask (`inspect_*`, `preview_*`, `change_*`, `exec_*` — 74 tools)
```json
[
  "change_apt",
  "change_boot_clear_oneshot",
  "change_boot_default",
  "change_boot_oneshot",
  "change_directory_remove",
  "change_dnf",
  "change_file_remove",
  "change_file_replace",
  "change_file_write",
  "change_host_reboot",
  "change_kernel_module_load",
  "change_kernel_module_parameter",
  "change_kernel_module_unload",
  "change_mkdir",
  "change_network_address_add",
  "change_network_address_remove",
  "change_network_link_down",
  "change_network_link_up",
  "change_network_neighbor_remove",
  "change_network_route_add",
  "change_network_route_remove",
  "change_nic_channels",
  "change_nic_coalesce",
  "change_nic_eee",
  "change_nic_features",
  "change_nic_fec",
  "change_nic_pause",
  "change_nic_rings",
  "change_nic_rss",
  "change_package",
  "change_rename",
  "change_sysctl_config",
  "change_sysctl_runtime",
  "change_systemd_manager_reload",
  "change_systemd_runtime_limits",
  "change_systemd_signal",
  "change_systemd_unit",
  "change_systemd_unit_file",
  "change_target_quarantine_clear",
  "exec_argv",
  "exec_command",
  "exec_sudo",
  "inspect_boot_entry",
  "inspect_cgroup_processes",
  "inspect_directory",
  "inspect_dns_lookup",
  "inspect_file",
  "inspect_hardware_identifiers",
  "inspect_icmp_probe",
  "inspect_journal",
  "inspect_journal_record",
  "inspect_kernel_log",
  "inspect_network_path_probe",
  "inspect_output",
  "inspect_process",
  "inspect_process_fds",
  "inspect_processes",
  "inspect_sockets",
  "inspect_systemd_unit_config",
  "inspect_tcp_connect_probe",
  "preview_apt",
  "preview_dnf",
  "preview_kernel_module_load",
  "preview_package",
  "preview_sysctl",
  "preview_systemd_service"
]
```
