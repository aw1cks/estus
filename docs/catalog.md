# Catalog

The bundled catalog is a versioned set of reviewed tool templates: TOML
definitions plus, for native collectors, `payloads/<tool>/{collector.py,
manifest.json}`. Installing a package ships it under `share/estus/catalog`
(`_catalog` in the wheel); `catalog/` in this repository is the canonical asset
source.

Current inventory: 104 templates, manifest schema 3, inventory version 10.
96 are native Python payloads that need only a target interpreter; 8 are
`ansible_module` entries that need an operator-built bundle. Installing the
package enables nothing and grants no credential or sudo.

## list and export

```sh
estus catalog list
estus catalog list --json
estus catalog list --root "$PWD/catalog"
estus catalog export --preset linux-health --output ./health
estus catalog export --tool observe_host_summary --output ./host-review
```

Neither command needs SSH, Ansible or ambient configuration; an explicit
`--config`, `--ssh` or `--ssh-config` is rejected rather than ignored, and an
invalid `--root` fails instead of selecting another catalog. Export requires at
least one `--tool` or `--preset`, at most 256 names, and a new output directory
(existing paths are never replaced, and a partial export is removed).

Export writes mode-0700 directories and mode-0600 files:
`tools.toml` (inert `[tools.<name>]` tables only, with `execution.source`
rewritten to the copied collector), `payloads/<tool>/…` for payload tools, and
`catalog-selection.json` describing schema/version/qualification. It creates no
credentials, approvals or configuration.

An export is a review starting point, not a site configuration: the shipped
definitions hold no targets, authority or policy. Copy each table into your
`[tools.<name>]` keys, or keep the file beside the site and restate policy with a
`[tools.<name>]` overlay — then add `[selection]`, `[targets]` and
`[automation]` yourself.

`list` prints one line per template:
`name<TAB>qualification<TAB>policy note<TAB>description<TAB>requires`.
`--json` emits `{schema, version, presets, tools}` with
`{name, description, qualification, policy_required, requires}` per tool.

Presets name tools and nothing else:

| Preset | Members |
| --- | --- |
| `linux-health` | `observe_cpu`, `observe_memory`, `observe_pressure` |
| `network-observe` | `observe_network`, `observe_network_device`, `observe_network_routes`, `observe_network_route_lookup`, `observe_network_rules`, `observe_network_namespaces` |
| `network-probes` | `inspect_dns_lookup`, `inspect_icmp_probe`, `inspect_tcp_connect_probe`, `inspect_network_path_probe` |
| `sensitive-observe` | `inspect_processes`, `inspect_process`, `inspect_process_fds`, `inspect_sockets`, `inspect_journal`, `inspect_kernel_log`, `inspect_journal_record` |

There is no `all` or `admin` preset; reboot, module/package/repository mutation,
NIC tuning and other maintenance are individual opt-ins.

## Qualification labels

`qualification` describes the template, not a configured binding, and not a
successful deployment:

- `site_policy_template` (90 entries) — reviewed shape with placeholder
  allowlists; the site must restate `fixed_args`, `constraints` or
  `input_schema` before enabling (`policy_required = true`).
- `laboratory_only` (14 entries) — hard-coded synthetic-device or fixture
  contracts (`netdevsim`, the `estus_nic_model` driver, MD/NVMe fixtures). Not
  production defaults.
- `unqualified` — no readiness claim.

`deployment_qualified` is reserved for documented complete workflow evidence and
no current entry carries it. Inspection marks non-catalog bindings unqualified.

## Enabling tools

Site configuration enables catalog tools by name; the site supplies only the
policy it knows — targets, authority and fixed arguments.

```toml
mode = "headless"
capabilities = { named = true }

[selection]
allow = ["observe_cpu", "observe_memory", "observe_pressure"]

[catalog]
version = "10"

[targets.server]
ssh_host = "server-ordinary"

[automation.targets.server]
destination = "server-ordinary"
python = "/usr/bin/python3"
```

`[selection] presets = ["linux-health"]` is equivalent and needs no export.
Unit names, interfaces, paths, module parameters, package names and repositories
outside `linux-health` are generally **fixture policies**: adapt the closed input
enums, fixed policy and allowlists together.

Shipped definitions are tool tables only: they name no targets and no
allowlists. Targets default to every configured destination (and per-target
permission is still checked separately); a `policy_required` template must be
given `fixed_args`, `constraints` or `input_schema` (for tools whose caller enum
is the allowlist, such as kernel modules or devices) before it can be
materialised. Templates with nothing site-specific are not `policy_required`
and are enabled by name alone.
Policy arguments — `allowed_units`, `allowed_keys`, `allowed_entries`,
`approved_keys`, `approved_root`, `allowed_packages`, `operator_policy`,
`configured_paths`, `reviewed_devices` — are therefore absent from the catalog,
and a collector that needs one fails closed until you supply it. The systemd
tools ship their full `allowed_operations` set; restate it to narrow.

## Site overlays

A `[tools.<name>]` table without `execution` overlays the installed definition.
Only `targets`, `authority`, `fixed_args`, `constraints`, `input_schema`,
`input_map` and `limits` may be overridden; description, revision, effects,
result and contract come from the catalog and are rejected as site overrides, so
a site cannot rewrite what a tool claims.

`fixed_args`, `constraints` and `limits` merge key by key: restating
`allowed_units` keeps `target_python` and `manager_scope` from the catalog.
`targets`, `authority`, `input_schema` and `input_map` replace the catalog value
wholesale.

```toml
[tools.change_systemd_unit]
targets = ["server"]
authority = "automation:catalog"
constraints = { allowed_units = ["site-app.service"] }
```

Domain policy is site-wide, so two hosts needing different allowlists declare two
definition names and each target selects the one it may call:

```toml
[selection]
allow = ["change_systemd_unit", "change_systemd_unit_web"]

[tools.change_systemd_unit]
targets = ["db-1"]
authority = "automation:catalog"
constraints = { allowed_units = ["postgresql.service"] }

[tools.change_systemd_unit_web]
targets = ["web-1"]
authority = "automation:catalog"
constraints = { allowed_units = ["nginx.service"] }

[targets.db-1]
ssh_host = "db-1-ordinary"
selection = { allow = ["change_systemd_unit"] }

[targets.web-1]
ssh_host = "web-1-ordinary"
selection = { allow = ["change_systemd_unit_web"] }
```

## Collector integrity

Two separate checks, both drift detection rather than attestation:

- At activation, the collector bytes must equal the installed manifest's
  `source_sha256`; an edited collector fails to load.
- Immediately before dispatch, the source bytes are checked again and the
  manifest's `requires` list is verified on the target in the same round trip
  that runs the collector: interpreter floor, importable modules and resolvable
  executables. Nothing is cached, so the answer describes the target now; an
  explicit interpreter failure never falls back to another one.

A missing declared utility fails before dispatch as `resource_unavailable` with
`remote_state_unknown=false`. Anyone who can rewrite both the collector and its
manifest can also replace the binary.

## Preview and facts policy

Facts-backed definitions reuse maintained Ansible facts or a query-only status
API instead of adding a second collector:

| Binding | Reused facts |
| --- | --- |
| `observe_systemd_unit` | `systemd_service` query-only `status` |
| `observe_hardware_system`, `inspect_hardware_identifiers` | `setup` DMI fields |
| `observe_storage_devices`, `observe_storage_device` | `setup` device/link facts |
| `observe_storage_mounts` | `mount_facts` |
| `observe_packages` | `package_facts` |
| `observe_nic_features` | `setup` network feature facts |

For query-only unit status, omit `state`, `enabled` and `masked` and fix daemon
reload/reexec flags false — `enabled=false`/`masked=false` request changes.
`observe_host_summary`, `observe_cpu` and `observe_memory` remain native payloads
because setup does not provide the boot UUID, raw CPU tick counters/two-sample
deltas, or exact byte gauges with the selected VM counters.

Under `require_preview = true`, a qualified preview must precede the matching
change with the same inputs. The gate covers only named `change`/`exec` bindings
that declare such a pairing; builtin `change_*`/`exec_*` tools are not gated, and a
named binding with no pairing is refused rather than delayed.
`preview_sysctl` with `{name, value, state:
"present"}` pairs with `change_sysctl_config` (a dedicated sysctl.d file plus
exact-file apply and readback); adding `sysctl_set = true` pairs with
`change_sysctl_runtime` (single-key runtime write, no persistence). Packages:
`preview_package`/`preview_apt`/`preview_dnf` share the `estus.packages` domain
and bind the requested names and canonical state, so a preview never authorizes a
different module or extra option. A preview is single-use, expires after five
minutes, and is invalidated by any intervening change.

## Offline module bundles

Module execution uses a prebuilt pack: a directory containing `bundle.json`,
`wrapper.py` and `modules/<fqcn>.zip` per included module.

```sh
estus bundle build --python /opt/ansible/bin/python \
  --collections-path /opt/collections --output /etc/estus/bundle
estus bundle inspect --bundle /etc/estus/bundle
```

- `--python` must be absolute and already have ansible-core (plus any selected
  collections); the builder runs it isolated with a fixed locale and installs
  nothing. Ansible 14.4.0 / Core 2.21.5 with baseline collections is the pinned
  build environment; Core alone is insufficient for collection modules such as
  `community.general.apk`.
- `--collections-path` is repeatable. `--module` is repeatable and defaults to
  the stock SRE set: `ansible.builtin.systemd_service`, `ansible.posix.sysctl`,
  `ansible.builtin.apt`, `ansible.builtin.dnf`, `ansible.builtin.dnf5`,
  `ansible.builtin.package_facts`, `ansible.builtin.stat`,
  `ansible.builtin.service_facts`.
- `--output` must be new; the builder refuses to replace an existing directory
  and removes partial output on failure. `--timeout-secs` bounds the build
  (1–600, default 120).

`inspect` verifies without Python, Ansible or SSH and prints one JSON line:
`status`, `error_code`, `ansible_core_version`, `bundle_sha256`, `module_count`;
failure exits non-zero. Loading enforces manifest schema, canonical-JSON bundle
digest, wrapper digest, per-module archive digests, sizes, FQCN shapes and router
targets. A tampered or partially written pack fails closed.

Selection order: `[automation].bundle`, then `ESTUS_ANSIBLE_BUNDLE`, then
executable-relative discovery (`../share/estus/bundle`, `../../_bundle`,
`../_bundle`). A binding may pin its own `bundle`. `[automation].required = true`
makes a missing or broken pack a startup failure.

### Cross-distro packages

`ansible.builtin.package` is a router: the bundle maps it to the manager detected
on the target (apt, dnf/dnf5, apk, zypper, pacman; `yum`/`yum4`/`dnf4` normalize
to `dnf`). An undetected manager fails closed with `unsupported` — never a shell
fallback. `change_package` wraps the router; `change_apt` and `change_dnf` are
escape hatches for manager-specific options. Target prerequisites
(`python3-apt`, `python3-dnf`/`python3-libdnf5`) are operator-provisioned;
`auto_install_module_deps = false` means a missing binding fails as
`dependency_unavailable`.

## What is not in the catalog

Roles and playbooks are not execution kinds, and the binding schema accepts only
`native_argv`, `controller_script`, `native_payload` and `ansible_module`. There
is no `execution.role_path`, no `--role-path`, no role snapshot and no
compatibility shim. Rework a legacy site to a canonical catalog tool (preferred),
a native payload, or a bundle module binding.

Privileged and sensitive entries declare `automation:catalog` authority where
required; that is never inferred from a native sudo grant. Inputs cannot choose
flags, paths, environment, inventory, credentials or privilege beyond the
reviewed domain.
