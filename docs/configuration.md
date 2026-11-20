# Configuration

Estus reads exactly one TOML file, selected explicitly. There is no automatic
discovery, no include mechanism and no partial merge.

```sh
estus --config /etc/estus/estus.toml
```

Every key below is accepted by `src/config/`; unknown keys are rejected with a
fixed `schema_path` diagnostic naming the section, never the offending value.
Retired spellings (`[directory]`, `[rules]`, `destination_policy`,
`enabled_tools`, `tool_presets`, `disabled_tools`, per-target `capabilities`) are
rejected with a message naming their replacement.

## Precedence

For each of the three path selections the order is CLI flag, then environment
variable, then TOML:

| Selection | CLI | Environment | TOML |
| --- | --- | --- | --- |
| Configuration | `--config` | `ESTUS_CONFIG` | — |
| SSH executable | `--ssh` | `ESTUS_SSH` | `[ssh].executable` |
| SSH config | `--ssh-config` | `ESTUS_SSH_CONFIG` | `[ssh].config_file` |

A selected path is literal: no tilde or variable interpolation, no `PATH` search.
`--ssh`/`ESTUS_SSH` relative paths resolve against the launch directory;
`[ssh]` relative paths against the TOML file's directory. An invalid override
fails loading instead of falling back to a lower-priority source. The executable
is resolved once and shared by native SSH, `doctor` and automation; without an
explicit selection, `ssh` is looked up on `PATH`, skipping non-absolute entries.

Numeric limits also accept environment overrides:
`ESTUS_CONNECT_TIMEOUT_SECS`, `ESTUS_OPERATION_TIMEOUT_SECS`,
`ESTUS_MAX_TIMEOUT_SECS`, `ESTUS_MAX_OUTPUT_BYTES`, `ESTUS_MAX_FILE_BYTES`.
Catalog and bundle additionally read `ESTUS_CATALOG_ROOT` and
`ESTUS_ANSIBLE_BUNDLE`. `--workstation` may be replaced by any non-empty
`ESTUS_WORKSTATION`.

## Top level

```toml
mode = "headless"          # headless (default) | workstation
require_preview = false    # requires a matching preview for preview-paired named tools
disclose_sudo_policy = false
```

- `mode = "headless"` is the default for any configuration file. `--workstation`
  may only restate a declared `mode = "workstation"`; it never upgrades a file.
  With no file at all, `--workstation` is required to get anything beyond the
  read-only inspection builtins.
- `require_preview` applies to named bindings whose tier is `change` or `exec`; a
  target may override it. It never gates the builtin `change_*`/`exec_*` tools. It
  does not simply delay `exec` work for approval: a named `exec` binding with no
  qualified preview pairing is refused with `preview_required`. Bindings that do
  have a pairing (the qualified `preview_*`/change pairs) must present a fresh
  matching preview, consumed once and expiring after five minutes.
- `disclose_sudo_policy` includes declared sudo users/programs in target
  discovery output.

## `[capabilities]`

Five independent exposure ceilings. Explicit configuration defaults to
`actions_only` (only `named`); zero-config workstation mode defaults to all five.

```toml
capabilities = { named = true, file_read = true, file_write = false, exec = false, sudo = false }
```

| Key | Publishes |
| --- | --- |
| `named` | catalog/named bindings at all |
| `file_read` | `inspect_file`, `observe_stat`, `inspect_directory` |
| `file_write` | `change_file_write`, `change_mkdir`, `change_rename`, `change_file_remove`, `change_directory_remove`, `change_file_replace` |
| `exec` | `exec_command`, `exec_argv` |
| `sudo` | `exec_sudo`, and catalog bindings under `automation:<authority>` |

`observe_targets`, `inspect_output` and `change_target_quarantine_clear` are
always available when the target policy permits them. Capabilities are not
account sandboxes.

## `[ssh]`

```toml
[ssh]
executable = "/opt/openssh/bin/ssh"     # default: ssh from PATH
config_file = "/etc/estus/ssh_config"   # replacement, not an overlay
```

`config_file` must be a readable regular file at load; a broken replacement never
falls back to the invoking user's SSH configuration.

## `[limits]`

```toml
[limits]
connect_timeout_secs = 10
operation_timeout_secs = 60
max_timeout_secs = 600
max_output_bytes = 1048576
max_file_bytes = 1048576
```

All values must be strictly positive; `connect_timeout_secs` and
`operation_timeout_secs` must not exceed `max_timeout_secs`. `max_timeout_secs`
and `max_file_bytes` are also injected as `maximum` into the published builtin
input schemas.

## `[output]`

Retention for `retain_output=true` command handles.

```toml
[output]
enabled = true
per_stream_bytes = 1048576   # 1 … 4194304
total_bytes = 16777216       # ≥ 2×per_stream_bytes, ≤ 67108864
max_handles = 8              # 1 … 64
ttl_secs = 300               # 1 … 3600
```

## `[quarantine]`

```toml
[quarantine]
state_dir = "/var/lib/estus/quarantine"
```

Directory for durable quarantine records. When set, a new quarantine is written and
`fsync`ed — via a temporary name and atomic rename — before the reply that reports
it is returned, and a clear unlinks the record before the gate opens. Records are
restored on the next start, so a quarantine survives a restart of the server
process. The directory must be owned by the current UID with mode 0700 and hold
only owned regular records; anything else fails startup. When omitted, quarantine
is in-memory only for the life of the process.

## `[targets.<name>]`

The destination authority boundary. Any `[targets]` table — even an empty one —
authorizes exactly the logical names it lists; its absence (workstation mode only)
lets the caller name a raw SSH destination. Headless configurations always have
the table.

```toml
[targets.server]
ssh_host = "server-ordinary"        # required; an OpenSSH destination
description = "web front end"       # ≤ 1024 bytes
labels = { env = "prod", role = "web" }   # ≤ 16 labels, key ≤ 64, value ≤ 256
max_tier = "inspect"                # observe | inspect | preview | change | exec
require_preview = true              # overrides the global flag
selection = { allow = ["observe_cpu", "observe_memory"] }

[targets.server.sudo]
mode = "separate-identity"          # disabled (default) | same-account | separate-identity
ssh_host = "server-elevated"        # required for separate-identity, distinct from every ordinary alias
users = ["root"]                    # default ["root"], POSIX account names
programs = ["/usr/bin/systemctl"]   # optional absolute executable allowlist
```

- `ssh_host` must be non-empty, contain no NUL or whitespace, and not start with
  `-`. `sudo.ssh_host` must not equal any configured ordinary alias.
- `max_tier` denies every **builtin** whose published tier exceeds it on that
  host. Named catalog tools are gated by `selection` and their own authority.
- `selection` is the same shape as the global `[selection]` and only narrows it:
  `allow`/`presets` list what this host may call, `deny` subtracts, a present
  table with every list empty denies every named tool, and an omitted table
  inherits the global set.
- Sudo policy is per-target and never inherited by catalog bindings, which
  declare `automation` or `automation:<authority>` authority instead.

## `[selection]`

```toml
[selection]
presets = ["linux-health"]
allow = ["observe_cpu", "change_systemd_unit"]
deny = ["change_host_reboot"]
```

The global set is every builtin the capability ceiling permits, plus `presets`
and `allow`; `deny` always subtracts. Presets are catalog data and only name
tools. Unknown or duplicate names fail loading; up to 256 named bindings are
supported.

A name with a local `[tools.<name>]` table is used as written. A name with no
local definition is a catalog template and is materialized from the installed
catalog; only then is the catalog loaded.

## `[tools.<name>]`

Named tool definitions, and the site overlay for catalog templates.

```toml
[tools.change_systemd_unit]
targets = ["db-1"]
authority = "automation:catalog"
constraints = { allowed_units = ["postgresql.service"] }
limits = { timeout_secs = 30 }
```

Keys: `description`, `revision`, `targets`, `authority`, `effects`, `execution`,
`input_schema`, `fixed_args`, `input_map`, `argument_types`, `constraints`,
`result`, `limits`.

- A table **with** `execution` is a complete operator-authored definition used as
  written (a custom tool, or an edited export).
- A table **without** `execution` for a catalog name is site policy only, and may
  override only `targets`, `authority`, `fixed_args`, `constraints`,
  `input_schema`, `input_map` and `limits`. Anything else — description,
  revision, effects, result, contract — comes from the catalog and is rejected as
  a site override.
- `constraints` accepts `allowed_units`, `allowed_keys`, `allowed_interfaces`,
  `allowed_packages`. It is site-wide: two hosts needing different allowlists
  declare two definition names.
- Execution kinds are `native_argv`, `controller_script`, `native_payload` and
  `ansible_module`. Roles and playbooks are not execution kinds.
- A binding whose `authority` is `automation` (or `automation:<name>`) must name
  targets declared under the matching `[automation…]` mapping; `ansible_module`
  bindings additionally need a non-empty target `python`.

## `[catalog]`

```toml
[catalog]
root = "/opt/estus/catalog"   # explicit installed asset directory
version = "9"                 # optional assertion against the installed inventory
```

An explicit invalid root fails rather than selecting another catalog. When
`version` is present it must equal the installed manifest version, so a reviewed
pin cannot silently adopt an upgrade.

## `[controller]`

```toml
[controller]
workspace_root = "/var/lib/estus/workspace"   # bounded absolute path
```

Scratch space for controller-script execution, default 16 MiB / 512 entries,
polled rather than hard-quota enforced.

## `[automation]`

```toml
[automation]
required = false                      # missing/broken bundle becomes a startup failure
bundle = "/etc/estus/bundle"          # wins over ESTUS_ANSIBLE_BUNDLE
max_concurrent = 8                    # 1 … 16

[automation.targets.server]
destination = "server-ordinary"       # OpenSSH destination for module/payload transport
python = "/usr/bin/python3"           # absolute target interpreter; required for ansible_module

[automation.authorities.ops]
ssh_config_file = "/etc/estus/automation-ssh.conf"
bundle = "/opt/estus/bundle"          # optional; inherits the ordinary pack
ssh_auth_sock = "/run/estus/agent.sock"   # optional explicit agent; omitting disables inheritance
become = { method = "sudo", user = "root", executable = "/usr/bin/sudo" }

[automation.authorities.ops.targets.server]
destination = "server-automation"
python = "/usr/bin/python3"
```

`automation.targets` fixes the SSH destination and target interpreter for
ordinary `automation` authority — independent of native sudo. Named authorities
(`automation.<name>`, at most 16, identifier ≤ 64 bytes) add a replacement SSH
configuration, an optional separate bundle, an optional agent socket and a fixed
`become` user; `become.executable` is an operator-pinned absolute path (use
`/run/wrappers/bin/sudo` on NixOS). Declared mappings must name configured
logical targets. `[automation.authorities.<name>.targets]` and
`[automation.targets]` both validate the destination shape and the absolute
Python path.

## `doctor`

```sh
estus doctor --target server                 # policy + ssh -G resolution
estus doctor --target server --runtime ansible
```

`doctor` reports the resolved `ssh_executable`, per-target
`effective_ssh_policy` from `ssh -G -- <destination>`
(`strict_host_key_checking`, `update_host_keys`, `batch_mode`, warnings when
host-key checking is disabled) and, with `--runtime ansible`, the same pack
verification `estus bundle inspect` performs. It executes no workload and
establishes no target/module compatibility. Note that OpenSSH `ssh -G` evaluates
`Match exec` stanzas.

`doctor`, `bundle` and `catalog` are the only subcommands; there is no
`estus schema`.
