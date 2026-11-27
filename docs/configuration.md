# Configuration

Use this page to set up Estus for your SSH hosts and tune its runtime settings.
For the rules that decide what an agent can call, see [policy](policy.md).

## One host, read-only catalog tools

Save this as `estus.toml`. Replace `web-1` on the right-hand side of `ssh_host`
and `destination` with an OpenSSH destination you already use. The agent still
calls the logical target `web-1`.

```toml
capabilities = { named = true }

[selection]
allow = ["observe_cpu", "observe_memory"]

[targets.web-1]
ssh_host = "web-1"
max_tier = "observe"

[automation.targets.web-1]
destination = "web-1"
```

The `[automation.targets]` entry gives the catalog collectors their SSH
destination. These two collectors default to `/usr/bin/python3` on the remote
host; they do not need an Ansible bundle.

Check the policy without connecting, then pass `--config estus.toml` in your
[MCP client's launch arguments](clients.md).

```sh
estus --config estus.toml auth can-i observe_cpu web-1
```

## Production and development hosts

Use labels to apply the same policy to several targets. Here the `prod` group
allows telemetry and inspection, while the `dev` group also allows ordinary
command execution. The fallback denies access if you omit or mistype a label.

```toml
capabilities = { named = true, file_read = true, exec = true }
default_profile = "deny"

[selection]
allow = ["observe_memory"]

[targets.web-1]
ssh_host = "web-1"
labels = { env = "prod" }

[targets.db-1]
ssh_host = "db-1"
labels = { env = "prod" }

[targets.dev-1]
ssh_host = "dev-1"
labels = { env = "dev" }

[[groups]]
name = "prod"
match_labels = { env = "prod" }

[[groups]]
name = "dev"
match_labels = { env = "dev" }

[automation.targets.web-1]
destination = "web-1"

[automation.targets.db-1]
destination = "db-1"

[automation.targets.dev-1]
destination = "dev-1"
```

See [profiles and groups](policy.md#profiles-and-groups) for other ways to
match targets and combine profiles.

## A separate SSH identity for sudo

Set up `web-1` and `web-1-elevated` as OpenSSH aliases that log in with different
accounts. On the host, grant the elevated login non-interactive sudo access
for `/usr/bin/id` as root. This config exposes `exec_sudo` but not ordinary
`exec_command` or `exec_argv`.

```toml
capabilities = { sudo = true }

[targets.web-1]
ssh_host = "web-1"
max_tier = "exec"

[targets.web-1.sudo]
mode = "separate-identity"
ssh_host = "web-1-elevated"
users = ["root"]
programs = ["/usr/bin/id"]
```

Different alias names alone do not separate credentials. See
[deployment](deployment.md) for setting up and checking the identities.

To check the route without running a command, use
`estus --config estus.toml auth can-i exec_sudo web-1`.

## Nix or Home Manager drop-ins

Have your configuration manager generate these files. The paths in the main
file are relative to the directory containing `estus.toml`. Each directory
entry may be a symlink to a regular file in the Nix store.

`estus.toml`:

```toml
capabilities = { named = true }
default_profile = "deny"
profiles_dir = "profiles.d"
groups_dir = "groups.d"
targets_dir = "targets.d"

[selection]
allow = ["observe_memory"]

[automation.targets.web-1]
destination = "web-1"
```

`profiles.d/telemetry.toml`:

```toml
extends = "prod"
max_tier = "observe"
```

`groups.d/frontends.toml`:

```toml
profile = "telemetry"
match_hosts = ["web-*"]
```

`targets.d/web-1.toml`:

```toml
ssh_host = "web-1"
```

`estus --config estus.toml auth explain web-1` shows which files supplied the
target, group and profile. See [drop-in rules](policy.md#drop-in-directories)
for file formats and duplicate handling.

## Choosing a configuration file

Choose one readable, regular TOML file using `--config` or `ESTUS_CONFIG`.
Estus does not search for a config file. Unknown keys fail validation. The
only extra TOML files it reads as part of your configuration are the
explicitly configured drop-ins.

| Path | First choice | Then | Then |
| --- | --- | --- | --- |
| Estus config | `--config` | `ESTUS_CONFIG` | No file |
| SSH executable | `--ssh` | `ESTUS_SSH` | `[ssh].executable` |
| SSH config | `--ssh-config` | `ESTUS_SSH_CONFIG` | `[ssh].config_file` |

CLI and environment paths in this table are relative to the launch directory.
Relative paths in TOML are relative to the selected file's directory where
the setting accepts them. Estus uses paths literally, without `~` or
environment-variable expansion. An invalid higher-priority path is an error,
not a reason to try the next setting. Catalog, bundle and numeric settings
have their own [environment precedence](#environment-variables).

## Modes

| Mode | How to select it | Destination and capability defaults |
| --- | --- | --- |
| Headless | Default, with or without a file; `mode = "headless"` states it explicitly | Closed target list, empty if you declare none. See the [capability defaults](policy.md#capabilities). |
| Workstation | `mode = "workstation"` in a file, or `--workstation` without a file | Open destinations unless you declare `[targets]` or `targets_dir`. Unspecified capabilities default to on; elevated calls still need a sudo route. |
| `--yolo` | Flag only; rejects a file selected by `--config` or `ESTUS_CONFIG` | Open destinations, all capabilities, same-account root sudo and the non-lab catalog. For throwaway hosts only. |

`--workstation` may restate `mode = "workstation"` in a file but cannot upgrade
a headless file. No environment variable selects workstation or `--yolo`
mode. `--include-lab` requires `--yolo` and adds laboratory-only catalog
tools.

## SSH: `[ssh]`

| Key | Default | What it sets |
| --- | --- | --- |
| `executable` | First usable `ssh` in an absolute directory on `PATH` | OpenSSH executable used by Estus. The resolved path must be at most 4096 UTF-8 bytes and point to a regular file with an execute bit set. Estus does not search `PATH` for an explicit value. |
| `config_file` | OpenSSH's normal configuration | Replacement OpenSSH configuration, passed with `-F`. It must be a readable regular file. It is not an overlay. |

## Runtime limits: `[limits]`

| Key | Default | What it limits |
| --- | ---: | --- |
| `connect_timeout_secs` | `10` | SSH connection setup, in seconds |
| `operation_timeout_secs` | `60` | Default operation deadline, in seconds |
| `max_timeout_secs` | `600` | Maximum requested operation timeout, in seconds |
| `max_output_bytes` | `1048576` | Captured command output per stream, in bytes, before response framing |
| `max_file_bytes` | `1048576` | File transfer, command stdin and output-handle read requests, in bytes |

All values must be positive integers. The connection and default operation
timeouts must be at most `max_timeout_secs`. Per-tool and wire limits can
reduce how much data a call can return. See [tool results](tools/results.md).

## Output retention: `[output]`

These settings apply to [output handles](tools/results.md), not the inline
command response.

| Key | Default | Allowed values |
| --- | ---: | --- |
| `enabled` | `true` | `true` or `false` |
| `per_stream_bytes` | `1048576` | `1`–`4194304` bytes per stream |
| `total_bytes` | `16777216` | At least twice `per_stream_bytes`, up to `67108864` bytes per session |
| `max_handles` | `8` | `1`–`64` handles per session |
| `ttl_secs` | `300` | `1`–`3600` seconds |

## Persistent quarantine: `[quarantine]`

Set `state_dir` to keep [quarantine](concepts.md#when-a-change-goes-wrong-uncertainty-and-quarantine)
records across Estus restarts. It defaults to unset, which keeps them in
memory only. Create the directory before startup, owned by the user running
Estus and with mode `0700`. The final directory entry cannot be a symlink.
On Windows, Estus rejects symlinks and non-directories but does not verify
NTFS ACLs or owner SIDs; restrict directory permissions yourself.
Dedicate it to Estus: it restores up to 256 owned regular records of at most
4 KiB each and refuses unexpected entries. It ignores temporary `.tmp-*`
entries left by interrupted writes.

## Catalog assets: `[catalog]`

| Key | Default | What it sets |
| --- | --- | --- |
| `root` | Unset | Directory containing `catalog.json`. An explicit root must be a real directory, not a symlink. |
| `version` | Unset | Exact string expected in the manifest's `version` field. A mismatch fails startup. |

Estus uses the first catalog it finds, in this order:

1. `[catalog].root` (`--root` for the `estus catalog` commands).
2. `ESTUS_CATALOG_ROOT`.
3. `../share/estus/catalog` relative to the `estus` executable.

An explicit root that turns out to be invalid is an error, not a reason to try
the next one. If nothing is found, anything that needs the catalog fails with
`catalog_not_installed`; run [`estus catalog install`](catalog.md#install-the-catalog)
to write the catalog built into the binary next to it. The wheel and the Nix
package supply their own copy and set `ESTUS_CATALOG_ROOT` for you.

`estus catalog list`, `export` and `install` are standalone commands; use their
`--root` or `--dir` option, not `--config`. See [catalog](catalog.md).

## Local scripts: `[controller]`

`workspace_root` is unset by default and is required when you enable a custom
`controller_script` tool. Set it to an absolute path of at most 1024 bytes.
Create the directory with mode `0700` and make the user running Estus its
owner. Estus creates a private working directory there for each invocation.
Read [security](security.md) before enabling a local script.

## Automation routes: `[automation]`

An [authority](concepts.md#authority) determines how a catalog tool reaches a
target. Use `[automation.targets.<target>]` for the ordinary `automation`
authority. Use `[automation.authorities.<name>.targets.<target>]` for
`automation:<name>`. The keys of both tables are configured logical targets;
both mappings default to empty.

| Key in either target mapping | Default | What it sets |
| --- | --- | --- |
| `destination` | Required | OpenSSH destination for this authority. Use a nonempty string with no whitespace, NUL or leading `-`. |
| `python` | Unset | Absolute path to the remote interpreter. For native collectors, a configured path takes precedence over the tool's defaults. `ansible_module` tools on configured targets require an explicit path. |

A named authority uses the following keys under
`[automation.authorities.<name>]`.

| Key | Default | What it sets |
| --- | --- | --- |
| `ssh_config_file` | Required | Its own replacement OpenSSH configuration; a readable regular file when the authority is in use |
| `ssh_auth_sock` | Unset | Path to an agent socket. Omit to avoid inheriting the ordinary agent. |
| `become.method` | Required | `sudo` |
| `become.user` | Required | Fixed POSIX account name, at most 64 bytes |
| `become.executable` | `/usr/bin/sudo` | Absolute path to the remote sudo executable |
| `targets` | Required | Per-target destination and interpreter mappings |
| `bundle` | Inherits the ordinary bundle | Optional bundle override, only for Ansible module tools. Use an absolute path so the override does not depend on the launch directory. |

You can declare up to 16 named authorities. Names are 1–64 ASCII bytes:
letters or `_` first, then letters, digits, `_` or `-`. Interpreter, SSH config,
agent socket and sudo executable paths must be absolute, at most 4096 bytes
and contain no NUL.

| Key in `[automation]` | Default | What it sets |
| --- | --- | --- |
| `max_concurrent` | `8` | Session-wide concurrency across native collectors and Ansible module tools; `1`–`16` |
| `bundle` | Unset | Ordinary Ansible bundle path; takes precedence over `ESTUS_ANSIBLE_BUNDLE` |
| `required` | `false` | `true` requires a usable Ansible bundle at server startup even if no module tool needs it. It does not enable tools. |

`[automation].bundle` and `ESTUS_ANSIBLE_BUNDLE` must be absolute paths of at
most 4096 bytes. The `bundle` and `required` settings only affect the optional
[Ansible bundle runtime](ansible-bundles.md).

## Environment variables

| Variable | What it sets | Precedence |
| --- | --- | --- |
| `ESTUS_CONFIG` | Estus TOML file | Below `--config` |
| `ESTUS_SSH` | OpenSSH executable | Below `--ssh`, above `[ssh].executable` |
| `ESTUS_SSH_CONFIG` | Replacement OpenSSH config | Below `--ssh-config`, above `[ssh].config_file` |
| `ESTUS_CONNECT_TIMEOUT_SECS` | Connection timeout in seconds | Overrides `[limits].connect_timeout_secs` |
| `ESTUS_OPERATION_TIMEOUT_SECS` | Default operation timeout in seconds | Overrides `[limits].operation_timeout_secs` |
| `ESTUS_MAX_TIMEOUT_SECS` | Maximum operation timeout in seconds | Overrides `[limits].max_timeout_secs` |
| `ESTUS_MAX_OUTPUT_BYTES` | Command output cap in bytes | Overrides `[limits].max_output_bytes` |
| `ESTUS_MAX_FILE_BYTES` | File and stdin cap in bytes | Overrides `[limits].max_file_bytes` |
| `ESTUS_CATALOG_ROOT` | Catalog asset directory | Below `[catalog].root` (or `--root`), above the directory next to the executable |
| `ESTUS_ANSIBLE_BUNDLE` | Ansible bundle directory | Below `[automation].bundle`, above installed bundle discovery |

Set numeric overrides as positive decimal integers without whitespace or
signs.

## Check a configured host with `doctor`

```sh
estus --config estus.toml doctor --target web-1
estus --config estus.toml doctor --runtime ansible
```

With `--target`, `doctor` connects using the ordinary SSH identity and probes
SFTP. It reports results as JSON without running a remote command or testing
sudo. When available, its `effective_ssh_policy` reports OpenSSH's
`StrictHostKeyChecking`, `UpdateHostKeys` and `BatchMode` settings. This comes
from `ssh -G`, which can evaluate local `Match exec` stanzas.

Repeat `--target` for up to 32 distinct configured targets. `--timeout-secs`
sets a single deadline for the run and defaults to `operation_timeout_secs`.
`--runtime ansible` verifies the ordinary bundle locally; it does not check
module compatibility on a target. For an offline answer about which tools are
allowed, use [`auth`](policy.md#check-policy-with-auth) instead.
