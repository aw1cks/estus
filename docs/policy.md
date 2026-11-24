# Access policy

Use this page to decide what your agent may run on each host and to check the
result without logging in. Start with a [configuration recipe](configuration.md)
if you don't have an `estus.toml` yet.

## Check policy with `auth`

Save the [production and development example](configuration.md#production-and-development-hosts)
as `estus.toml`. Ask Estus which profile applies to `web-1`:

```sh
estus --config estus.toml auth explain web-1
```

Output, omitting the final tool-count line:

```text
Target:          web-1 (configured mode)
Matched groups:
  - group "prod" -> profile "prod" (labels {env="prod"})
Effective policy (strictest-wins across 1 match):
  allowed:         yes
  max_tier:        inspect    (group "prod" -> profile "prod")
  require_preview: true       (group "prod" -> profile "prod")
  capabilities:    named, file_read
  sudo:            disabled
```

`allowed: yes` means the target is allowed, not that every tool is. To check
one exact tool name, run:

```sh
estus --config estus.toml auth can-i exec_command web-1
```

```text
no   (capability "exec" disabled by matched profile(s) (group "prod" -> profile "prod"))
```

```sh
estus --config estus.toml auth can-i exec_command dev-1
```

```text
yes
```

Both commands accept `--json`. For a valid invocation, exit `0` means allowed
and `1` means denied; CLI or configuration errors use exit `2`. `auth` checks
startup policy, not call arguments, live quarantine state, preview receipts or
runtime readiness. It opens no SSH session. In open mode, host matching can
run local `ssh -G`, which can evaluate `Match exec` in your SSH config.

## How a call is authorized

These are the policy layers, not a guarantee of the order in which individual
errors are reported. See [concepts](concepts.md#how-a-call-is-authorized) for an
overview.

1. **Capabilities** set the server-wide ceiling.
2. **Selection** determines which tools to offer within that ceiling.
3. **Target policy** restricts the destination, tool names, tier and sudo route.
4. **Profiles and groups** add limits for this host; the strictest matching
   profile rules win.
5. **Call checks** validate the actual arguments and limits before dispatch.
   Quarantine and any required matching preview can still stop a mutation.

A tool listed by the server is not necessarily allowed on every target. Local
control tools such as `observe_targets` do not use the remote call path.

## Capabilities

| Key in `[capabilities]` | What it controls |
| --- | --- |
| `named` | Configured catalog and custom tools |
| `file_read` | `inspect_file`, `inspect_directory`, `observe_stat` |
| `file_write` | Builtin file and directory changes |
| `exec` | `exec_command` and `exec_argv` |
| `sudo` | `exec_sudo` and calls using a named automation authority |

In headless mode, if you omit `[capabilities]`, only `named` defaults to `true`.
If you supply the table, each omitted key defaults to `false`. In workstation
mode omitted keys default to `true`. Turning on `named` alone does not select
any tools in headless mode. Turning on `sudo` does not set up a sudo route.

`observe_targets` and `inspect_output` need no capability. Publishing
`change_target_quarantine_clear` requires at least one of `named`, `file_write`,
`exec` or `sudo`. You can remove these local control tools with global
`selection.deny`. See the [builtin tool reference](tools/builtin.md).

## Targets

The agent passes the logical name in `host`, not the SSH alias. Headless mode
accepts only configured names. Workstation mode can accept raw SSH destinations
if neither `[targets]` nor `targets_dir` is present.

| Key in `[targets.<name>]` | Default | What it controls |
| --- | --- | --- |
| `ssh_host` | Required | Ordinary OpenSSH destination. Must be nonempty, with no whitespace, NUL or leading `-`. |
| `description` | Unset | Advisory text in discovery, up to 1024 UTF-8 bytes |
| `labels` | Empty | Up to 16 labels for discovery and group matching. Keys are 1–64 bytes and values up to 256 bytes. Descriptions and label keys and values share a 65536-byte budget across all targets. |
| `max_tier` | No extra ceiling | Highest [tier](concepts.md#tiers) this target permits for remote tools |
| `selection` | Inherit | Target-specific tool filter, intersected with the global set |
| `require_preview` | Inherit | Override the effective preview rule; see [preview gating](#preview-gating) |
| `profile` | Unset | Built-in or custom profile to combine with any matching groups |
| `sudo` | No explicit route | Policy for `exec_sudo`; separate from catalog automation authorities |

### Sudo routes

| Key in `[targets.<name>.sudo]` | Default | What it controls |
| --- | --- | --- |
| `mode` | `disabled` if the table is absent; otherwise required | `disabled`, `same-account` (ordinary SSH login), or `separate-identity` (different SSH destination) |
| `ssh_host` | Required in `separate-identity` mode only | Elevated destination. It cannot equal any configured ordinary SSH destination string. |
| `users` | `["root"]` | Nonempty list of distinct POSIX account names |
| `programs` | Unrestricted by Estus if omitted | Exact permitted `argv[0]` paths. Use distinct absolute paths without a trailing slash or NUL. `[]` denies all programs. |

`programs` does not filter the remaining arguments. OpenSSH and the host's
sudo policy still decide whether the login and command succeed. See the
[separate-identity recipe](configuration.md#a-separate-ssh-identity-for-sudo)
and [deployment](deployment.md).

Top-level `disclose_sudo_policy` defaults to `false`. Set it to `true` to show
explicit target sudo users and programs in the `estus://targets/{host}/policy`
resource. It doesn't change what the agent may run.

## Selection

In headless mode, the global selection starts with the builtins permitted by
`[capabilities]`. Each list defaults to empty:

| Key in `[selection]` | Effect |
| --- | --- |
| `presets` | Adds the members of each named [catalog preset](catalog.md). |
| `allow` | Adds tools by exact name. It cannot turn on a capability. |
| `deny` | Removes names, including builtins. It wins over `allow` and `presets`. |

Global lists require known names with no duplicates within a list. The loader
accepts up to 32 preset entries and 256 entries per global `allow` or `deny`
list, and up to 256 tool definitions. Use headless mode for site-controlled
catalog selection. Workstation mode has its own automatically loaded catalog
and does not use global `[selection]` as an allowlist for that catalog.

For `[targets.<name>.selection]`, `allow` or `presets` starts a narrower list;
`deny` alone subtracts from the global set. An empty table denies all remote
tools on that target. Omitting the table inherits the global selection.

A profile's `selection` uses the same keys. With `allow` or `presets`, it
keeps capability-permitted builtins as well as the named additions; use
`deny` to remove a builtin. A `deny`-only table subtracts from the global
selection, and an empty table denies all remote tools. Omitting a profile's
selection inherits its parent profile's selection, if any.

## Catalog overlays and custom definitions

In headless mode, a `[tools.<name>]` table without `execution` sets site policy
for a selected catalog tool. For example, this allows the NIC stats collector
for one interface and shortens its timeout:

```toml
capabilities = { named = true }

[selection]
allow = ["observe_nic_stats"]

[targets.web-1]
ssh_host = "web-1"

[automation.targets.web-1]
destination = "web-1"

[tools.observe_nic_stats]
targets = ["web-1"]
constraints = { allowed_interfaces = ["eth0"] }
limits = { timeout_secs = 20 }
```

| Overlay keys | How Estus applies them |
| --- | --- |
| `targets`, `authority`, `input_schema`, `input_map` | Replace the corresponding value as a whole. If you omit `targets`, the tool starts with all configured targets, subject to the per-tool target limit and other policy. |
| `fixed_args`, `limits`, `constraints` | Merge tables by key. New values replace the entire value at that key, including lists. Estus discards any template `constraints` first: allowlists come from your site. |

The catalog supplies all other fields, including the description, revision,
effects and result contract. The `limits` keys are `timeout_secs` and
`max_output_bytes`. `constraints` supports `allowed_units`, `allowed_keys`,
`allowed_interfaces` and `allowed_packages`; see the
[tool reference](tools/catalog-reference.md) for the policy each tool accepts.
If a template requires site policy, supply it in `fixed_args`, `constraints`
or `input_schema` before you enable it. Every target on a tool must have a
mapping for the tool's [automation authority](configuration.md#automation-routes-automation).
A remote definition accepts up to 32 distinct configured targets.

A table **with** `execution` is a complete custom definition, not an overlay.
It sets `description`, `revision`, `authority`, `effects`, `execution` and
`result`, plus `targets` for a configured remote tool. It can also set
`input_schema`, `fixed_args`, `input_map`, `argument_types`, `constraints` and
`limits` where the executor supports them. Supported execution kinds are
`native_argv`, `native_payload`, `ansible_module` and `controller_script`.

### Use different allowlists on two hosts

An overlay is shared across its targets. To let `web-1` inspect only `eth0` and
`db-1` inspect only `bond0`, [export](catalog.md) `observe_nic_stats` and copy
its full definition twice into your main config. Use an absolute export path
so each copy can refer to the exported collector. Rename each tool table and
its nested tables:

| Definition name | `targets` | `constraints.allowed_interfaces` |
| --- | --- | --- |
| `observe_nic_stats_web` | `["web-1"]` | `["eth0"]` |
| `observe_nic_stats_db` | `["db-1"]` | `["bond0"]` |

Keep an `[automation.targets]` mapping for each host. Select both new names
in `selection.allow` instead of the original. Check each name against both
hosts with `auth can-i`. When copying a mutation, check preview support too:
renaming a native tool can break its built-in pairing.

## Profiles and groups

Profiles are reusable limits, not a way to turn on a disabled global
capability. The built-in profiles have no additional selection filter.

| Profile | `max_tier` | `require_preview` | Capabilities allowed | Sudo policy | `allow_ip_literals` |
| --- | --- | --- | --- | --- | --- |
| `deny` | No calls | `true` | None | Disabled | `false` |
| `prod` | `inspect` | `true` | `named`, `file_read` | Disabled | `false` |
| `prod-change` | `change` | `true` | `named`, `file_read` | Disabled | `false` |
| `dev` | `exec` | `false` | `named`, `file_read`, `file_write`, `exec` | Disabled | `false` |
| `lab` | `exec` | `false` | All | Same-account root | `true` |

In `[profiles.<name>]`, `extends` names a parent profile. Without it, a custom
profile starts from `prod`. Set `max_tier`, `require_preview`, `capabilities`,
`sudo`, `selection` or `allow_ip_literals` to override inherited settings.
Capability keys override individually; `sudo` and `selection` replace their
inherited settings. Estus rejects inheritance cycles and bounds recursive
inheritance resolution to eight levels. You cannot redefine built-in profiles.

| Key in each `[[groups]]` entry | Effect |
| --- | --- |
| `name` | Required, unique group identifier |
| `profile` | Built-in or custom profile to apply; defaults to `name` |
| `match_hosts` | Up to 64 nonempty patterns of up to 256 bytes each, without ASCII whitespace or control characters. Any pattern may match; glob matching is ASCII case-insensitive, with `*` and `?`. |
| `match_labels` | Up to 16 exact key/value matches on a configured target. All pairs must match. Keys and values are nonempty and at most 64 and 256 bytes, respectively. |

Set at least one matcher. If you set both, both must match. Estus accepts up to
64 custom profiles and 64 groups, including drop-ins. Their names are 1–64
bytes: ASCII letters, digits, `-`, `_` or `.`.

**Strictest wins.** Estus combines all matching group profiles plus any
explicit target `profile`. A denial wins, the lowest `max_tier` applies,
capabilities and selections intersect, and any matching `require_preview = true`
sets the profile's preview requirement. Profile sudo grants intersect: modes
must agree, separate-identity destinations must agree, and only common users
and programs remain. File order has no effect.

For `exec_sudo`, an explicit enabled target sudo route supplies the users and
programs; profile capability, tier and selection limits still apply. Without
such a route, an effective same-account profile grant can supply it. A profile
does not by itself supply a separate-identity route for `exec_sudo`.

If no group or explicit target profile applies, Estus uses `default_profile`
if set. If profile policy is active but no profile applies and there's no
fallback, Estus denies access. Use `default_profile = "deny"` to make the
fallback explicit.

### SSH aliases and IP literals

For configured targets, `match_hosts` tests the logical name and `ssh_host`.
For open destinations, Estus also tries `ssh -G` and tests the returned
`hostname` when available. An alias pointing at a hostname matched by a stricter
group can therefore match that group too. This is SSH config resolution, not
an address lookup or verification of the remote host. Use configured targets
if you need a closed inventory.

Estus skips an otherwise matching group with `allow_ip_literals = false` when
the destination is an IPv4 or IPv6 literal. This also covers a configured
`ssh_host` literal or one found via `ssh -G`. The guard skips groups; it does
not override an explicit target profile or `default_profile`. Use a restrictive
fallback so a skipped group cannot give a literal broader access.

## Drop-in directories

See the [Nix or Home Manager recipe](configuration.md#nix-or-home-manager-drop-ins)
for complete files. Set the directory paths at the top level of the main file:

| Key | Single-entry file | Multi-entry file |
| --- | --- | --- |
| `profiles_dir` | Profile fields; filename stem is its name | `[profiles.<name>]` tables |
| `groups_dir` | Group fields; `name` defaults to the filename stem | `[[groups]]` entries |
| `targets_dir` | Target fields; filename stem is its name | `[targets.<name>]` tables |

All three paths default to unset. Relative paths resolve against the main
TOML file's directory. An explicit directory must exist and be readable. Estus
scans only the immediate directory for `.toml` entries, up to 64 files per
directory and 1 MiB per file. Symlinks to readable regular files are allowed.
A drop-in can define only entries for its directory's section. Duplicate
names, including names already in the main file, fail startup rather than
replacing a definition. An empty `targets_dir` still closes destinations to
configured targets. Check drop-in sources with `auth explain`.

## Preview gating

Set top-level `require_preview = true` to allow only
[previewable remote changes](concepts.md#preview-before-change); it defaults to
`false`. A matching profile can also require a preview. A target's explicit
`require_preview` is the final value: `false` turns the requirement off even if
the global setting or a matching profile says `true`.

**Builtin remote `change_*` and `exec_*` tools have no preview pairing.**
Estus refuses them with `preview_required` when the gate is on, including
`exec_sudo`. This does not block reads, previews or the local
`change_target_quarantine_clear` control tool. Catalog changes without a
qualified pairing for the requested operation are also refused.

For a paired change, run the corresponding preview on the same target with
the same change intent under the same authority role. The change rechecks
remote pre-state before dispatch and consumes the matching preview if it is
still valid. If the arguments or pre-state differ, the preview expired, or
it was already used, run it again. `auth can-i` can report that a route
requires a preview; it does not prove a specific invocation can be paired or
that a matching preview exists.
