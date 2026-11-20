# Estus

A stdio MCP server for operator-configured SSH authority. The Rust application owns
MCP, SSH connections, limits and cleanup. Only MCP JSON is written to server stdout.

## Migrating from ssh-mcp

The command, Cargo package/binary and Python distribution/import package are now
`estus`. Update product environment variables to `ESTUS_*` and deployment paths
such as `/etc/estus`, `/var/lib/estus` and `/opt/estus`. There are no compatibility
aliases. Ansible internal variables use the `estus_` prefix.

Reimport and review existing automation snapshots before enabling them: helper
identity and content-hash namespaces have changed, so previous approval digests
are not reusable. Deploy the reviewed content and update configuration accordingly.

The automation-only `automation.ssh_executable` setting and
`ESTUS_AUTOMATION_SSH` environment variable have been removed without aliases.
Move the setting to `[ssh] executable = "/path/to/ssh"` (preserving any existing
`config_file` in that table), or use the shared `ESTUS_SSH` environment variable.
The selection now applies to native SSH, doctor and automation alike.

Destination authority is closed by default: no configuration, an omitted targets
table and an empty `[targets]` table all authorize no remote destination.
Configurations that deliberately accept caller-selected SSH destinations must
set `destination_policy = "open"` at the TOML root and omit the targets table.
Combining open mode with any targets table is rejected. Otherwise only exact
configured logical names are accepted; backend aliases do not grant authority.

Workstation mode is an explicit opt-in: pass `--workstation` (or set
`ESTUS_WORKSTATION`) and omit the targets table, or declare
`mode = "workstation"` in a configuration file. With a configuration file, the
flag may only restate that declared mode; it never upgrades a headless file.
No-config startup without the flag uses the restrictive `headless` default with
`[capabilities]` `named = true` only: no exec, sudo, file-write or catalog
exposure. `mode = "workstation"` enables all five capability ceilings (`named`,
`file_read`, `file_write`, `exec`, `sudo`) with open ordinary SSH resolution.
`exec_sudo` is published only when some configured target declares sudo policy,
and open resolution never elevates: dynamic catalog bindings that require
`automation:<authority>` stay unpublished unless a configured target grants
unrestricted root sudo or a matching `[automation.authorities.<name>]` mapping
exists. Per-target `[targets.<name>.capabilities]` fields only narrow the global
set.

## Base wheel

Build a platform wheel and source archive with Python 3.14 and Rust 1.88 or newer:

```sh
uv build --python 3.14
```

Install the resulting wheel as an isolated tool, without activating a virtualenv:

```sh
uv tool install --python 3.14 ./dist/estus-*.whl
estus --help
estus --config /absolute/path/to/operator.toml
```

Alternatively, run the local wheel with `uvx --from ./dist/estus-*.whl estus`.
These instructions use locally built artifacts; no public-index release is implied.
Current wheel acceptance targets CPython 3.14 on arm64 macOS/Linux; older-OS runtime
compatibility and x86_64 execution are not implied by the artifact tags.

The wheel contains a private Rust executable and a Python console launcher that
immediately replaces itself with that executable. It requires Python for bootstrap
and trusts that Python environment. It does not embed CPython or host MCP in Python.
Host OpenSSH must be installed and available to the application. Existing operator
SSH identity, host-key policy and configuration still apply.

The base wheel does not depend on Ansible, install packages at startup, or enable
additional tools. An explicitly selected existing runtime bundle remains usable
through the native application's configuration.

## Packaging support contract

Installed wheels and native builds are supported workflows. PEP660/editable
installation is not supported: an isolated `uv pip install --editable` builds the
private executable but does not map the generated catalog assets into the source
package. Offline catalog discovery then fails. Use a wheel or an explicitly
prepared native build rather than relying on `--editable`.

Recorded installed qualification uses CPython 3.14.6 on Darwin25 arm64, for both
base and `ansible`-extra channels, including interpreter selection, asset discovery,
stdio purity and process lifecycle. Launcher-only checks in `tests/wheel.rs`
parameterize the target Python version (`ESTUS_TEST_LAUNCHER_PYTHONS`) across
`--help` and an MCP handshake, while `[ansible]` remains pinned to 3.14. Because
multi-platform `3.10`/`3.12`/`3.14` launcher qualification has not yet passed across
all supported packaging platforms, package metadata retains `requires-python =
">=3.14,<3.15"` and `cp314-cp314` tags rather than widening prematurely. A
standalone executable's lack of CPython linkage does not qualify another Python
version, platform or OS release; the declared native payload baselines are audited
separately below.

Source archives select catalog definitions/roles/payloads through the manifest-driven
build hook, not a second tool-name list in `MANIFEST.in`. They include required Rust
sources and embedded helpers, while excluding generated caches, demonstrations,
test fixtures, local plans and build outputs.

The opt-in `source_distribution_roundtrip_preserves_manifest_selected_assets`
wheel test builds sdists from a clean tracked-source export, extracts them outside
the checkout, builds/installs wheels solely from those extracted sources and checks
asset bytes against native installation. It repeats with one added valid catalog
entry without editing the source manifest. Set `ESTUS_TEST_SOURCE_ARCHIVE`,
`ESTUS_TEST_BUILD_PYTHON` (the pinned backend environment),
`ESTUS_TEST_NATIVE_CATALOG` and an outside-Nix3.14 `ESTUS_TEST_PYTHON`, then run:

```sh
cargo test --test wheel source_distribution_roundtrip_preserves_manifest_selected_assets -- --ignored --exact
```

Building may fetch locked Cargo dependencies; installed catalog discovery/export
needs neither network nor Ansible. This roundtrip qualifies the build host, not an
older-OS runtime baseline.

## Local SSH executable

Estus selects one local OpenSSH executable in this order:
`--ssh PATH` > `ESTUS_SSH` > `[ssh].executable` > `ssh` found on `PATH`.
For example:

```toml
[ssh]
executable = "/opt/openssh/bin/ssh"
config_file = "/etc/estus/ssh_config"
```

The executable is resolved once at configuration load to a validated absolute
path shared by native SSH, doctor and automation. Explicit relative paths from
`--ssh` or `ESTUS_SSH` are relative to the launch directory; a relative
`[ssh].executable` is relative to the TOML file's directory. Explicit selections
are literal paths, with no tilde or environment-variable interpolation and no
`PATH` lookup; `PATH` lookup skips non-absolute entries. An invalid override fails
configuration loading rather than falling back to a lower-priority source.

The native Nix package prefixes `PATH` with its pinned OpenSSH, leaving explicit
CLI, environment and TOML selections free to override that default. It does not
set `ESTUS_SSH`; an environment default would incorrectly outrank TOML.

`estus doctor --target <name>` reports `ssh_executable` and per-target
`effective_ssh_policy` parsed from `ssh -G -- <destination>`
(`strict_host_key_checking`, `update_host_keys`, `batch_mode`, and warnings
when host-key checking is disabled). Note that OpenSSH `ssh -G` can evaluate
`Match exec` stanzas from the configured or user SSH config.
## Builtin input contracts

Tool discovery publishes nonempty executable/path constraints, positive timeout
and read-size bounds, listing pages of1–1000 entries, checksum/handle formats,
and explicit replacement consent. Timeout/read-size maxima reflect this server's
resolved configuration. First-argument constraints use JSON Schema2020-12
`prefixItems`; empty later argv elements and empty file contents remain valid.

Schemas do not grant authority or replace runtime validation. Combined UTF-8 byte
limits, shell-escaping cost, actual-request-ID reply budgets and cross-field
limits still apply at runtime; no byte limit is advertised as a character limit.

## Pinned Nix wheel build and acceptance

Nix orchestrates the same PEP 517 build and metadata, with Rust 1.88 and the pinned
Python/build-backend inputs. It does not copy the native Nix wrapper into the wheel.

```sh
system=$(nix eval --impure --raw --expr builtins.currentSystem)
mkdir -p nix/result/wheel
nix build .#wheel --out-link "nix/result/wheel/$system"
uv tool install --python 3.14 "./nix/result/wheel/$system"/estus-*.whl
uvx --from "./nix/result/wheel/$system"/estus-*.whl estus
uv run --no-project --with "./nix/result/wheel/$system"/estus-*.whl estus
```

The producer declares macOS 11.0 for the arm64 Mach-O payload and manylinux glibc
2.17 for Linux. These are build/audit baselines for our executable, not a promise
that every optional dependency supports the same minimum OS. The wheel needs no
Nix runtime; compatible Python and host OpenSSH remain external prerequisites.

Project commands use explicit, ignored output links:

| Link | Immutable output |
| --- | --- |
| `nix/result/native/default` | Native package |
| `nix/result/native/msrv` | MSRV package |
| `nix/result/wheel/<system>` | Portable wheel |
| `nix/result/fixtures/<name>` | Fixture artifact |
| `nix/result/acceptance/<name>` | Acceptance executable |

Create each parent directory before `nix build --out-link`. Bare `nix build` still
uses `./result`; this is a project convention, not a global Nix setting. CI uses
`--no-link` where no persistent link is needed. Keep mutable disks, keys, private
configuration and logs under `target/estus-dev/` (or another owned private runtime
directory), not under output links. Reserve `dist/` for distributions. Existing
local result/fixture links are not automatically migrated or removed.

Run explicit installed acceptance as a non-root user with trusted temporary paths:

```sh
nix run .#wheel-acceptance
```

This downloads managed, outside-Nix Python 3.14 and optional dependencies into owned
temporary caches. It exercises the actual uvx, tool-install and uv-run entry points,
base/extra health, stdio/RPC and signals, owned controller-child cleanup and ordinary
SSH/file access. It is not part of sandboxed checks or a hosted CI requirement.
`ESTUS_TEST_PYTHON` may select an existing absolute outside-Nix Python 3.14.

## Bounded directory enumeration

With `file_read = true` capability enabled, call `inspect_directory` with a logical host,
literal UTF-8 path and optional `max_entries` (1–1000, default200). One request
returns a single bounded page of at most `max_entries` entries within the entry
byte budget; `truncated=true` means more entries existed, not an error.

The result is not a filesystem snapshot. Mutation during enumeration remains
server-defined; a truncated or complete page does not establish a consistent
historical directory view. Raw filename bytes are preserved through
`name_base64`; non-UTF-8 names still cannot be addressed directly by the
existing UTF-8 path tools.

Entry payloads are bounded to1MiB per page and the complete reply budget still
applies. A single entry that cannot fit fails explicitly rather than producing
an endless empty page. Discovery reports this limit. No sorting, recursion,
shell fallback or replay.

## Ordinary SFTP directory creation

`change_mkdir` creates one literal directory on the ordinary SSH identity:

```json
{"host":"server","path":"/srv/example/new-directory","timeout_secs":10}
```

Success returns `{"created":true}` inside the standard tool envelope, only after
MKDIR acknowledgement and bounded channel cleanup. Parents must already exist.
Any observed existing entry, including a file or final symlink, is rejected as
`already_exists`; no `exist_ok`, recursion, permission-mode override, sudo or
shell/SCP fallback is supported. Server umask and filesystem rules apply.

Paths are literal UTF-8: no tilde, variable or wildcard expansion and no path
sandbox. The existing-entry check is diagnostic, not a race-free no-follow
guarantee; intermediate components retain server symlink semantics. MKDIR itself
does not replace an existing entry.

Configurations enabling `file_write = true` can publish the tool; read-only and
named-only capabilities omit it. Target restrictions, argument/deadline validation
and the complete response budget apply before connecting. Calls use the existing
global admission, ordinary master and independently owned SFTP cleanup path.

Handshake/preflight failure cannot have sent MKDIR. After dispatch, any failure
retains `remote_state_unknown=true`, including server refusal, timeout or cleanup
failure. The server does not replay, undo creation or infer rollback from channel
closure. A missing parent remains a backend error, never recursive creation.

`nix run .#mkdir-acceptance-msrv` exercises real creation, entry preservation,
nonrecursive failure and uncertainty boundaries outside the Nix sandbox with the
usual non-root/private-runtime-directory prerequisites.

## Ordinary SFTP rename

`change_rename` renames one entry through the ordinary SSH identity:

```json
{"host":"server","source":"/srv/example/old","destination":"/srv/example/new","overwrite":true,"timeout_secs":10}
```

**This example explicitly permits replacement of an existing destination.**
`overwrite` defaults to `false`; the SFTP v3 backend cannot guarantee atomic
no-overwrite rename, so false/omitted returns `unsupported` without mutation,
even if the destination is absent. It never substitutes stat-then-rename or
link-then-unlink. Explicit `true` requires the server's advertised
`posix-rename@openssh.com` extension; missing support also rejects without
mutation. There is no standard-rename, copy/delete, sudo or shell/SCP fallback.

Success returns `{"renamed":true}` in the standard envelope after acknowledgement
and bounded channel cleanup. Files, directories and final source symlinks retain
ordinary POSIX rename rules; the symlink entry moves rather than its target.
Paths are literal UTF-8 and intermediate symlinks retain server semantics. No
cross-filesystem, path sandbox, metadata-preservation or crash-durability promise
is added.

Policy, pre-SSH validation, admission and channel ownership match `change_mkdir`.
Any error after rename dispatch retains `remote_state_unknown=true`, including
server refusal or cleanup failure; no replay or rollback is inferred.
`nix run .#rename-acceptance-msrv` exercises real moves, replacement consent,
unsupported protection and dispatch uncertainty with the same native prerequisites.

## Ordinary SFTP file unlink

`change_file_remove` removes one named file or final symlink entry:

```json
{"host":"server","path":"/srv/example/obsolete-file","timeout_secs":10}
```

This is destructive, not secure erasure. A final symlink itself is unlinked; its
file/directory target survives. Directories and missing entries remain backend
errors. There is no recursion, wildcard expansion, `missing_ok`, sudo, RMDIR,
canonicalization or shell/SCP fallback. Intermediate symlinks and other filesystem
rules remain server-defined; paths are literal UTF-8, not a path sandbox.

Success returns `{"removed":true}` in the standard envelope after acknowledgement
and bounded cleanup. Profile/admission/ordinary-channel ownership matches the other
SFTP mutations. Invalid or denied calls reject before SSH; handshake failure cannot
have dispatched REMOVE. Every failure after REMOVE polling retains
`remote_state_unknown=true`, including server refusal or cleanup failure. The
operation is never replayed and channel closure never proves rollback.

`nix run .#remove-file-acceptance-msrv` exercises actual entries, preserved link
targets, literal names and dispatch uncertainty with the same native prerequisites.

## Ordinary SFTP empty-directory removal

`change_directory_remove` removes one empty directory:

```json
{"host":"server","path":"/srv/example/empty-directory","timeout_secs":10}
```

One SFTP RMDIR performs the server's emptiness check. Nonempty directories and their
children survive; files and missing entries remain backend errors. There is no
recursive walk, wildcard expansion, `missing_ok`, REMOVE/unlink fallback,
canonicalization, sudo or shell/SCP fallback. Paths are literal UTF-8; components,
symlinks and trailing slashes retain server filesystem rules, not a no-follow,
entry-identity or path-sandbox guarantee.

Success returns `{"removed":true}` in the standard envelope after acknowledgement
and bounded cleanup. Policy, admission, pre-SSH validation and channel ownership
match the other ordinary SFTP mutations. Errors after RMDIR polling retain
`remote_state_unknown=true`, including negative server replies and cleanup failure.
There is no replay or rollback inference.

`nix run .#remove-directory-acceptance-msrv` proves empty-only effects, preserved
contents and dispatch uncertainty with the same native prerequisites.

## Explicit atomic file replacement

`change_file_replace` requires explicit replacement consent:

```json
{"host":"server","path":"/srv/example/config.json","content":"{\"enabled\":true}\n","overwrite":true}
```

`encoding` also accepts strict padded `base64`; decoded content obeys the same
configured file limit as direct writes. False consent, root/trailing-slash/dot
final entries, invalid content/timeouts and insufficient reply budget reject
before SSH. A missing destination may be created, but `overwrite=true` is still
required.

The server must advertise POSIX rename before any filesystem mutation. Estus
exclusively creates a random `.estus-replace-<32 hex digits>` sibling in the
original OPEN, chmods it to mode0600 by handle before writing any content,
completes the full write and CLOSE, then atomically renames it over the
destination. The empty stage briefly has the server's creation default mode
before that chmod. Unsupported atomicity never falls back to standard rename,
destination truncate, unlink/copy/delete, sudo or shell/SCP.

A final destination symlink entry is replaced, not its target. The new inode uses
mode0600 and the SSH account/server parent-group inheritance rules; old
ownership/mode/ACL/xattrs and hardlink identity are not preserved. Components retain
server semantics: no sandbox, no-follow, adversarial pathname protection,
compare-and-swap or concurrent-writer exclusion. This guarantees atomic visibility,
not fsync/power-loss durability.

Success returns `{"bytes_written":N}` in the standard envelope after acknowledgement
and bounded channel cleanup. Any failure after mutating OPEN polling retains
uncertainty, even if normal pre-rename cleanup succeeds. Only an acknowledged,
exclusively created staging entry may be removed before rename polling. No cleanup
ever deletes the destination or a staging pathname after rename starts. Cancel,
timeout, connection loss or ambiguous rename may leave `.estus-replace-*` siblings;
review possible leftovers out of band rather than automatically retrying or
sweeping names. Channel closure never proves rollback. Direct `change_file_write`
retains its existing non-atomic contract.

`nix run .#replace-file-acceptance-msrv` exercises atomic visibility, metadata,
failure cleanup and real lost-rename-ack uncertainty with native prerequisites.

## Opt-in bounded command output retrieval

Native shell/argv/sudo commands and configured native/remote/controller scripts
accept an optional envelope control `retain_output=true`:

```json
{"host":"server","argv":["/usr/bin/printf","diagnostic output\n"],"retain_output":true}
```

Execution remains synchronous, with its original remote deadline. By default no
raw output, artifact directories or handles are retained, and the result's
`output` field is omitted. Automation module and payload requests reject this
control: private worker output is never exposed.

A requested result includes `output.status`: `ready` supplies an opaque `handle`,
expiry and separate stdout/stderr `bytes_retained`, `total_bytes` observed, and
`truncated` flags. `unavailable` supplies a fixed local reason without changing the
command's observed exit code, termination, signal, uncertainty or cleanup evidence.
Inline truncation/lossiness is independent of exact raw artifact bytes.

Use the returned handle with `inspect_output(handle, stream, offset, max_bytes,
encoding)`, where stream is `stdout` or `stderr`. Reads use strict UTF-8 or padded
lossless base64 and SHA-256 of the returned raw range. `eof` means end of the
retained prefix, not proof that the original stream was complete. File/read limits
and actual-ID reply budgeting still apply. The read tool is local and hostless:
no SSH is opened, no caller pathname is accepted, and expired/unknown/foreign
process-session handles fail without disclosing secrets. Handles are capabilities;
keep them private. They and output bytes/paths are excluded from audit records.

Operator-only limits, shown at their defaults:

```toml
[output]
enabled = true
per_stream_bytes = 1048576
total_bytes = 16777216
max_handles = 8
ttl_secs = 300
```

Per-stream limits allow 1 byte–4 MiB; aggregate storage must cover both stream
reservations and be at most64 MiB; handles allow1–64 and expiry1–3600 seconds.
Pending captures/publications, stored artifacts and active read leases retain
their resource credits. Outstanding read workers are independently bounded, so
full storage remains readable. Disabled/quota-exhausted retention still executes
and drains the command, returning an unavailable receipt.

Bounded raw prefixes stay in memory while streams drain: no local storage IO can
block remote draining. After execution evidence is observed, publication writes
private mode0600 files in mode0700 request-owned directories, with at most250ms
local finalization grace. A storage failure never triggers command replay or
rewrites its result. Ready handles expire even while idle; expiry/shutdown remove
owned artifacts when active IO leases finish. A running blocking filesystem call
cannot be forcibly cancelled: its bounded resource owner keeps credits and cleanup
until it returns and cannot publish after timeout/shutdown. This is not a hard
shutdown guarantee on a broken OS.

`nix run .#output-acceptance-msrv` exercises real SSH/controller streams, exact
ranges, expiry, permissions, quota/storage failures and cleanup with native test
prerequisites.

## Client-requested progress

Include `_meta.progressToken` in `tools/call` parameters to request advisory
`notifications/progress` updates. Tokens are strings or integers and must be unique
across active requests. Requests without a token produce no progress.

```json
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"exec_command","arguments":{"host":"server","command":"your-command"},"_meta":{"progressToken":"request-7"}}}
```

Native/controller command progress counts actual stdout+stderr bytes drained,
including bytes discarded beyond capture limits. SFTP reports observed channel,
handshake and acknowledgement milestones. Module execution reports only
validated started/ready/task observations, never private frame bytes, names or results.
Values increase; fixed messages identify the units. Unknown totals are omitted.
Fast operations may complete without an update.

Updates coalesce into one latest snapshot per request, at most four notifications
per second, with at most16 active reporters and256-byte string tokens. Invalid,
oversized, duplicate-active or capacity-exhausted tokens simply get no progress;
execution and final results are unchanged. Tokens never enter audit or results.

Progress producers never await delivery. A busy protocol writer drops advisory
updates rather than queuing them behind normal replies. Reporting stops at
terminal handling, cancellation or handler loss. A JSON frame already being
written must finish to preserve framing, before any final response; cancellation
cannot retract bytes already sent. A blocked consumer can delay protocol output,
not stream draining, execution deadlines, reaping or owned cleanup. Progress is
not output retrieval, proof of completion, replay, or a background-task API.

Up to 64 requests may execute concurrently when the client reads `stdout`
normally; requests above 64 receive an individual JSON-RPC `-32000` busy error
without dropping the session. If `stdout` is blocked with more than 16 unread
replies (or a duplicate live request ID arrives), the overloaded session
terminates with `mcp_session_overloaded`, and clients must reconnect.

`nix run .#progress-acceptance-msrv` exercises real native, controller, and SFTP
progress.

## Best-effort audit delivery

JSON diagnostics on stderr use a dedicated writer, independent of request and
cleanup owners. Producers never wait for stderr or queue capacity. At most 64
records of 4096 bytes each (256 KiB total, including serialization and the in-flight
record) are retained. Oversized/unserializable records and overflow are dropped
whole; accepted records preserve enqueue order. When delivery resumes,
`{"event":"diagnostic_loss","dropped_records":N}` reports accumulated loss.
A closed/broken sink disables delivery without affecting execution.

After application cleanup and runtime shutdown, diagnostic draining gets at
most100ms. A still-blocked diagnostic-only thread is abandoned at process exit;
remaining records may be lost. Audit is not a durable or complete execution log.

Operator failures retain fixed cause codes and failing phases. Configuration
failures also expose fixed `schema_path` context and, for malformed TOML when
available, one-based line/column locations (columns count Unicode characters).
Catalog and startup wrappers preserve these safe causes instead of replacing
them with generic failures. CLI parse errors never echo rejected arguments;
help hides environment values. Malformed MCP arguments carry separate fixed
`argument_shape` diagnostics. None of these surfaces render source snippets,
unknown keys, private paths, request values or backend stderr.


Rejected requests omit sudo user/program identifiers, including validation,
policy, admission and pre-dispatch cancellation failures. Accepted native sudo
operations retain validated user/program identifiers in start/finish records;
ordinary command payloads and arguments are not logged.

## Optional Ansible build environment

The server never needs an Ansible runtime at startup or during a request. An
operator needs one once, offline, to build the bundle pack. Either use the wheel's
`ansible` extra in a throwaway environment or any existing ansible-core install:

```sh
wheel=./dist/estus-0.1.0-cp314-cp314-macosx_11_0_arm64.whl
uv tool install --python 3.14 "${wheel}[ansible]"
estus bundle build --python "$(uv tool dir)/estus/bin/python" \
  --collections-path /opt/collections --output /etc/estus/bundle
estus bundle inspect --bundle /etc/estus/bundle
```

The extra pins Ansible 14.4.0 and Core 2.21.5 and supplies the baseline
collections; Core alone is insufficient for collection modules such as
`community.general.apk`. The builder needs only ansible-core plus those
collections: ansible-runner is no longer a declared dependency and is not
required to build or inspect a pack. pip/uv resolves transitive dependencies at
installation time, so the build environment is not itself locked or immutable —
only the produced pack is digest-verified. Nothing is installed during MCP
requests, and installing a build environment never enables a tool.

Explicit `[automation].bundle` configuration wins over `ESTUS_ANSIBLE_BUNDLE`;
either wins over executable-relative discovery. A broken explicit selection fails
without falling back elsewhere. Without enabled bundle bindings, an explicit
health request or `[automation] required = true`, Rust does not load a pack.

`doctor --runtime ansible` and required startup verify the same pack that
`bundle inspect` checks: manifest schema, canonical bundle digest, wrapper digest,
per-module archive digests, sizes, FQCN shapes and router targets. It executes no
workload and establishes no target/module compatibility. A pack built from a
mutable Python environment retains that environment's unverified third-party
imports; digests cover the pack, not the interpreter that produced it.

The build interpreter and its normal console-bootstrap hooks are trusted. Rust
runs the fixed builder in an isolated, bounded subprocess with private
configuration/temp paths and no ambient Ansible configuration or Python search
path. Process ownership and isolation are not a security sandbox.

## Offline module bundles

Ansible module execution uses a prebuilt bundle pack: an ordinary directory
containing `bundle.json`, `wrapper.py` and one `modules/<fqcn>.zip` per included
module. Building and inspecting happen outside the MCP server lifecycle, so no
local Python or Ansible runtime is consulted at startup or during a request.

```sh
estus bundle build --python /opt/ansible/bin/python \
  --collections-path /opt/collections --output /etc/estus/bundle
estus bundle inspect --bundle /etc/estus/bundle
```

`--python` must be an absolute interpreter path that already has ansible-core
(and any selected collections) installed; the builder runs it in isolated mode
with a fixed locale and never installs anything. `--collections-path` is
repeatable. `--module` is repeatable and defaults to the builder's stock SRE set
(`ansible.builtin.systemd_service`, `ansible.posix.sysctl`, `ansible.builtin.apt`,
`ansible.builtin.dnf`, `ansible.builtin.dnf5`, `ansible.builtin.package_facts`,
`ansible.builtin.stat`, `ansible.builtin.service_facts`). `--output` must be new:
the builder refuses to replace an existing directory and removes its partial
output on failure. `--timeout-secs` bounds the whole build (1–600, default 120).

`bundle inspect` verifies the pack without Python, Ansible or SSH and prints one
JSON line: `status` (`passed`/`failed`), `error_code`, `ansible_core_version`,
`bundle_sha256` and `module_count`; failure exits non-zero. Loading enforces the
manifest schema, the canonical-JSON bundle digest, the wrapper digest and every
module archive digest, sizes, FQCN shapes and router targets. A tampered or
partially written pack fails closed instead of degrading to another runtime.

Select the pack with `[automation].bundle` (which wins), then
`ESTUS_ANSIBLE_BUNDLE`, otherwise executable-relative discovery
(`../share/estus/bundle`, `../../_bundle`, `../_bundle`). `[automation].required =
true` makes a missing or broken pack a startup failure; installing a pack never
enables a tool. The manifest records the ansible-core version that produced it and
the target Python floor implied by that version; the target still needs an
interpreter at the configured absolute path.

Module bindings name the module and never carry a snapshot path:

```toml
[tools.automation_probe]
revision = "2"
targets = ["server"]
authority = "automation"
effects = ["probe"]
execution = { kind = "ansible_module", module = "ansible.builtin.ping", no_log = false }
input_schema = { type = "object", properties = {}, additionalProperties = false }
fixed_args = { data = "pong" }
input_map = {}
result = { kind = "ansible_summary" }
limits = { timeout_secs = 10 }
```

A binding may pin its own `bundle` path; otherwise the configured pack applies.
Reviewed `input_schema`, `fixed_args` and `input_map` are the same closed contract
used elsewhere: the module's documented argument object is imported from the pack
at binding-compile time, the caller supplies only declared inputs, and fixed
values never come from upstream documentation defaults. `check_mode`/`diff` are
rejected unless the pack advertises support and the reviewed result fields approve
disclosure. Module results are summary-only (`ansible_summary`) or select declared
members (`ansible_projection`); raw events, arguments, environment and private
paths are never returned, and `no_log` stays censored.

## Cross-distro package changes

`ansible.builtin.package` is a router. The bundle maps it to the manager detected
on the target: apt, dnf/dnf5, apk, zypper or pacman (`yum`, `yum4` and `dnf4`
normalize to `dnf`). An undetected or unsupported manager fails closed with an
`unsupported` tool error; it never falls back to a shell command or a different
backend. The generic contract accepts a non-empty `name` string or list, `state`
(`present`/`absent`/`latest`) and `update_cache`. An exact `version` is allowed
only with `state = "present"` and a single package name, and is rewritten as
`name=version` for apt and `name-version` for dnf/dnf5/zypper.

`change_package` wraps that router; `change_apt` and `change_dnf` are explicit
escape hatches for manager-specific options (`purge`, `allow_downgrade`; or
`enablerepo`, `disablerepo`, `allowerasing`, `nobest`). Build the pack with the
backends your fleet needs and inspect it before enabling:

```sh
estus bundle build --python /opt/ansible/bin/python \
  --collections-path /opt/collections --output /etc/estus/bundle \
  --module ansible.builtin.package --module ansible.builtin.apt \
  --module ansible.builtin.dnf --module ansible.builtin.dnf5 \
  --module community.general.apk --module community.general.zypper \
  --module community.general.pacman
```

See [`examples/change_package.toml`](examples/change_package.toml),
[`examples/change_apt.toml`](examples/change_apt.toml) and
[`examples/change_dnf.toml`](examples/change_dnf.toml). Requirements and
repositories remain operator-provisioned prerequisites: no request installs a
dependency, refreshes a cache unless that reviewed option is approved, and no
interrupted transaction is replayed.
Target-host Python bindings are prerequisites for the package tools:
`preview_package`/`change_package` and `preview_apt`/`change_apt` need
`python3-apt` on Debian/Ubuntu, and `preview_dnf`/`change_dnf` need
`python3-dnf` or `python3-libdnf5` on RHEL/Fedora. Estus does not install
module dependencies (`auto_install_module_deps = false`): a missing binding
fails closed as `dependency_unavailable`, and check-mode runs never mutate the
target. `observe_packages` is a pure-stdlib collector and needs no manager
binding.

### Sysctl preview pairing

Under `require_preview = true`, a qualified `preview_sysctl` run must precede
the matching change tool with the same key and value:
`preview_sysctl` with `{name, value, state: "present"}` pairs with
`change_sysctl_config` (dedicated sysctl.d file plus exact-file apply, with
verified readback), and `preview_sysctl` with
`{name, value, state: "present", sysctl_set: true}` pairs with
`change_sysctl_runtime` (single-key runtime write, no persistence). A preview
authorizes only its paired change tool and the inputs it was given.

## Ordinary Ansible modules

[`examples/automation_probe.toml`](examples/automation_probe.toml) enables one real,
fixed `ansible.builtin.ping` binding against an operator-built bundle. Build and
inspect the pack first, then start the server with the same configuration:

```sh
estus bundle build --python /opt/ansible/bin/python \
  --module ansible.builtin.ping --output /etc/estus/bundle
estus bundle inspect --bundle /etc/estus/bundle
estus --config examples/automation_probe.toml
```

The example's conventional absolute paths must be provisioned for the MCP account.
No Ansible runtime is installed into the server; the pack is the only Ansible
artifact consulted, and building one still does not enable a tool.

Module calls use `{"host":"server","inputs":{}}`; optional `timeout_secs` is a
transport field. The entire reviewed domain schema is published under `inputs`,
preserving conditional, property-count, enum and const constraints without
mixing them with transport controls. Native/controller tool input shapes are
unchanged. Malformed input shapes produce protocol errors; valid shapes violating
reviewed bounds or choices produce tool errors before execution.

Each module definition fixes its `execution.module`, optional `execution.bundle`,
`authority = "automation"`, `result.kind`, effects, logical targets,
`input_schema`, `fixed_args` and `input_map`. Only explicitly enabled and
capability-effective definitions compile a contract or dispatch; enabled bindings
whose module is absent from the pack fail before MCP starts, and requests never
regenerate approval or install dependencies.

`[automation.targets.<logical>]` fixes the SSH destination and absolute target
Python interpreter independently of native sudo authority. This ordinary authority
never becomes; named broader authorities below are separate. OpenSSH resolves
operator aliases and the replacement SSH file. Module transport does not use the
Rust pool: sharing, forwarding, host-key updates, password prompts and remote TTY
allocation are disabled. Automation uses the same validated local OpenSSH
executable as native SSH and doctor; see
[Local SSH executable](#local-ssh-executable) for selection and path resolution.
An existing bounded absolute `SSH_AUTH_SOCK` reference is preserved for an
out-of-band agent. The product does not load keys, create an agent, prompt for
credentials or accept key/password contents as tool inputs.

Summary-only results contain logical host, status, the runner return code, bounded
task counts, change/censorship/completion, duration and local cleanup evidence.
They still exclude module values. Typed bindings may expose only explicitly
selected fields as described below; whole raw events/arguments/environment are not
returned. `no_log` remains censored. Caller argument trees are wrapped with
`!unsafe`, preventing nested Jinja evaluation while preserving string types —
including empty, numeric-looking, boolean-looking and null-looking strings.
Per-scalar unsafe tags are not used because Core can re-resolve their quoted
contents as YAML native values.
Failed modules may report mutation even when Core omits their changed count.
That observation survives a known failure; it is not rewritten as unchanged or
discarded as a protocol error.
A singleton skipped module is complete success when the run reports successful
completion with return code zero and matching skipped task statistics (for
example, a verbosity-gated `debug` task). It preserves `tasks.skipped = 1`
and known unchanged evidence; `no_log` keeps `changed = null`, not a fabricated
`false`. Contradictory status, counts or change evidence still fail closed.

`automation.max_concurrent` defaults to 2; each logical target admits one automation
invocation at a time. The existing global operation cap also applies. Admission
and private workspaces remain owned through cleanup, including client loss.
Cancellation first lets the owned worker propagate termination through its
cleanup; bounded fallback remains available. Neither local cleanup nor a cancelled
reply proves remote termination, rollback or escaped-child containment. No
operation is automatically replayed.

Scratch under `[controller].workspace_root` defaults to 16 MiB/512 entries. Byte and
file polling cancels on an observed watermark, not a hard filesystem or memory
quota. Transient worker files can contain secrets; duplicate output/event capture
is suppressed and invocation files are removed after ownership ends. Same-UID Unix
sockets beneath the invocation's private temporary directory are permitted for
Python multiprocessing IPC and still count toward the entry limit. Symlinks,
sockets elsewhere and other special files remain rejected. Crash recovery does not
promise secure erasure. Privilege escalation and retained raw events remain outside
this implementation.

## Native catalog payloads

Catalog tools that are not bundle modules are controller-owned native Python
payloads: `catalog/payloads/<tool>/{collector.py,manifest.json}`. No Ansible
runtime, role snapshot or controller workspace is involved. The reviewed
`native_payload` binding fixes the collector source, its manifest, the target
interpreter and the argument adapter, and the collector runs over the ordinary
SSH identity:

```toml
execution = { kind = "native_payload", snapshot = "/etc/estus/observe_host_summary.payload.json", source = "/etc/estus/payloads/observe_host_summary/collector.py", no_log = false }
```

Produce that pair through `catalog export` and `catalog prepare`, which copy the
reviewed collector bytes and write the snapshot manifest next to them:

```sh
estus catalog export --tool observe_host_summary --output ./health-export
# Review health-export/payloads/observe_host_summary/{collector.py,manifest.json}.
estus catalog prepare --site ./site.toml --definitions ./health-export/tools.toml \
  --target server --output ./health-reviewed
estus catalog inspect --site ./health-reviewed/estus.toml
estus --config ./health-reviewed/estus.toml
```

Preparation is offline: it approves collector source, adapter, typed contract and
policy without importing Ansible and without contacting a target. Existing output
paths are refused, and a changed source or manifest is never refreshed silently —
export, review and prepare again.

Payloads use the same `{"host":"server","inputs":{...}}` envelope, target and
capability authorization, timeout/admission, child owner and cancellation path as
modules. Rust validates and canonicalizes the assembled inputs before dispatch.
Source bytes are checked again immediately before the payload runs; that is drift
detection, not immutable attestation.

Results are `capability_projection` (declared `mcp_result` members selected by the
reviewed schema and aggregate bounds) or `command`. Missing or invalid results
produce an independent output error without erasing verified execution, change or
failure evidence; `no_log` remains censored.

The catalog contains 112 controller-owned native Python payloads and 8
`ansible_module` entries that require a bundle. Native
`payloads/<tool>/collector.py` bytes are approved together with a typed contract,
fixed policy, argument adapter, requirements and authority. Delivery uses
interpreter stdin, not a target source installation or cache. Declared
requirements are checked on the target in the same round trip that runs the
collector, immediately before `exec`: interpreter floor, importable modules and
resolvable executables. Nothing is cached and no fingerprints are compared, so
the answer always describes the target as it is right now. An explicit
interpreter failure never falls back to another one. These checks are a
pre-dispatch refusal, not immutable attestation.

Native revisions have the `_native1` suffix. Domain data remains at
`data.projection.value`; `runner_rc` now carries the actual collector exit code
and a completed failing collector reports `payload_failed`. Positive mutation
evidence survives failure; failed operations do not publish success projections.
`owned_group_cleanup="not_applicable"` means no per-request controller process
group exists on this backend, not that remote work never started or all descendants
are gone. Use completion and uncertainty fields for execution evidence.

Native network link/address/route mutations declare `/usr/bin/ip` as a mandatory
prerequisite. Module load declares `/usr/bin/modinfo`, `/usr/bin/modprobe` and
`/usr/bin/ip` (needed for the approved load-parameter readback); unload requires
the two kmod utilities. These declarations are bound into the reviewed manifest.
Existing snapshots do not acquire them automatically: export, review and prepare
a fresh approval to adopt them.

The eight native NIC setters (channels, rings, coalescing, pause, RSS, features,
FEC and EEE) similarly bind `/usr/bin/ethtool` as a required executable. Missing
utility discovery is distinct from an unsupported driver control or a failed
readback: those remain explicit payload failures, never successful no-ops.
Interface/MAC/driver checks and the original collector bytes remain unchanged.

Native NVMe health observation binds `/usr/bin/nvme` as a prerequisite. It reads
the fixed controller's [raw SMART log](https://manpages.debian.org/testing/nvme-cli/nvme-smart-log.1.en.html),
preserves wide counters as exact decimal strings, and omits the identity-guard
serial from published telemetry. The MD RAID observer instead reads existing
[kernel sysfs attributes](https://docs.kernel.org/admin-guide/md.html) under
ordinary authority: it requires neither `mdadm` nor raw block-device access.
Do not add changing array attributes or controller counters to requirement
checks; observations must remain fresh within an active MCP session.

A missing utility fails before payload dispatch with `resource_unavailable` and
`remote_state_unknown=false`. Because nothing is cached, a utility replaced
between requests is observed by the very next one: there is no stale entry to
invalidate and no rediscovery step. This does not attest modprobe hooks,
configuration or all target dependencies. Parameter-setting keeps its explicit
unsupported/no-write receipt when the approved sysfs parameter is absent; it does
not require that optional parameter path during the requirement check.

Collectors are plain Python modules with no third-party imports beyond the
standard library their manifests declare. Migration to the native path does not
promote laboratory or site-policy qualifications. Fast tests import the actual
collectors; real guest tests retain transport, permission, mutation and
postcondition coverage.

```sh
nix run .#catalog-acceptance-msrv
```

This runs the shipped catalog suite outside the Nix sandbox, using the same
private-directory/non-root prerequisites as native acceptance. Native selections
need no selected Ansible runtime; bundle-backed module tools require a built pack.

## Deployment trust boundary

Estus enforces MCP request validation and dispatch policy, not a sandbox.
Remote SSH identities and target OS authorization remain authoritative.
**A client with arbitrary execution under the server's OS identity is outside
the claimed restriction:** it can use that identity's credentials, SSH control
sockets and runtimes without going through MCP.

Named tool metadata and catalog inspection expose the executor, configured
authority, execution location, trusted-controller-code requirement and restriction
boundary. Ansible and controller code are trusted operator code running with the
service account's access, including access to its credentials. `no_log`,
projections and process cleanup do not make that code safe or sandbox it.

When the client also has local execution, use distinct client and service
accounts with private service credentials/runtime directories and a root-owned,
forced-command stdio ingress. The client must not have service-account shell,
sudo/root, shared privileged groups, or host/container-administration access.
The [separated-account example](examples/separated-accounts/) makes this concrete
without introducing another production daemon or container requirement.
Estus does not provision or verify production account isolation; inspection
explicitly reports `operator_managed_not_observed`.

## Bundled operational catalog

Normal wheels and Nix packages include the versioned catalog: definitions,
payload sources and manifests. Eight entries are `ansible_module` templates and
need an operator-built bundle; the other 112 are native payloads and need only the
target interpreter. Installing the package does **not** enable catalog tools or
grant credentials or sudo. The repository's `catalog/` tree is the canonical
shipped asset source; `examples/` contains demonstrations and deployment examples.

Source-checkout migration: use `catalog/` for catalog roots and selected
definitions. Installed `_catalog` and `share/estus/catalog` layouts, inventory
version7 and reviewed payload bytes are unchanged. Existing exports and prepared
approvals remain valid when their recorded paths and content remain unchanged.
Update configurations and commands that explicitly name an old source root or
that referenced removed role sources; if an approval's recorded source path
changes, explicitly export, review and prepare again. Estus never rewrites or
silently refreshes an approval. No obsolete source copy or compatibility symlink
remains.

```sh
estus catalog list
estus catalog list --json
estus catalog export --preset linux-health --output ./health
```

Listing and export need no SSH connection or Ansible runtime and work without a
checkout. Normal launchers select their installed assets; development commands
can use `estus catalog --root "$PWD/catalog" list`. An explicit invalid root
fails rather than silently selecting another catalog.

Catalog manifest/list format3 includes executor-specific assets and explicit
qualification alongside `policy_required` and `requires`; inventory version7 applies.
`site_policy_template` requires site review, while `laboratory_only` identifies
hard-coded synthetic-device or fixture contracts, not production defaults.
`unqualified` makes no readiness claim. `deployment_qualified` is reserved for
documented complete workflow evidence; no current entry has that designation.
Qualification describes the catalog template, not a configured binding's
authority or a successful deployment. Inspection labels this scope explicitly
and marks non-catalog bindings unqualified.

| Preset | Scope |
|---|---|
| `linux-health` | CPU counters, memory gauges and PSI |
| `network-observe` | Reviewed passive interface/address/route observations |
| `network-probes` | Explicitly approved active destinations/resolvers/ports |
| `sensitive-observe` | Separately approved process/socket/journal disclosures |

There is no `all` or `admin` preset. Reboot, module/package/repository mutation,
NIC tuning and other maintenance remain individual opt-ins.

FEC tools are individually opt-in: `observe_nic_fec` reads the configured/active
encoding, and `change_nic_fec` changes the reviewed runtime mode (`off` or `rs`)
with driver readback and an honest no-op receipt. The lab uses Linux
`netdevsim` as `fec0`, separate from its management interface. These tools
qualify virtual-driver configuration, not physical error correction.

The lab-only `estus_nic_model` driver adds isolated `model0` for
`observe_nic_eee`, `change_nic_eee` and `observe_nic_transceiver`. These tools use the normal
reviewed native payload path, real kernel ethtool callbacks and the real ethtool binary;
the driver is not installed on production targets by Estus.

EEE setting accepts an enabled flag and a 0–1000000 microsecond Tx LPI timer,
always requesting Tx LPI on. Configuration is not negotiation: the model remains
inactive even when enabled, and an LPI-off hidden timer is omitted, not zero.
Setters check actual readback, skip writes on no-ops and never replay or roll back.
Transceiver observation publishes only vendor/part and selected typed sensors
from an explicitly synthetic SFF-8472 EEPROM; serial, date and raw pages are not
published. It never writes EEPROM or runs an active hardware diagnostic.

### Review and prepare a site configuration

Export creates private **inert** `tools.toml`, executor-specific payload assets,
exact JSON overlays and `catalog-selection.json` qualification/prerequisite metadata.
It creates no credentials or active approvals. Review the selected definitions and
each `payloads/<tool>/{collector.py,manifest.json}` first. Unit names, interfaces,
paths, module parameters, package names and repositories outside `linux-health` are
generally **fixture policies**, not production defaults: adapt the closed input
enums, fixed policy and allowlists together.

For native Linux health tools, provide the actual SSH mapping in `site.toml`;
no controller Ansible bundle or workspace is needed:

```toml
mode = "headless"
capabilities = { named = true }
tool_presets = ["linux-health"]
disabled_tools = []

[catalog]
version = "8"

[targets.server]
ssh_host = "server-ordinary"
# Omitted selection inherits globally; [] explicitly denies all named tools.
enabled_tools = ["observe_cpu", "observe_memory", "observe_pressure"]

[automation.targets.server]
destination = "server-ordinary"
python = "/usr/bin/python3"
```

For a single-tool export, replace the global `tool_presets` selector with
`enabled_tools = ["<tool>"]` and narrow the target's `enabled_tools` likewise.
Do not retain a preset that selects definitions absent from that export.

Then explicitly import the reviewed contracts, inspect the output, and launch:

```sh
estus catalog prepare --site ./site.toml --definitions ./health/tools.toml \
  --target server --output ./reviewed
estus catalog inspect --site ./reviewed/estus.toml
estus --config ./reviewed/estus.toml
```

Preparation is offline. Native selections approve immutable collector source,
adapters and typed policy without consulting Ansible. Selected `ansible_module`
definitions instead compile their reviewed contract against the authority's bundle
(or the configured pack) and fail with `runtime_unavailable` if none is present; no
module is executed. It writes a new configuration and never contacts targets.
Missing authority is not fabricated. The overall deadline includes all preparation
(`--timeout-secs`, default60).
Existing output paths and definition collisions fail; output parents must be
controlled by the account/root, not foreign-owned or non-sticky shared writable
directories. Relative site paths retain the supplied site's directory even
when the site file is a symlink.

`inspect` and `prepare` honor the shared SSH selection precedence: explicit
`--ssh`/`--ssh-config`, then their environment variables, then site settings
(and PATH for an otherwise unspecified executable). CLI/environment relative
paths use the launch directory; site-relative paths use the site's directory.
An explicit `--config` conflicts with `--site` and is rejected; ambient
`ESTUS_CONFIG` does not replace the explicit site.

Preparation pins the effective executable and replacement SSH configuration as
absolute paths in `estus.toml`. A subsequent launch without overrides therefore
uses that selection even from another directory. Later CLI/environment overrides
still follow the normal precedence; clear them when using the pinned values.
The SSH configuration's contents remain operator-managed, not snapshotted.

Named automation authorities keep their separate SSH configuration files; the
shared executable selection still applies.

Offline `list`/`export` ignore ambient configuration/SSH variables and need no SSH
or Ansible. Explicit `--config`, `--ssh` or `--ssh-config` on those commands is
rejected rather than silently ignored.

`inspect` explains resolved named-tool exposure and per-target permission,
including the global native command-execution, file-read and file-write exposure
booleans. These are global ceilings, not additional per-target grants. Inspection
does not verify runtime health or remote capabilities; use `doctor` for explicit health
checks. Review the prepared collectors, manifests and overlays before using the
generated configuration; `catalog prepare` is the only authoring path, and no
request-time approval refresh exists.

### Selection, authority and upgrades

Global named selection is preset membership plus `enabled_tools`, minus
`disabled_tools`. Target selectors only narrow that result; omission inherits,
explicit empty selection denies, and global disable always wins. Unknown or
duplicate names fail. Catalog templates are inert until reviewed definitions
are supplied; up to 256 named bindings are supported.

Presets require an explicit catalog version; use the version reported by
`estus catalog list --json` after reviewing the installed inventory. Catalog
schema3/version8 declares per-entry workstation policy, so workstation mode
loads only reviewed templates; version7 added executor-specific assets and the
native catalog cutover.
Review existing pins rather than silently adopting an upgrade. Source/runtime/
overlay drift still invalidates snapshots; startup never refreshes approval.

`[capabilities]` (`named`, `file_read`, `file_write`, `exec`, `sudo`) sets
independent exposure ceilings, **not** task presets. Explicit configuration files
default to `mode = "headless"` (`named = true` only); no-config startup needs the
explicit `--workstation` opt-in to enable all five ceilings with dynamic ordinary
SSH resolution. `[rules."<pattern>"]` narrows per-host permissions via `deny_tiers`,
`allow_tools`, and per-tool `constraints`. Capabilities are not OS/account sandboxes.

Every registered tool publishes `_meta.risk_tier` (`observe`, `inspect`, `preview`,
`change`, `exec`). For MCP client approval rules, allow exact `observe_*` tools
(`observe_targets`, `observe_stat`, and read-only `observe_*` catalog tools) and
require confirmation (`ask`) for `inspect_*`, `preview_*` (until qualified),
`change_*`, and `exec_*`.

Privileged/sensitive entries require separately configured `automation:catalog`
authority where declared, never an inferred native sudo grant. Typed sensitive
reads use `no_log=false` intentionally; protect private scratch and approve
disclosure independently. Inputs cannot choose flags, paths, environment,
inventory, credentials or privilege beyond the reviewed domain.

Unit-file enable/disable/mask/unmask retain `--no-reload`; manager activation is
the separate `change_systemd_manager_reload` capability. Runtime changes do not imply
persistence. Reboot scheduling is not confirmed reboot completion. Interrupted
mutations are never automatically replayed and do not imply rollback.

### Four reviewed operational workflows

These recipes are the narrow operational qualification set, not blanket approval
of every catalog entry or site. The first three select canonical definitions and
produce concrete runtime/content approvals through `catalog prepare`; their
recipe TOML is not a runnable server configuration. Follow the public
export/review/prepare/inspect/start commands in each recipe. Never copy an
approval from another runtime or silently refresh one.

| Workflow | Reviewed input | Independent confirmation |
| --- | --- | --- |
| Host inspection | `examples/workflows/health.toml` / `observe_host_summary` | Actual boot identity, kernel, architecture and bounded uptime; no application-health or isolation assertion |
| Service diagnosis | `examples/workflows/service-diagnosis.toml` / `observe_systemd_unit` | Active/inactive/failed manager state and selected properties; state is not application health |
| Controlled restart | `examples/workflows/service-restart.toml` / `change_systemd_restart` | Selected unit PID/invocation changes; completion reports health not checked; cancellation is not rollback/replay |
| Configuration replacement | `examples/workflows/config-replacement.toml` | Restricted SFTP, expected-digest read, complete old/new visibility, independent SHA-256 and new mode0600 inode |

Catalog workflows expose only their reviewed named tool and non-executing
discovery/output tools. Replacement deliberately uses `files-only`, not
`actions-only`, with a dedicated root-owned chroot/forced-internal-SFTP boundary;
only `/config` is writable in the disposable qualification target. The file
capability is not itself a pathname sandbox. Replacement does not promise crash
durability or compare-and-swap against concurrent writers.

```sh
nix run .#workflow-catalog-acceptance
# Select an explicit DOCKER_HOST and matching deployment-fixture-image first:
ESTUS_TEST_FIXTURE="$PWD/nix/result/fixtures/deployment-x86_64-linux" \
  nix run .#workflow-files-acceptance
```

`workflow-acceptance` runs both components; matching `-msrv` entrypoints remain
separate. Each scenario owns clean disposable state and verifies policy denial,
setup diagnostics and/or interrupted/uncertain outcomes without a generic-shell
escape hatch. A manager job may complete after cancellation; independently
inspect it before deciding anything. A conservative failed replacement may leave
a private stage: never automatically replay it or delete an unproven pathname.

Recorded catalog scope: x86_64 Linux controller with CPython 3.14.8 and an
Ansible Core 2.21.5 bundle build environment; pinned disposable NixOS 26.11 x86_64
guest with Linux
6.18.60. Replacement uses the Nix-built x86_64 Linux deployment image through an
explicit Docker-compatible backend on Darwin 25 arm64. These fixture results do
not qualify another site's identities, service health signals, storage durability
or physical hardware.

### Extended catalog qualification

```sh
nix run .#catalog-acceptance-msrv
nix run .#catalog-acceptance-msrv -- tools::observe_pressure::observe_pressure --exact
```

Every real scenario owns a fresh preprovisioned EFI guest, keys, disk and EFI
state. Signed local apt repositories use an explicitly public test-only signing
key, not production trust. No workstation services, interfaces, modules,
bootloader or physical devices are changed. Injected SSH keys have one writer;
OS key generation is disabled and installation errors go to the private console.
Fast parser tests use stdlib Python from Nix check inputs, not Ansible.

The native mutation wave covers module load/unload/parameter setting and network
link/address/route add/remove on the disposable fixture, without a controller
Ansible runtime. Its oracles check kernel/sysfs and `ip -j` state independently.
Strict network add/remove operations remain strict operations, not implicit
replace/ensure-state calls. A same-value parameter write remains a write attempt,
not an inferred no-op.

The persistent-session prerequisite scenario removes and replaces the real `ip`
executable, checks that the missing utility is refused before mutation, and
observes exactly one mutation/readback per accepted request. A later request with
the utility swapped re-resolves it, since each call re-checks requirements. The
wrapper delegates to the actual utility; it does not simulate network state.
Select it with:

```sh
nix run .#catalog-acceptance-msrv -- \
  tools::change_network_link_down::network_link_down_requires_stable_executable --exact
```

Recorded native-wave verification: ten scenarios on a Darwin arm64 controller
against disposable x86_64 Linux EFI guests, with no selected Ansible runtime.
The control-plane launcher disabled emulated interrupt remapping after a QEMU
boot panic; mutation and policy oracles were unchanged. Existing laboratory and
site-policy labels remain in force; this is not physical-device qualification.

The isolated lab qualifies selected Virtio/veth/e1000e controls, Linux
`netdevsim` FEC configuration, modeled EEE state and synthetic module decoding,
Linux MD RAID1 and virtual NVMe-reported telemetry. The NIC model exposes
root-only fault controls for unsupported/read-error replies, rejected writes,
accepted-but-unapplied writes, partial effects, delayed reads and malformed
module data. Tests use real ethtool calls and Rust assertions, including
independent readback and management-path survival.

Native NIC mutation acceptance checks both the typed domain receipt and outer
change evidence, plus ordinary UID1000 management-path survival. EEE fault cases
observe the model's independent kernel setter counter: unsupported/read-error
observations perform no write; rejected, unapplied and partially applied writes
remain failed receipts without replay or rollback. Completed failure with
`changed=null` does not establish unchanged device state.

The persistent EEE session also removes and replaces `ethtool`, requiring
prerequisite rejection before any setter callback, on every request. A later
explicit request re-resolves the utility; a rejected request must not invoke the
setter. This uses the actual utility and kernel callbacks, not a simulated
command result:

```sh
nix run .#catalog-acceptance-msrv -- \
  tools::change_nic_eee::nic_eee_set_requires_stable_ethtool --exact
```

Recorded native NIC wave: ten real guest scenarios and two FEC parser checks
passed on a Darwin arm64 controller with disposable x86_64 Linux EFI targets and
no selected Ansible runtime. This used the same documented `intremap=off` launch
workaround. All eight setters retained their source and qualification labels;
EEE remains a software model, and FEC readback is not physical-link validation.

Recorded native storage wave: two real guest scenarios and five captured/boundary
parser checks passed without an Ansible runtime. One MD session observed healthy,
degraded and subsequently absent state; missing state failed rather than replaying
cached telemetry or assembling an array. The NVMe session rejected missing
`nvme-cli` before dispatch, recovered only on a later request, and matched changed
I/O counters against independent controller queries. Both observations retained
read-only change evidence and ordinary-access boundaries.

This used disposable Linux MD/NVMe devices with the same documented launcher
workaround. MD values remain non-atomic kernel-reported redundancy observations;
NVMe values remain virtual-controller reports, not physical-media health verdicts.
Collector bytes and existing qualification labels are unchanged.

This is software configuration/API and decoding qualification—not physical
power savings, peer negotiation, optical accuracy, arbitrary-driver support,
physical FEC or wire-level pause proof. Physical confirmation remains deferred.
Site-specific deployment procedures remain unqualified, without placeholders.

## Catalog policy: facts first

The catalog does not maintain a second native/custom collector when maintained
Ansible facts or a safely fixed query-only status API supply the declared
observation. Selection, filters and formatting alone are not additional insight.
Keep distinct collectors only for useful extra data, fidelity or query/sampling semantics.

The audit against Ansible Core2.21.5, ansible.posix2.2.2 and
community.general13.4.0 makes these opt-in definitions facts-backed, without
introducing second collectors:

| Binding | Reused facts | No second collector for |
|---|---|---|
| `observe_systemd_unit` | [`systemd_service`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/systemd_service_module.html) query-only `status` | Selected per-unit properties in a fixed system/user scope; no mutation arguments |
| `observe_hardware_system` | [`setup`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/setup_module.html) DMI fields | Manufacturer/model, board and BIOS versions |
| `inspect_hardware_identifiers` | `setup` DMI fields | Serials, UUIDs and asset tags; retain separate sensitive-read approval |
| `observe_storage_devices`, `observe_storage_device` | `setup` device/link facts | Basic block inventory, geometry, partitions and holder/master relationships |
| `observe_storage_mounts` | [`mount_facts`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/mount_facts_module.html) | Dynamic mount inventory and mount capacity/inode data |
| `observe_packages` | [`package_facts`](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/package_facts_module.html) | Installed package/version inventory and reported backend metadata |
| `observe_nic_features` | `setup` network feature facts | Reported `ethtool -k` offload states, including fixed-state annotations |

Use opt-in reviewed bindings and closed bounded projections, never a public
dump-all-facts tool. Fix fact subsets, backend/source choices and timeouts;
exclude raw event/context/environment data and undeclared identifiers. Setup
filtering limits returned keys, not every internal probe. Mount facts must select
current sources rather than silently mixing fstab with live mounts. Package
prerequisites are preprovisioned: no dependency install or repository refresh.
The catalog acceptance suite exercises these bindings against real guest state.

For query-only unit status, omit `state`, `enabled` and `masked`, and fix daemon
reload/reexec flags false. Do not use `enabled=false` or `masked=false` as a
read-only setting: those request changes. Publish only approved status properties.

The shipped `observe_host_summary`, `observe_cpu` and `observe_memory` remain useful:
setup does not provide the boot UUID, raw CPU tick counters/two-sample deltas,
or exact byte gauges plus the selected cumulative VM counters. They are currently
native payload collectors (`catalog/payloads/<tool>`), not bundle modules, so
they need only the target interpreter.

Keep richer systemd inventory/jobs/relationships, routing/address scope, live counters,
PCI/DIMM/slot/health data, configured-path filesystem queries and package file
ownership where they exceed facts. Do not justify a duplicate basic inventory
getter with speculative future fields. SSH/SFTP execution/transfer primitives
and their API demonstrations are different capabilities, not fact collectors.

## Opt-in Linux host summary

[`catalog/observe_host_summary.toml`](catalog/observe_host_summary.toml) binds the reviewed
[`observe_host_summary` collector](catalog/payloads/observe_host_summary) to one ordinary
SSH target. It is not enabled by default. This is a native payload: no Ansible
runtime, role snapshot or controller workspace is involved, and only the target's
`/usr/bin/python3` is needed. No packages are installed automatically and no
privilege escalation is used.

Configure the `server-ordinary` SSH alias, identity and host-key policy, then run
the offline catalog workflow; preparation copies the collector, writes its
snapshot manifest and pins the interpreter:

```sh
estus catalog export --tool observe_host_summary --output ./host-review
# Review host-review/payloads/observe_host_summary/{collector.py,manifest.json}.
estus catalog prepare --site ./site.toml --definitions ./host-review/tools.toml \
  --target server --output ./host-approved
estus catalog inspect --site ./host-approved/estus.toml
estus --config ./host-approved/estus.toml
```

Preparation does not execute the collector. Review the copied source, manifest and
overlay; no preapproved snapshot is shipped. The example selects only
`observe_host_summary` under `named = true`, restricts it to `server`, and caps
execution at 30 seconds. Its only domain input is the empty object:

```json
{"host":"server","inputs":{}}
```

The closed typed projection returns `system`, `distribution`,
`distribution_version`, `kernel`, `architecture`, `boot_id`, `uptime_seconds`,
`observed_at`, `scope`, `virtualization_type`, `virtualization_role` and
`unavailable`, alongside normal execution/change/completion/cleanup evidence.
There are no caller-selected paths, Python programs, arguments or payload. The
collector reads a fixed set of standard-library sources and at most 128 bytes from
each proc file it touches. Unavailable optional observations are omitted and named
in `unavailable`; malformed readable proc contents fail instead of becoming
invented zeroes. Results are bounded to 4096 bytes, 64 items and depth 4, and do
not expose raw facts, command output or private paths.

`observed_at` is the collector's UTC timestamp, not an atomic snapshot.
`scope="ssh_process_view"` means what the SSH process can observe: boot ID and
uptime may be shared with a host or affected by procfs/time namespaces.
Virtualization values are heuristic hints, not complete layering or isolation
attestation; absent hints are unavailable, not proof of bare metal. Linux is
required before proc reads; no other operating system is supported. The payload
reports no persistent changes, but it still creates transient target work under
the normal cleanup contract.

`nix run .#workflow-catalog-acceptance-msrv` exercises the shipped payload
through `catalog prepare` and the MCP endpoint against a disposable Linux EFI
guest, via `reviewed_health_workflow` and
[`examples/workflows/health.toml`](examples/workflows/health.toml). The wrapper
supplies `ESTUS_TEST_CATALOG_VM` and `ESTUS_TEST_ANSIBLE_BUNDLE`; no Docker
backend is involved. No host account, service or sudo policy is changed.

## Opt-in Linux CPU counters and topology

[`catalog/observe_cpu.toml`](catalog/observe_cpu.toml) selects the reviewed
[`observe_cpu` payload](catalog/payloads/observe_cpu), retaining ordinary `automation`
authority and the `named = true` capability. It requires target `/usr/bin/python3`,
not Ansible or a controller workspace. Nothing installs packages, escalates,
changes services/sysctls or hotplugs CPUs.

Use the public catalog workflow with the site mapping above:

```sh
estus catalog export --tool observe_cpu --output ./cpu-review
# Review source, manifest and fixed policy before approval.
estus catalog prepare --site ./site.toml --definitions ./cpu-review/tools.toml \
  --target server --output ./cpu-approved
estus --config ./cpu-approved/estus.toml
```

The example permits only `server`, read effects and a20-second execution budget.
The closed caller domain accepts optional `limit` (1–16 topology rows) and
`sample_ms` (0–2000 milliseconds). The approved argument adapter supplies8 and0,
not by injecting JSON-schema defaults. Empty input reads counters once; sampling
is explicit:

```json
{"host":"server","inputs":{}}
{"host":"server","inputs":{"limit":2,"sample_ms":100}}
```

The typed result contains `system="Linux"`, `scope="procfs_sysfs_view"`,
`observed_at`, `clock_ticks_per_second`, `online_cpu_count`, `counters`,
`topology`, `topology_truncated` and `unavailable`, with optional `boot_id`.
The ten aggregate counters are raw Linux USER_HZ clock ticks: `user`, `nice`,
`system`, `idle`, `iowait`, `irq`, `softirq`, `steal`, `guest`, `guest_nice`.
`clock_ticks_per_second` is the target's actual `SC_CLK_TCK`, not an assumed100.
Guest time is already included in user time, and guest_nice in nice; adding these
again double-counts it. No utilization, percentages, rates or load are invented.
All numeric observations are checked bounded integers. Unsupported/incomplete
aggregate fields and malformed readable data fail, rather than becoming zero.

With positive `sample_ms`, exactly two counter observations and one sleep produce
`counters` (first), `counters_end` (second), actual `sample_elapsed_ns`,
`counter_decrease` and `identity_changed`. Elapsed monotonic time is measured at
the observations, not copied from the requested delay; scheduling can extend it.
`delta` is emitted only if both boot IDs are known and equal, CPU-ID sets match,
and all ten counters are nondecreasing. Otherwise it is omitted and named in
`unavailable`; negative differences are never clamped. Linux `iowait` can
legitimately decrease, so a decrease is not proof of reboot/reset.
`identity_changed` means the CPU-ID set changed or two known boot IDs differ;
a missing boot ID is unavailable, not proof of identity change. `boot_id`
describes the final observation when available; `unavailable` names `boot_id`
if the final boot-ID read was unavailable. An unsampled result has none of
the elapsed/end/delta/decrease/identity fields.

Topology uses sorted logical CPU IDs from the final `/proc/stat` observation,
bounded by `limit`; `online_cpu_count` counts that whole view, not just returned
rows. Rows contain `cpu_id`, optional raw sysfs `package_id` and `core_id`, and
`unavailable`. Unreadable or negative kernel sentinel IDs are omitted and named
there. Kernel IDs/defaults are not asserted physical socket/core counts.
The collector bounds each proc CPU line to4096 bytes, the CPU prefix to262144
bytes and CPU rows to4096 (IDs at most262143), stopping before parsing non-CPU rows such as interrupts.
Boot-ID and individual topology reads are each bounded to128 bytes.

`observed_at` is UTC at the final counter observation, not an atomic snapshot
with boot ID or later topology reads. Procfs/sysfs may expose host/global CPUs
even when the process/container is constrained: these are not affinity, cpuset,
quota, available-capacity or isolation measurements. Missing values remain
unknown; no caller paths, code, environment, runtime or privilege controls exist.
The projection exposes no raw command output, proc contents, interpreter or
private paths, and retains normal execution/change/completion/cleanup evidence.
It is bounded to4096 bytes,256 items and depth5. `topology_truncated` describes
only the requested row limit; the projection status is authoritative if its
aggregate byte/item budget truncates output. The logical IDs/global count still
describe the observed view, not an effective CPU allowance.
The payload reports no persistent changes; normal transient target work still
follows the cleanup contract.

`nix run .#ssh-native-msrv` exercises both observation modes on a loopback
fixture (`ssh_workstation_dynamic_bundled_health_payloads`, plus the payload
unit and concurrency cases); no Docker backend is involved.
Accounting and topology semantics follow the kernel's
[/proc documentation](https://docs.kernel.org/filesystems/proc.html) and
[CPU topology ABI](https://docs.kernel.org/admin-guide/cputopology.html).

## Opt-in Linux memory gauges and VM counters

[`catalog/observe_memory.toml`](catalog/observe_memory.toml) selects the reviewed
[`observe_memory` payload](catalog/payloads/observe_memory), retaining ordinary
`automation` authority and actions-only exposure. It requires target
`/usr/bin/python3`, not Ansible or a controller workspace, and installs nothing.
No sudo, service changes or sysctl writes occur.

```sh
estus catalog export --tool observe_memory --output ./memory-review
# Review source, manifest and fixed policy before approval.
estus catalog prepare --site ./site.toml --definitions ./memory-review/tools.toml \
  --target server --output ./memory-approved
estus --config ./memory-approved/estus.toml
```

Preparation does not execute the payload. The example permits only `server`, read
effects and a20-second budget. Its closed caller domain is empty:

```json
{"host":"server","inputs":{}}
```

The typed result returns `system="Linux"`, `scope="procfs_view"`, `observed_at`,
`page_size_bytes`, `memory_bytes`, `vm_counters`, `unavailable` and optional
`boot_id`, alongside normal execution/change/completion/cleanup evidence.
`memory_bytes` contains required `mem_total_bytes` and `mem_free_bytes`, plus
available selected `mem_available_bytes`, `buffers_bytes`, `cached_bytes`,
`swap_total_bytes`, `swap_free_bytes`, `dirty_bytes`, `writeback_bytes`,
`slab_bytes`, `sreclaimable_bytes` and `sunreclaim_bytes`. These are the matching
`/proc/meminfo` gauges normalized from exact `kB` units by multiplying by1024,
not1000. `MemAvailable` is a kernel estimate, not effective cgroup headroom.
No used-memory/cache totals, percentages, swap estimates or synthetic
`MemAvailable` fallback are derived; gauge/slab identities are not asserted
atomic.

`vm_counters` selects `page_faults` (`pgfault`), `major_page_faults`
(`pgmajfault`), `swap_in_pages` (`pswpin`), `swap_out_pages` (`pswpout`),
`oom_kill_events` (`oom_kill`), `kswapd_scan_pages` (`pgscan_kswapd`) and
`direct_scan_pages` (`pgscan_direct`) from `/proc/vmstat`. These are cumulative
events or base pages as named, not gauges, rates or kB. The reported
`page_size_bytes` is the target's actual `SC_PAGE_SIZE`, never an assumed4096;
page counters remain in pages. Missing aggregate keys are not reconstructed by
summing per-zone variants.

Real zeroes, including zero swap and counters, remain zero. Missing optional
gauges/counters and unreadable optional boot ID are omitted and identified by
their exact dotted paths (or `boot_id`) in `unavailable`. An absent or denied
`/proc/vmstat` yields an empty `vm_counters` and all seven unavailable paths.
Malformed readable selected fields, duplicate selected keys, missing required
gauges, noncanonical boot IDs and values outside0–9007199254740991 fail rather
than becoming invented zeroes. Unrelated proc keys, including unitless hugepage
counts, are ignored.

The fixed shell-free isolated Python command reads complete `/proc/meminfo`
and `/proc/vmstat` with respective131072- and262144-byte caps, detects oversize
with one extra byte, and limits each source to4096 lines and each selected line
to4096 bytes. Boot-ID reads are bounded to128 bytes. The closed projection is
bounded to4096 bytes,128 items and depth4. No caller paths, code, environment,
runtime or privilege controls exist; public output/audit exposes no raw proc
contents, command stdout or private paths.

`observed_at` is target UTC at collection end, not an atomic snapshot across
proc sources. Procfs may expose host/global memory even inside a container;
these values are not effective cgroup, NUMA, cpuset or quota allowance.
There is no sampling or derived delta. The payload reports no persistent changes;
normal transient target work and private controller scratch still follow the
automation cleanup contract.

`nix run .#ssh-native-msrv` exercises the shipped assets on a loopback fixture
(`ssh_workstation_dynamic_bundled_health_payloads` and the `observe_memory`
parser cases); no Docker backend is involved.
Field semantics follow the kernel's
[/proc documentation](https://docs.kernel.org/filesystems/proc.html),
[`proc_meminfo(5)`](https://man7.org/linux/man-pages/man5/proc_meminfo.5.html)
and [`proc_vmstat(5)`](https://man7.org/linux/man-pages/man5/proc_vmstat.5.html).

## No role or playbook execution

Roles and playbooks are not execution kinds. The catalog cutover replaced
controller-owned role sources with native payloads, and the binding schema accepts
only `native_argv`, `controller_script`, `native_payload` and `ansible_module`.
There is no `ansible_role`, no `ansible_playbook`, no `execution.role_path`,
`execution.project_root` or `--role-path`, and no `estus schema` command:
`estus --help` offers `doctor`, `bundle` and `catalog` only.

Existing role- and playbook-based approvals are not migrated. Rework each site to a
native payload (preferred: `catalog export`/`prepare` of a canonical tool) or to a
bundle module binding, then review the resulting collector or module contract.
Estus never rewrites or silently refreshes an approval, and no compatibility shim
reads an old snapshot.

The security properties that applied to trusted controller code still apply to both
replacement paths: collector and module argument trees are validated and canonical
before dispatch, caller strings stay literal data (`!unsafe` for wrapped trees)
rather than template expressions, `no_log` remains censored, projections expose
only declared members, and unsupported execution evidence fails closed instead of
implying effects were prevented or rolled back. Neither path adds detached async,
elevation beyond the configured authority, multi-host scheduling, automatic replay,
dependency installation or a rollback guarantee.

## Explicit broader automation authorities

`authority="automation"` remains ordinary. A reviewed module or payload binding
may instead select `authority="automation:ops"` and be explicitly enabled.
Configure that private capability independently from native sudo allowlists:

```toml
[automation.authorities.ops]
ssh_config_file = "/etc/estus/automation-ssh.conf"
bundle = "/opt/estus/bundle"
become = { method = "sudo", user = "root" }

[automation.authorities.ops.targets.server]
destination = "server-automation"
python = "/usr/bin/python3"
```

`become.executable` optionally pins an absolute remote sudo executable; the
default is `/usr/bin/sudo`. For NixOS, select `/run/wrappers/bin/sudo`.
The same operator-pinned path applies to native payloads and bundle modules; callers
cannot override it, and it does not enable generic command or sudo tools.

The replacement SSH configuration selects independently provisioned credentials
through ordinary OpenSSH `IdentityFile` or `IdentityAgent` settings. No privileged
key is installed on ordinary targets. An optional `ssh_auth_sock` selects an
existing bounded absolute agent socket; omitting it disables ambient agent
inheritance for this authority. Estus never loads keys or creates agents.

`bundle` may be omitted to inherit the pack selected for ordinary automation.
An explicit authority bundle does not depend on an unused ordinary pack or ambient
agent, and it must contain every module that authority's bindings name. Bundle
identity and source approval are not refreshed on calls.

Authorities name declared logical targets only, never fallback native/elevated aliases.
Missing authorities/mappings and malformed definitions fail startup even if disabled;
inactive valid file/runtime references remain unopened. Global and target startup
capabilities still apply, and all authorities share admission for the same logical target.
Public metadata advertises only the logical authority name. Audit uses
`identity_role="automation"` and authoritative automation finish `complete`; it
does not expose private destinations, configuration, socket or key paths.

Sudo fixes its builtin plugin, user, `/usr/bin/sudo` and `-H -n -k`. Generated
high-precedence transport variables apply in all execution modes; password aliases
are empty, and caller fields cannot choose become/user/authority/runtime/credentials.
Password-required sudo fails noninteractively even with a valid cached ticket.
With a command, [`-k`](https://www.sudo.ws/docs/man/1.9.17/sudo.man/#k) bypasses the
ticket; it does not promise to revoke it. Ordinary bindings are fixed no-become.
The target's actual sudoers policy remains an independently provisioned requirement.

Permission to run an interpreter as root is broad authority, not a narrow executable
allowlist. Trusted controller/project/plugin code still has its OS account's power;
this is policy/credential selection, not a security sandbox. Privileged mutation
and partial failures remain observable; cancellation never implies rollback or
remote quiescence.

`nix run .#ssh-baseline` exercises distinct keys/accounts and real root-owned
effects through `ssh_sudo_authority` and the other `ssh_e2e` scenarios. `ci` and
`ci-msrv` supply `ESTUS_TEST_FIXTURE` and require an explicit Docker-compatible
backend (`DOCKER_HOST`); no host sudoers or accounts are changed.

## Typed module result fields

[`examples/observe_platform.toml`](examples/observe_platform.toml) selects platform
and Python facts from the real setup module. Import its reviewed snapshot first;
the result declaration fixes paths and schema, never a caller expression:

```toml
[tools.observe_platform.result]
kind = "ansible_projection"
fields = { platform = ["ansible_facts", "ansible_system"] }
schema = { type = "object", properties = { platform = { type = "string", maxLength = 64 } }, required = ["platform"], additionalProperties = false }
max_bytes = 1024
max_items = 32
max_depth = 4
```

The response adds `data.projection`: `complete` or `truncated` contains a
schema-validated `value`; `censored`, `invalid` and `unavailable` contain no value.
Execution `status`, `complete`, `changed`, counts and uncertainty retain their
independent meanings. Invalid/unavailable projection after successful execution
is an `invalid_result` tool error, not empty success or evidence of rollback.
Summary-only bindings keep their original shape without `projection`.

Object properties are selected recursively by the closed schema, arrays keep a
bounded prefix, and strings keep a bounded Unicode prefix. `max_bytes` is 64–4096,
`max_items` counts 1–256 values/containers, and `max_depth` is 1–8 from root depth 0.
Finite per-node limits and smaller aggregate caps are joint upper bounds, not
guarantees every schema-required minimum can fit. Truncation is returned only if
the bounded candidate still satisfies the schema; no defaults/coercions are added.
The final MCP budget includes escaping and both result representations before
dispatch.

Known private/event/argument/environment/diff containers are not selectable.
Declared stdout strings and fact fields can still contain secrets: selection is
not general redaction. Task or selected nested censorship suppresses values.
The pinned core can omit oversized result data while retaining task statistics;
that yields `unavailable` without discarding known execution completion.

`nix run .#ssh-native-msrv` runs the focused projection suite
(`ssh_native_payload_*` cases: read concurrency, candidate discovery failures
and preview gating) with the same non-root/private-runtime-directory
prerequisites as native SSH acceptance. No request-time dependencies are installed.

## Native / Nix

The same application remains available without a Python launcher:

```sh
cargo build --release --locked
./target/release/estus --help
nix run .#msrv -- --help
```

Native Nix packaging supplies OpenSSH and has no Python/Ansible runtime dependency.
The separate `.#automation-msrv` output supplies a pinned ansible-core environment
usable for `estus bundle build`.
See `examples/automation_runtime.toml` for explicit, non-mutating bundle health.
That health check verifies pack digests and structure, not module execution.

The OpenSSH control-socket readiness check requires Tokio's `fs` Cargo feature.

SFTP uses the published `openssh-sftp-protocol` 0.26.1 release for lossless Unix
filename handling; no vendored protocol fork is required.

Catalog fixture-only kernel sources, public test-only signing material, service
templates, captured observations and provenance live under `tests/fixtures/catalog/`.
Their derivations live under `nix/tests/catalog/`; generated packages, indexes,
rootfs and disks remain build outputs. Never trust the published fixture signing
identity outside the disposable guest.
`catalog-vm.nix` composes the explicit x86_64 Linux `guest.nix`, focused disk
derivation and `launcher.nix` using host-selected QEMU/tools. Default and lab
launchers retain per-run private disks, EFI state and keys.

### Direct development MCP app

From the checkout root:

```sh
nix run --no-write-lock-file .#dev-mcp
```

Nix builds the current native package when needed, then the app `exec`s it with
`--workstation` and no `--config`, so the server starts in explicit zero-config
workstation mode: all five capability ceilings enabled, ordinary SSH destinations
resolved normally, and the catalog templates that declare a reviewed workstation
policy loaded from the installed assets. Workstation eligibility is catalog data:
only templates with a `workstation` block in `catalog.json` (the generic
read-only `observe_*`/`inspect_*` collectors) load, and site-policy or
`laboratory_only` templates never do. Nothing is widened or inferred at runtime.
No preparation command, readiness record or checkout-local launch script is
required. The same `estus-dev-mcp` executable is available in the pinned default
devshell.

The wrapper clears inherited `ESTUS_CONFIG`, `ESTUS_SSH_CONFIG`, `ESTUS_SSH`,
`ESTUS_CATALOG_ROOT`, `ESTUS_PYTHON_RUNTIME` and `ESTUS_WORKSTATION`, and pins
`ESTUS_ANSIBLE_BUNDLE` to the Nix-built direct module bundle, so bundle-backed
module tools work without an operator-built pack. Workstation mode still grants no
credentials and performs no remote action until a request arrives; it provisions
no fixtures and never refreshes approvals. `examples/dev-no-targets.toml` remains
an explicit, restrictive policy for launching the ordinary app by hand.

Build diagnostics go to stderr; server stdout remains MCP JSON. After startup,
EOF and signals use the server's normal process lifecycle. A cold launch can take
longer while Nix builds or downloads dependencies; cached launches reuse the store
artifact. New source changes take effect when the client starts the app again.
Local Git flakes use tracked files, so add newly introduced source files before
expecting Nix to include them.

For another explicitly reviewed policy, use the ordinary app instead:

```sh
nix run --no-write-lock-file . -- --config /absolute/path/to/reviewed.toml
```

### Local bootstrap and bundle CLI tests

The default devshell supplies Python 3.14 and Cargo for running the target
bootstrap protocol suite and the offline `estus bundle` CLI tests locally:

```sh
python3 -I -m unittest discover -s src/native_payload -p 'test_bootstrap.py' -v
cargo test --test bundle_cli
```

### OMP workspace client

The tracked `.omp/mcp.json` invokes `nix run --no-write-lock-file .#dev-mcp`
from the checkout root; the app itself passes `--workstation`, so the client gets
explicit workstation mode with `ESTUS_ANSIBLE_BUNDLE` set to the Nix-built base
module bundle. Set `"disabled": true` or use
`disabledServers` in your profile if you want to disable it locally.

The entry allows 300,000 ms for MCP requests, including cold initialization.
That client-side timeout is separate from the server's own limits: zero-config
workstation startup keeps the default `max_timeout_secs` of 600 and per-tool
timeouts, and this entry changes neither. Removing `--workstation` from the app
drops the client to the headless default rather than changing any of these
limits. `OMP_MCP_TIMEOUT_MS` overrides the entry
process-wide.

OMP18.19.0 discards subprocess stderr and reports startup failure as generic EOF.
For actionable build or configuration diagnostics, use the same app directly:

```sh
nix run --no-write-lock-file .#dev-mcp </dev/null
```

MCP execution remains client-owned: no proxy, detached service, automatic restart,
or mutable preparation state is added.

## CI coverage

The generated workflow (`nix/ci.nix`; regenerate with
`nix run .#generate-workflows`) runs on Linux x86_64/arm64 and macOS arm64:

| Layer | Hosted coverage |
| --- | --- |
| Sandboxed checks | Default compiler and Rust 1.88 network-free tests; acceptance executable compilation; formatting and workflow consistency |
| Installed MSRV native | Real SSH/SFTP, controller scripts, doctor and native/controller/SFTP progress |
| Installed MSRV bundle | Bundle build/inspect, digest drift, real SSH module execution, typed projections and progress |
| Linux containers | Default/MSRV SSH baseline; bundle-backed module smoke, automation authority and shipped host-summary, CPU and memory payloads |

The native Nix source filter keeps `skills/estus-sre/SKILL.md`,
`python/estus/__init__.py`, and `setup.py` for the catalog distribution checks.

Local SSH suites use a private runtime directory under the runner's home.
Linux automation suites build the dedicated `ssh-automation-fixture-image` and
select it explicitly through `ESTUS_TEST_FIXTURE`, with an explicit Docker socket.
These are workload tests, not just Ansible import checks: existing assertions
exercise failure, cancellation, cleanup, private-output boundaries and remote effects.

Fixture identity checks support both classic image stores and Docker's containerd
store. When the daemon reports a manifest ID instead of the artifact's config
digest, the harness exports that immutable image with the pinned Docker CLI and
GNU tar, verifies the config bytes against `image-id`, then selects and checks
the daemon ID for every running fixture. A changed tag or config still fails.

Wheel installation/launcher acceptance remains opt-in (`nix run .#wheel-acceptance`);
hosted coverage of the native package and Nix bundle does not prove the
outside-Nix Python/wheel path.

## Fuzzing

Five cargo-fuzz targets exercise real production modules — command
encoding/limits, the complete 16 MiB reply budget, file codecs, raw filename
metadata and binding-schema compilation — never copied parsers or mocked
executors. Harnesses and seed corpora live in `fuzz/`; the root build excludes
them, so fuzzing never changes production dependencies. The optional shell pins
nightly Rust and cargo-fuzz:

```sh
nix develop .#fuzz -c cargo fuzz run binding_schema fuzz/corpus/binding_schema -- -runs=0 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
nix develop .#fuzz -c cargo fuzz run command_encoding fuzz/corpus/command_encoding -- -runs=0 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
```

`binding_schema` drives reviewed-module contract import, recursive alias
mapping, caller-input rejection of authority/transport fields and numeric
bounds through the actual compiler; generated fixtures stay inside the
production depth/node/byte budget or are rejected by it. `command_encoding`
expands every fixture inside the same caps production enforces, then checks
escaped length and byte accounting through the actual pinned encoder, so
oversize commands and zero timeouts must fail as `invalid_argument` without
ever marking remote state unknown.

Time-bounded mutation campaigns write only to ignored
`fuzz/generated-corpus/` directories, keeping committed seeds deterministic:

```sh
mkdir -p fuzz/generated-corpus/binding_schema fuzz/generated-corpus/command_encoding
nix develop .#fuzz -c cargo fuzz run binding_schema fuzz/generated-corpus/binding_schema fuzz/corpus/binding_schema -- -max_total_time=30 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
nix develop .#fuzz -c cargo fuzz run command_encoding fuzz/generated-corpus/command_encoding fuzz/corpus/command_encoding -- -max_total_time=30 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
```

Fuzzing never connects to SSH or Docker, does not execute Ansible workloads,
and does not replace the real integration suites. Crash artifacts belong in
`fuzz/artifacts/<target>/` for minimization and a consumer-visible regression
before any fix.