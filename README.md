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

## Pinned Nix wheel build and acceptance

Nix orchestrates the same PEP 517 build and metadata, with Rust 1.88 and the pinned
Python/build-backend inputs. It does not copy the native Nix wrapper into the wheel.

```sh
nix build .#wheel
uv tool install --python 3.14 ./result/estus-*.whl
uvx --from ./result/estus-*.whl estus
uv run --no-project --with ./result/estus-*.whl estus
```

The producer declares macOS 11.0 for the arm64 Mach-O payload and manylinux glibc
2.17 for Linux. These are build/audit baselines for our executable, not a promise
that every optional dependency supports the same minimum OS. The wheel needs no
Nix runtime; compatible Python and host OpenSSH remain external prerequisites.

Run explicit installed acceptance as a non-root user with trusted temporary paths:

```sh
nix run .#wheel-acceptance
```

This downloads managed, outside-Nix Python 3.14 and optional dependencies into owned
temporary caches. It exercises the actual uvx, tool-install and uv-run entry points,
base/extra health, stdio/RPC and signals, owned controller-child cleanup and ordinary
SSH/file access. It is not part of sandboxed checks or a hosted CI requirement.
`ESTUS_TEST_PYTHON` may select an existing absolute outside-Nix Python 3.14.

## Ordinary SFTP directory creation

`ssh_mkdir` creates one literal directory on the ordinary SSH identity:

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

Baseline/files-only startup profiles can publish the tool; read-only-files and
actions-only profiles omit it. Target restrictions, argument/deadline validation
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

`ssh_rename` renames one entry through the ordinary SSH identity:

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

Policy, pre-SSH validation, admission and channel ownership match `ssh_mkdir`.
Any error after rename dispatch retains `remote_state_unknown=true`, including
server refusal or cleanup failure; no replay or rollback is inferred.
`nix run .#rename-acceptance-msrv` exercises real moves, replacement consent,
unsupported protection and dispatch uncertainty with the same native prerequisites.

## Ordinary SFTP file unlink

`ssh_remove_file` removes one named file or final symlink entry:

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

`ssh_remove_directory` removes one empty directory:

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

`ssh_replace_file` requires explicit replacement consent:

```json
{"host":"server","path":"/srv/example/config.json","content":"{\"enabled\":true}\n","overwrite":true}
```

`encoding` also accepts strict padded `base64`; decoded content obeys the same
configured file limit as direct writes. False consent, root/trailing-slash/dot
final entries, invalid content/timeouts and insufficient reply budget reject
before SSH. A missing destination may be created, but `overwrite=true` is still
required.

The server must advertise POSIX rename before any filesystem mutation. Estus
exclusively creates a random `.estus-replace-<32 hex digits>` sibling, sets mode0600
before writing content, completes the full write and CLOSE, then atomically
renames it over the destination. The initial empty stage briefly uses server
creation defaults before chmod; no payload is written until chmod succeeds.
Unsupported atomicity never falls back to standard rename, destination truncate,
unlink/copy/delete, sudo or shell/SCP.

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
sweeping names. Channel closure never proves rollback. Direct `ssh_write_file`
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
`output` field is omitted. Automation module/role/playbook requests reject this
control: private Runner/control output is never exposed.

A requested result includes `output.status`: `ready` supplies an opaque `handle`,
expiry and separate stdout/stderr `bytes_retained`, `total_bytes` observed, and
`truncated` flags. `unavailable` supplies a fixed local reason without changing the
command's observed exit code, termination, signal, uncertainty or cleanup evidence.
Inline truncation/lossiness is independent of exact raw artifact bytes.

Use the returned handle with `ssh_read_output(handle, stream, offset, max_bytes,
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

## Optional Ansible environment

Instead of the base installation, install the wheel's `ansible` extra. Set `wheel`
to the artifact built for your platform; for the currently exercised macOS build:

```sh
wheel=./dist/estus-0.1.0-cp314-cp314-macosx_11_0_arm64.whl
uv tool install --python 3.14 "${wheel}[ansible]"
estus doctor --runtime ansible
```

The extra pins Ansible 14.4.0, Core 2.21.5 and Runner 2.4.3. The Ansible distribution
supplies the baseline collections; Core and Runner alone are insufficient.
pip/uv resolves their transitive dependencies at installation time. This is not a
fully locked or immutable environment, and no installer runs during MCP requests.

The launcher supplies its own interpreter, installed package and script locations
to Rust without requiring virtualenv activation or searching PATH for Python.
Explicit roots also support uv-run overlays without importing arbitrary ambient
Python paths. Explicit `[automation].runtime` configuration wins over
`ESTUS_ANSIBLE_RUNTIME`; either wins over the launcher's environment.
A broken explicit selection fails without falling back elsewhere.
Without an explicit health request or `[automation] required = true`, Rust does not
consult the optional runtime. Installing the extra never enables tools.

`doctor --runtime ansible` and required startup check actual public imports,
versions and baseline collection manifests. Installer-managed identity reports
`provenance.kind = "python_environment"`, not an immutable runtime ID. Nix bundle
identity instead reports `provenance.kind = "nix_bundle"` with its pinned runtime ID.
Neither check executes a workload or establishes target/module compatibility.

The selected Python environment and its normal console-bootstrap hooks are trusted.
Rust runs the fixed health helper in an isolated, bounded subprocess with private
configuration/temp paths and no ambient Ansible configuration or Python search path.
Process ownership and isolation are not a security sandbox.

## Offline module contracts

Import metadata from the explicitly selected, already-provisioned environment:

```sh
nix run .#automation-msrv -- schema import ansible.builtin.stat \
  --output ./stat.schema.json --overlay ./stat.binding.json
nix run .#automation-msrv -- schema verify ./stat.schema.json \
  --input ./stat.request.json
```

The same `schema` commands work through the wheel's public `estus` launcher.
No target connection, module execution, dependency installation, online catalog or
tool registration occurs. `--output` must be new: imports never overwrite a reviewed
snapshot. `--timeout-secs` bounds the selected worker's lifetime.

For example, `stat.binding.json` fixes the backend path and exposes only a boolean:

```json
{
  "input_schema": {
    "type": "object",
    "properties": {"follow": {"type": "boolean"}},
    "required": ["follow"],
    "additionalProperties": false
  },
  "fixed_args": {"path": "/srv/frontend/config"},
  "input_map": {"follow": "follow"}
}
```

`stat.request.json` can contain `{"follow": false}`. Verification validates the
fully assembled backend argument object without printing its values or executing
it. A request cannot supply `path` or an undeclared argument. An optional
`schema verify --overlay FILE` checks an alternate reviewed overlay without
changing the snapshot.

Snapshots record runtime provenance, imported recursive structure/aliases and
reviewed schema/content digests. Verification reimports installed metadata and
rejects drift; it never silently refreshes approval. Documentation defaults remain
metadata, not supplied arguments. Unsupported types/constraints fail explicitly;
this is not complete Ansible argument-spec emulation. Effects, target authority and
execution policy are not inferred from documentation.

Backend argument names belong to the module's closed argument object, not the
transport envelope. Documented `argv`/`stdin` are data; public `host`, timeout and
execution controls remain reserved. The documented `free_form` pseudo-option is
not a named argument: imports mark it unbindable and retain a review note. Use
typed named parameters such as `argv`; unspecified types elsewhere still fail.

Content digests detect changes to the selected Ansible/module collection source
trees; they are not a sandbox, an immutable-environment attestation, or protection
against a same-user attacker replacing trusted files. Mutable content can still
change after verification. Enabled module execution checks selected source content
again before dispatch; this is drift detection, not immutable attestation.

## Offline role contracts

Role authoring uses the same selected runtime and closed binding validator:

```sh
estus schema import-role site.operations.observe --entry-point main \
  --output observe.role.json --overlay observe.binding.json
estus schema verify-role observe.role.json --input observe.request.json
```

Collection roles resolve only inside that runtime's selected collections. A
standalone role requires its exact directory on both commands; its basename must
match the role name:

```sh
estus schema import-role observe --role-path /etc/estus/roles/observe \
  --output observe.role.json --schema observe.inputs.json
estus schema verify-role observe.role.json \
  --role-path /etc/estus/roles/observe
```

`--schema` supplies a reviewed closed JSON Schema when public role metadata
exposes no argspec entry, for example:

```json
{
  "type": "object",
  "properties": {"instance": {"type": "string", "minLength": 1}},
  "required": ["instance"],
  "additionalProperties": false
}
```

It cannot replace an available argspec. Role defaults are never inferred as
inputs or injected. Recursive argspec `options`, aliases, choices, types and
requiredness reuse module contract rules; unknown structural constraints fail
explicitly. Use a reviewed `--overlay` with `input_schema`, `fixed_args` and
`input_map` to narrow inputs or express supported JSON Schema conditionals;
`verify-role --input` requires such an overlay. Neither command publishes a tool.

Snapshots bind the role/entry point, runtime/collection identity, whole selected
role or collection plus Core content, explicit schema and overlay. They omit
private source paths, refuse overwrite and detect drift without refreshing
approval. Source hashing rejects interior symlinks/nonregular files and is
bounded; it is not transitive dependency attestation or protection against
same-user changes after verification.
Write snapshots outside the hashed source trees, including through symlinked
parents. Canonical search paths containing `:`, `$` or Jinja delimiters are
rejected because Ansible would reinterpret them rather than select literal content.

Role tasks and dependencies do not execute during import/verification. Upstream
role dependencies can run before the dependent role's argspec validation:
Rust prevalidation remains the approval boundary, not upstream execution order.
Import/verification does not enable execution; fixed role bindings are described below.

## Ordinary Ansible modules

[`examples/automation_probe.toml`](examples/automation_probe.toml) enables one real,
fixed `ansible.builtin.ping` binding. Provision its private workspace and import
the snapshot from the same selected runtime before startup:

```sh
nix run .#automation-msrv -- schema import ansible.builtin.ping \
  --output /etc/estus/ping.schema.json
nix run .#automation-msrv -- --config examples/automation_probe.toml
```

The example's conventional absolute paths must be provisioned for the MCP account.
The wheel's `estus` command accepts the same configuration with its installed
`ansible` extra. Installing dependencies still does not enable a tool.

Module calls use `{"host":"server","inputs":{}}`; optional `timeout_secs` is a
transport field. The entire reviewed domain schema is published under `inputs`,
preserving conditional, property-count, enum and const constraints without
mixing them with transport controls. Native/controller tool input shapes are
unchanged. Malformed input shapes produce protocol errors; valid shapes violating
reviewed bounds or choices produce tool errors before execution.

Each module definition fixes `execution.snapshot`, `authority = "automation"`,
`result.kind = "ansible_summary"`, effects, logical targets, `input_schema`,
`fixed_args` and `input_map`. A stored snapshot overlay, when present, must match.
Only explicitly enabled/profile-effective definitions inspect snapshots or start
Python. Enabled stale/incompatible bindings fail before MCP starts; requests
never regenerate approval or install dependencies.

`[automation.targets.<logical>]` fixes the SSH destination and absolute target
Python interpreter independently of native sudo authority. This ordinary authority
never becomes; named broader authorities below are separate. OpenSSH resolves operator aliases and the replacement SSH
file. Runner connections do not use the Rust pool: sharing, forwarding, host-key
updates, password prompts and remote TTY allocation are disabled. OpenSSH is
selected by `automation.ssh_executable`, then `ESTUS_AUTOMATION_SSH`, then
`/usr/bin/ssh`; the Nix package supplies its pinned default.
An existing bounded absolute `SSH_AUTH_SOCK` reference is preserved for an
out-of-band agent. The product does not load keys, create an agent, prompt for
credentials or accept key/password contents as tool inputs.

Summary-only results contain logical host, status, Runner return code, bounded task
counts, change/censorship/completion, duration and local cleanup evidence. They
still exclude module values. Typed bindings may expose only explicitly selected
fields as described below; whole raw events/arguments/environment are not returned.
`no_log` remains censored. Nested module input strings use documented `!unsafe`
tags rather than caller-supplied Jinja evaluation.
Failed modules may report mutation even when Core omits their changed count.
That observation survives a known failure; it is not rewritten as unchanged or
discarded as a protocol error.

`automation.max_concurrent` defaults to 2; each logical target admits one automation
invocation at a time. The existing global operation cap also applies. Admission
and private workspaces remain owned through cleanup, including client loss.
Cancellation first lets the owned CLI propagate termination through Ansible's
worker cleanup; bounded fallback remains available. Neither local cleanup nor a
cancelled reply proves remote termination, rollback or escaped-child containment.
No operation is automatically replayed.

Scratch defaults to 16 MiB/512 entries. Byte/file polling cancels on an observed
watermark, not a hard filesystem or memory quota. Runner's unavoidable private
metadata/transient files can contain secrets; supported duplicate output/event
capture is suppressed and invocation files are removed after ownership ends.
Crash recovery does not promise secure erasure. Privilege escalation and retained
raw events remain outside this implementation.

## Fixed ordinary Ansible roles

[`examples/app_config.toml`](examples/app_config.toml) and
[`examples/roles/app_config`](examples/roles/app_config) converge one ordinary
application JSON file. The role validates its contract, writes trusted JSON
without evaluating caller strings, reads the actual bytes/checksum, asserts its
postcondition and publishes a typed receipt. It does not install software,
restart a service or escalate privilege.

Deploy the reviewed role independently, provision the configured private
workspace and import its snapshot before enabling the binding:

```sh
estus schema import-role app_config \
  --role-path /etc/estus/roles/app_config \
  --output /etc/estus/app_config.schema.json
estus --config examples/app_config.toml
```

Use the wheel's installed `ansible` extra or the selected Nix automation package.
A reviewed `--overlay` may also bind the snapshot to the exact configured
`input_schema`, `fixed_args` and `input_map`; when stored, it must match startup.
Standalone execution fixes `role_path`; collection execution omits it and resolves
only within the selected runtime. The reviewed snapshot fixes role and entry
point. No caller can select role/path/entry, extra-vars, tags or connection controls.

Roles use the same `{"host":"server","inputs":{...}}` envelope, target/profile
authorization, timeout/admission, child owner and cancellation path as modules.
Rust validates and canonicalizes the assembled inputs before starting any role
or dependency. Source content is checked again before Runner dispatch; no
per-request documentation introspection or approval refresh occurs.

Existing roles can return `ansible_summary` without a custom result protocol.
For domain data, a role may `set_fact: mcp_result: ...`; `ansible_projection`
selects only declared members beneath that fact, with the same recursive schema
and aggregate bounds as module projections. Collection runs after ordinary role
handlers. Missing/invalid results produce an independent output error without
erasing verified execution, change or failure evidence; `no_log` remains censored.

Summaries include authoritative failed/skipped outcomes and nonzero
`tasks.rescued`/`tasks.ignored`; rescued or ignored failures do not become invisible.
Observed prior changes survive a later failure or incomplete run. Execution is
bounded to 128 root results/256 starts; loop items are not retained as raw events.

Role tasks, dependencies, handlers and templates are trusted operator code, not a
sandbox. Selected-tree hashes do not attest external dependency trees or prevent
same-user replacement after verification. No detached async tasks are generated;
reviewed roles must not use them. Visible async metadata is rejected, including
loop results, but public `no_log` events can hide it. Completion attests reconciled
Runner workflow evidence, not remote quiescence, rollback or process confinement.

```sh
nix run .#role-acceptance-msrv
```

This runs the installed real SSH/Runner role suite outside the Nix sandbox, using
the same private-directory/non-root prerequisites as native acceptance.

## Fixed ordinary Ansible playbooks

Review a deployed project without parsing or executing its YAML:

```sh
estus schema import-playbook site.yml \
  --project-root /etc/estus/project \
  --input-schema backend.schema.json --overlay binding.json \
  --output /etc/estus/site.schema.json
estus schema verify-playbook /etc/estus/site.schema.json \
  --project-root /etc/estus/project --input request-inputs.json
```

`backend.schema.json` is an explicit closed schema for the complete constructed
argument object. `binding.json` contains the reviewed caller `input_schema`,
`fixed_args` and `input_map`, using the same recursive validator as roles.
Store the snapshot outside the project, including through case/symlink aliases.
Project roots must not contain the importer's or invocation's temporary workspace.
The entry is a fixed canonical relative `.yml`/`.yaml` path; no caller path or YAML
is accepted. Import does not infer a contract from play variables or defaults.

An explicitly enabled tool uses `authority="automation"`, its reviewed overlay,
operator-declared effects and an `ansible_summary` or `ansible_projection` result.
Its fixed execution selector is:

```toml
[tools.site.execution]
kind = "ansible_playbook"
snapshot = "/etc/estus/site.schema.json"
project_root = "/etc/estus/project"
```

Calls retain `{"host":"server","inputs":{...}}`. The playbook reads only the
constructed dictionary as `estus_arguments`, for example
`"{{ estus_arguments.configuration }}"`. Recursive caller strings are literal
data, not arbitrary top-level extra-vars. Inventory, host patterns, tags, selected
playbook/project, connection/interpreter and become controls are not caller inputs.
The generated initial inventory contains only `estus_target`; the CLI fixes its
limit, transport/interpreter settings and `ansible_become=false`. Existing target
authorization, admission, timeouts, cancellation and cleanup remain in force.

Runtime identity and bounded Core/project bytes are checked at startup and again
before dispatch. Interior symlinks/nonregular files are rejected. Relative task,
vars and template paths use the fixed project; project-local roles, plugins and
`collections/ansible_collections` are reviewed content, not ambient search paths.
The generated private configuration and HOME replace ambient Ansible settings.
Source may still change after verification: this is drift detection, not immutable
or transitive dependency attestation.

Multi-play summaries use the same bounded reconciled evidence as roles. Optional
`ansible_projection` selects declared `mcp_result` members after the imported plays;
failed or missing output never erases known workload failure or earlier mutation.
Binding `no_log=true` suppresses public values/change evidence even when trusted
plays override their own logging defaults.

Playbooks, plugins, lookups and external includes are trusted operator code.
Initial inventory/CLI limits do not confine delegated or controller-side effects.
The linear strategy/logging settings are defaults, not a rewrite of trusted play
keywords. Unsupported execution evidence fails closed; it does not prove effects
were prevented or rolled back. No detached async, elevation, multi-host scheduler,
automatic replay, dependency installation or rollback guarantee is added.

`nix run .#playbook-acceptance-msrv` runs the installed real SSH/Runner suite with
the same non-root/private-directory prerequisites as role acceptance.

## Explicit broader automation authorities

`authority="automation"` remains ordinary. A reviewed module, role or playbook
binding may instead select `authority="automation:ops"` and be explicitly enabled.
Configure that private capability independently from native sudo allowlists:

```toml
[automation.authorities.ops]
ssh_config_file = "/etc/estus/automation-ssh.conf"
runtime = "/opt/estus/ansible-runtime"
become = { method = "sudo", user = "root" }

[automation.authorities.ops.targets.server]
destination = "server-automation"
python = "/usr/bin/python3"
```

The replacement SSH configuration selects independently provisioned credentials
through ordinary OpenSSH `IdentityFile` or `IdentityAgent` settings. No privileged
key is installed on ordinary targets. An optional `ssh_auth_sock` selects an
existing bounded absolute agent socket; omitting it disables ambient agent
inheritance for this authority. Estus never loads keys or creates agents.

`runtime` may be omitted to inherit the existing selected runtime at startup.
An explicit authority runtime does not depend on an unused ordinary runtime or
ambient agent. Import the binding snapshot against that same runtime using the
operator authoring configuration. Source/runtime approval is not refreshed on calls.

Profiles name declared logical targets only, never fallback native/elevated aliases.
Missing profiles/mappings and malformed definitions fail startup even if disabled;
inactive valid file/runtime references remain unopened. Global and target startup
profiles still apply, and all authorities share admission for the same logical target.
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

`nix run .#authority-acceptance-msrv` exercises distinct keys/accounts and real
root-owned effects in the explicit automation fixture. It requires
`ESTUS_TEST_FIXTURE` pointing to the built `ssh-automation-fixture-image` artifact
and an explicit Docker-compatible backend (`DOCKER_HOST`); no host sudoers or
accounts are changed.

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
Pinned Runner can omit oversized result data while retaining task/statistics;
that yields `unavailable` without discarding known execution completion.

`nix run .#projection-acceptance-msrv` runs the focused real Runner suite with the
same non-root/private-runtime-directory prerequisites as native SSH acceptance.
It does not activate hosted CI or install request-time dependencies.

## Native / Nix

The same application remains available without a Python launcher:

```sh
cargo build --release --locked
./target/release/estus --help
nix run .#msrv -- --help
```

Native Nix packaging supplies OpenSSH and has no Python/Ansible runtime dependency.
The separate `.#automation-msrv` output supplies the optional pinned Ansible runtime;
see `examples/automation_runtime.toml` for explicit, non-mutating runtime health.
That health check verifies imports and identity, not Ansible workload execution.
