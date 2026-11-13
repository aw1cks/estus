# ssh-mcp

A stdio MCP server for operator-configured SSH authority. The Rust application owns
MCP, SSH connections, limits and cleanup. Only MCP JSON is written to server stdout.

## Base wheel

Build a platform wheel and source archive with Python 3.14 and Rust 1.88 or newer:

```sh
uv build --python 3.14
```

Install the resulting wheel as an isolated tool, without activating a virtualenv:

```sh
uv tool install --python 3.14 ./dist/ssh_mcp-*.whl
ssh-mcp --help
ssh-mcp --config /absolute/path/to/operator.toml
```

Alternatively, run the local wheel with `uvx --from ./dist/ssh_mcp-*.whl ssh-mcp`.
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
uv tool install --python 3.14 ./result/ssh_mcp-*.whl
uvx --from ./result/ssh_mcp-*.whl ssh-mcp
uv run --no-project --with ./result/ssh_mcp-*.whl ssh-mcp
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
`SSH_MCP_TEST_PYTHON` may select an existing absolute outside-Nix Python 3.14.

## Optional Ansible environment

Instead of the base installation, install the wheel's `ansible` extra. Set `wheel`
to the artifact built for your platform; for the currently exercised macOS build:

```sh
wheel=./dist/ssh_mcp-0.1.0-cp314-cp314-macosx_11_0_arm64.whl
uv tool install --python 3.14 "${wheel}[ansible]"
ssh-mcp doctor --runtime ansible
```

The extra pins Ansible 14.4.0, Core 2.21.5 and Runner 2.4.3. The Ansible distribution
supplies the baseline collections; Core and Runner alone are insufficient.
pip/uv resolves their transitive dependencies at installation time. This is not a
fully locked or immutable environment, and no installer runs during MCP requests.

The launcher supplies its own interpreter, installed package and script locations
to Rust without requiring virtualenv activation or searching PATH for Python.
Explicit roots also support uv-run overlays without importing arbitrary ambient
Python paths. Explicit `[automation].runtime` configuration wins over
`SSH_MCP_ANSIBLE_RUNTIME`; either wins over the launcher's environment.
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

The same `schema` commands work through the wheel's public `ssh-mcp` launcher.
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
ssh-mcp schema import-role site.operations.observe --entry-point main \
  --output observe.role.json --overlay observe.binding.json
ssh-mcp schema verify-role observe.role.json --input observe.request.json
```

Collection roles resolve only inside that runtime's selected collections. A
standalone role requires its exact directory on both commands; its basename must
match the role name:

```sh
ssh-mcp schema import-role observe --role-path /etc/ssh-mcp/roles/observe \
  --output observe.role.json --schema observe.inputs.json
ssh-mcp schema verify-role observe.role.json \
  --role-path /etc/ssh-mcp/roles/observe
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
parents. Canonical search paths containing `:`, `# ssh-mcp

A stdio MCP server for operator-configured SSH authority. The Rust application owns
MCP, SSH connections, limits and cleanup. Only MCP JSON is written to server stdout.

## Base wheel

Build a platform wheel and source archive with Python 3.14 and Rust 1.88 or newer:

```sh
uv build --python 3.14
```

Install the resulting wheel as an isolated tool, without activating a virtualenv:

```sh
uv tool install --python 3.14 ./dist/ssh_mcp-*.whl
ssh-mcp --help
ssh-mcp --config /absolute/path/to/operator.toml
```

Alternatively, run the local wheel with `uvx --from ./dist/ssh_mcp-*.whl ssh-mcp`.
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
uv tool install --python 3.14 ./result/ssh_mcp-*.whl
uvx --from ./result/ssh_mcp-*.whl ssh-mcp
uv run --no-project --with ./result/ssh_mcp-*.whl ssh-mcp
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
`SSH_MCP_TEST_PYTHON` may select an existing absolute outside-Nix Python 3.14.

## Optional Ansible environment

Instead of the base installation, install the wheel's `ansible` extra. Set `wheel`
to the artifact built for your platform; for the currently exercised macOS build:

```sh
wheel=./dist/ssh_mcp-0.1.0-cp314-cp314-macosx_11_0_arm64.whl
uv tool install --python 3.14 "${wheel}[ansible]"
ssh-mcp doctor --runtime ansible
```

The extra pins Ansible 14.4.0, Core 2.21.5 and Runner 2.4.3. The Ansible distribution
supplies the baseline collections; Core and Runner alone are insufficient.
pip/uv resolves their transitive dependencies at installation time. This is not a
fully locked or immutable environment, and no installer runs during MCP requests.

The launcher supplies its own interpreter, installed package and script locations
to Rust without requiring virtualenv activation or searching PATH for Python.
Explicit roots also support uv-run overlays without importing arbitrary ambient
Python paths. Explicit `[automation].runtime` configuration wins over
`SSH_MCP_ANSIBLE_RUNTIME`; either wins over the launcher's environment.
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

The same `schema` commands work through the wheel's public `ssh-mcp` launcher.
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
ssh-mcp schema import-role site.operations.observe --entry-point main \
  --output observe.role.json --overlay observe.binding.json
ssh-mcp schema verify-role observe.role.json --input observe.request.json
```

Collection roles resolve only inside that runtime's selected collections. A
standalone role requires its exact directory on both commands; its basename must
match the role name:

```sh
ssh-mcp schema import-role observe --role-path /etc/ssh-mcp/roles/observe \
  --output observe.role.json --schema observe.inputs.json
ssh-mcp schema verify-role observe.role.json \
  --role-path /etc/ssh-mcp/roles/observe
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
 or Jinja delimiters are
rejected because Ansible would reinterpret them rather than select literal content.

Role tasks and dependencies do not execute during import/verification. Upstream
role dependencies can run before the dependent role's argspec validation:
Rust prevalidation remains the approval boundary, not upstream execution order.
Fixed ordinary role bindings use `execution.kind = "ansible_role"` with a reviewed
snapshot and fixed source. Inputs are validated before roles or dependencies run;
summary-only output or declared `mcp_result` projections use the existing owner.

## Ordinary Ansible modules

[`examples/automation_probe.toml`](examples/automation_probe.toml) enables one real,
fixed `ansible.builtin.ping` binding. Provision its private workspace and import
the snapshot from the same selected runtime before startup:

```sh
nix run .#automation-msrv -- schema import ansible.builtin.ping \
  --output /etc/ssh-mcp/ping.schema.json
nix run .#automation-msrv -- --config examples/automation_probe.toml
```

The example's conventional absolute paths must be provisioned for the MCP account.
The wheel's `ssh-mcp` command accepts the same configuration with its installed
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
Python interpreter independently of native sudo authority. No become support is
added. OpenSSH still resolves operator aliases and the configured replacement SSH
file. Runner connections do not use the Rust pool: sharing, forwarding, host-key
updates, password prompts and remote TTY allocation are disabled. OpenSSH is
selected by `automation.ssh_executable`, then `SSH_MCP_AUTOMATION_SSH`, then
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
./target/release/ssh-mcp --help
nix run .#msrv -- --help
```

Native Nix packaging supplies OpenSSH and has no Python/Ansible runtime dependency.
The separate `.#automation-msrv` output supplies the optional pinned Ansible runtime;
see `examples/automation_runtime.toml` for explicit, non-mutating runtime health.
That health check verifies imports and identity, not Ansible workload execution.
