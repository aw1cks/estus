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
