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
Current wheel acceptance targets Python 3.14. Portable release artifacts and a
broader compatibility matrix are not yet established.

The wheel contains a private Rust executable and a Python console launcher that
immediately replaces itself with that executable. It requires Python for bootstrap
and trusts that Python environment. It does not embed CPython or host MCP in Python.
Host OpenSSH must be installed and available to the application. Existing operator
SSH identity, host-key policy and configuration still apply.

The base wheel does not depend on Ansible, install packages at startup, or enable
additional tools. Installer-managed Ansible environments and an `[ansible]` extra
are not implemented yet. An explicitly selected existing runtime bundle remains
usable through the native application's configuration.

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

Runtime health reports pinned bundle provenance as `provenance.kind = "nix_bundle"`
with its runtime ID. This is distinct from observed installer-managed identity.
