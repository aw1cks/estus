# Testing

Use this guide to choose the smallest suite that exercises your change. Start with local tests; use [acceptance](acceptance.md) when you need a real SSH session, guest or installed package.

## Run local tests

Unit tests and the stdio protocol tests run without a network connection. The stdio suites launch the real server; they test how it handles requests without needing an SSH server. `nix develop` supplies the tools used by the broader local suite, including Python, OpenSSH and coreutils.

```sh
cargo test --locked --lib
cargo test --locked --test stdio_protocol --test stdio_catalog --test stdio_policy --test stdio_auth
```

For changes to the Python bootstrap used by collectors, run its framing, execution and package prestate tests from the repository root:

```sh
python3 -I -m unittest discover -s src/native_payload -p 'test_bootstrap.py' -v
```

## Pick a suite

Pass the suite name to `cargo test --test`. Tests that need extra setup are marked ignored; use the [acceptance apps](acceptance.md) rather than turning on all ignored tests at once.

| Suite | What it exercises |
| --- | --- |
| `stdio_protocol` | MCP framing, lifecycle, malformed input and shutdown |
| `stdio_catalog`, `stdio_tools` | Discovery, schemas, resources and configured tool routes |
| `stdio_policy`, `stdio_auth` | Target and profile policy, preview gating, and offline `auth` decisions |
| `stdio_files`, `stdio_output`, `stdio_exec` | File and command validation, output handles and request budgets |
| `stdio_controller`, `controller` | Controller tool contract and local child process lifecycle |
| `catalog_cli`, `catalog_distribution` | Offline catalog discovery, export and asset validation |
| `payloads` | Python collector parsers and their result bounds |
| `bundle_cli` | Bundle inspection, verification and, with a pinned runtime, building and execution |
| `doctor`, `progress` | Diagnostics and progress notifications, including real process and transport tests |
| `ssh_local_exec`, `ssh_local_files`, `ssh_local_output`, `ssh_local_payload`, `ssh_local_quarantine` | Real loopback SSH, SFTP, output retention, collectors and write quarantine |
| `ssh_e2e`, `sftp_protocol`, `deployment_boundary` | Container-backed transport, filename fidelity and isolated service accounts; `sftp_protocol` also has a network-free check |
| `catalog` | Operational catalog tools and workflows against disposable QEMU guests |
| `wheel` | Installed wheel behavior, portability and the source archive round-trip |

## Run a loopback SSH suite

Use a non-root local account with a POSIX-compatible login shell and permission to open loopback listeners. Run inside `nix develop`: the fixture checks that `sshd` comes from Nix, and some tests also need Nix coreutils or Python. Keep the runtime directory short and under your home. OpenSSH rejects writable ancestors, even a sticky `/tmp`.

```sh
nix develop --command bash -c '
  set -eu
  XDG_RUNTIME_DIR=$(mktemp -d "$HOME/.estus-test.XXXXXXXX")
  export XDG_RUNTIME_DIR
  trap '\''rm -rf -- "$XDG_RUNTIME_DIR"'\'' EXIT
  cargo test --locked --test ssh_local_exec -- --ignored
'
```

For container-backed tests, use a dedicated Docker-compatible Unix socket and the matching Nix-built fixture image. See [acceptance prerequisites](acceptance.md#fixture-and-runtime-inputs).

## Catalog fixtures

`tests/fixtures/catalog/` holds fixture sources, captured observations and their provenance. `nix/tests/catalog/` builds the disposable guests and package repositories from them. Packages, indexes and VM disks are build outputs. The checked-in signing material is public and test-only; never trust it outside the fixture.
