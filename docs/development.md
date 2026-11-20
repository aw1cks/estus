# Development

## Build

```sh
cargo build --release --locked
./target/release/estus --help
nix run .#msrv -- --help
```

Rust 1.88+ (the MSRV checked in CI). Host OpenSSH must be installed; nothing else
is needed at runtime. The Nix package prefixes `PATH` with its pinned OpenSSH and
has no Python or Ansible dependency. `.#automation-msrv` supplies a pinned
ansible-core environment for `estus bundle build`.

Toolchain without Nix:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
cargo test --test stdio_protocol --test stdio_catalog --test stdio_files --test stdio_output \
  --test stdio_exec --test stdio_policy --test stdio_tools --test stdio_controller
cargo test --test catalog_distribution
cargo test --test wheel
```

## Wheel

```sh
uv build --python 3.14
uv tool install --python 3.14 ./dist/estus-*.whl
estus --help
```

The wheel contains a private Rust executable and a Python console launcher that
replaces itself with it. It needs Python only for bootstrap and trusts that
environment; it does not embed CPython or host MCP in Python. Metadata pins
`requires-python = ">=3.14,<3.15"` and `cp314-cp314` tags. PEP 660/editable
installs are not supported — an editable install builds the executable but does
not map generated catalog assets, so offline discovery fails.

Source archives select catalog definitions, roles and payloads through the
manifest-driven build hook, not a second name list in `MANIFEST.in`. The opt-in
`source_distribution_roundtrip_preserves_manifest_selected_assets` test builds
sdists from a clean tracked-source export, extracts them outside the checkout,
builds and installs wheels from those sources, and compares asset bytes with the
native install. It needs `ESTUS_TEST_SOURCE_ARCHIVE`, `ESTUS_TEST_BUILD_PYTHON`,
`ESTUS_TEST_NATIVE_CATALOG` and an outside-Nix `ESTUS_TEST_PYTHON`:

```sh
cargo test --test wheel source_distribution_roundtrip_preserves_manifest_selected_assets -- --ignored --exact
```

The Nix build orchestrates the same PEP 517 build:

```sh
system=$(nix eval --impure --raw --expr builtins.currentSystem)
mkdir -p nix/result/wheel
nix build .#wheel --out-link "nix/result/wheel/$system"
```

Output links are explicit and ignored:

| Link | Output |
| --- | --- |
| `nix/result/native/default` | Native package |
| `nix/result/native/msrv` | MSRV package |
| `nix/result/wheel/<system>` | Portable wheel |
| `nix/result/fixtures/<name>` | Fixture artifact |
| `nix/result/acceptance/<name>` | Acceptance executable |

Create each parent directory first. Keep mutable disks, keys, private
configuration and logs under `target/estus-dev/`, and reserve `dist/` for
distributions.

## Tests

Unit and protocol tests are network-free and run in the sandbox:

```sh
cargo test --lib
cargo test --test stdio_protocol  # MCP framing, lifecycle, malformed input
cargo test --test stdio_catalog   # discovery, schemas, configuration, resources
cargo test --test stdio_files     # file tool validation and policy
cargo test --test stdio_output    # output read contracts and retained handles
cargo test --test stdio_exec      # command execution inputs and budgets
cargo test --test stdio_policy    # targets, profiles, tier and preview policy
cargo test --test stdio_tools     # named tools, fixed sudo, remote scripts
cargo test --test stdio_controller # hostless controller contract
cargo test --test catalog         # catalog manifest, definitions, payload manifests
cargo test --test catalog_cli
cargo test --test catalog_distribution
cargo test --test bundle_cli
cargo test --test payloads
cargo test --test controller
cargo test --test progress
cargo test --test doctor
```

`tests/ssh_local_*.rs`, `tests/ssh_e2e.rs`, `tests/sftp_protocol.rs` and
`tests/deployment_boundary.rs` cover real SSH/SFTP behaviour; they need a private
runtime directory under the runner's home and a non-root user.

Bootstrap protocol and bundle CLI locally:

```sh
python3 -I -m unittest discover -s src/native_payload -p 'test_bootstrap.py' -v
cargo test --test bundle_cli
```

## Acceptance

Acceptance apps run outside the Nix sandbox as a non-root user with trusted
temporary paths. They provision disposable guests and containers; none changes
host services, interfaces, keys or sudoers.

| App | Coverage |
| --- | --- |
| `nix run .#ssh-baseline` | Real SSH/SFTP, controller scripts, distinct keys/accounts, root-owned sudo effects |
| `nix run .#ssh-native` | Native/controller/SFTP execution, projection suite, bundled health payloads |
| `nix run .#mkdir-acceptance` / `rename-` / `remove-file-` / `remove-directory-` / `replace-file-acceptance` | One SFTP mutation each, including uncertainty boundaries |
| `nix run .#output-acceptance` | Retained output handles: exact ranges, expiry, permissions, quota failures |
| `nix run .#progress-acceptance` | Progress notifications for native, controller and SFTP work |
| `nix run .#doctor-acceptance` | Target policy and `ssh -G` resolution |
| `nix run .#bundle-acceptance` | Bundle build/inspect, digest drift, real module execution, projections |
| `nix run .#catalog-acceptance` | Shipped catalog against disposable guests (network, NIC, storage, boot, packages) |
| `nix run .#workflow-acceptance` | The four reviewed `examples/workflows/` recipes |
| `nix run .#wheel-acceptance` | Installed wheel through uvx, tool-install and uv-run; stdio/RPC, signals, cleanup |
| `nix run .#sdist-acceptance` | Source-archive roundtrip |

Each has an `-msrv` variant that runs against the MSRV build. Exact scenarios:

```sh
nix run .#catalog-acceptance-msrv -- tools::observe_pressure::observe_pressure --exact
nix run .#catalog-acceptance-msrv -- \
  tools::change_network_link_down::network_link_down_requires_stable_executable --exact
```

`workflow-files-acceptance` needs an explicit `DOCKER_HOST` and the matching
`ESTUS_TEST_FIXTURE`; `workflow-catalog-acceptance` needs only the disposable
guest. Linux automation suites build `ssh-automation-fixture-image` and select it
through `ESTUS_TEST_FIXTURE`.

`ESTUS_TEST_PYTHON` may point `wheel-acceptance` at an existing outside-Nix
Python 3.14.

## Fuzzing

Five cargo-fuzz targets drive real production modules — command encoding and
limits, the 16 MiB reply budget, file codecs, raw filename metadata and
binding-schema compilation. Harnesses and seeds live in `fuzz/`; the root build
excludes them, so fuzzing never changes production dependencies.

```sh
nix develop .#fuzz -c cargo fuzz run binding_schema fuzz/corpus/binding_schema -- -runs=0 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
nix develop .#fuzz -c cargo fuzz run command_encoding fuzz/corpus/command_encoding -- -runs=0 -seed=1 -max_len=16384 -rss_limit_mb=1024 -timeout=10
```

Time-bounded campaigns write only to the ignored `fuzz/generated-corpus/`; crash
artifacts belong in `fuzz/artifacts/<target>/`. Fuzzing never connects to SSH or
Docker and never executes Ansible workloads.

## CI

`nix/ci.nix` generates the workflows (regenerate with
`nix run .#generate-workflows`); the generated files are tracked.

| Layer | Hosted coverage |
| --- | --- |
| Sandboxed checks | Default and MSRV build, network-free tests, acceptance-executable compilation, formatting, clippy, workflow consistency |
| Installed MSRV native | Real SSH/SFTP, controller scripts, doctor, native/controller/SFTP progress |
| Installed MSRV bundle | Bundle build/inspect, digest drift, real module execution, typed projections |
| Linux containers | Default/MSRV SSH baseline; bundle module smoke, automation authority, shipped payloads |

Runs on Linux x86_64/arm64 and macOS arm64. Wheel acceptance stays opt-in;
hosted coverage of the native package does not prove the outside-Nix Python path.

## Development MCP app

```sh
nix run --no-write-lock-file .#dev-mcp
```

Builds the current package if needed, then execs it with `--workstation` and no
`--config`: all five capability ceilings, ordinary SSH destinations, and the
catalog templates that declare a reviewed `workstation` block. The wrapper clears
inherited `ESTUS_*` selections (except pinning `ESTUS_ANSIBLE_BUNDLE` to the
Nix-built bundle) so bundle-backed module tools work without an operator build.
Local flakes use tracked files, so add new source files before expecting Nix to
include them.

For a reviewed policy instead:

```sh
nix run --no-write-lock-file . -- --config /absolute/path/to/reviewed.toml
```

The tracked `.omp/mcp.json` invokes `.#dev-mcp` with a 300,000 ms client timeout;
that is a client-side limit, separate from the server's `max_timeout_secs`. OMP
discards subprocess stderr and reports startup failure as a generic EOF, so run
the app directly (`nix run ... .#dev-mcp </dev/null`) for real diagnostics.

## Fixtures

Catalog fixture sources, public test-only signing material, service templates and
captured observations live under `tests/fixtures/catalog/`, with derivations in
`nix/tests/catalog/`. Generated packages, indexes, rootfs and disks are build
outputs. The fixture signing identity is disposable and must never be trusted
outside the guest.

The MD/NVMe and netdevsim scenarios rely on documented launcher workarounds
(emulated interrupt remapping disabled after a QEMU boot panic). Their labels
stay `laboratory_only`: the results qualify software configuration and decoding,
not physical hardware.
