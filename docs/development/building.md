# Building from source

Use this guide to build Estus from a checkout or run the development MCP server. Run the commands from the repository root.

## Build with Cargo

Use Rust 1.88 or later and a host C toolchain for linking. Have OpenSSH on `PATH` when you run Estus against a target.

```sh
cargo build --release --locked
./target/release/estus --help
```

## Build with Nix

With flakes enabled, run the checkout's default build or the build pinned to the minimum supported Rust version (MSRV):

```sh
nix run . -- --help
nix run .#msrv -- --help
nix run .#automation-msrv -- --help
```

The native packages put Nix-provided OpenSSH first on `PATH`. `.#automation-msrv` wraps the MSRV build with a prebuilt [Ansible bundle](../ansible-bundles.md). Use `nix develop` for a shell with the build and test tools. Nix only sees files included in the Git checkout: add new source files to Git before building the flake.

## Run the development MCP server

```sh
nix run --no-write-lock-file .#dev-mcp
```

The tracked `.omp/mcp.json` starts this app with a five-minute client timeout. Without extra arguments the wrapper clears inherited Estus config and path overrides, pins the prebuilt bundle, and starts Estus with `--workstation` and no config. Run it directly if you need to see startup diagnostics on stderr.

This app exposes the catalog's ordinary workstation overlays, such as `inspect_journal`, through your ordinary SSH identity. It leaves named-authority overlays hidden in this default setup. For those overlays, use a reviewed workstation config with a matching [authority](../concepts.md#authority) or an explicit unrestricted root sudo route. Use a [headless config](../configuration.md) instead when testing a fixed target policy.

## Keep build outputs separate

Use `--out-link` for Nix builds you want to keep. Create the parent directory first:

```sh
mkdir -p nix/result/native
nix build .#msrv --out-link nix/result/native/msrv
```

| Link | Output |
| --- | --- |
| `nix/result/native/default` | Default native package |
| `nix/result/native/msrv` | MSRV native package |
| `nix/result/wheel/<system>` | Portable wheel |
| `nix/result/fixtures/<name>` | Fixture artifact |
| `nix/result/acceptance/<name>` | Acceptance package |

Git ignores `nix/result/`. Keep mutable disks, keys, private configs and logs under `target/estus-dev/`, and distributions under `dist/`.
