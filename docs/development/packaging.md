# Packaging

Use this guide to build and check a wheel or source distribution from your checkout. If you only need the native executable, see [Building from source](building.md).

## Build and try a local wheel

Use `uv`, a Python 3.10 or later interpreter, Rust 1.88 or later, and a host linker. From the checkout root, run this with an empty `dist/local/` so the glob selects just the new wheel:

```sh
uv build --python 3.14 --out-dir dist/local
uv tool install --python 3.14 ./dist/local/estus-*.whl
"$(uv tool dir --bin)/estus" --help
```

`uv build` creates the source distribution (sdist) first and then builds the wheel from it. To build just a wheel directly from the checkout, pass `--wheel`. If you already installed a local wheel with the same version, pass `--force` to `uv tool install` to replace it.

## What's in the wheel

The wheel contains a private platform-specific Rust executable and a Python launcher. The launcher selects the installed catalog directory and replaces itself with the executable, leaving MCP stdio and process lifecycle to Rust. The executable also carries its own copy of the catalog (see `build.rs`), which is how a plain `cargo install` build can write one out with `estus catalog install`; the wheel does not need that copy. Wheels use the tag `py3-none-<platform>` because the executable does not link to a CPython ABI.

| Task | Python requirement |
| --- | --- |
| Run a prebuilt wheel | 3.8 or later |
| Build from source, including from an sdist | 3.10 or later for the pinned setuptools build backend |
| Use the optional `[ansible]` extra | 3.12 or later; below 3.12 its Ansible dependencies are not installed |

`setup.py` selects tool definitions and native payload assets using `catalog/catalog.json`. The same selection goes into the sdist and the wheel, where it lives under `estus/_catalog/`. Build a real wheel to test offline catalog discovery; an editable install does not include those generated assets.

## Build the portable wheel with Nix

```sh
system=$(nix eval --impure --raw --expr builtins.currentSystem)
mkdir -p nix/result/wheel
nix build .#wheel --out-link "nix/result/wheel/$system"
```

The Nix recipe runs the same Python build backend without build isolation, using pinned dependencies and vendored Cargo sources. It builds with Zig on Linux (`manylinux_2_17` on x86-64 and arm64) and Clang/LLD on macOS (`macosx_11_0_arm64`). It skips Nix fixup so the executable inside the wheel does not link to libraries in the Nix store.

## Test the source archive

```sh
nix run .#sdist-acceptance
```

The round-trip harness starts from a clean source export, builds and extracts the sdist outside the checkout, then builds and installs a wheel from the extracted sources. It checks that both artifacts preserve the manifest-selected bytes, that the baseline matches the native package, and that private files and bytecode do not leak into the distributions.

The app sets the archive, build interpreter and catalog paths. If you run the harness directly, supply:

| Variable | Value |
| --- | --- |
| `ESTUS_TEST_SOURCE_ARCHIVE` | Clean source tarball with `Cargo.toml` at its root |
| `ESTUS_TEST_BUILD_PYTHON` | Interpreter with `build` and the pinned setuptools build dependencies |
| `ESTUS_TEST_NATIVE_CATALOG` | Absolute path to the native package's installed catalog directory |
| `ESTUS_TEST_PYTHON_3_14` or `ESTUS_TEST_PYTHON` | Optional absolute path to outside-Nix Python 3.14; otherwise the harness obtains it with uv |

With those inputs and `uv`, `tar` and a Rust toolchain available, run:

```sh
cargo test --locked --test wheel source_distribution_roundtrip_preserves_manifest_selected_assets -- --ignored --exact
```
