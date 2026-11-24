# Acceptance tests

Use these Nix apps to test the installed binary against real SSH servers, disposable containers and guests, or an installed wheel. Run outside the build sandbox as a non-root user and use the fixtures, not your own targets.

## Run one scenario

The catalog app accepts libtest arguments. List scenarios, then select one by its full name:

```sh
nix run .#catalog-acceptance-msrv -- --list
nix run .#catalog-acceptance-msrv -- tools::observe_pressure::observe_pressure --exact
```

## Choose an app

Run an app with `nix run .#<app>`. Where the table says yes, append `-msrv` to test the minimum supported Rust build. The wheel and sdist apps already use MSRV test harnesses and have no separate `-msrv` names.

| App | What it exercises | `-msrv` |
| --- | --- | --- |
| `ssh-stdio` | Stdio protocol suites against the installed native binary | No |
| `ssh-baseline` | Container-backed SSH, SFTP and sudo with separate accounts | No |
| `ssh-native` | Loopback SSH and SFTP, output, collectors and quarantine | Yes |
| `mkdir-acceptance`, `rename-acceptance`, `remove-file-acceptance`, `remove-directory-acceptance`, `replace-file-acceptance` | Individual loopback SFTP mutations | Yes |
| `output-acceptance` | Output retention and range reads over native and controller routes | Yes |
| `progress-acceptance` | Progress on native, controller and SFTP routes | Yes |
| `controller-scripts` | Hostless controller scripts and local process handling | Yes |
| `doctor-acceptance` | Startup checks and target SSH resolution | Yes |
| `bundle-acceptance` | Bundle build, inspection, digest verification and module execution | Yes |
| `catalog-acceptance` | Shipped catalog tools against EFI-booted Linux guests | Yes |
| `workflow-catalog-acceptance` | Health, service diagnosis and service restart examples in the catalog guest | Yes |
| `workflow-files-acceptance` | Configuration-replacement example in the deployment container | Yes |
| `workflow-acceptance` | Both workflow apps, catalog first | Yes |
| `wheel-acceptance` | Wheel portability and installed behavior through `uvx`, `uv tool install` and `uv run` | No |
| `sdist-acceptance` | Source archive round-trip; see [Packaging](packaging.md#test-the-source-archive) | No |

## Fixture and runtime inputs

For loopback apps, use the account, Nix tools and private `XDG_RUNTIME_DIR` from the [SSH test setup](testing.md#run-a-loopback-ssh-suite). Catalog apps supply their own QEMU launchers. The catalog guest is x86-64; on a different host you need an x86-64 Linux Nix builder or substituter for the guest artifacts.

For container-backed apps, set `DOCKER_HOST` to an explicit local Unix socket (`unix:///absolute/path/to/docker.sock`). Use a dedicated test daemon and clear conflicting Docker or Testcontainers overrides. `ssh-baseline` needs `.#ssh-fixture-image`; `workflow-files-acceptance` and `workflow-acceptance` need `.#deployment-fixture-image`. These fixture packages are Linux-only. For example, after setting `DOCKER_HOST`:

```sh
ESTUS_TEST_FIXTURE=$(nix build --no-link --print-out-paths .#deployment-fixture-image)
export ESTUS_TEST_FIXTURE
nix run .#workflow-files-acceptance
```

| Variable | What to pass |
| --- | --- |
| `ESTUS_TEST_FIXTURE` | Directory from the matching Nix-built container fixture, not the archive inside it |
| `ESTUS_TEST_BINARY` | Estus binary or wrapper to test when invoking a harness directly; the packaged apps set it |
| `ESTUS_TEST_CATALOG_VM`, `ESTUS_TEST_CATALOG_LAB_VM` | Regular and lab guest launchers; set by the catalog apps |
| `ESTUS_TEST_CATALOG_ASSETS` | Catalog directory the harness should use as its reference |
| `ESTUS_TEST_ANSIBLE_BUNDLE`, `ESTUS_TEST_ANSIBLE_PYTHON` | Prebuilt bundle and bundle-build interpreter; the bundle app sets both |
| `ESTUS_TEST_PYTHON` | Optional path to an existing outside-Nix Python 3.14 for wheel and sdist acceptance; otherwise the harness uses uv to obtain it |
| `ESTUS_TEST_LAUNCHER_PYTHONS`, `ESTUS_TEST_PYTHON_<MAJOR>_<MINOR>` | Comma-separated additional launcher versions to test and optional per-version interpreter paths, such as `ESTUS_TEST_PYTHON_3_8` |

## What the lab qualifies

The laboratory scenarios exercise Linux MD arrays on virtual disks, an emulated NVMe controller and NIC features through `netdevsim`. A `laboratory_only` qualification is evidence for the exercised software configuration and decoding, not for physical hardware, firmware or the network data path. See the [catalog guide](../catalog.md) for how to handle those tools.
