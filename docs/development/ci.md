# Continuous integration

Use this guide to see which checks GitHub runs and where to change them. Edit `nix/ci.nix`, not the generated workflow files.

## Regenerate workflows

From the checkout root:

```sh
nix run .#generate-workflows
```

Include the changes under `.github/workflows/` in your PR. `nix flake check` checks that the generated files match.

## What runs on GitHub

The SSH baseline workflow runs on Linux x86-64, Linux arm64 and macOS arm64. The container step runs only on Linux. The fuzz workflow runs on Linux x86-64.

The SSH baseline workflow runs on every pull request and every push to `main`. A push to a branch other than `main` does not run it; open a pull request. Each push to `main` runs in its own concurrency group, so every commit gets a result and runs of consecutive pushes overlap. A pull request's runs share one group, so a new push to the PR cancels the previous run. The fuzz workflow runs only on pull requests that change `src/`, `fuzz/`, `Cargo.toml` or `Cargo.lock`, and weekly.

| Layer | What it covers |
| --- | --- |
| Flake checks | Default and MSRV native builds and network-free tests, acceptance harness compilation, wheel build, formatting, Clippy, RustSec advisory checks, Python bootstrap and static checks, generated workflow consistency |
| Packaged MSRV native | Loopback SSH/SFTP, controller scripts, `doctor`, and progress notifications |
| Packaged MSRV bundle | Bundle build, inspection, digest and module execution checks |
| Linux containers | Installed stdio suites and the SSH/SFTP/sudo baseline against the native fixture, for both the default and MSRV packages |
| Python distributions | Installed wheel acceptance and source archive round-trip on each SSH baseline platform |
| Fuzzing | Build and replay committed corpora on relevant PRs; time-bounded mutation campaigns on scheduled and manual runs |

## What to run yourself

The wheel and sdist tests opt out of ordinary `cargo test` and are not part of `nix flake check` beyond the wheel build. Hosted CI explicitly runs both acceptance apps afterward. It tests Python 3.14 by default, not every supported launcher version. Use [acceptance](acceptance.md) to check other interpreters, the full catalog guest suites or the sample workflows; hosted CI does not run those guest and workflow suites.
