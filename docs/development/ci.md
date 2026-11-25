# Continuous integration

Use this guide to see which checks GitHub runs and where to change them. Edit `nix/ci.nix`, not the generated workflow files.

## Regenerate workflows

From the checkout root:

```sh
nix run .#generate-workflows
```

Include the changes under `.github/workflows/` in your PR. `nix flake check` checks that the generated files match, and runs [zizmor](https://docs.zizmor.sh/) on them (`checks.zizmor`, offline, configured in `.github/zizmor.yml`). A zizmor finding fails the check: fix the workflow in `nix/ci.nix`, or, if the finding does not apply, add a scoped ignore to `.github/zizmor.yml` with the reason next to it.

## What runs on GitHub

The SSH baseline workflow runs on Linux x86-64, Linux arm64 and macOS arm64. The container step runs only on Linux. The fuzz workflow runs on Linux x86-64.

The SSH baseline workflow runs on every pull request and every push to `main`. A push to a branch other than `main` does not run it; open a pull request. Each push to `main` runs in its own concurrency group, so every commit gets a result and runs of consecutive pushes overlap. A pull request's runs share one group, so a new push to the PR cancels the previous run. The fuzz workflow runs only on pull requests that change `src/`, `fuzz/`, `Cargo.toml` or `Cargo.lock`, and weekly.

A repository ruleset requires `ssh-baseline-linux` and `ssh-baseline-linux-arm64` to pass before a pull request can merge into `main`; branches don't need to be up to date with `main` first. `ssh-native-macos-arm64` is not required, because GitHub's macOS arm64 runners are sometimes unavailable for long enough that GitHub cancels the queued job. The required checks are tied to the GitHub Actions app, so a status set by anything else doesn't satisfy them.

GitHub sometimes fails to run a job at all, most often a macOS arm64 job that never gets a runner. SSH baseline, Release artifacts and Publish end with a retry job that, when anything failed or was cancelled, dispatches **CI retry** (`ci-retry.yml`, run from `main`). That waits for the run to finish, reads each failed job's annotations, and re-runs the failed jobs only if every one of them failed because GitHub didn't run it: the job was never acquired by a runner, or the runner lost contact or shut down. A job that ran and failed, timed out or was cancelled by a newer push is left alone, and a run gets at most three attempts. `scripts/ci-retry.sh` makes the decision; `RUN_ID=<run> GH_REPO=aw1cks/estus DRY_RUN=1 scripts/ci-retry.sh` shows what it would do for any run. Inside the jobs, the smoke tests retry container package installs up to three times and print the last attempt's output if they all fail.

Three more workflows handle releases. **Release artifacts** (`release-artifacts.yml`) builds and tests the release binaries and wheels; it runs on pull requests that touch the release files, on demand, and as the first stage of publishing. **Release Please** (`release-please.yml`) runs on every push to `main` and keeps the release pull request up to date. **Publish** (`publish.yml`) builds and publishes, and only for an unpublished release on a `v*` tag on `main`. Anything `GITHUB_TOKEN` creates, a pull request or a tag, triggers no workflows, so Release Please dispatches **SSH baseline** and **Release artifacts** on the release branch, and **Publish** on the new tag. See [Releasing](release.md).

Two workflows report to GitHub code scanning, so findings show on the changed lines of a pull request and in the repository's Security tab. **Code scanning** (`code-scanning.yml`) runs on pull requests, on pushes to `main` and weekly. It uploads zizmor's findings with the online audits, which need the network and so can't run inside `nix flake check`: impostor commits, known-vulnerable actions, ref confusion and stale pins. It also uploads every clippy finding as SARIF. The blocking zizmor and clippy gates stay in `nix flake check`. **Scorecard** (`scorecard.yml`) runs the OpenSSF Scorecard on pushes to `main` and weekly, and publishes the result for the README badge. Publishing only works while that workflow keeps to Scorecard's rules: no workflow-level env, defaults or write permissions, and only Scorecard's approved actions in its job. CodeQL runs from GitHub's default setup, which is configured in the repository settings rather than in a workflow file.

| Layer | What it covers |
| --- | --- |
| Flake checks | Default and MSRV native builds and network-free tests, acceptance harness compilation, wheel build, formatting, Clippy, RustSec advisory checks, dependency bans, licenses and sources, documentation links, spelling, Python bootstrap and static checks, generated workflow consistency |
| Packaged MSRV native | Loopback SSH/SFTP, controller scripts, `doctor`, and progress notifications |
| Packaged MSRV bundle | Bundle build, inspection, digest and module execution checks |
| Linux containers | Installed stdio suites and the SSH/SFTP/sudo baseline against the native fixture, for both the default and MSRV packages |
| Python distributions | Installed wheel acceptance and source archive round-trip on each SSH baseline platform |
| Fuzzing | Build and replay committed corpora on relevant PRs; time-bounded mutation campaigns on scheduled and manual runs |
| Release artifacts | Builds every release binary, wheel and the sdist, checks the glibc floor and static linkage, installs each in a distribution container or on macOS, and dry-runs the crate publish |
| Code scanning | zizmor (with online audits) and clippy findings as SARIF on pull requests, weekly zizmor re-audit; OpenSSF Scorecard; CodeQL default setup |

## What to run yourself

The wheel and sdist tests opt out of ordinary `cargo test` and are not part of `nix flake check` beyond the wheel build. Hosted CI explicitly runs both acceptance apps afterward. It tests Python 3.14 by default, not every supported launcher version. Use [acceptance](acceptance.md) to check other interpreters, the full catalog guest suites or the sample workflows; hosted CI does not run those guest and workflow suites.
