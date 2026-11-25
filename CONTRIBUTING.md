# Contributing

Thanks for working on Estus. Start here to report a problem or send a patch.

## Report a bug or ask a question

Open an issue in `aw1cks/estus`. For a bug, include the Estus version, your platform, the smallest configuration and steps that reproduce it, and what you expected versus what happened. Strip credentials, private hostnames and sensitive command output before posting. Report vulnerabilities privately; see [Security](SECURITY.md).

## Before opening a pull request

Follow [Building from source](docs/development/building.md) to set up your checkout. Run these commands from the repository root. The last two are integration checks; use the [test guide](docs/development/testing.md) to add suites relevant to your change.

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --lib
cargo test --locked --test stdio_protocol --test stdio_catalog --test stdio_policy --test stdio_auth
cargo test --locked --test catalog_distribution
```

Use Conventional Commit subjects: `fix(catalog): describe the fix` or `docs: describe the change`. They are not just style. [release-please](docs/development/release.md) builds each release's version bump and notes from them, so `feat:` and `fix:` appear in the changelog and `feat!:` marks a breaking change. Keep the PR focused. Explain why the change is needed, link the issue if there is one, and list the checks you ran. Include a regression test for a bug fix and update the docs when behavior changes.

## Change a catalog tool

Start with a similar tool and the [catalog guide](docs/catalog.md). Register the tool and its executor in `catalog/catalog.json`, and put its definition in `catalog/<tool>.toml`. For a Python collector, update `catalog/payloads/<tool>/collector.py` and its `manifest.json`, including the source digest if the collector changed. Add tests for the tool's inputs and results.

After a Cargo release build, regenerate the [catalog reference](docs/tools/catalog-reference.md) and include it in the PR:

```sh
export PATH="$PWD/target/release:$PATH"
python3 scripts/gen-catalog-reference.py
```

## License

Estus is licensed under the [GNU Affero General Public License, version 3 or later](LICENSE) (`AGPL-3.0-or-later`). Contributions are accepted under the same license.
