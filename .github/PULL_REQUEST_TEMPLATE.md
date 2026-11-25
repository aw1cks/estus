## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## How I checked it

<!-- The commands you ran and what you saw. See CONTRIBUTING.md for the pre-PR checklist. -->

## Checklist

- [ ] `cargo fmt --check` and `cargo clippy --all-targets --all-features -- -D warnings` pass
- [ ] Relevant tests pass
- [ ] Docs updated if behaviour, config or a tool changed
- [ ] Commit subjects follow Conventional Commits (`feat:`, `fix:`, `docs:`, ...); release notes are generated from them, so don't edit `CHANGELOG.md`
- [ ] If a catalog tool changed: `python3 scripts/gen-catalog-reference.py` re-run
