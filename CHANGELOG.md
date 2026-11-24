# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Estus is pre-1.0:
configuration keys and tool schemas may change between releases, and every such
change will be listed under **Changed** or **Removed**.

## [Unreleased]

### Added

- `estus catalog install` writes the catalog built into the binary to disk, by
  default next to the executable (`<prefix>/share/estus/catalog`). A binary from
  `cargo install` or a download no longer depends on packaging to find its
  catalog. Re-run with `--replace` after upgrading.
- AGPL-3.0-or-later license.
- Generated catalog reference (`docs/tools/catalog-reference.md`), produced by
  `scripts/gen-catalog-reference.py`.
- `SECURITY.md`, `CONTRIBUTING.md`, and issue and pull request templates.

### Changed

- Headless configurations and the `estus catalog` commands now find a catalog
  next to the executable, as workstation mode already did. With no catalog
  anywhere, they report `catalog_not_installed` instead of `catalog_missing_asset`.
- The repository's own `catalog/` is now picked up automatically only by binaries
  under a cargo `target/` directory (previously any executable location).
- Documentation rewritten from scratch and reorganised under `docs/`.
- The wheel's minimum Python is now 3.8 (was 3.10). Building from source still
  needs Python 3.10 or later.
- Package description updated.

### Fixed

- `estus auth can-i` denied a catalog tool with a native sudo route when the
  global `sudo` capability was off, although the server publishes and runs it.
  It also missed the preview pairing for `change_kernel_module_load`; the
  pairing list now lives next to the preview logic it describes.
- `SKILL.md` named the `inspect_journal` input `continuation_cursor`; the input
  is `cursor`.
- The sdist acceptance check required vendored `openssh-sftp-client` sources that
  the project no longer ships.
- `dev-no-targets.toml` failed to load; its timeout ceiling was below what the
  workstation catalog needs.
