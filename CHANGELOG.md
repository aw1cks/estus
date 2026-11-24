# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Estus is pre-1.0:
configuration keys and tool schemas may change between releases, and every such
change will be listed under **Changed** or **Removed**.

## [Unreleased]

### Added

- AGPL-3.0-or-later license.
- Generated catalog reference (`docs/tools/catalog-reference.md`), produced by
  `scripts/gen-catalog-reference.py`.
- `SECURITY.md`, `CONTRIBUTING.md`, and issue and pull request templates.

### Changed

- Documentation rewritten from scratch and reorganised under `docs/`.
- The wheel's minimum Python is now 3.8 (was 3.10). Building from source still
  needs Python 3.10 or later.
- Package description updated.
