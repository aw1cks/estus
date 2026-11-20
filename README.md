# Estus

Estus is a stdio MCP server that gives an LLM agent a curated set of Linux SRE
operations over operator-configured SSH: structured observation, sensitive
inspection, previews, single-purpose changes, generic command execution, and an
opt-in catalog of reviewed collectors and Ansible modules. It is **not** a
sandbox, an SSH credential store, a bastion, or a policy engine for arbitrary
shell work: the Rust process owns MCP framing, SSH transport, limits, cleanup and
the in-memory write quarantine, while remote SSH identities, the remote OS and
the operator's `sudoers` remain authoritative. A client that can execute as the
service account can bypass Estus entirely. See
[docs/threat-model.md](docs/threat-model.md).

Only MCP JSON is written to server stdout; diagnostics go to stderr.

## Quickstart

Build and run (Rust 1.88+), or install the wheel with Python 3.14:

```sh
cargo build --release --locked && ./target/release/estus --help
uv build --python 3.14 && uv tool install --python 3.14 ./dist/estus-*.whl
```

A minimal closed configuration — one host, read-only catalog tools only:

```toml
mode = "headless"
capabilities = { named = true, file_read = true }
require_preview = false

[selection]
presets = ["linux-health"]

[targets.server]
ssh_host = "server-ordinary"      # an ordinary OpenSSH destination
sudo = { mode = "disabled" }      # the default

[automation.targets.server]
destination = "server-ordinary"
python = "/usr/bin/python3"       # target interpreter for catalog collectors
```

```sh
estus --config /etc/estus/estus.toml
```

`[targets]` is the authority boundary: any `[targets]` table (even empty)
authorizes exactly the logical names it lists, and only those names are accepted
as `host` values. Its absence leaves the caller naming a raw SSH destination and
is only reachable in workstation mode.

For local development with no configuration file, `--workstation` (or
`ESTUS_WORKSTATION=1`) opts into open destinations and all five capability
ceilings. Without it, a no-config start is headless: `named` only, no exec, sudo,
file-write or catalog exposure.

```sh
estus --workstation                       # zero-config development
nix run --no-write-lock-file .#dev-mcp    # same, with the Nix-built module bundle
```

MCP client entry (Claude Desktop, OMP, or any stdio client):

```json
{
  "mcpServers": {
    "estus": {
      "command": "estus",
      "args": ["--config", "/etc/estus/estus.toml"]
    }
  }
}
```

## Tool tiers

Every published tool carries `_meta.risk_tier`. Configure client approval on
exact names; the tier is the recommended default.

| Tier | Builtins | Meaning | Approval |
| --- | --- | --- | --- |
| `observe` | `observe_targets`, `observe_stat`, read-only catalog collectors | Read-only telemetry | allow |
| `inspect` | `inspect_file`, `inspect_directory`, `inspect_output`, sensitive reads, probes | Sensitive reads or active probes | ask |
| `preview` | `preview_*` catalog tools | Read-only pre-change check | ask |
| `change` | `change_*` file/SFTP and catalog mutations, `change_target_quarantine_clear` | Single-purpose mutation | ask |
| `exec` | `exec_command`, `exec_argv`, `exec_sudo` | Arbitrary remote execution | ask |

[skills/estus-sre/SKILL.md](skills/estus-sre/SKILL.md) carries the generated
allow/ask lists for the full published inventory (15 builtins plus the 104
bundled catalog tools).

Per-target narrowing is separate from the tier: `max_tier` denies every builtin
above a ceiling, `selection` names the tools that host keeps, and
`require_preview` (global, with a per-target override) demands a fresh matching
preview for `change`/`exec` work.

## Layout

- [docs/configuration.md](docs/configuration.md) — every configuration key,
  precedence and environment variable.
- [docs/catalog.md](docs/catalog.md) — catalog list/export, enabling tools, site
  overlays, collector integrity, offline bundle build/inspect.
- [docs/tools.md](docs/tools.md) — builtin tool behaviour, output handles,
  progress, quarantine and uncertainty semantics.
- [docs/threat-model.md](docs/threat-model.md) — adversaries, what Estus
  enforces, what it does not.
- [docs/development.md](docs/development.md) — build, Nix, tests, acceptance
  suites, fuzzing, CI.

Examples live in [`examples/`](examples): `dev-no-targets.toml`,
`automation_probe.toml`, the four reviewed `examples/workflows/*.toml` recipes and
`examples/separated-accounts/` for the recommended two-account deployment.

## Limits

Configuration ceilings are enforced before connecting: escaped command 65536
bytes, per-request reply budget 16 MiB, `max_output_bytes` and `max_file_bytes`
1 MiB by default, `max_timeout_secs` 600. Server-wide concurrency is 64 requests;
the session reports `mcp_session_overloaded` rather than buffering more.

## Licence

See [Cargo.toml](Cargo.toml).
