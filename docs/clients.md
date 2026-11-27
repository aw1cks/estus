# Connecting a client

How to launch Estus from an MCP client and set approval prompts that match each
tool's [tier](concepts.md#tiers).

Estus is a stdio MCP server. Every client does the same thing: run `estus` as a
child process and talk to it over stdin/stdout. Estus writes only MCP messages to
stdout; diagnostics go to stderr.

Always pass an **absolute path** to the config file. The client's working
directory is not yours.

## Claude Code

```sh
claude mcp add estus -- estus --config /absolute/path/to/estus.toml
```

Everything after `--` is the command Claude Code runs. Add `--scope user` to make
it available in every project, or `--scope project` to share it through
`.mcp.json`. Check the connection with `claude mcp list`, or `/mcp` inside a
session.

### Approvals

Claude Code names MCP tools `mcp__<server>__<tool>`. With the server named
`estus`, set approvals by tier in `.claude/settings.json` (or your user settings):

```json
{
  "permissions": {
    "allow": ["mcp__estus__observe_*"],
    "ask": [
      "mcp__estus__inspect_*",
      "mcp__estus__preview_*",
      "mcp__estus__change_*",
      "mcp__estus__exec_*"
    ]
  }
}
```

Allow rules accept a glob only after the literal `mcp__<server>__` prefix, which
is what the `observe_*` rule above does. If you named the server something other
than `estus`, change the prefix to match.

### Prompts and the skill

Estus publishes four MCP prompts: `triage_host`, `diagnose_service`,
`safe_change` and `network_triage`. In Claude Code they run as
`/mcp__estus__triage_host` and so on.

[`skills/estus-sre/SKILL.md`](../skills/estus-sre/SKILL.md) is an agent skill that
teaches a model the Estus workflow: observe first, preview before change, and how
to handle uncertainty. To use it, copy the `estus-sre` directory into
`~/.claude/skills/` (all projects) or `.claude/skills/` (one project). The same
file also lists every tool name by tier, and is a convenient source for approval
rules.

## Claude Desktop, Cursor and other JSON-configured clients

Most clients read a JSON file with an `mcpServers` object. Find where your client
keeps it, and add:

```json
{
  "mcpServers": {
    "estus": {
      "command": "estus",
      "args": ["--config", "/absolute/path/to/estus.toml"]
    }
  }
}
```

If `estus` isn't on the client's `PATH` (GUI apps often have a short one), use
the full path to the binary as `command`.

## Home Manager

The Nix flake exports `homeModules.default`. It needs a Home Manager release
that has [`programs.mcp`](https://github.com/nix-community/home-manager/blob/release-26.05/modules/programs/mcp.nix),
26.05 or later.

```nix
{
  imports = [ inputs.estus.homeModules.default ];
  programs.estus = {
    enable = true;
    settings = {
      capabilities = { named = true; };
      selection.allow = [ "observe_cpu" "observe_memory" ];
      targets.web-1.ssh_host = "web-1";
      automation.targets.web-1.destination = "web-1";
    };
  };
}
```

`settings` is the [configuration](configuration.md) as Nix, written to
`$XDG_CONFIG_HOME/estus/estus.toml`. With a target declared, Home Manager loads
it with Estus at build time, so a rejected config fails `home-manager switch`
rather than the client's startup. Set `programs.estus.validate = false` if it
names a file the build sandbox cannot see, such as `ssh.config_file`.

The module adds an `estus` entry to `programs.mcp.servers` with the absolute
config path and enables `programs.mcp`. Clients that support it pick the entry
up through their own switch, for example
`programs.claude-code.enableMcpIntegration = true`. Set
`programs.estus.mcp.enable = false` to skip this and wire the client yourself.
Approval rules and the skill are not part of `programs.mcp`; set them on the
client, as in the sections above.

Use `programs.estus.package = inputs.estus.packages.${pkgs.stdenv.hostPlatform.system}.automation`
for the build that ships an Ansible bundle. The default package puts its own
OpenSSH first on `PATH`. On macOS that replaces Apple's `ssh`, which can break
Keychain-backed keys and `UseKeychain` lines in `~/.ssh/config`; set
`settings.ssh.executable = "/usr/bin/ssh"` to keep Apple's.

### Overlay

`inputs.estus.overlays.default` adds `estus` and `estus-automation` to `pkgs`,
built with your nixpkgs instead of the one this flake pins. It needs a Rust
1.88 or later in that set, and the binary cache below won't have it. Use it with
`programs.estus.package = pkgs.estus;`.

### The skill

`inputs.estus.packages.${system}.skills` holds one directory per agent skill.
For Claude Code:

```nix
programs.claude-code.skills.estus-sre =
  "${inputs.estus.packages.${pkgs.stdenv.hostPlatform.system}.skills}/estus-sre";
```

### Binary cache

CI pushes `default`, `automation` and `skills` for every commit on `main` that
passes, on x86_64-linux, aarch64-linux and aarch64-darwin, to
`https://aw1cks-estus.cachix.org`. Without it, Nix builds Estus from source.
A flake's `nixConfig` doesn't apply to flakes you import, so add the cache to
your own Nix settings. On NixOS or nix-darwin:

```nix
nix.settings = {
  substituters = [ "https://aw1cks-estus.cachix.org" ];
  trusted-public-keys = [ "aw1cks-estus.cachix.org-1:J4jI1cSMiSkNNjHbyA1wyavdwMeqT2EHAwuboKZ/jNk=" ];
};
```

With standalone Home Manager, put the same in `nix.conf`
(`extra-substituters`, `extra-trusted-public-keys`). Only trusted users can
add substituters. `nix run github:aw1cks/estus` offers the cache through the
flake's `nixConfig`; answer yes to the prompt, or pass `--accept-flake-config`.
Don't set `inputs.nixpkgs.follows` on `inputs.estus`, or your build differs from
the cached one. A commit is cached once CI has passed on it, so a lock that
points at a commit on `main` or at a release tag normally hits the cache.

## OMP

OMP reads project MCP servers from `.omp/mcp.json`:

```json
{
  "mcpServers": {
    "estus": {
      "type": "stdio",
      "command": "estus",
      "args": ["--config", "/absolute/path/to/estus.toml"],
      "timeout": 300000
    }
  }
}
```

`timeout` is the client's own limit in milliseconds. It is separate from the
limits in your Estus config (`operation_timeout_secs`, `max_timeout_secs`; see
[configuration](configuration.md)), so set it at least as high as the longest
operation you allow. OMP hides the server's stderr and reports a failed start as
a generic EOF; see [troubleshooting](troubleshooting.md).

## Choosing approvals

Suggested defaults, matching the tiers:

| Tier | Prefix | Suggested |
| --- | --- | --- |
| observe | `observe_` | allow |
| inspect | `inspect_` | ask. These can read logs, files and process lists |
| preview | `preview_` | ask |
| change | `change_` | ask |
| exec | `exec_` | ask |

Client approvals are a convenience, not the control. A client prompt only helps
if you read it, and some clients can be told to skip prompts entirely. The
enforceable controls live in Estus: [capabilities, `max_tier`, selection and
`require_preview`](policy.md) decide what a host can do no matter what the client
is configured to allow. Set those to the most you would ever want an agent to do
on that host, then use client prompts for day-to-day friction.

If your client can't set approvals per tool or by prefix, lower `max_tier` for
the target instead (for example `max_tier = "inspect"` for a read-only host).
