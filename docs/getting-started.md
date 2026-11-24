# Getting started

This walks you from nothing to an agent triaging one of your hosts, read-only.
It takes about ten minutes. You need Estus installed (see the
[README](../README.md#install)) and SSH access to a Linux host.

## 1. Check the basics

**On the machine that runs Estus** (your laptop or workstation) you need OpenSSH
and a way to log in to the target without typing anything: a key, or a running
agent. Estus can't answer prompts. Confirm this works from your terminal:

```sh
ssh web-1 true && echo ok
```

Use a real `Host` entry in `~/.ssh/config` (or any file; see
[`--ssh-config`](configuration.md)). Estus runs the `ssh` you have, so
`IdentityFile`, `ProxyJump`, `known_hosts` and `StrictHostKeyChecking` all apply
exactly as they do for you.

**On the target** you need `sshd`, and `python3` for catalog tools. Python 3.8 is
enough for nearly all of them; a handful of tools declare a newer minimum. The
builtin file and exec tools need only SSH (and SFTP for files).

## 2. Write a config

Create `estus.toml`. This is the smallest useful configuration: one host,
read-only, with a small set of health tools.

```toml
mode = "headless"
capabilities = { named = true, file_read = true }

[selection]
presets = ["linux-health"]       # observe_cpu, observe_memory, observe_pressure

[targets.web-1]
ssh_host = "web-1"               # the Host name from your ssh config

[automation.targets.web-1]
destination = "web-1"            # how catalog tools reach it
python = "/usr/bin/python3"      # the interpreter on the target
```

What this allows: the agent can address exactly one host, `web-1`, and call the
three `linux-health` tools plus the read-only file tools. It cannot run commands,
write files, or use sudo. The same host appears twice because builtin tools
([`[targets]`](policy.md)) and catalog tools (`[automation]`) are configured
separately; see [concepts](concepts.md#authority).

## 3. Ask Estus what it will allow

Before any agent is involved, check the policy without connecting anywhere:

```sh
estus --config estus.toml auth explain web-1
```

```text
Target:          web-1 (configured mode)
Matched groups:  (none)
Effective policy (strictest-wins across 0 matches):
  allowed:         yes
  max_tier:        exec       (unconstrained)
  require_preview: false
  capabilities:    named, file_read
  sudo:            disabled
  tools:           6 permitted (observe: 4, inspect: 2, preview: 0, change: 0, exec: 0)
```

```sh
estus --config estus.toml auth can-i exec_command web-1
# no   (disabled by global [capabilities] (requires exec))
```

Then check connectivity and SSH policy:

```sh
estus --config estus.toml doctor --target web-1
```

`doctor` prints one JSON object. Each target reports `ssh`, `sftp` and `sudo`
status, plus the effective SSH settings Estus resolved (host-key checking, batch
mode). It connects over SSH and checks that SFTP negotiates; it runs no remote
command and doesn't test sudo. If it fails, see [troubleshooting](troubleshooting.md).

## 4. Connect your MCP client

Estus is a stdio server: your client launches it. For Claude Code:

```sh
claude mcp add estus -- estus --config /absolute/path/to/estus.toml
```

For other clients see [Connecting a client](clients.md). Use an absolute path to
the config.

## 5. Try it

Ask the agent something concrete:

> Is web-1 under memory or CPU pressure right now?

You should see calls to `observe_memory`, `observe_cpu` and `observe_pressure`.
Catalog tools take a `host` and an `inputs` object (empty for these three); the
file tools take a `host` and a `path`:

```json
{"host": "web-1", "inputs": {}}
```

Each call returns a structured result: how the run went (`status`, `complete`)
and the data under `projection`. [Reading results](tools/results.md) explains
every field.

If nothing happens, or the client reports that the server exited, run the
command by hand to see its error output. See [troubleshooting](troubleshooting.md).

## 6. Grow it, one step at a time

Each step is a small config change. Run `auth explain` after each one.

| You want | Change | Read |
| --- | --- | --- |
| More read-only tools | Add presets (`network-observe`, `sre-core`, ...) or names to `[selection]` | [Catalog](catalog.md) |
| Logs and processes | Add the `sensitive-observe` preset. These are `inspect` tools: set your client to ask first | [Connecting a client](clients.md) |
| Several hosts with different rules | Add `[[groups]]` and profiles such as `prod` | [Policy](policy.md) |
| Let the agent change things | Enable specific `change_*` tools, set `require_preview = true` | [Concepts: preview](concepts.md#preview-before-change) |
| A generic shell | Turn on `exec` in `[capabilities]`. This is the broadest permission Estus has | [Security](security.md) |

> **Note:** Don't start from `--workstation` or `--yolo` for real hosts. They
> exist for local development and throwaway machines: they let the agent name any
> SSH destination and open every capability. Use a config file.
