# Define your own Ansible tool

Any Ansible module in your [bundle](ansible-bundles.md) can become a tool. You
choose what the agent may pass in, fix everything else, and pick which fields of
the result come back. The agent gets a typed call, not a playbook.

This is the most flexible thing Estus does, and the one that needs the most
review: a module runs as code on the target, under the authority you give it.
Read [what you are trusting](#what-you-are-trusting) before you enable one.

## A worked example

This tool reports whether a path exists, using `ansible.builtin.stat`. That
module is in the default bundle, so there is nothing to rebuild.

```toml
mode = "headless"
capabilities = "catalog_only"

[selection]
allow = ["observe_path_stat"]

[targets.web-1]
ssh_host = "web-1"

[automation]
bundle = "/etc/estus/bundle"

[automation.targets.web-1]
destination = "web-1"
python = "/usr/bin/python3"

[tools.observe_path_stat]
description = "Report whether a path exists and its basic attributes."
revision = "1"
targets = ["web-1"]
authority = "automation"
effects = ["read"]
execution = { kind = "ansible_module", module = "ansible.builtin.stat" }
input_map = { path = "path" }
fixed_args = { get_checksum = false, get_mime = false, get_attributes = false }
input_schema = { type = "object", additionalProperties = false, required = ["path"], properties = { path = { type = "string", minLength = 1, maxLength = 256 } } }
limits = { timeout_secs = 30 }

[tools.observe_path_stat.result]
kind = "ansible_projection"
fields = { exists = ["stat", "exists"], is_dir = ["stat", "isdir"], mode = ["stat", "mode"] }
max_bytes = 1024
max_items = 8
max_depth = 3
schema = { type = "object", properties = { exists = { type = "boolean" }, is_dir = { type = "boolean" }, mode = { type = "string", maxLength = 8 } }, required = ["exists"], additionalProperties = false }
```

Estus publishes it as `observe_path_stat`, an `observe` tool. The agent supplies
`host` and one input, `path`. The three `get_*` options are fixed off, so it can
never ask for a checksum or a MIME type. The `timeout_secs` it may request is
capped at the 30 seconds in `limits`.

## What each key does

| Key | Meaning |
| --- | --- |
| `description` | What the agent sees. Required; up to 1024 bytes. |
| `revision` | A short identifier, such as `"1"`. Required. |
| `targets` | One to 32 [configured targets](policy.md#targets) the tool is offered on. |
| `authority` | `automation` runs as your ordinary identity. `automation:<name>` uses a [named authority](configuration.md#automation-routes-automation) with its own SSH route and sudo. |
| `effects` | What the tool does: `read`, `sensitive_read`, `probe`, `runtime_write`, `persistent_write`, `availability` or `unknown`. At least one, no repeats. |
| `execution` | `kind = "ansible_module"` and the module's full name. Optional: `bundle` (an absolute path to a different bundle), `no_log` (withhold the module's output; the reply is marked `censored`), `check_mode` and `diff`. |
| `input_schema` | What the agent may pass. A closed schema: `additionalProperties = false`, no regexes or references. |
| `input_map` | Maps each module argument to one input, as `module_argument = "input_name"`. |
| `fixed_args` | Module arguments the agent can't change. |
| `limits` | `timeout_secs` and `max_output_bytes` for the call. |
| `result` | What comes back. See [choose what comes back](#choose-what-comes-back). |

## The name sets the tier

Name your tool with a tier prefix and Estus checks that its `effects` agree. The
tier is what your client's [approval rules](clients.md#choosing-approvals) match.

| Name starts with | `effects` must be |
| --- | --- |
| `observe_` | `read` only |
| `inspect_` | no mutating effect, and at least one of `sensitive_read` or `probe` |
| `preview_` | no mutating effect |
| `change_` | at least one mutating effect: `runtime_write`, `persistent_write`, `availability` or `unknown` |

A mismatch is rejected at startup. Use the prefix that matches what the module
does, and don't give a changing module an `observe_` name to get past an approval
prompt: Estus won't let you.

## Choose what comes back

- **`ansible_summary`** returns the outcome only: whether the call succeeded and
  whether anything changed. Use it when the effect is all you need.
- **`ansible_projection`** also returns the fields you list. `fields` maps an
  output name to a path in the module's result, and `schema` describes the
  output. They appear under `projection` in the reply; see
  [reading results](tools/results.md).

The projection is your disclosure boundary: only the fields you list leave the
target. Estus won't project `invocation`, `module_args`, `args`, `argv`, `cmd`,
`env`, `environment`, `ansible_env`, or anything starting with `_`. The schema
must be closed (no `$ref`, regexes, defaults or open objects), and `max_bytes`,
`max_items` and `max_depth` bound the result.

## Previews and changes

A `preview_` tool can set `check_mode = true` to run the module without changing
anything. Add `diff = true` to return the module's diff; that needs a projection
field sourced from `diff`, and `no_log` off.

Estus pairs previews with changes only for the tools it ships. A `change_` tool
you define has no pairing, so with `require_preview = true` it is refused:

```text
$ estus --config estus.toml auth can-i change_path_stat web-1
no   (no qualified preview pairing under require_preview = true (require_preview policy))
```

If you need a preview-gated change, use the shipped package tools, or keep the
host on `require_preview = false` and rely on [`max_tier` and
selection](policy.md) to control who can call it.

## Mistakes Estus catches at startup

Estus checks every definition against the bundle when it starts and refuses to
run if one is wrong. Nothing is served until you fix it.

| Mistake | Error |
| --- | --- |
| An input that isn't in `input_map` | `invalid_binding_schema` |
| A mapped argument that is also in `fixed_args` | `invalid_binding_schema` |
| A required module argument that is neither fixed nor a required input | `invalid_binding_schema` |
| A fixed argument the module doesn't have | `invalid_binding_arguments` |
| A module that isn't in the bundle | `module_not_in_bundle` |
| `check_mode = true` on a tool not named `preview_…` | `check_mode is only supported on preview_* ansible_module bindings` |
| `diff = true` without `check_mode`, or with `no_log` | `diff requires preview check_mode without no_log` |
| A relative `execution.bundle` | `Invalid Ansible bundle path` |

`estus auth explain` loads the config but doesn't check tools against the bundle.
To see these errors, start the server, for example by connecting your client or
by running `estus --config estus.toml` and sending it an `initialize` request.

## What you are trusting

- **The module.** It runs on the target as the authority's user, with whatever
  that user can do. Estus limits what the agent can ask for, not what the module
  can do once it runs. Review it like any code you deploy.
- **The bundle.** Estus verifies the bundle's digests, which catches changes. It
  doesn't tell you the modules were safe to begin with. Build from a source you
  trust, and keep the directory out of anything the agent can write to.
- **Python on the target.** Each target needs an explicit `python` under
  `[automation.targets.<name>]`, at or above the bundle's `target_python_floor`.

See the [security model](security.md) for how this fits with the rest of Estus.
