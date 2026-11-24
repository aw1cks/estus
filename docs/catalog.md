# Catalog

Use the catalog to give your agent specific Linux operations without granting
it a shell. Estus ships the tool definitions; you choose which ones your site
enables.

## Enable a preset

Save this as `estus.toml` and replace `web-1` with your target and its SSH
destination. The `linux-health` preset enables CPU, memory and pressure
observations.

```toml
capabilities.named = true
selection.presets = ["linux-health"]
targets.web-1.ssh_host = "web-1"
automation.targets.web-1.destination = "web-1"
automation.targets.web-1.python = "/usr/bin/python3"
```

A preset selects tool names. It does not provide allowlists or grant authority.
See the [preset list](tools/catalog-reference.md#presets) for current members.

## Enable an individual tool

To enable only `observe_host_summary`, replace `selection.presets` in the
example above with:

```toml
# fragment
selection.allow = ["observe_host_summary"]
```

Keep both keys if you want the named tool in addition to a preset. Check the
[reference](tools/catalog-reference.md) before adding a tool: some require a
site allowlist, a named [authority](concepts.md#authority), or an
[Ansible bundle](ansible-bundles.md).

## Install the catalog

The wheel and the Nix package come with the catalog. A binary you built with
Cargo or downloaded on its own carries a copy inside it, and needs it written to
disk once:

```sh
estus catalog install
```

It prints one line of JSON (the file count varies by release):

```json
{"dir":"/home/you/.cargo/share/estus/catalog","files":301,"installed":true,"ok":true,"version":"10"}
```

By default this writes `../share/estus/catalog` relative to the executable, so
`~/.cargo/bin/estus` installs to `~/.cargo/share/estus/catalog`. That is the
first place Estus looks, so nothing else needs configuring. To put it somewhere
else, pass `--dir` and point Estus at it with `[catalog] root` or
`ESTUS_CATALOG_ROOT` (see [configuration](configuration.md#catalog-assets-catalog)).

Running it again is safe. If the files already match this build, it reports
`"installed": false` and changes nothing. If a different catalog is there, it
refuses with `catalog_install_exists` rather than overwrite it. **After you
upgrade Estus, run `estus catalog install --replace`** so the installed catalog
matches the new binary; Estus does not update it for you.

Install writes only the catalog, with directories `0755` and files `0644`. It
enables no tool and grants no access. For a locked-down deployment, run it as
root into a root-owned directory; see [deployment](deployment.md).

## List or export tools

Run `estus catalog list` to see the presets and tool definitions in your
installed catalog. Here is one line from the output:

```text
observe_cpu	site_policy_template	ready to enable	Read aggregate CPU tick counters and topology IDs, optionally sampling twice. The view may be host-wide, not your affinity or quota.	linux,python3
```

Use `estus catalog list --json` for structured output. Pass `--root` to read a
specific catalog directory instead of the installed one.

To review the definitions and collector sources offline, export a tool with
`--tool` or a preset with `--preset`. Use a new output directory:

```sh
estus catalog export --preset linux-health --output health-review
```

```json
{"enabled":false,"ok":true,"qualification_file":"catalog-selection.json","tools":["observe_cpu","observe_memory","observe_pressure"],"version":"10"}
```

The export contains `tools.toml`, `catalog-selection.json`, and a `payloads/`
directory for collector sources and manifests. This is review material, not a
site configuration. You do not need an export to enable installed tools.

## Read the qualification labels

Qualification describes the template, not whether it will work on your hosts.

| Label | Meaning |
| --- | --- |
| `site_policy_template` | A reviewed tool definition. Check `policy_required` to see whether you need to supply site policy before enabling it. |
| `laboratory_only` | The tool expects a specific lab fixture or synthetic device. Keep it out of production. |
| `unqualified` | No readiness claim. |
| `deployment_qualified` | Reserved for a tool with documented evidence for a complete deployment workflow. |

## Supply site policy

If `catalog list --json` reports `policy_required` as `true`, add a
`[tools.<name>]` overlay with the policy that tool expects. Estus requires at
least one of these keys; which one you need depends on where the tool applies
its allowlist.

| Key | Use it to |
| --- | --- |
| `fixed_args` | Set values the caller cannot choose, such as an approved root directory. |
| `constraints` | Supply an allowlist or a bound the collector enforces, such as `allowed_units`. |
| `input_schema` | Limit caller input at validation, for example by making an argument an enum of approved names. |

This configuration lets the agent read status for `example.service` on
`web-1`. It leaves the installed tool's system-manager scope and input mapping
unchanged.

```toml
capabilities.named = true
selection.allow = ["observe_systemd_unit"]
targets.web-1.ssh_host = "web-1"
automation.targets.web-1.destination = "web-1"
automation.targets.web-1.python = "/usr/bin/python3"

[tools.observe_systemd_unit]
constraints = { allowed_units = ["example.service"] }
```

Save it as `estus.toml` and check the tool's authorization without connecting
to the host:

```sh
estus --config estus.toml auth can-i observe_systemd_unit web-1
```

An overlay keeps the installed tool and changes its site settings. It can also
restrict the target list, select an authority, or adjust limits and input
mapping. See [Policy](policy.md) for the overlay keys and merge rules.

## Check target requirements

The [reference](tools/catalog-reference.md) shows the required target Python
and lists utilities and platform requirements. Most native collectors need
Python 3.8 or newer; some NIC tools need 3.10. The `requires` field in
`catalog list --json` lists platform or utility requirements such as `systemd`
or `ethtool`. Set the interpreter path for your target if it differs from the
one in the example.

Estus checks the installed collector against the SHA-256 in its manifest when
it loads the tool. Before running the collector, the target bootstrap checks
the received bytes and the manifest's declared prerequisites, including the
Python version, modules and executables. Missing prerequisites fail before
the collector runs. These checks detect drift; they do not attest to the
installation or the target.

## Read facts and preview changes

Use the dedicated read tool for facts: `observe_systemd_unit` reads status,
`observe_hardware_system` reads firmware identifiers such as the product name,
and `observe_packages` reads installed packages. They run native collectors, so
you do not need a bundle to get these facts.

Look up the preview paired with a change in the
[reference](tools/catalog-reference.md). Enable and configure both tools when
your [preview policy](concepts.md#preview-before-change) requires a matching
preview. Some changes have no pairing.
