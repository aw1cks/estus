# Ansible bundles

Some tools run Ansible modules on the target: the package tools such as
`preview_package` and `change_package`, and any [Ansible tool you write
yourself](ansible-tools.md). They need a **bundle**: a directory of modules
compiled ahead of time. Estus runs them from the bundle, so neither the machine
running Estus nor the target needs Ansible installed at run time.

Most catalog tools don't need a bundle. The [catalog reference](tools/catalog-reference.md)
marks the ones that do.

## Get a bundle

| Where you run Estus | What to do |
| --- | --- |
| Nix | Run the `automation` package, `nix run github:aw1cks/estus#automation`. It comes with a prebuilt bundle (set through `ESTUS_ANSIBLE_BUNDLE`). The default package has none. |
| A wheel or `cargo install` build | Build one, as below, and point `[automation].bundle` at it. Neither ships a bundle. |
| A distribution package | The package can install a bundle next to the executable. Estus looks in `../share/estus/bundle`, `../../_bundle` and `../_bundle`. |

## Build a bundle

You build on a machine with `ansible-core` 2.19 or later and the collections for
the modules you want. Older `ansible-core` releases fail, because the builder
copies a wrapper file that only exists from 2.19.

The project's `[ansible]` extra pins a tested pair, `ansible 14.4.0` and
`ansible-core 2.21.5`, and needs Python 3.12 or later. This recipe uses the same
pins:

```sh
uv venv --python 3.12 /opt/estus-ansible
uv pip install --python /opt/estus-ansible/bin/python ansible==14.4.0 ansible-core==2.21.5

estus bundle build \
  --python /opt/estus-ansible/bin/python \
  --collections-path /opt/estus-ansible/lib/python3.12/site-packages \
  --output /etc/estus/bundle
```

```json
{
  "ok": true,
  "ansible_core_version": "2.21.5",
  "target_python_floor": [3, 9],
  "bundle_sha256": "…",
  "modules": ["ansible.builtin.apt", "ansible.builtin.dnf", "ansible.builtin.dnf5", "ansible.builtin.package_facts", "ansible.builtin.stat", "community.general.apk", "community.general.pacman", "community.general.zypper"],
  "routers": ["ansible.builtin.dnf", "ansible.builtin.package"]
}
```

> **Note:** `--collections-path` is needed even though the `ansible` package
> installs the collections. The builder doesn't scan the environment it runs in,
> so you pass the directory that contains `ansible_collections/`. For the
> `ansible` package that is the environment's `site-packages`. Without it the
> build fails with `builder_failed`.

The default module set is `ansible.builtin.apt`, `dnf`, `dnf5`, `package_facts`
and `stat`, plus `community.general.apk`, `zypper` and `pacman`. Pass `--module`
to build a different set, for example to add a module for [your own
tool](ansible-tools.md).

The builder creates a new directory containing `bundle.json`, `wrapper.py` and
`modules/*.zip`. It installs nothing, refuses to overwrite an existing path, and
removes partial output on failure. Keep the whole directory together on the
machine running Estus.

| Build option | Use it to |
| --- | --- |
| `--python PATH` | Select the interpreter that has Ansible installed. Required; use an absolute path. |
| `--collections-path PATH` | Add a collections root. Repeat to add more than one. |
| `--module FQCN` | Replace the default module set with the modules you list. Repeat for each module. For example, a Debian/Ubuntu-only bundle can use `--module ansible.builtin.apt`. |
| `--output PATH` | Name the new bundle directory. Required. |
| `--timeout-secs N` | Set the build deadline in seconds (1–600; default 120). |

## Check a bundle

`bundle inspect` verifies the manifest, wrapper and module archives without
Python, Ansible or an SSH connection:

```sh
estus bundle inspect --bundle /etc/estus/bundle
```

```json
{"status": "passed", "ansible_core_version": "2.21.5", "module_count": 8, "bundle_sha256": "…"}
```

A failed inspection reports `error_code` and exits non-zero. To check the bundle
that Estus would actually use, run `doctor` with your config:

```sh
estus --config estus.toml doctor --runtime ansible
```

```json
{
  "ok": true,
  "ssh_executable": "/usr/bin/ssh",
  "targets": [],
  "runtime": {"status": "passed", "ansible_core_version": "2.21.5", "bundle_sha256": "…", "module_count": 8}
}
```

Both checks look at local files only. They don't test whether a target has the
right interpreter, package manager, dependencies or privileges.

## Select the bundle

Set the bundle path in the config Estus starts with:

```toml
# fragment
[automation]
bundle = "/etc/estus/bundle"
required = true
```

`required` defaults to `false`. Set it to `true` to require a valid bundle at
startup even if no enabled tool needs one. This setting does not enable tools.
Configure an [authority and its targets](configuration.md#automation-routes-automation) for any
selected tool that requires a named authority.

For each module-backed tool, Estus uses the first applicable reference:

1. `execution.bundle` on a tool definition you supply.
2. `bundle` on the tool's named authority under `[automation.authorities.<name>]`.
3. `[automation].bundle`.
4. `ESTUS_ANSIBLE_BUNDLE`.
5. A bundle installed next to the executable, in the order listed above.

Use absolute paths for explicit bundle settings. An invalid selected bundle is
an error, not a reason to try the next one. `bundle inspect` without `--bundle`
uses the global configuration or discovery, not a particular tool's authority.
To inspect a tool's override, pass its path explicitly.

## Route package operations

`preview_package` and `change_package` use a router. Estus detects the target's
package manager and dispatches to the corresponding backend in the active
bundle. The default build includes routes for apt, dnf, dnf5, apk, zypper and
pacman. Yum and DNF4 targets use the `dnf` route. A custom module list includes
only the routes for the backends you build. Use `preview_apt`/`change_apt` or
`preview_dnf`/`change_dnf` when you need manager-specific options.

Provision the package manager and a Python interpreter that meets the bundle's
`target_python_floor` (reported by `bundle build` and recorded in
`bundle.json`). The target does not need a separate Ansible installation. On
apt and dnf targets, install the distro's Python bindings for the appropriate
backend: `python3-apt`, `python3-dnf` or `python3-libdnf5`. Use a target
interpreter that can import them. Estus disables automatic dependency
installation for apt and dnf5.

## If a bundle is unavailable

| Symptom | What to check |
| --- | --- |
| `builder_failed` | Most often a missing `--collections-path`: the collections are installed but the builder isn't told where. Otherwise the selected Python needs `ansible-core` 2.19 or later and every requested module. |
| Startup rejects a bundle or module | Run `bundle inspect` on the selected path. Replace an incomplete or altered bundle with an intact build, and check that it includes the requested module. A selected module tool on configured targets needs a bundle even if `required` is `false`. |
| `module_not_in_bundle` | A tool names a module the bundle doesn't contain. Rebuild with `--module` for it. |
| Generic package call returns `unsupported` | No route matches the detected manager in the active bundle. Add the appropriate backend or use a supported target. Estus does not fall back to a shell command. |
| `dependency_unavailable` in the tool error's `reason` | Provision the missing package-manager dependency for the configured target Python. |

See [Troubleshooting](troubleshooting.md) for diagnosing target failures.
