# Ansible bundles

Most catalog tools do not need an Ansible bundle. Use this guide if you enable
an Ansible-backed tool, such as `preview_package` or `change_package`; the
[catalog reference](tools/catalog-reference.md) marks the tools that need one.

## Build and inspect a bundle

Build on a machine with `ansible-core` and the collections for the modules you
want to use. Pick an absolute path to that environment's Python. The default
module set includes package backends from `community.general`, so pass a
collections root that contains `ansible_collections/community/general`.

```sh
estus bundle build \
  --python /opt/estus-ansible/bin/python \
  --collections-path /opt/ansible/collections \
  --output /etc/estus/bundle
estus bundle inspect --bundle /etc/estus/bundle
```

Choose an output path whose parent you can write to. The builder creates a
new directory containing `bundle.json`, `wrapper.py`, and `modules/*.zip`.
It installs nothing, refuses to overwrite an existing path, and removes
partial output on failure. Keep the whole directory together on the machine
running Estus.

| Build option | Use it to |
| --- | --- |
| `--python PATH` | Select the interpreter that already has Ansible installed. Required; use an absolute path. |
| `--collections-path PATH` | Add a collections root. Repeat to add more than one. |
| `--module FQCN` | Replace the default module set with the fully qualified modules you list. Repeat for each module. For example, a Debian/Ubuntu-only bundle can use `--module ansible.builtin.apt`. |
| `--output PATH` | Name the new bundle directory. Required. |
| `--timeout-secs N` | Set the build deadline in seconds (1–600; default 120). |

`bundle inspect` verifies the manifest, wrapper and module archives without
Python, Ansible or an SSH connection. It prints a JSON report with `status`;
on success it includes the core version, bundle hash and module count. A
failed inspection reports `error_code` and exits non-zero.

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
Configure an [authority and its targets](deployment.md) for any selected tool
that requires a named authority.

For each module-backed tool, Estus uses the first applicable reference:

1. `execution.bundle` on a tool definition you supply.
2. `bundle` on the tool's named authority under `[automation.authorities.<name>]`.
3. `[automation].bundle`.
4. `ESTUS_ANSIBLE_BUNDLE`.
5. An installed bundle relative to the executable, in order:
   `../share/estus/bundle`, `../../_bundle`, `../_bundle`.

Use absolute paths for explicit bundle settings. An invalid selected bundle
is an error, not a reason to try the next one. `bundle inspect` without
`--bundle` uses the global configuration or discovery, not a particular
tool's authority. To inspect a tool's override, pass its path explicitly.

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
| `builder_failed` | The selected Python must have a compatible `ansible-core` and be able to find every requested collection and module. |
| Startup rejects a bundle or module | Run `bundle inspect` on the selected path. Replace an incomplete or altered bundle with an intact build, and check that it includes the requested module. A selected module tool on configured targets needs a bundle even if `required` is `false`. |
| Generic package call returns `unsupported` | No route matches the detected manager in the active bundle. Add the appropriate backend or use a supported target. Estus does not fall back to a shell command. |
| `dependency_unavailable` in the tool error's `reason` | Provision the missing package-manager dependency for the configured target Python. |

A successful inspection checks local files, not whether a target has the
right interpreter, package manager, dependencies or privileges. See
[Troubleshooting](troubleshooting.md) for diagnosing target failures.
