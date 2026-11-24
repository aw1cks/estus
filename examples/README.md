# Examples

Use this index to pick a configuration or recipe to review before enabling a tool. A complete config is a standalone Estus TOML file, but you still need to provision any accounts, SSH aliases, helpers or bundles it refers to.

| Path | Demonstrates | Read next | Form |
| --- | --- | --- | --- |
| `dev-no-targets.toml` | Workstation mode with an empty target list, which rejects every remote call. `max_timeout_secs` must be at least 60 for the workstation catalog to load. | [Configuration](../docs/configuration.md) | Complete config |
| `automation_runtime.toml` | Requiring a verified offline Ansible bundle at startup without selecting any tools. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `automation_probe.toml` | Running the offline `ansible.builtin.ping` module with fixed `pong` data to check module execution on the target. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `observe_platform.toml` | Projecting two facts from `ansible.builtin.setup`, with fixed gather options and a bounded result. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `change_package.toml` | Installing, upgrading or removing packages using the target's detected package manager, with an optional version pin. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `change_apt.toml` | An apt-specific change with options such as `purge`, `allow_downgrade` and `update_cache`. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `change_dnf.toml` | A DNF-specific change with repository selection and solver options. | [Ansible bundles](../docs/ansible-bundles.md) | Complete config |
| `observe_account.toml` | Running a fixed `/usr/bin/id` command as the ordinary SSH account, with a literal account argument from an allowlist. | [Catalog](../docs/catalog.md) | Complete config |
| `observe_system.toml` | Reading the remote OS and UID with a fixed shell script that treats the caller's label as data. | [Catalog](../docs/catalog.md) | Complete config |
| `observe_root.toml` | Defining a fixed `/usr/bin/id -u --` observation through a separate sudo SSH identity. | [Policy](../docs/policy.md) | Complete config |
| `observe_controller.toml` | Defining a local controller tool with a private workspace, fixed Python interpreter and pinned source digest. | [Catalog](../docs/catalog.md) | Complete config |
| `observe_controller.py` | The companion script: read a label from a JSON input file and report local identity and scratch space. | [Security](../docs/security.md#out-of-scope) | Companion script |

## Workflows

| Path | Demonstrates | Read next | Form |
| --- | --- | --- | --- |
| `workflows/health.toml` | Selecting `observe_host_summary` for an SSH host observation, not an application health check. | [Catalog](../docs/catalog.md) | Recipe, not a config |
| `workflows/service-diagnosis.toml` | Inspecting systemd unit state as the ordinary identity, with a site-supplied unit allowlist. | [Catalog](../docs/catalog.md) | Recipe, not a config |
| `workflows/service-restart.toml` | Restarting an allowlisted systemd unit through a separate privileged catalog authority. | [Policy](../docs/policy.md) | Recipe, not a config |
| `workflows/config-replacement.toml` | Reading and replacing a configuration file through a dedicated chrooted SFTP account, without exec tools. | [Builtin tools](../docs/tools/builtin.md) | Complete config |

## Separate accounts

Use these files together, following the [deployment guide](../docs/deployment.md).

| Path | Demonstrates | Read next | Form |
| --- | --- | --- | --- |
| `separated-accounts/server.toml` | Selecting a fixed `record_identity` operation on one logical target. | [Deployment](../docs/deployment.md#set-up-the-service) | Complete Estus config |
| `separated-accounts/sshd_config` | Forcing stdio ingress and ruling out other SSH session features for the service account. | [Deployment](../docs/deployment.md#set-up-the-service) | OpenSSH daemon config fragment |
| `separated-accounts/outbound_ssh_config` | Pinning the outbound identity and trust file for unattended SSH to the target. | [Deployment](../docs/deployment.md#set-up-the-service) | Complete OpenSSH client config after setting the target address |
| `separated-accounts/estus-ingress` | Starting Estus through a fixed command with a cleared environment. | [Deployment](../docs/deployment.md#set-up-the-service) | Ingress script |
| `separated-accounts/estus-record-identity` | Writing the UID to a target-private file and returning it on stdout. | [Deployment](../docs/deployment.md#connect-the-client) | Target helper script |
