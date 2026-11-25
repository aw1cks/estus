# Troubleshooting

Use this guide when your MCP client cannot start Estus, a target cannot be reached, or a tool call returns an error.

## Estus fails to start

If OMP or another client reports EOF without showing subprocess stderr, run the **same executable and arguments** in a terminal. Use the same OS account, working directory, and relevant environment as the client so you can see the actual startup error.

```sh
estus --version
estus --config ./estus.toml
```

Replace the example command with the one in your client configuration. A healthy stdio server can sit silently while waiting for an MCP handshake; press Ctrl-C to stop the manual run. If it exits, check stderr for `code`, `phase`, `schema_path`, and any line and column. Check executable and config paths first. Estus does not search for a config file on its own. See [client setup](clients.md) and [configuration](configuration.md).

## SSH or SFTP fails

Run `doctor` with the same Estus config and the **logical target name**, not the backend hostname:

```sh
estus --config ./estus.toml doctor --target web-1
```

Read `targets[].ssh` first, then `targets[].sftp`. Each can be `passed`, `failed`, or `not_tested`. `doctor` connects as the ordinary SSH identity and probes SFTP negotiation without executing a remote command or testing sudo. Repeat `--target` for more hosts. `--timeout-secs` sets the deadline for the whole run. Exit `0` means the requested checks passed, `1` means a check or reporting failed, and `2` means invalid invocation or config.

- **SSH failed:** Check which `ssh` executable the client uses, the target's `ssh_host` alias, authentication, jump host, and known-host entries. Reproduce with `ssh -vv -o BatchMode=yes -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o AddKeysToAgent=no -N -T -- web-1`, replacing `web-1` with the actual `ssh_host`. If Estus uses a replacement SSH config, add `-F` with that same file. Verify the host key before provisioning it; an interactive password prompt is not a working Estus credential. This command opens an SSH connection without starting a remote shell; stop it with Ctrl-C after reading the diagnostics.
- **SSH passed, SFTP failed:** Check whether the SSH server offers the SFTP subsystem to that identity. A successful SFTP negotiation does not prove that a particular path is accessible or that the server supports POSIX rename.
- **Both passed, a catalog tool still fails:** Check the tool's prerequisites and the identity it actually uses in the [catalog reference](tools/catalog-reference.md). `doctor` does not exercise a separate automation or sudo route. To check the configured Ansible bundle locally, run `estus --config ./estus.toml doctor --runtime ansible`.

If present, `effective_ssh_policy` is what `ssh -G` reports from the SSH config, not the flags Estus adds to the probe. `ssh -G` can run local `Match exec` directives; use a trusted SSH config.

## A tool is missing or denied

Check policy before changing SSH settings. Use the same config and mode as the server:

```sh
estus --config ./estus.toml auth explain web-1
estus --config ./estus.toml auth can-i inspect_file web-1
```

`explain` shows which groups and profiles matched, the effective tier, capabilities, and preview rule. `can-i` checks one tool for that target: exit `0` means authorized, `1` means denied, and `2` means a CLI or configuration error. Add `--json` for structured output. These are offline policy checks, not tests of arguments, active previews, live quarantine, connectivity, or target support. If the client still cannot see the tool, compare its running configuration and `tools/list` with the CLI invocation. See [policy](policy.md).

## A write timed out or lost its reply

Check `error.remote_state_unknown` when a reply exists. If it is `true`, or if you lost the reply, inspect the actual target before you issue another mutation. Follow the [quarantine procedure](concepts.md#when-a-change-goes-wrong-uncertainty-and-quarantine). `doctor` cannot clear a running session's quarantine.

## Error codes

Look at where the error appeared. [Tool results](tools/results.md#tell-a-protocol-error-from-a-tool-error) explain the difference between the reply envelope, JSON-RPC errors, and optional payload reasons. If remote state is uncertain, that takes precedence over the action in any row below.

### Tool errors

| `error.code` | Cause | What to do |
| --- | --- | --- |
| `already_exists` | The SFTP destination already exists. | Inspect the entry, then choose a new path or an explicitly approved overwrite where supported. |
| `automation_failed` | An Ansible module reported failure or returned nonzero. | Read the execution evidence, then check target state and the module prerequisites. |
| `cancelled` | The request was cancelled or the server began shutting down. | Check the result for uncertainty and confirm why the client cancelled. |
| `checksum_mismatch` | Returned bytes did not match the expected digest. | Check the source and use the digest for the exact requested byte range. |
| `cleanup_incomplete` | Local controller process cleanup could not be confirmed. | Check the controller and its owned processes before running more work. |
| `command_failed` | A command exited nonzero. | Read the exit code and bounded stderr; verify the executable and arguments. |
| `connection_lost` | The SSH master or an active channel became unavailable. | Run `doctor`; for a mutation, reconcile before doing anything else. |
| `controller_resource_limit` | Controller resource-limit code reserved by the reply budget. | Review controller input/output bounds if reported. |
| `invalid_argument` | A value, combination, or byte bound failed validation. | Read the message and compare the arguments with the published schema and configured limits. |
| `invalid_encoding` | Input is not valid base64, or returned bytes are not complete UTF-8. | Send valid padded base64; for binary reads or split characters, request `base64`. |
| `invalid_projection` | The executor's output cannot be decoded or does not fit the approved projection contract. | Check `schema_path` and `constraint` if present; compare the collector/module and projection versions. Preserve any execution evidence. |
| `invalid_result` | Estus could not validate execution evidence or a worker's terminal reply. | Check version and runtime compatibility; check the host before repeating a mutation. |
| `io_error` | A worker, channel, SFTP operation, retained-output read, or local state file failed. | Use `message` to locate the failing step. Check paths, permissions, storage, or SSH as applicable. |
| `not_found` | A remote entry is missing, or a retained-output handle is unknown, expired, or belongs to another session. | Verify the literal path or use a valid handle from this session. |
| `payload_failed` | A native collector or module operation ran and failed. | Read the optional `reason` below, and check the target and prerequisites. |
| `payload_rejected` | The target bootstrap rejected the request frame or source before running the payload. | Check that the client-side Estus binary and payload assets belong to the same release. |
| `permission_denied` | The backend refused access. | Check the actual execution identity and target permissions. |
| `policy_denied` | The request is not authorized by Estus. | Run `auth explain` and `auth can-i`; check target selection, capabilities, tier, and relevant tool constraints. |
| `preview_required` | There is no usable matching preview, or the operation has no qualified preview. | Run the matching preview with the intended arguments. If there is no pairing, choose a previewable operation or review the policy with the operator. |
| `resource_limit` | A byte, worker, connection, or other capacity limit was reached. | Narrow the request, reduce concurrency, or review the applicable limit. |
| `resource_unavailable` | A required runtime, approved interpreter, command, or target subsystem could not be used. | Check the message and provision or repair the dependency under the intended identity. |
| `shutdown` | The server stopped a local retained-output read. | Reconnect if needed; handles do not carry over into a new session. |
| `spawn_failed` | A local controller child could not start. | Check the local executable, permissions, and runtime. |
| `ssh_connect_failed` | OpenSSH did not establish a connection. | Follow the SSH diagnostic steps above. |
| `ssh_spawn_failed` | The local SSH process or its workspace could not start. | Check the configured SSH executable, local process limits, and writable runtime directory. |
| `target_quarantined` | An earlier operation left the target's state uncertain. | Inspect and reconcile the target independently before clearing the gate. |
| `timeout` | A request or one of its stages exceeded its deadline. | Identify the slow stage; narrow the request or adjust the deadline within policy. Check for uncertainty first. |
| `unsupported` | The operation needs a feature the backend does not offer, or the requested variant is unsupported. | Check the tool's prerequisites. For SFTP rename or replace, check the server's POSIX rename extension. |

### Payload failure reasons

These are values of `error.reason`, not separate top-level tool codes. A dependency that fails a preflight check before the payload runs can instead produce `resource_unavailable`.

| `error.reason` | Cause | What to do |
| --- | --- | --- |
| `dependency_unavailable` | A required target utility, module, or subsystem is missing or failed. | Check the tool's target prerequisites, such as the package manager's Python bindings. |
| `output_bound_exceeded` | The collector source or output exceeded a safety bound. | Request a smaller range, page, or scope if the tool allows it. |
| `permission_denied` | The payload could not access a target resource. | Check permissions under its execution identity. |
| `policy_violation` | Input violates the collector's reviewed policy. | Compare the input and target constraints with the tool reference. |
| `precondition_failed` | Required target state was absent or changed. | Observe the current state and update the plan. |
| `target_not_found` | The requested resource does not exist on the target. | Verify its name or ID on that target. |
| `timeout` | A subprocess used by the collector timed out. | Check the slow subsystem before changing scope or deadlines. |
| `unsupported_platform` | The operation is not supported on that platform. | Use a tool that supports that target, or choose a different target. |
| `verification_failed` | The payload's post-change check failed. | Inspect the actual resulting state before taking further action. |

### MCP and operator diagnostics

| Code | Cause | What to do |
| --- | --- | --- |
| `-32601` | The server does not implement the requested MCP method. | Check the method name and the server capabilities announced at initialization. |
| `-32602` | Invalid JSON-RPC parameters, unknown tool or prompt, or a request that leaves insufficient reply budget. `argument_shape` is a phase, not a code. | Check `tools/list`, `prompts/list`, and the request parameters. Use a short request ID and smaller bounded reads where needed. |
| `-32002` | MCP resource not found. | Check the URI and configured target in `resources/list` or `resources/templates/list`. |
| `-32000` | The MCP session has reached concurrent-request capacity. | Drain replies and submit fewer concurrent requests. |
| `-32603` | An internal server error prevented an MCP reply from being built. | Record the method, Estus version, and sanitized diagnostics; report a reproducible failure. |
| `mcp_session_overloaded` | Estus closed the session due to reply backpressure, capacity, or a duplicate live request ID. | Drain stdout continuously, lower concurrency, and use unique IDs. Check unfinished changes before reconnecting. |
| `mcp_initialize_failed`, `mcp_session_failed`, `mcp_shutdown_failed` | The handshake, session, or shutdown failed. | Run Estus directly to see stderr, check the client's stdio configuration, and report persistent failures with versions and sanitized logs. |
| `invalid_cli_arguments` | Estus could not parse the command line. | Compare the invocation with `estus --help` or the subcommand's `--help`. |
| `invalid_toml`, `invalid_config` | The file cannot be parsed or the configuration is invalid. | Use `schema_path` and any line and column in the stderr record to locate the problem. |
| `runtime_start_failed`, `signal_setup_failed` | The local runtime or signal handling could not start. | Check local process limits and the launch environment. |
| `invalid_target_selection`, `invalid_timeout` | `doctor` was given invalid or duplicate targets, no target/runtime, too many targets, or a timeout outside its bounds. | Select configured logical targets or an explicit runtime, and use a timeout within configured limits. |
| `diagnostic_report_limit`, `doctor_output_failed` | `doctor` could not fit or publish the report. | Check fewer targets per run and make sure stdout is being drained. |
| `manifest_schema`, `manifest_constraints`, `source_bounds`, `source_digest` | A native payload manifest or its collector source failed validation. | Check the manifest and collector together. For bundled assets, reinstall a matching release rather than editing the digest. |
| `unsupported_module_contract`, `invalid_binding_schema`, `invalid_binding_arguments` | A configured tool's contract, input mapping, or fixed arguments cannot be compiled. | Review the tool definition and site policy against the approved backend schema. |
| `runtime_unavailable` | The selected Ansible runtime bundle could not be resolved. | Check the configured or installed bundle; see [Ansible bundles](ansible-bundles.md). |
| `bundle_unavailable`, `invalid_bundle_entry`, `bundle_size_exceeded` | A bundle file is unreadable, is not a regular file, or exceeds a size bound. | Check the pack path and file permissions or rebuild the pack. |
| `bundle_digest_mismatch`, `bundle_wrapper_drift`, `bundle_archive_drift` | The manifest, wrapper, or module archive does not match its recorded size or digest. | Replace or rebuild the complete verified pack. |
| `invalid_bundle_manifest`, `invalid_bundle_module`, `unsupported_bundle_module_contract`, `invalid_bundle_router`, `invalid_bundle_router_target`, `module_not_in_bundle` | The pack has invalid metadata, an unsupported contract, or cannot provide the requested module. | Inspect the pack and rebuild it with the required modules for your release. |
| `invalid_python_executable`, `builder_failed`, `bundle_output_exists`, `bundle_output_unavailable`, `bundle_builder_write_failed` | The offline bundle builder could not start or could not build into the requested output. | Check the absolute Python path and builder prerequisites; use a new output directory whose parent exists and is writable. For `builder_failed`, read the report's `detail` for the builder's own message. It usually means a missing `--collections-path` or an `ansible-core` older than 2.19; see [Ansible bundles](ansible-bundles.md#build-a-bundle). |
| `catalog_option_not_applicable` | An offline catalog command was given `--config`, `--ssh` or `--ssh-config`, or `install` was given `--root`. | Remove the option. `install` takes `--dir` instead of `--root`. |
| `catalog_tool_unknown`, `catalog_tool_unknown_or_duplicate`, `catalog_preset_unknown`, `catalog_preset_duplicate`, `catalog_selection_limit` | The catalog selection is unknown, duplicated, or too large. | Compare names with `estus catalog list`; deduplicate or narrow the selection. |
| `catalog_unavailable`, `catalog_missing_asset`, `catalog_asset_unreadable`, `catalog_asset_oversized`, `catalog_asset_malformed`, `catalog_path_unsafe`, `catalog_asset_unsupported`, `catalog_manifest_invalid`, `catalog_definition_invalid` | The catalog or an asset failed to load or validate. `catalog_path_unsafe` also means `export` was given an output path that passes through a symlink, or `install` a target that is one. | Check the selected catalog directory and restore the complete asset set for your release. For a symlinked path, use the real one: on macOS `$TMPDIR` sits under the `/var` symlink, so resolve it with `cd "$TMPDIR" && pwd -P`. |
| `catalog_not_installed` | No catalog was found: no `--root` or `[catalog].root`, no `ESTUS_CATALOG_ROOT`, and none next to the executable. | Run `estus catalog install`. See [install the catalog](catalog.md#install-the-catalog). |
| `catalog_install_exists` | `estus catalog install` found a different catalog at the target and will not overwrite it. | Check what is there, then run `estus catalog install --replace` to replace it. |
| `catalog_install_unavailable`, `catalog_install_dir_unknown` | The target directory could not be created or written, or Estus could not work out where its executable lives. | Check permissions on the parent directory, or pass `--dir`. |
| `catalog_definition_override_not_site_policy`, `catalog_definition_requires_site_policy`, `catalog_definition_requires_targets` | A catalog definition needs different site policy or explicit targets. | Review the tool's [catalog configuration](catalog.md). |
| `catalog_output_invalid`, `catalog_output_unavailable`, `catalog_output_exists_or_unavailable` | A catalog command could not format or write its output. | Check the destination and permissions; export to a new directory. |
| `master_close_failed`, `master_kill_failed`, `master_reap_failed`, `master_drain_failed`, `master_socket_cleanup_failed` | Local OpenSSH master cleanup failed. | Check for leftover SSH processes and control sockets under the service account. Keep the sanitized diagnostics if it recurs. |
| `master_session_ownership_mismatch`, `master_child_ownership_mismatch`, `master_entry_ownership_mismatch`, `master_finalizer_ownership_mismatch`, `master_finalization_interrupted`, `master_supervisor_panicked` | Estus could not account for all resources of an OpenSSH master. | Check the controller for leftover resources and report the error with version and sanitized logs. |
