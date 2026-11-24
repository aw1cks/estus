# Security

Read this page before giving an agent access to hosts you care about. Estus is a policy and honesty layer between the agent and OpenSSH. It checks what the agent is allowed to request and reports when it cannot tell what happened. It is not a sandbox. Anything that can run as the same OS user as Estus can bypass it.

## Threats Estus accounts for

| Threat | What to expect |
| --- | --- |
| A confused or prompt-injected agent | Estus treats every tool call as independently subject to policy. An instruction in a log, file or web page does not grant permission. |
| A hostile or compromised target | A target can hang, lie or send malformed results. Estus rejects malformed structured output and reports execution evidence separately from output validation. A well-formed reply can still contain false data. |
| A broken or hostile network | OpenSSH authenticates the peer and protects traffic in transit. If a channel drops after dispatch, Estus does not assume the operation rolled back or automatically replay it. |

Treat any tool results quoted into the model's context as **untrusted input**, even when they appear in structured fields. Stdout, filenames and log entries can all contain instructions planted by the target. Estus marks several builtin tool definitions with `_meta.untrusted_remote_output`; the absence of that flag is not a trust signal. Output is evidence to weigh, not permission to take another action.

## What Estus enforces

- **Destination and tool policy.** In headless mode, only exact names in the configured target list authorize remote calls, even if OpenSSH knows other aliases. An empty list authorizes none. Capability ceilings limit which tools Estus can publish; a published tool still needs to pass policy for the requested target. See [policy](policy.md) for how selection, tiers, profiles and groups interact.
- **Validation before SSH dispatch.** Estus checks authorization and argument shape, then applies the route's cross-field rules, timeouts, byte caps and response budget before opening a remote channel for the requested operation. The target still supplies facts such as whether a file can be opened or a remote program exists.
- **Noninteractive sudo.** `exec_sudo` lets the caller request a run-as user and executable, but Estus checks the user against `sudo.users` and, when configured, the executable against `sudo.programs`. Estus picks the configured SSH route and constructs `sudo -n -k -u USER --` without a PTY. The target's sudo policy still applies. An executable allowlist does not restrict what an allowed program can do with its arguments.
- **Previews.** Where [preview policy](concepts.md#preview-before-change) applies, Estus refuses remote mutations without a qualified preview path, including the builtin file mutations and `exec_*` tools. A qualified change must match a recorded preview and a fresh pre-state check.
- **Write quarantine.** Estus gates further writes when it records an uncertain mutation. With `[quarantine].state_dir` configured, it flushes the local record and its directory before replying on the normal path and reloads records on startup. If persistence fails, the running process keeps the gate closed and logs `quarantine_persist_failed`; do not count on the record surviving a restart. This is the [quarantine gate](concepts.md#when-a-change-goes-wrong-uncertainty-and-quarantine), not a lock on the remote system or on other running sessions.
- **Execution metadata.** Catalog tool metadata names the executor, authority, execution location, effects and restriction boundary. It reports service-account separation as `operator_managed_not_observed`, not as a verified property.
- **Headless SSH trust settings.** Estus asks OpenSSH to require known host keys, suppress host-key updates and avoid adding keys to the agent. You supply the known-hosts trust roots and the credentials.

## Out of scope

- **Confining generic SSH or SFTP operations.** `exec_command` runs a shell on the target; `exec_argv` still goes through the target's login shell. SFTP tools take literal paths. There is no per-host pathname or argument allowlist for generic tools: comparing text before dispatch cannot account for how the target resolves symlinks, `..` or equivalent command spellings. Remove the generic capability or enforce the narrower boundary with the target account's OS permissions.
- **Same-user execution or a compromised operator.** Anyone who can run as the Estus service user can use its credentials or control sockets directly. Anyone who controls the binary, policy, SSH configuration, catalog, bundles or state directory can change what Estus does. Estus neither provisions nor verifies separate accounts.
- **Untrusted operator code.** Review controller scripts and SSH helpers as service-account code: they can access what that account can access. Review collectors and Ansible modules as code running under the chosen authority on their target. Output projections, `no_log` and cleanup do not confine code.
- **Credential management.** Estus delegates SSH authentication to OpenSSH. It does not provision private keys or agents, prompt for passwords or take authentication credentials as tool parameters.
- **Attestation.** Matching a collector's digest to its manifest detects drift between those files. It does not attest the manifest, the host, its software or the identity separation you configured.
- **Durability or transactions on the target.** Remote file writes are not flushed to durable storage by Estus. An atomic rename is not compare-and-swap. Estus does not roll back operations.

## Hardening checklist

- Use headless mode with explicit targets. Start with the narrowest catalog tools and disable generic file or command access unless you need it.
- If the agent can execute locally, follow the [separate-account deployment guide](deployment.md). Keep credentials, config, catalog exports, bundles, state and logs out of the client's write access, and keep the MCP stream away from processes that should not be able to send requests.
- Give the ordinary SSH account only the rights it needs. Where elevation is necessary, use a dedicated elevated identity instead of reusing the ordinary or your personal account.
- Require client approval for sensitive operations, especially a quarantine clear. Verify remote state independently before approving a clear or deciding whether to issue a new change.
