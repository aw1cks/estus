# Threat model

One page: who the adversaries are, what Estus actually enforces, and what it
explicitly does not.

## Adversaries

1. **A confused or prompt-injected agent.** The model driving the MCP client can
   be talked into calling tools by hostile content it reads (logs, file bodies,
   web pages). Estus assumes tool calls may be arbitrary and adversarial *within
   the published surface*: it validates shapes and policy per call, never trusts
   caller intent, and never infers a safe successor action.
2. **A hostile or compromised target.** A remote host may lie, hang, return
   malformed collector output, refuse writes halfway, or drop the channel at the
   worst moment. Estus fails closed on malformed results, keeps execution evidence
   independent of result parsing, and records uncertainty instead of guessing.
3. **The network.** SSH transport may be interrupted. Estus never treats channel
   closure as proof of rollback, and never replays an interrupted mutation.

Not modelled: a same-UID local actor, a compromised operator account, or anyone
who can rewrite the configuration, the catalog, the bundle or the binary.

## What Estus enforces

- **Destination authority is structural.** A `[targets]` table — even an empty
  one — authorizes exactly the logical names it lists. Only exact configured
  names are accepted; backend aliases never grant authority. A headless
  configuration always has the table (an absent one is filled in as empty).
- **Capability ceilings.** `[capabilities]` (`named`, `file_read`, `file_write`,
  `exec`, `sudo`) decide which slices of the builtin surface are published at
  all. They are exposure switches, not presets.
- **Two-place permission.** For each `(host, tool)` pair, the global ceiling
  publishes the surface and the host's `[targets.<host>]` entry narrows it via
  `selection`, `max_tier`, `require_preview` and `sudo`. A site overlay
  `[tools.<name>]` supplies catalog domain policy.
- **Per-call validation before connecting.** Argument shape, cross-field rules,
  timeout bounds, byte caps and the full reply budget are checked before any SSH
  channel opens. Rejections carry fixed cause codes and never echo caller values.
- **Sudo is a fixed policy.** `exec_sudo` needs an operator-declared user and
  program allowlist on that target, runs `sudo -H -n -k` with no PTY, no password
  prompt, and no caller-selected user, program or executable.
- **Preview gating.** Under `require_preview`, a named `change`/`exec` binding that
  has a qualified preview pairing needs a prior `preview_*` matching target,
  authority, domain, arguments and independently observed pre-state; the preview is
  single-use and expires. A named binding with no pairing is refused outright, and
  the builtin `change_*`/`exec_*` tools are not gated at all.
- **Write quarantine.** Any mutation whose acknowledgement is lost sets
  `remote_state_unknown=true` and blocks further writes on that logical target
  until an operator asserts reconciliation via `change_target_quarantine_clear`.
  With `[quarantine].state_dir` set the record is `fsync`ed before that reply is
  returned and reloaded on restart, so the block outlives one process lifetime. It
  is a gate, not an isolation boundary: whoever can remove the record or start the
  server against an empty directory regains write access.
- **No replay, no rollback.** Interrupted work is never retried, undone or
  inferred complete.
- **Metadata honesty.** Every catalog tool publishes its executor, authority,
  execution location, effects and `restriction_boundary`. Service-account
  separation is reported as `operator_managed_not_observed`.

## What Estus explicitly does not do

- **It is not a sandbox.** `exec_command` runs arbitrary shell on the target,
  `exec_argv` still goes through the remote login shell, and the SFTP tools take
  literal caller paths with no path jail. Working directories, environment and
  filesystem permissions are the remote account's.
- **No per-host argument filtering for generic tools.** `inspect_file`,
  `change_file_write`, `exec_command` and friends accept whatever the caller
  sends on any host whose ceiling and tier permit them. A pathname or command
  boundary is an OS boundary; a pre-dispatch allowlist over the raw argument map
  cannot be one (no canonicalisation, no `..`/symlink resolution, equivalent
  spellings), which is why there is no such layer. Use `sudo.programs`, a
  capability ceiling that removes the tool, and the account's own permissions.
- **A same-UID local actor is out of scope.** A client with arbitrary execution
  under the service account can read its credentials, reuse its SSH control
  sockets, and run remote commands without MCP. No tool-level control changes
  that.
- **Trusted operator code is trusted.** Ansible modules, native payload
  collectors and controller scripts run with the service account's access,
  including access to its credentials. `no_log`, projections and process cleanup
  reduce disclosure; they do not sandbox that code.
- **No credential management.** Estus loads no keys, creates no agents, prompts
  for no passwords and accepts no key or password material as tool input. Host-key
  policy, `IdentityFile`/`IdentityAgent` and agent sockets come from OpenSSH
  configuration the operator supplies.
- **No attestation.** Collector-integrity checks catch accidental drift between
  a collector and its manifest. Anyone able to rewrite both files can also
  replace the binary.
- **No durability or transactional guarantee.** Writes are not fsynced, renames
  are not compare-and-swap, and no operation is rolled back.
- **No production account provisioning.** Estus neither creates nor verifies
  account separation.

## Deployment separation advice

When the agent also has local execution, run the server as a **different**
account from the client:

- private service credentials and runtime directories, unreadable by the client;
- a root-owned, forced-command stdio ingress for the MCP pipe;
- no client shell, sudo, shared privileged groups, or host/container admin on the
  service account;
- a dedicated SSH identity (and, where elevation is needed, a separate
  `separate-identity` sudo alias) rather than the operator's personal one.

[`examples/separated-accounts/`](../examples/separated-accounts/) is a concrete
sketch — an ingress wrapper, `sshd_config`, an `outbound_ssh_config` and a site
TOML — not a production daemon or container requirement.

Keep the configuration, catalog exports, bundle packs and logs in directories the
client cannot write. Transport the MCP pipe over something the client cannot
inject into, and treat every tool result quoted into the model's context as
untrusted input for the next call.
