# Tools

Behaviour of the fifteen builtin tools, plus the cross-cutting semantics that
apply to every tool: result envelope, output handles, progress, cancellation and
the write quarantine.

## Result envelope

Every tool returns the standard `ToolReply`: `ok`, `data` (tool-specific) and
`error` (fixed `code`, `phase`, `message`, `remote_state_unknown`). Execution
evidence — `status`, `complete`, `changed`, `uncertainty`, cleanup — stays
independent of result parsing, so a malformed or censored projection never erases
the fact that work ran.

Input-shape violations are protocol errors carrying a fixed `argument_shape`
diagnostic; shape-valid calls that violate reviewed bounds or choices are tool
errors produced before dispatch. Rejections never echo caller values, paths,
unknown keys or backend stderr.

## Files and SFTP

All seven file tools use an independently owned ordinary-identity SFTP channel.
Paths are literal UTF-8 — no shell, tilde, environment or wildcard expansion and
no path sandbox — and intermediate symlinks follow server semantics. None of them
retries, replays or rolls back.

| Tool | Tier | Behaviour |
| --- | --- | --- |
| `inspect_file` | inspect | Reads a bounded range. Strict UTF-8 (including split codepoints) or padded lossless base64. `content_sha256` covers returned raw bytes; optional `expected_content_sha256` mismatch returns `checksum_mismatch` without content. Verifies only that range. |
| `observe_stat` | observe | `lstat` by default, so a final symlink is reported itself; `follow_symlinks=true` queries its target. Missing attributes stay null, missing type is unknown, permissions contain only mode bits. |
| `inspect_directory` | inspect | One bounded page per call, `max_entries` 1–1000 (default 200). Server order, no dot entries, no per-entry symlink following. `name_base64` preserves raw filename bytes; `name` is null for non-UTF-8 names. `truncated=true` means more entries existed. |
| `change_file_write` | change | Exclusive create by default, refusing an existing destination including symlinks. `overwrite=true` truncates and follows server symlinks. Success needs write and close acknowledgements — not atomicity, not fsync. |
| `change_file_replace` | change | Requires `overwrite=true` and advertised POSIX rename. Stages one random EXCL-created mode-0600 sibling in the original OPEN, confirms permissions by handle, completes the write and CLOSE, then renames over the destination. Atomic visibility only. |
| `change_mkdir` | change | Creates one directory; parents must exist. Any entry observed at the path, including a final symlink, is `already_exists`. |
| `change_rename` | change | `overwrite` defaults to false and returns `unsupported` without mutating, because SFTP v3 cannot guarantee atomic no-overwrite rename. Explicit `true` needs `posix-rename@openssh.com`. A final source symlink moves; its target does not. |
| `change_file_remove` | change | Unlinks one file or final symlink entry. Directories and missing paths are backend errors; no recursion, no `missing_ok`, not secure erasure. |
| `change_directory_remove` | change | One RMDIR; the server enforces emptiness. Non-empty directories, files and missing entries are backend errors. |

`change_file_replace` may leave `.estus-replace-*` siblings after an uncertain
OPEN, cancellation or lost rename acknowledgement: review them out of band rather
than retrying or sweeping names automatically.

## Generic execution

| Tool | Tier | Behaviour |
| --- | --- | --- |
| `exec_command` | exec | Stateless noninteractive remote shell script (`/bin/sh`; Bash is opt-in). Escaped command ≤ 65536 bytes. |
| `exec_argv` | exec | Explicit argv on the ordinary identity, optional absolute cwd and bounded stdin. Boundaries are preserved through POSIX `--`, but the remote login shell still participates — use an absolute path to pin the executable, or `exec_command` for shell syntax. |
| `exec_sudo` | exec | An authorized absolute executable via `sudo -H -n -k` under the target's declared user/program policy. No password, PTY, environment preservation or retry; password-required sudo fails noninteractively. |

Output may be truncated to fit the fixed 16 MiB reply budget, stdout before
stderr. Timeout or cancellation closes only that channel: remote work may
continue, and nothing is replayed. Ordinary shell authority can bypass
same-account sudo separation, which is why the recommended deployment uses a
separate SSH identity for elevation.

## Discovery

`observe_targets` returns configured logical targets with public advisory
descriptions/labels, startup-permitted operations and resolved policy limits. It
connects to nothing and probes nothing, so permitted operations do not imply
remote support. Open (workstation) mode returns no inventory and never enumerates
SSH configuration; backend aliases, credential paths and authentication state are
never returned.

## Output handles

Native shell/argv/sudo commands and configured native/remote/controller scripts
accept `retain_output=true`. Execution stays synchronous; retention is opt-in and
automation module/payload requests reject the control.

```json
{"host":"server","argv":["/usr/bin/printf","diagnostic output\n"],"retain_output":true}
```

The result's `output.status` is `ready` (with an opaque `handle`, expiry,
per-stream `bytes_retained`/`total_bytes` and `truncated`) or `unavailable` (a
fixed local reason that does not change the command's exit, termination, signal,
uncertainty or cleanup evidence). Disabled or quota-exhausted retention still runs
and drains the command.

`inspect_output(handle, stream, offset, max_bytes, encoding)` reads strict UTF-8
or padded lossless base64 plus the SHA-256 of the returned raw range. It is local
and hostless: no SSH, no caller pathname, handles are session-scoped capabilities,
and expired/foreign/unknown handles return `not_found` without disclosing
secrets. `eof` is the end of the retained prefix, not proof the stream was
complete. Handles, output bytes and paths are excluded from audit records.

Configured by `[output]` (see [configuration.md](configuration.md)); per-stream
limit 1 byte–4 MiB, aggregate ≤ 64 MiB, 1–64 handles, expiry 1–3600 s. Prefixes are
kept in memory while streams drain; publication writes mode-0600 files into
mode-0700 request-owned directories with a 250 ms finalization grace.

## Progress

Include `_meta.progressToken` in `tools/call` parameters to request advisory
`notifications/progress` updates; without a token there are none. Tokens are
unique strings or integers across active requests.

Native/controller commands report actual stdout+stderr bytes drained (including
bytes dropped beyond capture limits); SFTP reports channel, handshake and
acknowledgement milestones; module execution reports only validated
started/ready/task observations. Values increase, unknown totals are omitted, and
fast operations may finish without an update. Updates coalesce to one snapshot
per request at most four times a second, with at most 16 active reporters and
256-byte tokens. Over-limit, duplicate or invalid tokens simply get no progress;
execution and final results are unchanged. Tokens never enter audit or results.

Up to 64 requests run concurrently. Beyond that, each extra request gets a
JSON-RPC `-32000` busy error without dropping the session; a blocked `stdout`
with more than 16 unread replies (or a duplicate live request ID) terminates the
session as `mcp_session_overloaded`.

## Quarantine and uncertainty

`remote_state_unknown=true` means the operation was dispatched and its
acknowledgement or owner was lost: server refusal, timeout, cleanup failure or
cancellation after the mutating request. It never means "succeeded" or "failed
cleanly", and channel closure never proves rollback.

An uncertain mutation quarantines writes on that logical host. Subsequent write
calls fail with `target_quarantined`; read, observe, inspect and preview tools stay
open so the real state can be examined (`observe_stat`, `inspect_file`,
`observe_systemd_unit`, `inspect_journal`). With `[quarantine].state_dir` the record
is written, `fsync`ed and atomically renamed into place before the reporting reply
is returned, and reloaded on the next start, so the quarantine outlives the process;
without it the gate lasts only for the session.

`change_target_quarantine_clear` requires `host` and
`acknowledge_remote_state_reconciled=true`; the flag is an operator assertion of
independent reconciliation, not proof that remote work stopped. Only a running
server clears its own gate, so `estus doctor` — a separate process — cannot; a
durable record it cannot unlink makes the clear fail rather than report success.
Clearing an unknown or non-quarantined target returns a bounded no-change result
without probing.

## Guidance surfaces

The server publishes MCP prompts `triage_host`, `diagnose_service`,
`safe_change` and `network_triage`, and resources `estus://guides/systemd`,
`estus://guides/linux-memory`, `estus://guides/networking`,
`estus://guides/preview`, `estus://guides/uncertainty-reconciliation` and
`estus://targets/{host}/policy`. They restate the tier, preview and quarantine
rules above and name only tools the current configuration actually publishes.
