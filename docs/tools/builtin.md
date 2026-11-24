# Builtin tools

Use this reference to choose a builtin tool and construct its MCP arguments. Prefer a [catalog tool](../catalog.md) when one covers the job.

## Find a target

**`observe_targets` · `observe`** — Lists configured targets, their advisory descriptions and labels, permitted operations, and policy limits. Takes no arguments. It makes no SSH connection: permission to call a tool is not evidence that the host supports it. In open mode it returns an empty target list rather than enumerating your SSH config.

```json
{}
```

Use the logical target name for `host` in the examples below. `tools/list` shows the tools and input schemas your server actually publishes. For any tool that accepts `timeout_secs`, omitting it uses the configured operation timeout (normally 60 seconds); overrides must be positive and within the configured maximum (normally 600 seconds).

With [`require_preview`](../policy.md#preview-gating) enabled, Estus refuses builtin remote writes and commands: they have no matching preview.

## Files over SFTP

These tools use the ordinary SSH identity. Paths are nonempty, NUL-free UTF-8 strings. Estus passes them literally: no `~`, environment variables, or wildcard expansion. Intermediate symlinks resolve according to the SFTP server. See the [security boundary](../security.md) and [preview policy](../policy.md) before enabling writes.

| Tool | Tier | Required arguments | Optional arguments |
| --- | --- | --- | --- |
| `observe_stat` | `observe` | `host`, `path` | `follow_symlinks` (default `false`), `timeout_secs` |
| `inspect_file` | `inspect` | `host`, `path` | `offset` (bytes, default `0`), `max_bytes`, `encoding`, `expected_content_sha256`, `timeout_secs` |
| `inspect_directory` | `inspect` | `host`, `path` | `max_entries` (1–1000, default `200`), `timeout_secs` |
| `change_file_write` | `change` | `host`, `path`, `content` | `overwrite` (default `false`), `encoding`, `timeout_secs` |
| `change_file_replace` | `change` | `host`, `path`, `content`, `overwrite: true` | `encoding`, `timeout_secs` |
| `change_mkdir` | `change` | `host`, `path` | `timeout_secs` |
| `change_rename` | `change` | `host`, `source`, `destination`, `overwrite: true` | `timeout_secs` |
| `change_file_remove` | `change` | `host`, `path` | `timeout_secs` |
| `change_directory_remove` | `change` | `host`, `path` | `timeout_secs` |

`encoding` is `utf8` by default or `base64` for padded, lossless bytes. The file byte limit applies to decoded write content. A bounded read defaults to 65,536 bytes or the configured file limit, whichever is smaller. Request fewer bytes if the encoded read would exceed the reply budget.

### Read files and metadata

**`observe_stat`** returns metadata rather than file contents. By default it reports a final symlink itself (`lstat`); use `follow_symlinks: true` for its target. Missing attributes are `null`; an unknown type is `unknown`. `permissions` contains only the permission and special mode bits.

```json
{"host":"web-1","path":"/etc/resolv.conf","follow_symlinks":true}
```

**`inspect_file`** reads a byte range. Use `next_offset` for the next range. Strict `utf8` rejects even a valid character split across two reads; use `base64` for arbitrary byte boundaries. `content_sha256` hashes the raw bytes of this range, not the whole file. Pass `expected_content_sha256` (64 hex digits) to check the range; a mismatch returns `checksum_mismatch` without the content.

```json
{"host":"web-1","path":"/etc/os-release","max_bytes":4096}
```

**`inspect_directory`** returns a prefix in server order, omitting `.` and `..`, without following individual entries' symlinks. Read `name_base64` for the exact name bytes; `name` is `null` for non-UTF-8 names. `truncated: true` means more entries existed. You can ask for a larger prefix, but there is no continuation cursor and repeated calls are not a snapshot.

```json
{"host":"web-1","path":"/var/log","max_entries":50}
```

### Write, move, and remove files

**`change_mkdir`** creates one directory. The parent must exist. An entry already at the path, including a final symlink, returns `already_exists` when detected.

```json
{"host":"web-1","path":"/var/tmp/estus-triage"}
```

**`change_file_write`** creates a file exclusively by default. `overwrite: true` opens the destination for truncation and follows a final symlink. The write is not atomic; acknowledgement of write and close is not an `fsync` guarantee.

```json
{"host":"web-1","path":"/var/tmp/estus-triage/notes.txt","content":"Review service logs.\n"}
```

**`change_file_replace`** stages a new mode-`0600` sibling, writes and closes it, then atomically renames it over the destination. The server must advertise `posix-rename@openssh.com`. A final destination symlink is replaced, not followed. This gives atomic visibility, not durability or preservation of the old file's metadata. Cancellation or a lost acknowledgement can leave `.estus-replace-*` siblings; inspect them out of band rather than retrying or sweeping them by name.

```json
{"host":"web-1","path":"/var/tmp/estus-triage/notes.txt","content":"Reviewed service logs.\n","overwrite":true}
```

**`change_rename`** moves one entry using the same POSIX rename extension. It requires explicit consent to overwrite because the backend cannot guarantee atomic no-overwrite rename. A final source symlink moves as a link, not as its target.

```json
{"host":"web-1","source":"/var/tmp/estus-triage/notes.txt","destination":"/var/tmp/estus-triage/reviewed.txt","overwrite":true}
```

**`change_file_remove`** unlinks one file or final symlink. It reports errors for directories and missing entries. Unlinking does not securely erase file contents.

```json
{"host":"web-1","path":"/var/tmp/estus-triage/reviewed.txt"}
```

**`change_directory_remove`** removes one empty directory. It does not recurse; a missing path, a file, or a nonempty directory is an error.

```json
{"host":"web-1","path":"/var/tmp/estus-triage"}
```

### Clear a write quarantine

**`change_target_quarantine_clear` · `change`** — Requires `host` and `acknowledge_remote_state_reconciled: true`; no optional arguments. Call it only after [independent reconciliation](../concepts.md#when-a-change-goes-wrong-uncertainty-and-quarantine). It makes no SSH connection. `cleared: false` and `was_quarantined: false` mean there was no gate to remove. If Estus cannot remove the durable record, it reports an error instead of clearing the gate.

```json
{"host":"web-1","acknowledge_remote_state_reconciled":true}
```

## Run a command

| Tool | Tier | Required arguments | Optional arguments |
| --- | --- | --- | --- |
| `exec_command` | `exec` | `host`, `command` | `shell` (`sh` by default, or `bash`), `cwd`, `stdin`, `timeout_secs`, `retain_output` (default `false`) |
| `exec_argv` | `exec` | `host`, `argv` | `cwd`, `stdin`, `timeout_secs`, `retain_output` (default `false`) |
| `exec_sudo` | `exec` | `host`, `argv` | `user` (default `root`), `stdin`, `timeout_secs`, `retain_output` (default `false`) |

`cwd` must be absolute. `stdin` is a string limited by `max_stdin_bytes`. The encoded remote command, including quoting and any wrapper, cannot exceed 65,536 bytes. Inline output is bounded by the configured capture limit and the fixed 16 MiB MCP reply budget. If the reply budget forces a cut, Estus fits a stdout prefix first, then stderr. Check the truncation flags or [request retained output](results.md#read-retained-output). A timeout or cancellation can leave remote work running.

**`exec_command`** runs a fresh, noninteractive script on the ordinary SSH identity. Use it when you need shell syntax. The default shell is `/bin/sh`; `shell: "bash"` asks for Bash on the remote host.

```json
{"host":"web-1","command":"df -h /var; uptime","timeout_secs":15}
```

**`exec_argv`** takes a nonempty array with the executable first. Estus preserves argument boundaries, but OpenSSH still invokes the remote login shell. Use an absolute path to select the executable without a `PATH` lookup; use `exec_command` for pipelines or redirects.

```json
{"host":"web-1","argv":["/usr/bin/journalctl","--unit=nginx.service","--lines=80","--no-pager"],"retain_output":true}
```

**`exec_sudo`** takes a nonempty `argv` with an absolute executable path first and a named `user`. Estus checks the requested account and executable against the target's [sudo policy](../policy.md), then supplies fixed flags: `sudo -n -k -u USER --`. You cannot supply sudo flags or a working directory. Sudo must allow the command without a password or PTY.

```json
{"host":"web-1","argv":["/usr/bin/journalctl","--unit=nginx.service","--lines=25","--no-pager"],"user":"root"}
```

## Read saved command output

**`inspect_output` · `inspect`** — Requires `handle` (32 lowercase hexadecimal characters) and `stream` (`stdout` or `stderr`). Optional: `offset` (bytes, default `0`), `max_bytes` (same bounds and default as `inspect_file`), and `encoding` (`utf8` or `base64`, default `utf8`). This is a local read; there is no `host` argument. Use the actual handle from an earlier call in the same session. See [how to read the receipt and ranges](results.md#read-retained-output).

```json
{"handle":"0123456789abcdef0123456789abcdef","stream":"stderr","max_bytes":4096,"encoding":"base64"}
```
