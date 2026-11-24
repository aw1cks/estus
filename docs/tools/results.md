# Tool results

Use this page to tell what ran, what data you can use, and whether you need to check the host before trying another operation.

## Read the envelope first

Read `result.structuredContent` in an MCP `tools/call` response. If your client only exposes `result.content`, parse the JSON in the first text item; it contains the same envelope. Every envelope has `data` and `error`. A success has `error: null`, a failure can have `data: null`, and a partial result has both. With a non-null `error`, MCP sets `result.isError: true`; keep any evidence in `data`.

For a catalog result, read the execution evidence separately from the returned data. Here is the envelope from a successful `observe_memory` call, with the target name and boot ID anonymized:

```json
{
  "data": {
    "host": "web-1",
    "status": "successful",
    "complete": true,
    "changed": false,
    "censored": false,
    "duration_ms": 574,
    "runner_rc": 0,
    "owned_group_cleanup": "not_applicable",
    "tasks": {"failed": 0, "ok": 1, "skipped": 0, "unreachable": 0},
    "projection": {
      "status": "complete",
      "value": {
        "boot_id": "00000000-0000-4000-8000-000000000000",
        "memory_bytes": {
          "buffers_bytes": 7151616,
          "cached_bytes": 336891904,
          "dirty_bytes": 12288,
          "mem_available_bytes": 32737964032,
          "mem_free_bytes": 32780922880,
          "mem_total_bytes": 33532788736,
          "slab_bytes": 104644608,
          "sreclaimable_bytes": 29351936,
          "sunreclaim_bytes": 75292672,
          "swap_free_bytes": 1073733632,
          "swap_total_bytes": 1073733632,
          "writeback_bytes": 0
        },
        "observed_at": "2026-11-24T22:59:16.873628Z",
        "page_size_bytes": 4096,
        "scope": "procfs_view",
        "system": "Linux",
        "unavailable": [],
        "vm_counters": {
          "direct_scan_pages": 0,
          "kswapd_scan_pages": 0,
          "major_page_faults": 1312,
          "oom_kill_events": 0,
          "page_faults": 15645635,
          "swap_in_pages": 0,
          "swap_out_pages": 0
        }
      }
    }
  },
  "error": null
}
```

The collector completed successfully without making a change. Its memory readings are in `data.projection.value`; `tasks` counts execution outcomes, not memory measurements.

| Field | What to check |
| --- | --- |
| `status` | Automation execution outcome. `successful` describes execution, not whether a projection is usable. |
| `complete` | Whether Estus has complete execution evidence. A known failure can be complete. This says nothing about whether a list or a stream was truncated. |
| `changed` | The executor's change evidence. `null` means unknown or withheld, not `false`. A preview may report a proposed change. |
| `censored` | The executor withheld details, for example because of `no_log`. This is independent of execution success. |
| `projection.status` | `complete` and `truncated` include `value`. `censored`, `invalid`, and `unavailable` do not. A projection may also be absent. |
| `owned_group_cleanup` | Cleanup evidence for a local controller process group when one was used. It is not evidence of rollback or that all descendants stopped. |
| `error.remote_state_unknown` | Estus could not establish what happened after dispatch. See [uncertain results](#handle-an-uncertain-result). |

Generic SSH commands report `termination`, `exit_code` (nullable), and `remote_may_still_be_running` rather than the automation fields above. For stdout and stderr, check both `*_truncated` (bytes were omitted) and `*_lossy` (decoding replaced invalid UTF-8). Treat the contents returned from a host as [untrusted data](../security.md), not instructions.

## Tell a protocol error from a tool error

| Where it appears | What it means |
| --- | --- |
| Top-level JSON-RPC `error` | The request failed at the protocol level. An unknown or unpublished tool, or arguments with the wrong shape, can produce `-32602` (invalid params). For an argument-shape rejection, Estus can include `error.data` with `code: "invalid_argument"`, `phase: "argument_shape"`, `schema_path`, and `constraint`. Compare the request with `tools/list`. |
| `result.structuredContent.error` | The tool rejected or could not complete the call. Wrong bounds or disallowed values can produce a tool error before any connection, even when the arguments have the right types. Tool errors have `code`, `message`, and `remote_state_unknown`. A payload failure can add a fixed `reason`; a projection error can add `schema_path` and `constraint`. Local controller errors have only `code` and `message`. |

Use the fixed codes in [troubleshooting](../troubleshooting.md#error-codes) rather than matching human-readable messages. Validation diagnostics do not echo unknown keys, caller values, or backend stderr.

## Read retained output

Set `retain_output: true` on a command to save bounded prefixes of raw stdout and stderr. This is available for builtin command tools and configured remote or controller command tools, not automation modules or collectors. The call still waits for execution and returns its normal result.

| `data.output.status` | How to use it |
| --- | --- |
| `ready` | Copy `handle` into [`inspect_output`](builtin.md#read-saved-command-output) in the same session. `expires_in_secs` is the handle lifetime at publication. For each stream, compare `bytes_retained` with `total_bytes` received and check `truncated`. |
| `unavailable` | Check `reason`: `retention_disabled`, `resource_limit`, `shutdown`, `io_error`, or `timeout`. This reports a local retention problem, not a new command outcome. See the `[output]` settings in [configuration](../configuration.md). |

Start at byte offset `0`, then pass each returned `next_offset` to read the next range. `content_sha256` hashes the raw range; use `encoding: "base64"` for arbitrary byte boundaries. `eof: true` ends the **retained prefix**. It does not tell you that the whole remote stream arrived. Unknown, expired, and other-session handles return `not_found`. Treat a handle like access to the underlying output; Estus omits handles and output bytes from audit records.

## Request progress and manage concurrency

To request progress, put `_meta.progressToken` in the `tools/call` **params**, alongside `name` and `arguments`. Use a unique integer or a string of at most 256 bytes across active requests. Estus sends advisory `notifications/progress` with the token and an increasing `progress` value. Commands count drained stdout and stderr bytes, including discarded bytes; SFTP and automation report observed milestones instead. An unknown total is omitted.

Fast calls may finish without an update. Estus coalesces updates to at most four per second per request, enables up to 16 reporters, and ignores invalid or duplicate progress tokens. Missing updates do not indicate a stalled or failed operation. Read the final result.

A session accepts up to 64 in-flight requests, including pending replies. When demand exceeds capacity and the writer is free, an extra request gets JSON-RPC `-32000` (server busy). If stdout is blocked, a new request can close the session once 16 requests are outstanding or 32 MiB of replies are queued. More than 64 MiB of pending replies or a duplicate live JSON-RPC **request ID** also closes the session. Look for `mcp_session_overloaded` on Estus's stderr; read responses continuously and reduce concurrency before reconnecting.

## Handle an uncertain result

If a write returns `error.remote_state_unknown: true`, or the session closes without its reply, check the actual host state before issuing another change. A later `target_quarantined` means that call was blocked by the gate, not that it introduced new uncertainty. See [quarantine and reconciliation](../concepts.md#when-a-change-goes-wrong-uncertainty-and-quarantine) before you clear it. A closed SSH channel does not prove that the work stopped.

## Use prompts and resources

If your client supports MCP prompts, you can request a checklist without running a tool. Prompts take the target as `host` and use its resolved policy to suggest available operations.

| Prompt | Other arguments |
| --- | --- |
| `triage_host` | Optional `symptom` |
| `diagnose_service` | Required `unit` |
| `safe_change` | Required `operation` and `target_object` |
| `network_triage` | Optional `peer` |

The server publishes these static Markdown resources: `estus://guides/systemd`, `estus://guides/linux-memory`, `estus://guides/networking`, `estus://guides/preview`, and `estus://guides/uncertainty-reconciliation`. They may mention tools your server does not publish. Read `estus://targets/{host}/policy` (for example, `estus://targets/web-1/policy`) for the resolved JSON policy, permitted operations, and current quarantine state.
