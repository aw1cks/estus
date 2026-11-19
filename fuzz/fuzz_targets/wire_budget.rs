#![no_main]
#![allow(dead_code)]

use estus::internal::{reply, wire};

use std::io::{self, Write};

use libfuzzer_sys::fuzz_target;
use reply::{CommandData, Termination, ToolError, ToolReply};
use rmcp::model::{CallToolResult, JsonRpcResponse, RequestId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wire::{MAX_RESPONSE_BYTES, ReplyBudget};

// JSON fixtures are at most 4 KiB. Ordinary cases expand each stream to at most
// 8 KiB; explicit boundary/oversized modes allow 32 KiB per stream. IDs have at
// most MAX_RESPONSE_BYTES + 4096 serialized bytes and no greater decoded length.
// String-to-SDK-ID conversion can transiently retain two bounded ID allocations.
// Even rejected replies are measured through a capped streaming writer, never
// through a second frame-sized Vec. Every serialization is capped at 18 MiB.
const MAX_INPUT: usize = 4096;
const MAX_COUNTED: usize = 18 * 1024 * 1024;

#[derive(Default)]
struct Count(usize);

impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_COUNTED)
            .ok_or_else(|| io::Error::other("harness serialization cap"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn size(value: &impl Serialize) -> usize {
    let mut count = Count::default();
    serde_json::to_writer(&mut count, value).unwrap();
    count.0
}

// Unknown fields are rejected so that seed mutations cannot silently select an
// unintended mode. Missing fields use the small, successful numeric-ID case.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Fixture {
    mode: Mode,
    number: i64,
    string_id: bool,
    id: String,
    id_repeat: u16,
    reserve: u32,
    stdout: String,
    stderr: String,
    stdout_repeat: u16,
    stderr_repeat: u16,
    no_data: bool,
    error: u8,
    remote_state_unknown: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_lossy: bool,
    stderr_lossy: bool,
    exit_code: Option<i32>,
    termination: u8,
    duration_ms: u64,
    remote_may_still_be_running: bool,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Small,
    Boundary,
    Oversized,
}

fn expanded(text: &str, repeat: u16, cap: usize) -> Option<String> {
    if text.len() > 512 || repeat > 4096 {
        return None;
    }
    let repeat = usize::from(repeat.max(1));
    (text.len().checked_mul(repeat)? <= cap).then(|| text.repeat(repeat))
}

impl Fixture {
    fn request_id(&self) -> Option<RequestId> {
        if self.id.len() > 128 {
            return None;
        }
        let target = match self.mode {
            Mode::Small => {
                if !self.string_id {
                    return Some(RequestId::Number(self.number));
                }
                if self.id_repeat > 64 {
                    return None;
                }
                return Some(RequestId::String(
                    self.id.repeat(usize::from(self.id_repeat.max(1))).into(),
                ));
            }
            Mode::Boundary => MAX_RESPONSE_BYTES.checked_sub(self.reserve.min(65_536) as usize)?,
            Mode::Oversized => MAX_RESPONSE_BYTES + 1 + self.reserve.min(4095) as usize,
        };
        // Count the actual serde encoding of the atom, not a handwritten escape
        // table. ASCII padding makes the requested serialized ID size exact.
        let atom = if self.id.is_empty() { "x" } else { &self.id };
        let atom_bytes = size(&atom) - 2;
        let repetitions = (target - 2) / atom_bytes;
        let padding = (target - 2) % atom_bytes;
        let mut text = String::with_capacity(atom.len() * repetitions + padding);
        for _ in 0..repetitions {
            text.push_str(atom);
        }
        text.extend(std::iter::repeat_n('x', padding));
        let id = RequestId::String(text.into());
        assert_eq!(size(&id), target);
        Some(id)
    }

    fn reply(&self, stdout: String, stderr: String) -> ToolReply<CommandData> {
        ToolReply {
            data: (!self.no_data).then_some(CommandData {
                stdout,
                stderr,
                stdout_truncated: self.stdout_truncated,
                stderr_truncated: self.stderr_truncated,
                stdout_lossy: self.stdout_lossy,
                stderr_lossy: self.stderr_lossy,
                exit_code: self.exit_code,
                termination: match self.termination % 4 {
                    0 => Termination::Exited,
                    1 => Termination::Timeout,
                    2 => Termination::Cancelled,
                    _ => Termination::ConnectionLost,
                },
                duration_ms: self.duration_ms,
                remote_may_still_be_running: self.remote_may_still_be_running,
                output: None,
            }),
            error: match self.error % 3 {
                0 => None,
                1 => Some(ToolError::SSH_CONNECT_FAILED),
                _ => Some(ToolError::new(
                    "connection_lost",
                    "SSH command channel was lost; remote execution state is unknown",
                    self.remote_state_unknown,
                )),
            },
        }
    }
}

fn sdk_result(value: Value, failed: bool) -> CallToolResult {
    if failed {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    }
}

// Move the real ID into and back out of the SDK response: no frame-sized clone.
fn frame_size(id: RequestId, result: &CallToolResult) -> (RequestId, usize) {
    let frame = JsonRpcResponse {
        jsonrpc: Default::default(),
        id,
        result,
    };
    let mut count = Count::default();
    serde_json::to_writer(&mut count, &frame).unwrap();
    count.write_all(b"\n").unwrap();
    (frame.id, count.0)
}

fn parity(result: &CallToolResult, expected: &Value, failed: bool) {
    assert_eq!(result.is_error, Some(failed));
    assert_eq!(result.structured_content.as_ref(), Some(expected));
    assert_eq!(result.content.len(), 1);
    let text = &result.content[0].as_text().unwrap().text;
    let decoded: Value = serde_json::from_str(text).unwrap();
    assert_eq!(&decoded, expected);
}

fn exercise(fixture: Fixture) {
    let cap = if matches!(fixture.mode, Mode::Small) {
        8192
    } else {
        32768
    };
    let Some(stdout) = expanded(&fixture.stdout, fixture.stdout_repeat, cap) else {
        return;
    };
    let Some(stderr) = expanded(&fixture.stderr, fixture.stderr_repeat, cap) else {
        return;
    };
    let Some(mut id) = fixture.request_id() else {
        return;
    };
    let id_size = size(&id);
    let budget = ReplyBudget::new(&id);
    assert_eq!(budget.is_ok(), id_size <= MAX_RESPONSE_BYTES);
    let Ok(budget) = budget else { return };

    let original = serde_json::to_value(fixture.reply(stdout.clone(), stderr.clone())).unwrap();
    let failed = !original["error"].is_null();
    let expected = sdk_result(original.clone(), failed);
    let (returned_id, original_size) = frame_size(id, &expected);
    id = returned_id;
    drop(expected);

    let remaining = budget.remaining(&fixture.reply(stdout.clone(), stderr.clone()));
    assert_eq!(remaining.is_ok(), original_size <= MAX_RESPONSE_BYTES);
    if let Ok(remaining) = remaining {
        assert_eq!(remaining, MAX_RESPONSE_BYTES - original_size);
    }
    let direct = budget.result(fixture.reply(stdout.clone(), stderr.clone()));
    assert_eq!(direct.is_ok(), original_size <= MAX_RESPONSE_BYTES);
    if let Ok(result) = direct {
        parity(&result, &original, failed);
        let (returned_id, actual_size) = frame_size(id, &result);
        id = returned_id;
        assert_eq!(actual_size, original_size);
    }

    let empty_reply = fixture.reply(String::new(), String::new());
    let empty_remaining = budget.remaining(&empty_reply);
    let empty_value = serde_json::to_value(&empty_reply).unwrap();
    let empty_sdk = sdk_result(empty_value, failed);
    let (returned_id, empty_size) = frame_size(id, &empty_sdk);
    id = returned_id;
    assert_eq!(empty_remaining.is_ok(), empty_size <= MAX_RESPONSE_BYTES);
    if let Ok(remaining) = empty_remaining.as_ref() {
        assert_eq!(*remaining, MAX_RESPONSE_BYTES - empty_size);
    }
    let capture = budget.command_capture_limit(false);
    if let Ok(limit) = capture {
        assert!(limit <= (MAX_RESPONSE_BYTES / 2) as u64);
        // The production conservative reservation must not promise more raw
        // stream bytes than this fixture's real empty envelope can accommodate.
        if let Ok(remaining) = empty_remaining.as_ref() {
            assert!(limit * 2 <= *remaining as u64);
        }
    } else if matches!(id, RequestId::Number(_)) {
        panic!("a numeric ID must leave room for command capture");
    }

    let clipped = budget.command_result(fixture.reply(stdout.clone(), stderr.clone()));
    assert_eq!(clipped.is_ok(), empty_remaining.is_ok());
    let Ok(result) = clipped else { return };
    let actual = result.structured_content.as_ref().unwrap();
    let mut expected = original;
    if !fixture.no_data {
        for (name, flag, source, was_truncated) in [
            (
                "stdout",
                "stdout_truncated",
                stdout.as_str(),
                fixture.stdout_truncated,
            ),
            (
                "stderr",
                "stderr_truncated",
                stderr.as_str(),
                fixture.stderr_truncated,
            ),
        ] {
            let output = actual["data"][name].as_str().unwrap();
            assert!(source.starts_with(output));
            assert!(source.is_char_boundary(output.len()));
            let truncated = was_truncated || output.len() < source.len();
            assert_eq!(actual["data"][flag], truncated);
            expected["data"][name] = Value::String(output.to_owned());
            expected["data"][flag] = Value::Bool(truncated);
        }
        // A fitting reply cannot lose bytes. Sticky truncation flags must never
        // turn false, including when no additional clipping was necessary.
        if original_size <= MAX_RESPONSE_BYTES {
            assert_eq!(actual["data"]["stdout"], stdout);
            assert_eq!(actual["data"]["stderr"], stderr);
        }
    }
    // Full-value equality checks every non-stream field, not only selected
    // evidence: error code/message/unknown-state, exit/termination/duration,
    // both lossy flags and remote-may-still-be-running all survive clipping.
    parity(&result, &expected, failed);
    let (mut id, actual_size) = frame_size(id, &result);
    assert!(actual_size <= MAX_RESPONSE_BYTES);
    if !fixture.no_data {
        for (name, source) in [("stdout", stdout.as_str()), ("stderr", stderr.as_str())] {
            let retained = actual["data"][name].as_str().unwrap();
            if let Some(next) = source[retained.len()..].chars().next() {
                let mut candidate = actual.clone();
                let mut extended = retained.to_owned();
                extended.push(next);
                candidate["data"][name] = Value::String(extended);
                let candidate = sdk_result(candidate, failed);
                let (returned_id, candidate_size) = frame_size(id, &candidate);
                id = returned_id;
                // Each false -> true flag saves one byte in each of the two
                // representations: at most four bytes beyond the reservation.
                assert!(candidate_size > MAX_RESPONSE_BYTES - 4);
            }
        }
    }
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() <= MAX_INPUT {
        if let Ok(fixture) = serde_json::from_slice::<Fixture>(bytes) {
            exercise(fixture);
        }
    }
});
