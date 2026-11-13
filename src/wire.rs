//! Bound complete stdio replies before allocating their duplicated representations.
use std::{io, sync::LazyLock};

use rmcp::{
    ErrorData, RoleServer,
    model::{
        CallToolResult, ClientJsonRpcMessage, JsonRpcResponse, RequestId, ServerJsonRpcMessage,
    },
    transport::Transport,
};
use serde::Serialize;

use crate::reply::{
    CommandData, ControllerData, ControllerError, ControllerReply, ControllerTermination,
    GroupCleanup, Termination, ToolError, ToolReply,
};

pub(crate) const MAX_RESPONSE_BYTES: usize = 16_777_216;

fn exceeded() -> ErrorData {
    ErrorData::invalid_params("Request leaves insufficient response budget", None)
}

fn size_error() -> io::Error {
    io::Error::other("response budget exceeded")
}

#[derive(Default)]
struct Counter(usize);

impl io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.checked_add(bytes.len()).ok_or_else(size_error)?;
        if self.0 > MAX_RESPONSE_BYTES {
            return Err(size_error());
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_size(value: &impl Serialize) -> Result<usize, ErrorData> {
    let mut count = Counter::default();
    serde_json::to_writer(&mut count, value).map_err(|_| exceeded())?;
    Ok(count.0)
}

// serde_json's compact string encoding, excluding the surrounding quotes.
fn escaped_byte_size(byte: u8) -> usize {
    match byte {
        b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 2,
        0..=0x1f => 6,
        _ => 1,
    }
}

struct DuplicatedSize {
    bytes: usize,
    remaining: usize,
}

impl io::Write for DuplicatedSize {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // The serializer emits JSON once into structuredContent and again as
        // a JSON-escaped string inside content[0].text. Never materialize either.
        let cost = bytes.iter().try_fold(bytes.len(), |cost, &byte| {
            cost.checked_add(escaped_byte_size(byte))
                .ok_or_else(size_error)
        })?;
        self.remaining = self.remaining.checked_sub(cost).ok_or_else(size_error)?;
        self.bytes += cost;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Cost of a value appearing in both structuredContent and JSON text content.
pub(crate) fn duplicated_size(value: &impl Serialize) -> Result<usize, ErrorData> {
    let mut size = DuplicatedSize {
        bytes: 0,
        remaining: MAX_RESPONSE_BYTES,
    };
    serde_json::to_writer(&mut size, value).map_err(|_| exceeded())?;
    Ok(size.bytes)
}

// Measure the SDK's actual result/frame shape once, rather than copying its
// fields or constructing a placeholder result on every size calculation.
fn tool_overhead(failed: bool) -> usize {
    static OVERHEAD: LazyLock<[usize; 2]> = LazyLock::new(|| {
        [false, true].map(|failed| {
            let null = serde_json::Value::Null;
            let result = if failed {
                CallToolResult::structured_error(null)
            } else {
                CallToolResult::structured(null)
            };
            let frame = JsonRpcResponse {
                jsonrpc: Default::default(),
                id: RequestId::Number(0),
                result,
            };
            // Remove the one-byte placeholder ID and the two four-byte null
            // payloads, retaining the text string's quotes. Include the newline.
            serialized_size(&frame).expect("fixed SDK frame fits the response budget") + 1 - 9
        })
    });
    OVERHEAD[usize::from(failed)]
}

#[derive(Clone, Copy)]
pub(crate) struct ReplyBudget {
    id_bytes: usize,
}

impl ReplyBudget {
    pub(crate) fn new(id: &RequestId) -> Result<Self, ErrorData> {
        Ok(Self {
            id_bytes: serialized_size(id)?,
        })
    }

    pub(crate) fn automation_reserve(
        &self,
        host: &str,
        max_projection_bytes: Option<usize>,
    ) -> Result<(), ErrorData> {
        // Reserve fixed evidence first, then the selected JSON's worst-case
        // structured form plus its escaped JSON-in-text duplicate (at most 3N).
        let mut reservation = serde_json::json!({
            "data":{
                "host":"","status":"resource_limit","runner_rc":i32::MIN,
                "changed":false,"tasks":{"ok":u32::MAX,"failed":u32::MAX,"unreachable":u32::MAX,"skipped":u32::MAX},
                "censored":false,"complete":false,"duration_ms":u64::MAX,
                "owned_group_cleanup":"signalled_and_reaped"
            },
            "error":{"code":"invalid_argument","message":"x".repeat(256),"remote_state_unknown":false}
        });
        let projection_bytes = if let Some(limit) = max_projection_bytes {
            if !(64..=4096).contains(&limit) {
                return Err(exceeded());
            }
            reservation["data"]["projection"] =
                serde_json::json!({"status":"truncated","value":null});
            limit.checked_mul(3).ok_or_else(exceeded)?
        } else {
            0
        };
        let size = self.value_size(&reservation, true)?;
        size.checked_add(duplicated_size(&host)?)
            .and_then(|size| size.checked_add(projection_bytes))
            .filter(|size| *size <= MAX_RESPONSE_BYTES)
            .map(|_| ())
            .ok_or_else(exceeded)
    }

    fn value_size(&self, value: &impl Serialize, failed: bool) -> Result<usize, ErrorData> {
        let overhead = self.id_bytes + tool_overhead(failed);
        let mut size = DuplicatedSize {
            bytes: overhead,
            remaining: MAX_RESPONSE_BYTES
                .checked_sub(overhead)
                .ok_or_else(exceeded)?,
        };
        serde_json::to_writer(&mut size, value).map_err(|_| exceeded())?;
        Ok(size.bytes)
    }

    fn tool_reply_size<T: Serialize>(&self, reply: &ToolReply<T>) -> Result<usize, ErrorData> {
        self.value_size(reply, reply.error.is_some())
    }

    pub(crate) fn remaining<T: Serialize>(&self, reply: &ToolReply<T>) -> Result<usize, ErrorData> {
        Ok(MAX_RESPONSE_BYTES - self.tool_reply_size(reply)?)
    }

    pub(crate) fn result<T: Serialize>(
        &self,
        reply: ToolReply<T>,
    ) -> Result<CallToolResult, ErrorData> {
        self.serialized_result(&reply, reply.error.is_some())
    }

    fn serialized_result(
        &self,
        reply: &impl Serialize,
        failed: bool,
    ) -> Result<CallToolResult, ErrorData> {
        // Bound before to_value/structured allocate copies and nested escaping.
        self.value_size(reply, failed)?;
        let value = serde_json::to_value(reply)
            .map_err(|_| ErrorData::internal_error("Could not serialize tool reply", None))?;
        Ok(if failed {
            CallToolResult::structured_error(value)
        } else {
            CallToolResult::structured(value)
        })
    }

    pub(crate) fn command_capture_limit(&self) -> Result<u64, ErrorData> {
        // Reserve the longest current error code/message and conservative scalar
        // widths before dispatch. A health failure without command data is smaller.
        // false is wider than true; i32::MIN/u64::MAX reserve every numeric width.
        let reservation = ToolReply {
            data: Some(CommandData {
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                stdout_lossy: false,
                stderr_lossy: false,
                exit_code: Some(i32::MIN),
                termination: Termination::ConnectionLost,
                duration_ms: u64::MAX,
                remote_may_still_be_running: false,
            }),
            error: Some(ToolError::SSH_CONNECT_FAILED),
        };
        // Even unescaped UTF-8 appears twice. No stream can contribute more raw
        // bytes than this, regardless of the operator's capture cap. Lossy
        // replacement and escaping are budgeted after decoding, before copying.
        Ok((self.remaining(&reservation)? / 2) as u64)
    }

    pub(crate) fn command_result(
        &self,
        mut reply: ToolReply<CommandData>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(data) = &mut reply.data {
            let mut stdout = std::mem::take(&mut data.stdout);
            let mut stderr = std::mem::take(&mut data.stderr);
            let remaining = MAX_RESPONSE_BYTES - self.tool_reply_size(&reply)?;
            if let Some(data) = &mut reply.data {
                trim_streams(
                    &mut stdout,
                    &mut stderr,
                    &mut data.stdout_truncated,
                    &mut data.stderr_truncated,
                    remaining,
                );
                data.stdout = stdout;
                data.stderr = stderr;
            }
        }
        self.result(reply)
    }

    pub(crate) fn controller_capture_limit(&self) -> Result<u64, ErrorData> {
        let reservation = ControllerReply {
            data: Some(ControllerData {
                stdout: String::new(),
                stderr: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                stdout_lossy: false,
                stderr_lossy: false,
                exit_code: Some(i32::MIN),
                signal: Some(i32::MIN),
                termination: ControllerTermination::Signalled,
                duration_ms: u64::MAX,
                owned_group_cleanup: GroupCleanup::SignalledAndReaped,
            }),
            error: Some(ControllerError::new(
                "controller_resource_limit",
                "Controller execution could not complete within the configured resource limits",
            )),
        };
        // Raw capture is bounded before decoding. Exact escaping and actual
        // error metadata are accounted for again before duplicated allocation.
        Ok(((MAX_RESPONSE_BYTES - self.value_size(&reservation, true)?) / 2) as u64)
    }

    pub(crate) fn controller_result(
        &self,
        mut reply: ControllerReply,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(data) = &mut reply.data {
            let mut stdout = std::mem::take(&mut data.stdout);
            let mut stderr = std::mem::take(&mut data.stderr);
            let remaining = MAX_RESPONSE_BYTES - self.value_size(&reply, reply.error.is_some())?;
            if let Some(data) = &mut reply.data {
                trim_streams(
                    &mut stdout,
                    &mut stderr,
                    &mut data.stdout_truncated,
                    &mut data.stderr_truncated,
                    remaining,
                );
                data.stdout = stdout;
                data.stderr = stderr;
            }
        }
        self.serialized_result(&reply, reply.error.is_some())
    }
}

fn trim_streams(
    stdout: &mut String,
    stderr: &mut String,
    stdout_truncated: &mut bool,
    stderr_truncated: &mut bool,
    mut remaining: usize,
) {
    let out_len = prefix_len(stdout, &mut remaining);
    let err_len = prefix_len(stderr, &mut remaining);
    *stdout_truncated |= out_len < stdout.len();
    *stderr_truncated |= err_len < stderr.len();
    stdout.truncate(out_len);
    stderr.truncate(err_len);
}

// Deterministic stdout-first prefixes. A truncation flag changing false -> true
// only makes metadata smaller, so the empty-stream size is a safe reservation.
fn prefix_len(text: &str, remaining: &mut usize) -> usize {
    let mut end = 0;
    for character in text.chars() {
        let cost = match character {
            '"' | '\\' => 6,
            '\x08' | '\t' | '\n' | '\x0c' | '\r' => 5,
            '\0'..='\x1f' => 13,
            _ => character.len_utf8() * 2,
        };
        let Some(next) = remaining.checked_sub(cost) else {
            break;
        };
        *remaining = next;
        end += character.len_utf8();
    }
    end
}

/// Final size guard on the existing RMCP transport, not another dispatcher.
pub(crate) struct BoundedTransport<T>(pub(crate) T);

impl<T: Transport<RoleServer, Error = io::Error>> Transport<RoleServer> for BoundedTransport<T> {
    type Error = io::Error;

    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // Validate the actual SDK message, including protocol errors and any
        // version-specific fields, before its encoder allocates the wire frame.
        let send = frame_fits(&message).then(|| self.0.send(message));
        async move {
            match send {
                Some(send) => send.await,
                None => Err(size_error()),
            }
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<ClientJsonRpcMessage>> + Send {
        self.0.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.close()
    }
}

fn frame_fits(message: &impl Serialize) -> bool {
    // The SDK encoder adds exactly one newline after compact JSON.
    serialized_size(message).is_ok_and(|bytes| bytes < MAX_RESPONSE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn fixed_automation_summary_reserves_normal_wire_budget() {
        let budget = ReplyBudget::new(&RequestId::Number(1)).unwrap();
        budget.automation_reserve("logical", None).unwrap();
        let oversized = RequestId::String("x".repeat(MAX_RESPONSE_BYTES).into());
        assert!(
            ReplyBudget::new(&oversized)
                .and_then(|budget| budget.automation_reserve("logical", None))
                .is_err()
        );
    }

    #[test]
    fn projected_escape_growth_is_reserved_before_a_large_id_can_dispatch() {
        use crate::reply::{AutomationData, AutomationStatus, AutomationTasks, ModuleProjection};
        let value = json!({"text":"\0\\\"".repeat(400)});
        assert!(serde_json::to_vec(&value).unwrap().len() <= 4096);
        let id = RequestId::String("x".repeat(MAX_RESPONSE_BYTES - 7000).into());
        let budget = ReplyBudget::new(&id).unwrap();
        assert!(budget.automation_reserve("logical", None).is_ok());
        assert!(budget.automation_reserve("logical", Some(4096)).is_err());
        let reply = ToolReply::success(AutomationData {
            host: "logical".into(),
            status: AutomationStatus::Successful,
            runner_rc: Some(0),
            changed: Some(false),
            tasks: AutomationTasks {
                ok: 1,
                ..Default::default()
            },
            censored: false,
            complete: true,
            duration_ms: 1,
            owned_group_cleanup: GroupCleanup::SignalledAndReaped,
            projection: Some(ModuleProjection::Complete { value }),
        });
        assert!(
            budget.result(reply).is_err(),
            "both result representations exceed the remaining frame"
        );
    }

    fn command(stdout: &str, stderr: &str) -> ToolReply<CommandData> {
        ToolReply::success(CommandData {
            stdout: stdout.into(),
            stderr: stderr.into(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_lossy: false,
            stderr_lossy: false,
            exit_code: Some(0),
            termination: Termination::Exited,
            duration_ms: 42,
            remote_may_still_be_running: false,
        })
    }

    fn actual_frame_size(id: RequestId, result: &CallToolResult) -> usize {
        serde_json::to_vec(&JsonRpcResponse {
            jsonrpc: Default::default(),
            id,
            result,
        })
        .unwrap()
        .len()
            + 1
    }

    #[test]
    fn counts_actual_sdk_frames_with_nested_escaping_and_request_ids() {
        let controls: String = (0..=127).map(char::from).collect();
        for id in [
            RequestId::Number(0),
            RequestId::Number(i64::MAX),
            RequestId::String("long-\"\\\n\0-é🙂".repeat(1024).into()),
        ] {
            for text in ["", controls.as_str(), "é🙂\u{fffd}\"\\\n"] {
                for error in [None, Some(ToolError::SSH_CONNECT_FAILED)] {
                    let mut reply = command(text, text);
                    reply.error = error;
                    let budget = ReplyBudget::new(&id).unwrap();
                    let predicted = budget.tool_reply_size(&reply).unwrap();
                    let result = budget.result(reply).unwrap();
                    assert_eq!(predicted, actual_frame_size(id.clone(), &result));
                    let content: Value =
                        serde_json::from_str(result.content[0].as_text().unwrap().text.as_str())
                            .unwrap();
                    assert_eq!(Some(content), result.structured_content);
                }
            }
        }
    }

    #[test]
    fn exact_response_ceiling_includes_the_newline() {
        let mut id = RequestId::Number(1);
        let mut budget = ReplyBudget::new(&id).unwrap();
        let mut reply = command("", "");
        let mut base = budget.tool_reply_size(&reply).unwrap();
        // Each unescaped ASCII byte occurs twice. Select an ID width that
        // permits an exact frame boundary without inventing serializer padding.
        if !(MAX_RESPONSE_BYTES - base).is_multiple_of(2) {
            id = RequestId::Number(10);
            budget = ReplyBudget::new(&id).unwrap();
            base = budget.tool_reply_size(&reply).unwrap();
        }
        let count = (MAX_RESPONSE_BYTES - base) / 2;
        reply.data.as_mut().unwrap().stdout = "x".repeat(count);
        assert_eq!(budget.tool_reply_size(&reply).unwrap(), MAX_RESPONSE_BYTES);
        let result = budget.result(reply).unwrap();
        assert_eq!(actual_frame_size(id, &result), MAX_RESPONSE_BYTES);
        drop(result);

        let mut excess = command("", "");
        excess.data.as_mut().unwrap().stdout = "x".repeat(count + 1);
        assert!(budget.tool_reply_size(&excess).is_err());
        let result = budget.command_result(excess).unwrap();
        let data = &result.structured_content.unwrap()["data"];
        assert_eq!(data["stdout"].as_str().unwrap(), "x".repeat(count));
        assert_eq!(data["stdout_truncated"], true);
        assert_eq!(data["stderr_truncated"], false);
        assert_eq!(data["exit_code"], 0);
    }

    #[test]
    fn prefixes_respect_control_costs_and_utf8_boundaries() {
        for (text, budget, expected) in [
            ("é🙂z", 3, ""),
            ("é🙂z", 4, "é"),
            ("é🙂z", 11, "é"),
            ("é🙂z", 12, "é🙂"),
            ("é🙂z", 14, "é🙂z"),
            ("\0\n\"\\", 12, ""),
            ("\0\n\"\\", 13, "\0"),
            ("\0\n\"\\", 18, "\0\n"),
            ("\0\n\"\\", 23, "\0\n"),
            ("\0\n\"\\", 24, "\0\n\""),
            ("\0\n\"\\", 30, "\0\n\"\\"),
            ("\u{fffd}", 5, ""),
            ("\u{fffd}", 6, "\u{fffd}"),
        ] {
            let mut remaining = budget;
            let end = prefix_len(text, &mut remaining);
            assert_eq!(&text[..end], expected, "budget {budget}, input {text:?}");
        }
    }

    #[test]
    fn clipping_preserves_interruption_and_loss_evidence() {
        let budget = ReplyBudget {
            id_bytes: MAX_RESPONSE_BYTES - 2048,
        };
        let mut reply = command(&"\u{fffd}\0".repeat(1024), &"é🙂".repeat(1024));
        let data = reply.data.as_mut().unwrap();
        data.stdout_lossy = true;
        data.exit_code = None;
        data.termination = Termination::ConnectionLost;
        data.remote_may_still_be_running = true;
        reply.error = Some(ToolError::new(
            "connection_lost",
            "SSH command channel was lost; remote execution state is unknown",
            true,
        ));
        let result = budget.command_result(reply).unwrap();
        assert_eq!(result.is_error, Some(true));
        let reply = result.structured_content.unwrap();
        assert_eq!(reply["error"]["code"], "connection_lost");
        assert_eq!(reply["error"]["remote_state_unknown"], true);
        let data = &reply["data"];
        assert_eq!(data["exit_code"], Value::Null);
        assert_eq!(data["termination"], "connection_lost");
        assert_eq!(data["remote_may_still_be_running"], true);
        assert_eq!(data["duration_ms"], 42);
        assert_eq!(data["stdout_lossy"], true);
        assert_eq!(data["stderr_lossy"], false);
        assert_eq!(data["stdout_truncated"], true);
        assert_eq!(data["stderr_truncated"], true);
        assert!(
            "\u{fffd}\0"
                .repeat(1024)
                .starts_with(data["stdout"].as_str().unwrap())
        );
    }

    #[test]
    fn impossible_command_envelope_rejects_without_allocating_capture() {
        let budget = ReplyBudget {
            id_bytes: MAX_RESPONSE_BYTES - 256,
        };
        assert!(budget.command_capture_limit().is_err());
        let budget = ReplyBudget::new(&RequestId::Number(1)).unwrap();
        assert!(budget.command_capture_limit().unwrap() < (MAX_RESPONSE_BYTES / 2) as u64);
        assert!(
            budget
                .result(ToolReply::success(
                    json!({"payload": "x".repeat(MAX_RESPONSE_BYTES / 2)})
                ))
                .is_err()
        );
    }

    #[test]
    fn final_guard_also_bounds_protocol_errors() {
        let mut frame = rmcp::model::JsonRpcError::new(
            Some(RequestId::Number(1)),
            ErrorData::invalid_params("", None),
        );
        let base = serde_json::to_vec(&frame).unwrap().len() + 1;
        frame.error.message = "x".repeat(MAX_RESPONSE_BYTES - base).into();
        assert_eq!(
            serde_json::to_vec(&frame).unwrap().len() + 1,
            MAX_RESPONSE_BYTES
        );
        assert!(frame_fits(&frame));
        frame.error.message.to_mut().push('x');
        assert!(!frame_fits(&frame));
    }

    fn controller(stdout: String, stderr: String) -> ControllerReply {
        ControllerReply {
            data: Some(ControllerData {
                stdout,
                stderr,
                stdout_truncated: false,
                stderr_truncated: false,
                stdout_lossy: true,
                stderr_lossy: false,
                exit_code: None,
                signal: Some(9),
                termination: ControllerTermination::Timeout,
                duration_ms: 42,
                owned_group_cleanup: GroupCleanup::Incomplete,
            }),
            error: Some(ControllerError::new(
                "controller_timeout",
                "Controller execution timed out",
            )),
        }
    }

    #[test]
    fn controller_boundary_precedes_copies_and_clipping_preserves_local_evidence() {
        let mut id = RequestId::Number(1);
        let mut budget = ReplyBudget::new(&id).unwrap();
        let empty = controller(String::new(), String::new());
        let mut base = budget.value_size(&empty, true).unwrap();
        if !(MAX_RESPONSE_BYTES - base).is_multiple_of(2) {
            id = RequestId::Number(10);
            budget = ReplyBudget::new(&id).unwrap();
            base = budget.value_size(&empty, true).unwrap();
        }
        let count = (MAX_RESPONSE_BYTES - base) / 2;
        let exact = controller("x".repeat(count), String::new());
        assert_eq!(budget.value_size(&exact, true).unwrap(), MAX_RESPONSE_BYTES);
        let result = budget.controller_result(exact).unwrap();
        assert_eq!(actual_frame_size(id.clone(), &result), MAX_RESPONSE_BYTES);
        drop(result);

        let excess = controller("x".repeat(count + 1), "é🙂\0\n\"\\".into());
        assert!(budget.serialized_result(&excess, true).is_err());
        let result = budget.controller_result(excess).unwrap();
        assert!(actual_frame_size(id, &result) <= MAX_RESPONSE_BYTES);
        assert_eq!(result.is_error, Some(true));
        let value = result.structured_content.unwrap();
        let data = &value["data"];
        assert_eq!(data["stdout"].as_str().unwrap().len(), count);
        assert_eq!(data["stderr"], "");
        assert_eq!(data["stdout_truncated"], true);
        assert_eq!(data["stderr_truncated"], true);
        assert_eq!(data["stdout_lossy"], true);
        assert_eq!(data["exit_code"], Value::Null);
        assert_eq!(data["signal"], 9);
        assert_eq!(data["termination"], "timeout");
        assert_eq!(data["owned_group_cleanup"], "incomplete");
        assert_eq!(value["error"]["code"], "controller_timeout");
        assert!(value["error"].get("remote_state_unknown").is_none());
        assert!(data.get("remote_may_still_be_running").is_none());
    }

    #[test]
    fn controller_sizes_nested_escaping_and_rejects_impossible_capture_envelopes() {
        let id = RequestId::String("controller-\"\\\0🙂".into());
        let budget = ReplyBudget::new(&id).unwrap();
        let reply = controller("é🙂\0\n\"\\".into(), "\u{fffd}\t\r".into());
        let predicted = budget.value_size(&reply, true).unwrap();
        let result = budget.controller_result(reply).unwrap();
        assert_eq!(predicted, actual_frame_size(id, &result));
        let text: Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
        assert_eq!(Some(text), result.structured_content);
        assert!(budget.controller_capture_limit().unwrap() < (MAX_RESPONSE_BYTES / 2) as u64);
        assert!(
            ReplyBudget {
                id_bytes: MAX_RESPONSE_BYTES - 256,
            }
            .controller_capture_limit()
            .is_err()
        );
    }
}
