#![no_main]
#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rmcp::model::{JsonRpcResponse, RequestId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use estus::internal::{
    filesystem_data as data,
    reply,
    wire,
};

use data::{Encoding, RawRead, ReadData, ReadRequest, WriteData, WriteRequest, encode};
use reply::{ToolError, ToolReply};
use wire::ReplyBudget;

// Parsing cannot allocate from an unchecked integer. Explicit collections are
// bounded by the raw JSON cap; compressed payloads are checked before expansion.
const MAX_JSON: usize = 16_384;
const MAX_PATTERN: usize = 4_096;
const MAX_EXPANSION: usize = 65_536;
const MAX_ID: usize = 1_024;

fn one() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Fixture {
    Write {
        request: Value,
        limit: u64,
        #[serde(default = "one")]
        repeat_content: usize,
    },
    Read {
        request: Value,
        limit: u64,
        bytes: Vec<u8>,
        #[serde(default = "one")]
        repeat: usize,
        eof: bool,
        #[serde(default)]
        digest: Option<String>,
        #[serde(default)]
        id: String,
    },
}

// Independent standard-base64 oracle: accumulate sextets, require exactly the
// encoder's padding and zero trailing bits. No production decoder is called.
fn canonical_bytes(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut bits = 0u32;
    let mut count = 0usize;
    let mut padding = 0usize;
    for byte in text.bytes() {
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if padding != 0 {
            return None;
        }
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(digit);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
        bits &= (1u32 << count) - 1;
    }
    if bits != 0
        || padding > 2
        || (out.len() + 2) / 3 * 4 != text.len()
        || (3 - out.len() % 3) % 3 != padding
    {
        return None;
    }
    Some(out)
}

fn known(error: &ToolError) {
    assert!(!error.remote_state_unknown);
}

// Inspect both actual SDK representations, then serialize the real JSON-RPC
// response (including newline), independently of ReplyBudget's size counter.
fn wire_reply<T: Serialize>(budget: ReplyBudget, id: RequestId, reply: ToolReply<T>) -> Value {
    let expected = serde_json::to_value(&reply).unwrap();
    let failed = reply.error().is_some();
    let result = budget.result(reply).unwrap();
    let actual = serde_json::to_value(&result).unwrap();
    assert_eq!(actual["structuredContent"], expected);
    assert_eq!(actual["isError"], failed);
    assert_eq!(actual["content"].as_array().unwrap().len(), 1);
    assert_eq!(actual["content"][0]["type"], "text");
    let text = actual["content"][0]["text"].as_str().unwrap();
    assert_eq!(serde_json::from_str::<Value>(text).unwrap(), expected);
    let frame = JsonRpcResponse {
        jsonrpc: Default::default(),
        id,
        result,
    };
    assert!(serde_json::to_vec(&frame).unwrap().len() < wire::MAX_RESPONSE_BYTES);
    expected
}

fn write_case(request: Value, limit: u64, repeat: usize) -> Option<()> {
    let mut request: WriteRequest = serde_json::from_value(request).ok()?;
    let length = request.content.len().checked_mul(repeat)?;
    if request.content.len() > MAX_PATTERN || repeat > MAX_EXPANSION || length > MAX_EXPANSION {
        return None;
    }
    request.content = request.content.repeat(repeat);
    let expected = match request.encoding {
        Encoding::Utf8 => Some(request.content.as_bytes().to_vec()),
        Encoding::Base64 => canonical_bytes(&request.content),
    };
    let id = RequestId::Number(1);
    let budget = ReplyBudget::new(&id).unwrap();
    match request.validate(limit, budget) {
        Ok(spec) => {
            let bytes = expected
                .as_ref()
                .expect("accepted base64 must be canonical");
            assert_eq!(&*spec.content, bytes);
            assert!(bytes.len() as u64 <= limit);
            assert!(!spec.path.is_empty() && !spec.path.contains('\0'));
            assert_ne!(request.timeout_secs, Some(0));
            wire_reply(
                budget,
                id,
                ToolReply::success(WriteData {
                    bytes_written: bytes.len() as u64,
                }),
            );
        }
        Err(error) => {
            known(&error);
            assert!(matches!(
                error.code(),
                "invalid_argument" | "invalid_encoding"
            ));
            let failed = wire_reply(budget, id, ToolReply::<WriteData>::failure(error));
            assert!(failed["data"].is_null());
        }
    }
    // An otherwise valid request must accept every canonical payload exactly at
    // its raw-byte cap, and reject the same bytes one below that cap.
    request.path = "literal/-é/../$HOME;\n*".into();
    request.timeout_secs = None;
    match expected {
        Some(bytes) => {
            let spec = request.validate(bytes.len() as u64, budget).unwrap();
            assert_eq!(&*spec.content, bytes);
            if !bytes.is_empty() {
                let error = request
                    .validate(bytes.len() as u64 - 1, budget)
                    .unwrap_err();
                assert_eq!(error.code(), "invalid_argument");
                known(&error);
            }
        }
        None => {
            let error = request.validate(u64::MAX, budget).unwrap_err();
            assert_eq!(error.code(), "invalid_encoding");
            known(&error);
        }
    }
    Some(())
}

fn read_case(
    request: Value,
    limit: u64,
    bytes: Vec<u8>,
    repeat: usize,
    eof: bool,
    digest: Option<String>,
    id: String,
) -> Option<()> {
    if bytes.len() > MAX_PATTERN || id.len() > MAX_ID || repeat > MAX_EXPANSION {
        return None;
    }
    let length = bytes.len().checked_mul(repeat)?;
    if length > MAX_EXPANSION {
        return None;
    }
    let bytes = bytes.repeat(repeat);
    let mut request: ReadRequest = serde_json::from_value(request).ok()?;
    // Compute expectations from the original fixture, never encoded output.
    let requested = request.max_bytes.unwrap_or(65_536.min(limit));
    let retained_len = usize::try_from(requested)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    let retained = &bytes[..retained_len];
    let hash = hex::encode(Sha256::digest(retained));
    match digest.as_deref() {
        Some("match") => request.expected_content_sha256 = Some(hash.clone()),
        Some("uppercase") => request.expected_content_sha256 = Some(hash.to_ascii_uppercase()),
        Some("mismatch") => {
            let mut wrong = hash.clone().into_bytes();
            wrong[0] = if wrong[0] == b'0' { b'1' } else { b'0' };
            request.expected_content_sha256 = Some(String::from_utf8(wrong).unwrap());
        }
        _ => {}
    }
    let id = RequestId::String(id.into());
    let budget = ReplyBudget::new(&id).unwrap();
    let spec = match request.validate(limit, budget) {
        Ok(spec) => spec,
        Err(error) => {
            known(&error);
            assert_eq!(error.code(), "invalid_argument");
            return Some(());
        }
    };
    assert_eq!(spec.max_bytes as u64, requested);
    assert!(requested > 0 && requested <= limit);
    // RawRead is the actual pure encoder input, not an emulated backend. Its
    // bounded fixture can contain lookahead beyond the requested byte range.
    let output = encode(
        RawRead {
            bytes: BytesMut::from(bytes.as_slice()),
            eof,
        },
        &spec,
    );
    let mismatch = request
        .expected_content_sha256
        .as_ref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(&hash));
    let next_offset = request.offset.checked_add(retained.len() as u64);
    let invalid_utf8 =
        matches!(request.encoding, Encoding::Utf8) && std::str::from_utf8(retained).is_err();
    match output {
        Ok(data) => {
            assert!(!mismatch && next_offset.is_some() && !invalid_utf8);
            let result = wire_reply(budget, id, ToolReply::success(data));
            let data = &result["data"];
            assert_eq!(data["content_sha256"], hash);
            assert_eq!(data["bytes_read"], retained.len() as u64);
            assert_eq!(data["next_offset"], next_offset.unwrap());
            assert_eq!(data["eof"], eof);
            match request.encoding {
                Encoding::Utf8 => {
                    assert_eq!(data["encoding"], "utf8");
                    assert_eq!(data["content"].as_str().unwrap().as_bytes(), retained);
                }
                Encoding::Base64 => {
                    assert_eq!(data["encoding"], "base64");
                    let content = data["content"].as_str().unwrap();
                    assert_eq!(canonical_bytes(content).unwrap(), retained);
                    assert_eq!(STANDARD.decode(content).unwrap(), retained);
                }
            }
        }
        Err(error) => {
            known(&error);
            let expected_code = if mismatch {
                "checksum_mismatch"
            } else if next_offset.is_none() {
                "invalid_argument"
            } else {
                assert!(invalid_utf8);
                "invalid_encoding"
            };
            assert_eq!(error.code(), expected_code);
            let reply = wire_reply(budget, id, ToolReply::<ReadData>::failure(error));
            assert!(reply["data"].is_null());
            assert!(reply["error"].get("content").is_none());
            assert!(reply["error"].get("content_sha256").is_none());
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_JSON {
        return;
    }
    let Ok(fixture) = serde_json::from_slice::<Fixture>(data) else {
        return;
    };
    match fixture {
        Fixture::Write {
            request,
            limit,
            repeat_content,
        } => {
            write_case(request, limit, repeat_content);
        }
        Fixture::Read {
            request,
            limit,
            bytes,
            repeat,
            eof,
            digest,
            id,
        } => {
            read_case(request, limit, bytes, repeat, eof, digest, id);
        }
    }
});
