//! Pure validation and lossless representations for bounded file operations.
use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::metadata::{FileKind, ListEntry, StatData};
use crate::{
    reply::{ToolError, ToolReply},
    wire::{ReplyBudget, duplicated_size},
};

const DEFAULT_READ_BYTES: u64 = 65_536;

pub(crate) const DIRECTORY_MAX_CURSORS: usize = 8;
pub(crate) const DIRECTORY_CURSORS_PER_TARGET: usize = 2;
pub(crate) const DIRECTORY_PAGE_BYTES: usize = 1_048_576;
pub(crate) const DIRECTORY_MAX_IDLE_SECS: u64 = 300;

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct DirectoryLimits {
    pub(crate) max_cursors: usize,
    pub(crate) idle_timeout_secs: u64,
}

impl Default for DirectoryLimits {
    fn default() -> Self {
        Self {
            max_cursors: DIRECTORY_MAX_CURSORS,
            idle_timeout_secs: 60,
        }
    }
}

impl DirectoryLimits {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !(1..=DIRECTORY_MAX_CURSORS).contains(&self.max_cursors) {
            return Err("max_cursors must be between 1 and 8");
        }
        if !(1..=DIRECTORY_MAX_IDLE_SECS).contains(&self.idle_timeout_secs) {
            return Err("idle_timeout_secs must be between 1 and 300");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Encoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub path: String,
    #[serde(default)]
    pub offset: u64,
    #[schemars(range(min = 1))]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub encoding: Encoding,
    #[schemars(length(equal = 64), pattern(r"^[0-9A-Fa-f]{64}$"))]
    pub expected_content_sha256: Option<String>,
    #[schemars(range(min = 1))]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub struct ReadSpec<'a> {
    pub path: &'a str,
    pub offset: u64,
    pub max_bytes: usize,
    pub encoding: Encoding,
    pub expected_content_sha256: Option<[u8; 32]>,
}

#[derive(Serialize, JsonSchema)]
pub struct ReadData {
    pub content: String,
    pub content_sha256: String,
    pub encoding: Encoding,
    pub bytes_read: u64,
    pub next_offset: u64,
    pub eof: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    pub host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub encoding: Encoding,
    #[serde(default)]
    pub overwrite: bool,
    #[schemars(range(min = 1))]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub struct WriteSpec<'a> {
    pub path: &'a str,
    pub content: Cow<'a, [u8]>,
    pub overwrite: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct WriteData {
    pub bytes_written: u64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MkdirRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) path: String,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct MkdirSpec<'a> {
    pub(crate) path: &'a str,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct MkdirData {
    pub(crate) created: bool,
}

impl MkdirRequest {
    pub(crate) fn validate(&self, budget: ReplyBudget) -> Result<MkdirSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                MkdirData { created: true },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for directory creation")
            })?;
        Ok(MkdirSpec { path: &self.path })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenameRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) source: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) destination: String,
    pub(crate) overwrite: bool,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct RenameSpec<'a> {
    pub(crate) source: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) overwrite: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RenameData {
    pub(crate) renamed: bool,
}

impl RenameRequest {
    pub(crate) fn validate(&self, budget: ReplyBudget) -> Result<RenameSpec<'_>, ToolError> {
        if [&self.source, &self.destination]
            .into_iter()
            .any(|path| path.is_empty() || path.contains('\0'))
        {
            return Err(invalid(
                "source and destination must be nonempty and NUL-free",
            ));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                RenameData { renamed: true },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| invalid("Request leaves insufficient response budget for rename"))?;
        Ok(RenameSpec {
            source: &self.source,
            destination: &self.destination,
            overwrite: self.overwrite,
        })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveFileRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) path: String,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct RemoveFileSpec<'a> {
    pub(crate) path: &'a str,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RemoveFileData {
    pub(crate) removed: bool,
}

impl RemoveFileRequest {
    pub(crate) fn validate(&self, budget: ReplyBudget) -> Result<RemoveFileSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                RemoveFileData { removed: true },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| invalid("Request leaves insufficient response budget for file removal"))?;
        Ok(RemoveFileSpec { path: &self.path })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveDirectoryRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) path: String,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct RemoveDirectorySpec<'a> {
    pub(crate) path: &'a str,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RemoveDirectoryData {
    pub(crate) removed: bool,
}

impl RemoveDirectoryRequest {
    pub(crate) fn validate(
        &self,
        budget: ReplyBudget,
    ) -> Result<RemoveDirectorySpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                RemoveDirectoryData { removed: true },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for directory removal")
            })?;
        Ok(RemoveDirectorySpec { path: &self.path })
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplaceRequest {
    pub(crate) host: String,
    #[schemars(
        length(min = 1),
        pattern(r"^[^\u0000]*$"),
        transform = replacement_path_schema
    )]
    pub(crate) path: String,
    pub(crate) content: String,
    #[serde(default)]
    pub(crate) encoding: Encoding,
    pub(crate) overwrite: bool,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

fn replacement_path_schema(schema: &mut schemars::Schema) {
    // Exclude empty, "." and ".." final entries, including after a slash.
    // Final line terminators are valid filename characters; ECMA-262 `$` may
    // match before them, so do not classify those paths as invalid entries.
    schema.insert(
        "not".to_owned(),
        serde_json::json!({
            "allOf": [
                {"pattern": r"(^|/)[.]{0,2}$"},
                {"not": {"pattern": r"[\r\n\u2028\u2029]$"}}
            ]
        }),
    );
}

#[derive(Debug)]
pub(crate) struct ReplaceSpec<'a> {
    pub(crate) path: &'a str,
    pub(crate) content: Cow<'a, [u8]>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ReplaceData {
    pub(crate) bytes_written: u64,
}

impl ReplaceRequest {
    pub(crate) fn take_validated(
        &mut self,
        max_file_bytes: u64,
        budget: ReplyBudget,
    ) -> Result<(String, Vec<u8>, Option<u64>), ToolError> {
        if !self.overwrite {
            return Err(invalid(
                "Atomic replacement requires explicit overwrite=true",
            ));
        }
        let leaf = self.path.rsplit('/').next().unwrap_or("");
        if self.path.contains('\0') || matches!(leaf, "" | "." | "..") {
            return Err(invalid(
                "path must name a nonempty NUL-free final file entry",
            ));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                ReplaceData {
                    bytes_written: u64::MAX,
                },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| invalid("Request leaves insufficient response budget for replacement"))?;
        let content = decode_content_owned(
            std::mem::take(&mut self.content),
            self.encoding,
            max_file_bytes,
        )?;
        Ok((std::mem::take(&mut self.path), content, self.timeout_secs))
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) follow_symlinks: bool,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct StatSpec<'a> {
    pub(crate) path: &'a str,
    pub(crate) follow_symlinks: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRequest {
    pub(crate) host: String,
    #[schemars(length(min = 1), pattern(r"^[^\u0000]*$"))]
    pub(crate) path: String,
    #[schemars(length(equal = 32), pattern(r"^[0-9a-f]{32}$"))]
    pub(crate) continuation: Option<String>,
    #[schemars(range(min = 1, max = 1000))]
    pub(crate) max_entries: Option<u64>,
    #[schemars(range(min = 1))]
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ListSpec<'a> {
    pub(crate) path: &'a str,
    pub(crate) max_entries: usize,
    pub(crate) remaining_bytes: usize,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ListData {
    #[schemars(length(max = 1000))]
    pub(crate) entries: Vec<ListEntry>,
    pub(crate) truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(length(equal = 32), pattern(r"^[0-9a-f]{32}$"))]
    pub(crate) continuation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub(crate) expires_in_secs: Option<u64>,
}

impl ListData {
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            truncated: false,
            continuation: None,
            expires_in_secs: None,
        }
    }

    pub(crate) fn set_continuation(&mut self, handle: String, idle_timeout_secs: u64) {
        self.truncated = true;
        self.continuation = Some(handle);
        self.expires_in_secs = Some(idle_timeout_secs);
    }

    // Reject only whole entries, retaining the server's prefix. The rejected
    // entry is positive lookahead, so truncation never guesses from the limit.
    pub(crate) fn push(
        &mut self,
        entry: ListEntry,
        spec: &mut ListSpec<'_>,
    ) -> Result<(), ListEntry> {
        let cost = duplicated_size(&entry)
            .ok()
            .and_then(|cost| cost.checked_add(if self.entries.is_empty() { 0 } else { 2 }));
        let remaining = cost.and_then(|cost| spec.remaining_bytes.checked_sub(cost));
        let Some(remaining) = remaining else {
            self.truncated = true;
            return Err(entry);
        };
        spec.remaining_bytes = remaining;
        self.entries.push(entry);
        Ok(())
    }
}

impl ListRequest {
    pub(crate) fn validate(&self, budget: ReplyBudget) -> Result<ListSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        if self.continuation.as_ref().is_some_and(|handle| {
            handle.len() != 32
                || !handle
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(invalid(
                "continuation must contain 32 lowercase hexadecimal characters",
            ));
        }
        let max_entries = self.max_entries.unwrap_or(200);
        if !(1..=1000).contains(&max_entries) {
            return Err(invalid("max_entries must be between 1 and 1000"));
        }
        // Reserve the larger, continued-page envelope up front. Empty ASCII
        // handles reserve the property/quotes; the 32 hex bytes appear twice.
        let mut reservation = ListData::empty();
        reservation.set_continuation(String::new(), DIRECTORY_MAX_IDLE_SECS);
        let remaining_bytes = budget
            .remaining(&ToolReply::success(reservation))
            .and_then(|remaining| {
                budget.remaining(&ToolReply::<ListData>::failure(
                    ToolError::SSH_CONNECT_FAILED,
                ))?;
                Ok(remaining)
            })
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for a directory listing")
            })?;
        let remaining_bytes = remaining_bytes
            .checked_sub(64)
            .ok_or_else(|| {
                invalid("Request leaves insufficient response budget for directory continuation")
            })?
            .min(DIRECTORY_PAGE_BYTES);
        Ok(ListSpec {
            path: &self.path,
            max_entries: max_entries as usize,
            remaining_bytes,
        })
    }
}

impl WriteRequest {
    pub fn validate(
        &self,
        max_file_bytes: u64,
        budget: ReplyBudget,
    ) -> Result<WriteSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                WriteData {
                    bytes_written: u64::MAX,
                },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for a write result")
            })?;
        let content = decode_content(&self.content, self.encoding, max_file_bytes)?;
        Ok(WriteSpec {
            path: &self.path,
            content,
            overwrite: self.overwrite,
        })
    }

    pub(crate) fn take_validated(
        &mut self,
        max_file_bytes: u64,
        budget: ReplyBudget,
    ) -> Result<(String, Vec<u8>, bool, Option<u64>), ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        budget
            .remaining(&ToolReply::partial(
                WriteData {
                    bytes_written: u64::MAX,
                },
                ToolError::SSH_CONNECT_FAILED,
            ))
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for a write result")
            })?;
        let content = decode_content_owned(
            std::mem::take(&mut self.content),
            self.encoding,
            max_file_bytes,
        )?;
        Ok((
            std::mem::take(&mut self.path),
            content,
            self.overwrite,
            self.timeout_secs,
        ))
    }
}

fn decode_content(
    content: &str,
    encoding: Encoding,
    max_file_bytes: u64,
) -> Result<Cow<'_, [u8]>, ToolError> {
    match encoding {
        Encoding::Utf8 => {
            if content.len() as u64 > max_file_bytes {
                return Err(invalid("content exceeds the configured file limit"));
            }
            Ok(Cow::Borrowed(content.as_bytes()))
        }
        Encoding::Base64 => decode_base64(content.as_bytes(), max_file_bytes).map(Cow::Owned),
    }
}

fn decode_content_owned(
    content: String,
    encoding: Encoding,
    max_file_bytes: u64,
) -> Result<Vec<u8>, ToolError> {
    match encoding {
        Encoding::Utf8 => {
            if content.len() as u64 > max_file_bytes {
                return Err(invalid("content exceeds the configured file limit"));
            }
            Ok(content.into_bytes())
        }
        Encoding::Base64 => decode_base64(content.as_bytes(), max_file_bytes),
    }
}

fn decode_base64(input: &[u8], max_file_bytes: u64) -> Result<Vec<u8>, ToolError> {
    if !input.len().is_multiple_of(4) {
        return Err(invalid_base64());
    }
    let padding = if input.ends_with(b"==") {
        2
    } else {
        usize::from(input.ends_with(b"="))
    };
    let decoded_len = (input.len() / 4)
        .checked_mul(3)
        .and_then(|len| len.checked_sub(padding))
        .ok_or_else(invalid_base64)?;
    // Inspect the raw length before allocating the exact decoded buffer.
    if decoded_len as u64 > max_file_bytes {
        return Err(invalid("content exceeds the configured file limit"));
    }
    let mut decoded = vec![0; decoded_len];
    STANDARD
        .decode_slice(input, &mut decoded)
        .map_err(|_| invalid_base64())?;
    Ok(decoded)
}

fn invalid_base64() -> ToolError {
    ToolError::invalid_encoding("content must be canonical padded standard base64", false)
}

impl StatRequest {
    pub(crate) fn validate(&self, budget: ReplyBudget) -> Result<StatSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        // Reserve both complete envelopes conservatively before opening SSH.
        // The longest kind and widest nullable scalar values dominate all
        // metadata replies; the fixed connection error dominates typed failures.
        let reservation = ToolReply::partial(
            StatData {
                kind: FileKind::Directory,
                size: Some(u64::MAX),
                permissions: Some(u32::MAX),
                uid: Some(u32::MAX),
                gid: Some(u32::MAX),
                modified_unix_secs: Some(u64::MAX),
            },
            ToolError::SSH_CONNECT_FAILED,
        );
        budget.remaining(&reservation).map_err(|_| {
            invalid("Request leaves insufficient response budget for file metadata")
        })?;
        Ok(StatSpec {
            path: &self.path,
            follow_symlinks: self.follow_symlinks,
        })
    }
}

fn invalid(message: &'static str) -> ToolError {
    ToolError::invalid_argument(message, false)
}

impl ReadRequest {
    pub fn validate(
        &self,
        max_file_bytes: u64,
        budget: ReplyBudget,
    ) -> Result<ReadSpec<'_>, ToolError> {
        if self.path.is_empty() || self.path.contains('\0') {
            return Err(invalid("path must be nonempty and NUL-free"));
        }
        if self.timeout_secs == Some(0) {
            return Err(invalid("timeout_secs must be positive"));
        }
        let expected_content_sha256 = self
            .expected_content_sha256
            .as_ref()
            .map(|value| {
                let mut digest = [0; 32];
                if value.len() != 64 || hex::decode_to_slice(value, &mut digest).is_err() {
                    return Err(invalid(
                        "expected_content_sha256 must contain exactly 64 hexadecimal ASCII characters",
                    ));
                }
                Ok(digest)
            })
            .transpose()?;
        let max_bytes = validate_read_range(self.max_bytes, self.encoding, max_file_bytes, budget)?;
        Ok(ReadSpec {
            path: &self.path,
            offset: self.offset,
            max_bytes,
            encoding: self.encoding,
            expected_content_sha256,
        })
    }
}

/// Validate the common local/remote byte range before acquiring any IO owner.
pub(crate) fn validate_read_range(
    requested: Option<u64>,
    encoding: Encoding,
    max_file_bytes: u64,
    budget: ReplyBudget,
) -> Result<usize, ToolError> {
    let max_bytes = requested.unwrap_or(DEFAULT_READ_BYTES.min(max_file_bytes));
    if max_bytes == 0 || max_bytes > max_file_bytes {
        return Err(invalid(
            "max_bytes must be positive and within the configured file limit",
        ));
    }
    // Reserve the complete duplicated reply, actual request ID included.
    let reservation = ToolReply::partial(
        ReadData {
            content: String::new(),
            content_sha256: String::new(),
            encoding,
            bytes_read: u64::MAX,
            next_offset: u64::MAX,
            eof: false,
        },
        ToolError::SSH_CONNECT_FAILED,
    );
    // The empty string reserves the digest property and its quotes. Its 64
    // ASCII hex characters appear twice and require no JSON escaping.
    let remaining = budget
        .remaining(&reservation)
        .ok()
        .and_then(|remaining| remaining.checked_sub(128))
        .ok_or_else(|| {
            invalid("Request leaves insufficient response budget for a lossless read")
        })?;
    let max_bytes = usize::try_from(max_bytes)
        .map_err(|_| invalid("max_bytes cannot be represented on this platform"))?;
    if max_bytes.checked_add(1).is_none()
        || wire_content_cost(max_bytes, encoding).is_none_or(|cost| cost > remaining)
    {
        return Err(invalid(
            "max_bytes exceeds the response budget for a lossless read",
        ));
    }
    Ok(max_bytes)
}

fn wire_content_cost(bytes: usize, encoding: Encoding) -> Option<usize> {
    match encoding {
        // A control byte becomes six JSON bytes, then seven in the text
        // representation: thirteen complete wire bytes per original byte.
        Encoding::Utf8 => bytes.checked_mul(13),
        Encoding::Base64 => bytes.checked_add(2)?.checked_div(3)?.checked_mul(8),
    }
}

pub struct RawRead {
    pub bytes: BytesMut,
    pub eof: bool,
}

pub fn encode(raw: RawRead, spec: &ReadSpec<'_>) -> Result<ReadData, ToolError> {
    encode_range(
        raw,
        spec.offset,
        spec.max_bytes,
        spec.encoding,
        spec.expected_content_sha256,
    )
}

pub(crate) fn encode_range(
    mut raw: RawRead,
    offset: u64,
    max_bytes: usize,
    encoding: Encoding,
    expected_content_sha256: Option<[u8; 32]>,
) -> Result<ReadData, ToolError> {
    raw.bytes.truncate(max_bytes);
    let digest: [u8; 32] = Sha256::digest(&raw.bytes).into();
    if expected_content_sha256.is_some_and(|expected| expected != digest) {
        return Err(ToolError::checksum_mismatch(
            "Returned bytes do not match expected_content_sha256",
            false,
        ));
    }
    let bytes_read = raw.bytes.len() as u64;
    let next_offset = offset
        .checked_add(bytes_read)
        .ok_or_else(|| invalid("Returned file offset cannot be represented"))?;
    let content = match encoding {
        Encoding::Utf8 => String::from_utf8(raw.bytes.into()).map_err(|_| ToolError::invalid_encoding(
            "Returned bytes are not complete UTF-8; use encoding base64 for lossless byte ranges",
            false,
        ))?,
        Encoding::Base64 => STANDARD.encode(&raw.bytes),
    };
    Ok(ReadData {
        content,
        content_sha256: hex::encode(digest),
        encoding,
        bytes_read,
        next_offset,
        eof: raw.eof,
    })
}

pub(crate) fn verify_script(
    bytes: Vec<u8>,
    eof: bool,
    expected_content_sha256: &[u8; 32],
    max_bytes: usize,
) -> Result<String, ToolError> {
    if !eof || bytes.len() > max_bytes {
        return Err(ToolError::resource_limit(
            "Script source exceeds its complete byte bound",
            false,
        ));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != *expected_content_sha256 {
        return Err(ToolError::checksum_mismatch(
            "Script source does not match its reviewed content_sha256",
            false,
        ));
    }
    if bytes.contains(&0) {
        return Err(ToolError::invalid_encoding(
            "Script source must be NUL-free UTF-8",
            false,
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| ToolError::invalid_encoding("Script source must be NUL-free UTF-8", false))
}

#[cfg(test)]
mod tests {
    use super::super::metadata::metadata_data;
    use super::*;
    use rmcp::model::RequestId;
    use serde_json::json;

    #[test]
    fn script_verification_requires_complete_exact_bytes_before_decoding() {
        let mut digest = [0; 32];
        hex::decode_to_slice(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            &mut digest,
        )
        .unwrap();
        assert_eq!(
            verify_script(b"abc".to_vec(), true, &digest, 3).unwrap(),
            "abc"
        );
        for (bytes, eof, limit, code) in [
            (b"abc".as_slice(), false, 3, "resource_limit"),
            (b"abcd".as_slice(), true, 3, "resource_limit"),
            (b"ab".as_slice(), true, 3, "checksum_mismatch"),
            (b"abd".as_slice(), true, 3, "checksum_mismatch"),
        ] {
            let error = verify_script(bytes.to_vec(), eof, &digest, limit).unwrap_err();
            assert_eq!(error.code(), code);
            assert!(!error.remote_state_unknown);
        }
        for bytes in [b"\xff".as_slice(), b"abc\0"] {
            let digest = Sha256::digest(bytes).into();
            let error = verify_script(bytes.to_vec(), true, &digest, bytes.len()).unwrap_err();
            assert_eq!(error.code(), "invalid_encoding");
        }
    }

    fn request() -> ReadRequest {
        serde_json::from_value(json!({ "host": "target", "path": "relative/file" })).unwrap()
    }

    fn budget() -> ReplyBudget {
        ReplyBudget::new(&RequestId::Number(1)).unwrap()
    }

    fn write_request(content: &str, encoding: &str) -> WriteRequest {
        serde_json::from_value(json!({
            "host": "target", "path": "literal/file", "content": content, "encoding": encoding,
        }))
        .unwrap()
    }

    #[test]
    fn write_decoding_obeys_exact_byte_caps_including_padding_and_utf8() {
        for (encoded, raw) in [
            ("", &b""[..]),
            ("Zg==", &b"f"[..]),
            ("Zm8=", &b"fo"[..]),
            ("Zm9v", &b"foo"[..]),
            ("AP8=", &b"\0\xff"[..]),
        ] {
            let request = write_request(encoded, "base64");
            assert_eq!(
                &*request
                    .validate(raw.len() as u64, budget())
                    .unwrap()
                    .content,
                raw
            );
            if !raw.is_empty() {
                let error = request
                    .validate(raw.len() as u64 - 1, budget())
                    .unwrap_err();
                assert_eq!(error.code(), "invalid_argument", "encoded: {encoded}");
                assert!(!error.remote_state_unknown);
            }
        }
        let request = write_request("é\0雪", "utf8");
        assert_eq!(
            &*request.validate(6, budget()).unwrap().content,
            "é\0雪".as_bytes()
        );
        assert_eq!(
            request.validate(5, budget()).unwrap_err().code(),
            "invalid_argument"
        );
    }

    #[test]
    fn write_rejects_noncanonical_base64_without_accepting_lossy_or_urlsafe_input() {
        for content in [
            "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "====", "--__", "Zm9v\n", "雪",
        ] {
            let error = write_request(content, "base64")
                .validate(100, budget())
                .unwrap_err();
            assert_eq!(error.code(), "invalid_encoding", "content: {content:?}");
            assert!(!error.remote_state_unknown);
        }
        // Same encoded length as a one-byte payload, but without padding this
        // contains three bytes. The encoded-length gate must account for that.
        assert_eq!(
            write_request("AAAA", "base64")
                .validate(1, budget())
                .unwrap_err()
                .code(),
            "invalid_argument",
        );
    }

    #[test]
    fn write_reserves_success_and_uncertain_failure_before_decoding() {
        let reservation = ToolReply::partial(
            WriteData {
                bytes_written: u64::MAX,
            },
            ToolError::SSH_CONNECT_FAILED,
        );
        let available = ReplyBudget::new(&RequestId::String("".into()))
            .unwrap()
            .remaining(&reservation)
            .unwrap();
        let id = RequestId::String("x".repeat(available).into());
        let boundary = ReplyBudget::new(&id).unwrap();
        assert!(write_request("", "utf8").validate(1, boundary).is_ok());
        assert!(
            boundary
                .result(ToolReply::success(WriteData {
                    bytes_written: u64::MAX
                }))
                .is_ok()
        );
        let mut error = ToolError::SSH_CONNECT_FAILED;
        error.remote_state_unknown = true;
        assert!(
            boundary
                .result(ToolReply::<WriteData>::failure(error))
                .is_ok()
        );
        let id = RequestId::String("x".repeat(available + 1).into());
        let error = write_request("Zg==", "base64")
            .validate(1, ReplyBudget::new(&id).unwrap())
            .unwrap_err();
        assert_eq!(error.code(), "invalid_argument");
        assert!(!error.remote_state_unknown);
    }

    fn list_entry() -> ListEntry {
        ListEntry {
            name: Some("é\"\\\n\u{1}".repeat(20)),
            name_base64: STANDARD.encode(b"raw filename"),
            metadata: metadata_data(openssh_sftp_client::metadata::MetaDataBuilder::new().create()),
        }
    }

    #[test]
    fn listing_counts_both_escaped_representations_and_commas_at_exact_wire_boundary() {
        let request: ListRequest =
            serde_json::from_value(json!({"host":"target","path":"directory"})).unwrap();
        let reply = ToolReply::success(ListData {
            entries: vec![list_entry(), list_entry()],
            truncated: true,
            continuation: Some("0".repeat(32)),
            expires_in_secs: Some(DIRECTORY_MAX_IDLE_SECS),
        });
        let remaining = ReplyBudget::new(&RequestId::String("".into()))
            .unwrap()
            .remaining(&reply)
            .unwrap();
        for extra in [0, 1] {
            let id = RequestId::String("x".repeat(remaining + extra).into());
            let budget = ReplyBudget::new(&id).unwrap();
            let mut spec = request.validate(budget).unwrap();
            let mut data = ListData::empty();
            assert!(data.push(list_entry(), &mut spec).is_ok());
            assert_eq!(data.push(list_entry(), &mut spec).is_ok(), extra == 0);
            if extra == 0 {
                assert!(!data.truncated, "exact fit was falsely truncated");
                assert_eq!(spec.remaining_bytes, 0);
                data.set_continuation("0".repeat(32), DIRECTORY_MAX_IDLE_SECS);
                let result = budget.result(ToolReply::success(data)).unwrap();
                let frame = rmcp::model::JsonRpcResponse {
                    jsonrpc: Default::default(),
                    id,
                    result,
                };
                assert_eq!(
                    serde_json::to_vec(&frame).unwrap().len() + 1,
                    crate::wire::MAX_RESPONSE_BYTES
                );
            } else {
                assert!(data.truncated);
                assert_eq!(data.entries.len(), 1);
                data.set_continuation("0".repeat(32), DIRECTORY_MAX_IDLE_SECS);
                assert!(budget.result(ToolReply::success(data)).is_ok());
            }
        }
    }

    #[test]
    fn listing_reports_truncation_when_no_whole_entry_fits() {
        let mut spec = ListSpec {
            path: "directory",
            max_entries: 1,
            remaining_bytes: 0,
        };
        let mut data = ListData::empty();
        assert!(data.push(list_entry(), &mut spec).is_err());
        assert!(data.entries.is_empty() && data.truncated);
    }

    #[test]
    fn stat_paths_remain_literal_and_following_requires_an_explicit_boolean() {
        let path = "-é/../~/$HOME; 'quoted'\n*";
        let mut request: StatRequest =
            serde_json::from_value(json!({"host": "target", "path": path})).unwrap();
        let spec = request.validate(budget()).unwrap();
        assert_eq!(spec.path, path);
        assert!(!spec.follow_symlinks);
        request.follow_symlinks = true;
        assert!(request.validate(budget()).unwrap().follow_symlinks);
        for path in ["", "a\0b"] {
            request.path = path.into();
            let error = request.validate(budget()).unwrap_err();
            assert_eq!(error.code(), "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
        request.path = "file".into();
        request.timeout_secs = Some(0);
        assert_eq!(
            request.validate(budget()).unwrap_err().code(),
            "invalid_argument"
        );
        for value in [
            json!({"host": "target", "path": "file", "follow_symlinks": "true"}),
            json!({"host": "target", "path": "file", "follow_symlinks": null}),
            json!({"host": "target", "path": "file", "sudo": true}),
        ] {
            assert!(serde_json::from_value::<StatRequest>(value).is_err());
        }
    }

    #[test]
    fn stat_reserves_the_complete_reply_at_the_actual_request_id_boundary() {
        let request: StatRequest =
            serde_json::from_value(json!({"host": "target", "path": "file"})).unwrap();
        let widest = StatData {
            kind: FileKind::Directory,
            size: Some(u64::MAX),
            permissions: Some(u32::MAX),
            uid: Some(u32::MAX),
            gid: Some(u32::MAX),
            modified_unix_secs: Some(u64::MAX),
        };
        let reservation = ToolReply::partial(widest, ToolError::SSH_CONNECT_FAILED);
        let empty_id = RequestId::String("".into());
        let remaining = ReplyBudget::new(&empty_id)
            .unwrap()
            .remaining(&reservation)
            .unwrap();
        let id = RequestId::String("x".repeat(remaining).into());
        let boundary = ReplyBudget::new(&id).unwrap();
        assert!(request.validate(boundary).is_ok());
        assert!(boundary.result(ToolReply::success(widest)).is_ok());
        assert!(
            boundary
                .result(ToolReply::<StatData>::failure(
                    ToolError::SSH_CONNECT_FAILED
                ))
                .is_ok()
        );
        let id = RequestId::String("x".repeat(remaining + 1).into());
        let error = request
            .validate(ReplyBudget::new(&id).unwrap())
            .unwrap_err();
        assert_eq!(error.code(), "invalid_argument");
        assert!(!error.remote_state_unknown);
    }

    // NIST SHAVS SHA256ShortMsg.rsp (empty and d3), published in
    // https://core.tcl-lang.org/tcltls/artifact/58d145302d6ac9b7;
    // FIPS 180-4's standard "abc" example.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const BINARY_SHA256: &str = "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1";

    #[test]
    fn returned_digests_match_published_raw_byte_vectors_not_base64_text() {
        for (bytes, digest, base64) in [
            (&b""[..], EMPTY_SHA256, ""),
            (&b"abc"[..], ABC_SHA256, "YWJj"),
            (&b"\xd3"[..], BINARY_SHA256, "0w=="),
        ] {
            let data = encoded(bytes, 10, 0, Encoding::Base64, true).unwrap();
            assert_eq!(data.content, base64);
            assert_eq!(data.content_sha256, digest, "raw bytes: {bytes:?}");
            assert_eq!(data.bytes_read, bytes.len() as u64);
            assert!(data.eof);
        }
        let data = encoded(b"abc", 3, 0, Encoding::Utf8, true).unwrap();
        assert_eq!(data.content, "abc");
        assert_eq!(data.content_sha256, ABC_SHA256);
    }

    #[test]
    fn uppercase_expected_digest_verifies_only_the_retained_offset_range() {
        let mut request = request();
        request.offset = 47;
        request.max_bytes = Some(3);
        request.expected_content_sha256 = Some(ABC_SHA256.to_ascii_uppercase());
        let spec = request.validate(100, budget()).unwrap();
        let data = encode(
            RawRead {
                bytes: BytesMut::from(&b"abc!"[..]),
                eof: false,
            },
            &spec,
        )
        .unwrap();
        assert_eq!(data.content, "abc");
        assert_eq!(data.content_sha256, ABC_SHA256);
        assert_eq!(data.bytes_read, 3);
        assert_eq!(data.next_offset, 50);
        assert!(!data.eof);

        request.offset = u64::MAX;
        request.expected_content_sha256 = Some(EMPTY_SHA256.into());
        let spec = request.validate(100, budget()).unwrap();
        let data = encode(
            RawRead {
                bytes: BytesMut::new(),
                eof: true,
            },
            &spec,
        )
        .unwrap();
        assert_eq!(data.content_sha256, EMPTY_SHA256);
        assert_eq!(data.next_offset, u64::MAX);
    }

    #[test]
    fn checksum_mismatch_returns_no_content_or_digest_and_known_remote_state() {
        let mut request = request();
        request.expected_content_sha256 = Some(EMPTY_SHA256.into());
        let spec = request.validate(100, budget()).unwrap();
        let error = encode(
            RawRead {
                bytes: BytesMut::from(&b"abc"[..]),
                eof: true,
            },
            &spec,
        )
        .err()
        .unwrap();
        let reply: ToolReply<ReadData> = ToolReply::failure(error);
        let reply = serde_json::to_value(reply).unwrap();
        assert_eq!(reply["data"], serde_json::Value::Null);
        assert_eq!(reply["error"]["code"], "checksum_mismatch");
        assert_eq!(reply["error"]["remote_state_unknown"], false);
    }

    #[test]
    fn malformed_expected_digests_fail_validation_before_io() {
        for value in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            format!("{} ", "a".repeat(63)),
            "é".repeat(32),
            format!("0x{}", "a".repeat(62)),
        ] {
            let mut request = request();
            request.expected_content_sha256 = Some(value);
            let error = request.validate(100, budget()).unwrap_err();
            assert_eq!(error.code(), "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }

    #[test]
    fn digest_budget_reservation_enforces_the_complete_duplicated_frame_boundary() {
        let id = RequestId::String("consumer-id".repeat(50).into());
        let budget = ReplyBudget::new(&id).unwrap();
        for encoding in [Encoding::Utf8, Encoding::Base64] {
            let mut reservation = ToolReply::partial(
                ReadData {
                    content: String::new(),
                    content_sha256: ABC_SHA256.into(),
                    encoding,
                    bytes_read: u64::MAX,
                    next_offset: u64::MAX,
                    eof: false,
                },
                ToolError::SSH_CONNECT_FAILED,
            );
            let remaining = budget.remaining(&reservation).unwrap();
            reservation.data_mut().unwrap().content_sha256.clear();
            assert_eq!(budget.remaining(&reservation).unwrap(), remaining + 128);
            reservation.data_mut().unwrap().content_sha256 = ABC_SHA256.into();
            let (max_bytes, content) = match encoding {
                Encoding::Utf8 => {
                    let count = remaining / 13;
                    (count, "\u{1}".repeat(count))
                }
                Encoding::Base64 => {
                    let groups = remaining / 8;
                    (groups * 3, "A".repeat(groups * 4))
                }
            };
            let mut request = request();
            request.encoding = encoding;
            request.max_bytes = Some(max_bytes as u64);
            assert!(request.validate(u64::MAX, budget).is_ok());
            request.max_bytes = Some(max_bytes as u64 + 1);
            assert_eq!(
                request.validate(u64::MAX, budget).unwrap_err().code(),
                "invalid_argument"
            );
            reservation.data_mut().unwrap().content = content;
            assert!(budget.remaining(&reservation).is_ok());
            // One additional raw byte costs a full base64 group, or thirteen
            // bytes for this UTF-8 control character, across both wire copies.
            reservation
                .data_mut()
                .unwrap()
                .content
                .push_str(match encoding {
                    Encoding::Utf8 => "\u{1}",
                    Encoding::Base64 => "AAAA",
                });
            assert!(budget.remaining(&reservation).is_err());
        }
    }

    #[test]
    fn defaults_cap_the_read_without_restricting_offsets_or_relative_paths() {
        let mut request = request();
        request.offset = u64::MAX;
        let spec = request.validate(100_000, budget()).unwrap();
        assert_eq!(spec.max_bytes, 65_536);
        assert_eq!(spec.offset, u64::MAX);
        assert_eq!(spec.path, "relative/file");
        assert_eq!(request.validate(10, budget()).unwrap().max_bytes, 10);
    }

    #[test]
    fn invalid_inputs_are_rejected_before_any_channel_or_content_allocation() {
        for path in ["", "a\0b"] {
            let mut request = request();
            request.path = path.into();
            assert_eq!(
                request.validate(100, budget()).unwrap_err().code(),
                "invalid_argument"
            );
        }
        for count in [0, 101, u64::MAX] {
            let mut request = request();
            request.max_bytes = Some(count);
            assert_eq!(
                request.validate(100, budget()).unwrap_err().code(),
                "invalid_argument"
            );
        }
        let mut request = request();
        request.timeout_secs = Some(0);
        assert!(
            !request
                .validate(100, budget())
                .unwrap_err()
                .remote_state_unknown
        );
        request.timeout_secs = None;
        assert!(request.validate(0, budget()).is_err());
    }

    #[test]
    fn unknown_fields_and_encodings_are_not_silently_accepted() {
        for value in [
            json!({"host":"target", "path":"file", "encoding":"UTF8"}),
            json!({"host":"target", "path":"file", "encoding":"lossy"}),
            json!({"host":"target", "path":"file", "sudo":true}),
        ] {
            assert!(serde_json::from_value::<ReadRequest>(value).is_err());
        }
    }

    #[test]
    fn budget_rejects_huge_requests_and_accounts_for_actual_id_and_encoding() {
        let mut request = request();
        request.max_bytes = Some(u64::MAX);
        assert!(request.validate(u64::MAX, budget()).is_err());
        request.max_bytes = Some(1_000_000);
        assert!(request.validate(u64::MAX, budget()).is_ok());
        let large_id = RequestId::String("x".repeat(4_000_000).into());
        let large_budget = ReplyBudget::new(&large_id).unwrap();
        assert!(request.validate(u64::MAX, large_budget).is_err());
        request.encoding = Encoding::Base64;
        assert!(request.validate(u64::MAX, large_budget).is_ok());
        assert_eq!(wire_content_cost(1, Encoding::Utf8), Some(13));
        assert_eq!(wire_content_cost(1, Encoding::Base64), Some(8));
        assert_eq!(wire_content_cost(3, Encoding::Base64), Some(8));
        assert_eq!(wire_content_cost(4, Encoding::Base64), Some(16));
        assert!(wire_content_cost(usize::MAX, Encoding::Utf8).is_none());
        assert!(wire_content_cost(usize::MAX, Encoding::Base64).is_none());
    }

    fn encoded(
        bytes: &[u8],
        max_bytes: usize,
        offset: u64,
        encoding: Encoding,
        eof: bool,
    ) -> Result<ReadData, ToolError> {
        encode(
            RawRead {
                bytes: BytesMut::from(bytes),
                eof,
            },
            &ReadSpec {
                path: "file",
                offset,
                max_bytes,
                encoding,
                expected_content_sha256: None,
            },
        )
    }

    #[test]
    fn strict_utf8_rejects_invalid_and_split_codepoints_without_lossy_replacement() {
        for bytes in [&b"\xff"[..], &b"\xe2\x82"[..], &b"\x82\xac"[..]] {
            let error = encoded(bytes, bytes.len(), 0, Encoding::Utf8, true)
                .err()
                .unwrap();
            assert_eq!(error.code(), "invalid_encoding");
            assert!(!error.remote_state_unknown);
        }
        // Even when lookahead completes a codepoint, the requested range must
        // stand on its own rather than silently dropping or returning bytes.
        assert!(encoded("€".as_bytes(), 2, 0, Encoding::Utf8, false).is_err());
        let data = encoded("€!".as_bytes(), 3, 7, Encoding::Utf8, false).unwrap();
        assert_eq!(data.content, "€");
        assert_eq!(data.bytes_read, 3);
        assert_eq!(data.next_offset, 10);
        assert!(!data.eof);
    }

    #[test]
    fn base64_is_padded_and_lookahead_never_counts_as_returned_bytes() {
        for (bytes, expected) in [
            (&b"f"[..], "Zg=="),
            (&b"fo"[..], "Zm8="),
            (&b"foo"[..], "Zm9v"),
        ] {
            let data = encoded(bytes, bytes.len(), 9, Encoding::Base64, true).unwrap();
            assert_eq!(data.content, expected);
            assert_eq!(data.next_offset, 9 + bytes.len() as u64);
            assert!(data.eof);
        }
        let data = encoded(b"\xff\0x", 2, 5, Encoding::Base64, false).unwrap();
        assert_eq!(data.content, "/wA=");
        assert_eq!(data.bytes_read, 2);
        assert_eq!(data.next_offset, 7);
        assert!(!data.eof);
    }

    #[test]
    fn empty_eof_preserves_even_the_maximum_offset_and_data_shape() {
        let data = encoded(b"", 10, u64::MAX, Encoding::Utf8, true).unwrap();
        assert_eq!(
            serde_json::to_value(data).unwrap(),
            json!({
                "content": "", "encoding": "utf8", "bytes_read": 0,
                "content_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "next_offset": u64::MAX, "eof": true,
            })
        );
        assert!(encoded(b"a", 1, u64::MAX, Encoding::Base64, true).is_err());
    }
}
