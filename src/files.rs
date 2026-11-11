//! Lossless, bounded file operations over independently owned ordinary SFTP channels.
//!
//! No remote commands or privilege changes are involved. Cancellation interrupts
//! the local protocol streams as well as disconnecting this channel, so a remote
//! FIFO cannot retain local library tasks or the caller's channel permit.
//!
//! SHA-256 covers only the returned raw byte range, not the lookahead or encoded
//! content. Separate reads are not a snapshot of a concurrently changing file.
use std::{
    future::Future,
    io::{self, SeekFrom},
    os::unix::ffi::OsStrExt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::BytesMut;
use futures_util::StreamExt;
use openssh::{Session, Stdio};
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions};
use openssh_sftp_error::SftpErrorKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::{
    server::{ToolError, ToolReply},
    wire::{ReplyBudget, duplicated_size},
};

const DEFAULT_READ_BYTES: u64 = 65_536;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Encoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadRequest {
    pub(crate) host: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) offset: u64,
    pub(crate) max_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) encoding: Encoding,
    pub(crate) expected_content_sha256: Option<String>,
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ReadSpec<'a> {
    pub(crate) path: &'a str,
    pub(crate) offset: u64,
    pub(crate) max_bytes: usize,
    pub(crate) encoding: Encoding,
    pub(crate) expected_content_sha256: Option<[u8; 32]>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ReadData {
    pub(crate) content: String,
    pub(crate) content_sha256: String,
    pub(crate) encoding: Encoding,
    pub(crate) bytes_read: u64,
    pub(crate) next_offset: u64,
    pub(crate) eof: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatRequest {
    pub(crate) host: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) follow_symlinks: bool,
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
    pub(crate) path: String,
    pub(crate) max_entries: Option<u64>,
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ListSpec<'a> {
    path: &'a str,
    max_entries: usize,
    remaining_bytes: usize,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ListEntry {
    name: Option<String>,
    name_base64: String,
    metadata: StatData,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ListData {
    entries: Vec<ListEntry>,
    truncated: bool,
}

impl ListData {
    fn empty() -> Self {
        Self {
            entries: Vec::new(),
            truncated: false,
        }
    }

    // Reject only whole entries, retaining the server's prefix. The rejected
    // entry is positive lookahead, so truncation never guesses from the limit.
    fn push(&mut self, entry: ListEntry, spec: &mut ListSpec<'_>) -> bool {
        let cost = duplicated_size(&entry)
            .ok()
            .and_then(|cost| cost.checked_add(if self.entries.is_empty() { 0 } else { 2 }));
        let remaining = cost.and_then(|cost| spec.remaining_bytes.checked_sub(cost));
        let Some(remaining) = remaining else {
            self.truncated = true;
            return false;
        };
        spec.remaining_bytes = remaining;
        self.entries.push(entry);
        true
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
        let max_entries = self.max_entries.unwrap_or(200);
        if !(1..=1000).contains(&max_entries) {
            return Err(invalid("max_entries must be between 1 and 1000"));
        }
        let remaining_bytes = budget
            .remaining(&ToolReply::success(ListData::empty()))
            .and_then(|remaining| {
                budget.remaining(&ToolReply::<ListData>::failure(
                    ToolError::SSH_CONNECT_FAILED,
                ))?;
                Ok(remaining)
            })
            .map_err(|_| {
                invalid("Request leaves insufficient response budget for a directory listing")
            })?;
        Ok(ListSpec {
            path: &self.path,
            max_entries: max_entries as usize,
            remaining_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub(crate) struct StatData {
    pub(crate) kind: FileKind,
    pub(crate) size: Option<u64>,
    pub(crate) permissions: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) modified_unix_secs: Option<u64>,
}

pub(crate) fn metadata_data(metadata: openssh_sftp_client::metadata::MetaData) -> StatData {
    let kind = match metadata.file_type() {
        Some(kind) if kind.is_file() => FileKind::File,
        Some(kind) if kind.is_dir() => FileKind::Directory,
        Some(kind) if kind.is_symlink() => FileKind::Symlink,
        Some(_) => FileKind::Other,
        None => FileKind::Unknown,
    };
    StatData {
        kind,
        size: metadata.len(),
        permissions: metadata
            .permissions()
            .map(|mode| mode.as_raw().bits() & 0o7777),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_unix_secs: metadata.modified().map(|time| u64::from(time.into_raw())),
    }
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
        let reservation = ToolReply {
            data: Some(StatData {
                kind: FileKind::Directory,
                size: Some(u64::MAX),
                permissions: Some(u32::MAX),
                uid: Some(u32::MAX),
                gid: Some(u32::MAX),
                modified_unix_secs: Some(u64::MAX),
            }),
            error: Some(ToolError::SSH_CONNECT_FAILED),
        };
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
    ToolError::new("invalid_argument", message, false)
}

impl ReadRequest {
    pub(crate) fn validate(
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
        let max_bytes = self
            .max_bytes
            .unwrap_or(DEFAULT_READ_BYTES.min(max_file_bytes));
        if max_bytes == 0 || max_bytes > max_file_bytes {
            return Err(invalid(
                "max_bytes must be positive and within the configured file limit",
            ));
        }
        // Reserve the complete duplicated reply, actual request ID included, before
        // opening SSH or allocating content. False and u64::MAX are widest.
        let reservation = ToolReply {
            data: Some(ReadData {
                content: String::new(),
                content_sha256: String::new(),
                encoding: self.encoding,
                bytes_read: u64::MAX,
                next_offset: u64::MAX,
                eof: false,
            }),
            error: Some(ToolError::SSH_CONNECT_FAILED),
        };
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
            || wire_content_cost(max_bytes, self.encoding).is_none_or(|cost| cost > remaining)
        {
            return Err(invalid(
                "max_bytes exceeds the response budget for a lossless read",
            ));
        }
        Ok(ReadSpec {
            path: &self.path,
            offset: self.offset,
            max_bytes,
            encoding: self.encoding,
            expected_content_sha256,
        })
    }
}

fn wire_content_cost(bytes: usize, encoding: Encoding) -> Option<usize> {
    match encoding {
        // A control byte becomes six JSON bytes, then seven in the text
        // representation: thirteen complete wire bytes per original byte.
        Encoding::Utf8 => bytes.checked_mul(13),
        Encoding::Base64 => bytes.checked_add(2)?.checked_div(3)?.checked_mul(8),
    }
}

pub(crate) struct FileContext<'a> {
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) ct: &'a CancellationToken,
    pub(crate) shutdown: &'a CancellationToken,
}

pub(crate) struct FileOutcome<T> {
    pub(crate) reply: ToolReply<T>,
    pub(crate) check_master: bool,
}

struct Failure {
    error: ToolError,
    check_master: bool,
}

impl Failure {
    fn io() -> Self {
        Self {
            error: ToolError::new("io_error", "SFTP file operation failed", false),
            check_master: false,
        }
    }

    fn cleanup() -> Self {
        Self {
            error: ToolError::new(
                "io_error",
                "SFTP channel cleanup did not complete within its deadline",
                true,
            ),
            check_master: false,
        }
    }
}

fn io_failure(error: &io::Error) -> Failure {
    let (code, message, check_master) = match error.kind() {
        io::ErrorKind::NotFound => ("not_found", "Remote file was not found", false),
        io::ErrorKind::PermissionDenied => {
            ("permission_denied", "Remote file access was denied", false)
        }
        io::ErrorKind::Unsupported => ("unsupported", "SFTP operation is not supported", false),
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::NotConnected => {
            ("connection_lost", "SFTP channel connection was lost", true)
        }
        _ => return Failure::io(),
    };
    Failure {
        error: ToolError::new(code, message, false),
        check_master,
    }
}

fn sftp_failure(error: SftpError) -> Failure {
    let (code, message) = match error {
        SftpError::SftpError(SftpErrorKind::NoSuchFile, _) => {
            ("not_found", "Remote file was not found")
        }
        SftpError::SftpError(SftpErrorKind::PermDenied, _) => {
            ("permission_denied", "Remote file access was denied")
        }
        SftpError::SftpError(SftpErrorKind::OpUnsupported, _)
        | SftpError::UnsupportedSftpProtocol { .. }
        | SftpError::UnsupportedExtension(_) => ("unsupported", "SFTP operation is not supported"),
        SftpError::IOError(error) => return io_failure(&error),
        SftpError::RecursiveErrors(errors) => {
            let mut original = sftp_failure(errors.original_error);
            original.check_master |= sftp_failure(errors.occuring_error).check_master;
            return original;
        }
        SftpError::RecursiveErrors3(errors) => {
            let mut original = sftp_failure(errors.err1);
            original.check_master |= sftp_failure(errors.err2).check_master;
            original.check_master |= sftp_failure(errors.err3).check_master;
            return original;
        }
        SftpError::AwaitableError(_) | SftpError::BackgroundTaskFailure(_) => {
            return Failure {
                error: ToolError::new("connection_lost", "SFTP channel connection was lost", false),
                check_master: true,
            };
        }
        _ => return Failure::io(),
    };
    Failure {
        error: ToolError::new(code, message, false),
        check_master: false,
    }
}

fn ssh_failure(error: openssh::Error) -> Failure {
    match error {
        // openssh maps a subsystem process's exit 127 to Remote(NotFound).
        // That is not an SFTP file-status response and must not blame the path.
        openssh::Error::Remote(error) if error.kind() == io::ErrorKind::NotFound => Failure::io(),
        openssh::Error::Remote(error) | openssh::Error::ChildIo(error) => io_failure(&error),
        openssh::Error::Master(_)
        | openssh::Error::Connect(_)
        | openssh::Error::SshMux(_)
        | openssh::Error::Disconnected
        | openssh::Error::RemoteProcessTerminated => Failure {
            error: ToolError::new(
                "connection_lost",
                "SFTP channel could not be opened or was lost",
                false,
            ),
            check_master: true,
        },
        _ => Failure::io(),
    }
}

// The native child alone is not sufficient cancellation: library tasks own the
// transferred pipes. Each pipe also has an independent local cancellation wakeup.
// Its completion signal lets bounded cleanup await release of those task-owned
// streams, including cancellation during Sftp::new's initialization handshake.
struct ChannelStream<T> {
    inner: T,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
    // Field drop order matters: signal only after the inner pipe is released.
    _released: oneshot::Sender<()>,
}

impl<T> ChannelStream<T> {
    fn new(inner: T, cancel: &CancellationToken) -> (Self, oneshot::Receiver<()>) {
        let (released, receiver) = oneshot::channel();
        (
            Self {
                inner,
                cancelled: Box::pin(cancel.clone().cancelled_owned()),
                _released: released,
            },
            receiver,
        )
    }

    fn interrupted(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancelled.as_mut().poll(cx).is_ready()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ChannelStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.interrupted(cx) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ChannelStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.interrupted(cx) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.interrupted(cx) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.interrupted(cx) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct RawRead {
    bytes: BytesMut,
    eof: bool,
}

async fn read_handle(
    file: &mut openssh_sftp_client::file::File,
    spec: &ReadSpec<'_>,
) -> Result<RawRead, Failure> {
    // OpenSSH's server uses signed OS offsets. Do not turn a regular file's
    // unrepresentable, past-EOF offset into an error, or infer EOF from FIFO size.
    if spec.offset > i64::MAX as u64 {
        let metadata = file.metadata().await.map_err(sftp_failure)?;
        if metadata.file_type().is_some_and(|kind| kind.is_file())
            && metadata.len().is_some_and(|len| spec.offset >= len)
        {
            return Ok(RawRead {
                bytes: BytesMut::new(),
                eof: true,
            });
        }
    }
    let target = spec.max_bytes.checked_add(1).ok_or_else(Failure::io)?;
    let mut bytes = BytesMut::with_capacity(target);
    while bytes.len() < target {
        let offset = spec
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(Failure::io)?;
        // File::read advances its own cursor by requested n, even on a short
        // response. Always reset from actual bytes received, never that cursor.
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|error| io_failure(&error))?;
        let count = (target - bytes.len())
            .min(u32::MAX as usize)
            .min((u64::MAX - offset).min(usize::MAX as u64) as usize);
        if count == 0 {
            return Err(Failure::io());
        }
        // Split off spare capacity and join adjacent buffers without copying.
        let spare = bytes.split_off(bytes.len());
        match file.read(count as u32, spare).await.map_err(sftp_failure)? {
            None => return Ok(RawRead { bytes, eof: true }),
            Some(chunk) if chunk.is_empty() || chunk.len() > count => return Err(Failure::io()),
            Some(chunk) => bytes.unsplit(chunk),
        }
    }
    Ok(RawRead { bytes, eof: false })
}

async fn read_sftp(sftp: Sftp, spec: &ReadSpec<'_>) -> Result<RawRead, Failure> {
    let (result, file) = match sftp.open(spec.path).await {
        Ok(mut file) => (read_handle(&mut file, spec).await, Some(file)),
        Err(error) => (Err(sftp_failure(error)), None),
    };
    let close = async {
        let file_close = match file {
            Some(file) => file.close().await.map_err(sftp_failure),
            None => Ok(()),
        };
        combine_close(file_close, sftp.close().await.map_err(sftp_failure))
    };
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, close)
        .await
        .unwrap_or_else(|_| Err(Failure::cleanup()));
    combine_close(result, close)
}

async fn stat_sftp(sftp: Sftp, spec: StatSpec<'_>) -> Result<StatData, Failure> {
    let result = {
        // Fs retains library resources: drop it before waiting for Sftp::close.
        let mut fs = sftp.fs();
        let metadata = if spec.follow_symlinks {
            fs.metadata(spec.path).await
        } else {
            fs.symlink_metadata(spec.path).await
        };
        metadata.map(metadata_data).map_err(sftp_failure)
    };
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
    combine_close(result, close)
}

async fn list_sftp(sftp: Sftp, mut spec: ListSpec<'_>) -> Result<ListData, Failure> {
    let result = async {
        let dir = {
            let mut fs = sftp.fs();
            fs.open_dir(spec.path).await.map_err(sftp_failure)?
        };
        let stream = dir.read_dir();
        tokio::pin!(stream);
        let mut data = ListData::empty();
        while let Some(entry) = stream.next().await {
            let entry = entry.map_err(sftp_failure)?;
            let bytes = entry.filename().as_os_str().as_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            if data.entries.len() == spec.max_entries {
                data.truncated = true;
                break;
            }
            let entry = ListEntry {
                name: std::str::from_utf8(bytes).ok().map(str::to_owned),
                name_base64: STANDARD.encode(bytes),
                metadata: metadata_data(entry.metadata()),
            };
            if !data.push(entry, &mut spec) {
                break;
            }
        }
        Ok(data)
    }
    .await;
    // ReadDir has no explicit close API: its drop schedules the library-owned
    // directory close. Drop the stream first, then await all protocol work via
    // Sftp::close under the same bounded cleanup used by other file operations.
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
    combine_close(result, close)
}

fn combine_close<T>(result: Result<T, Failure>, close: Result<(), Failure>) -> Result<T, Failure> {
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(mut original), Err(cleanup)) => {
            original.check_master |= cleanup.check_master;
            original.error.remote_state_unknown |= cleanup.error.remote_state_unknown;
            Err(original)
        }
    }
}

fn encode(mut raw: RawRead, spec: &ReadSpec<'_>) -> Result<ReadData, ToolError> {
    raw.bytes.truncate(spec.max_bytes);
    let digest: [u8; 32] = Sha256::digest(&raw.bytes).into();
    if spec
        .expected_content_sha256
        .is_some_and(|expected| expected != digest)
    {
        return Err(ToolError::new(
            "checksum_mismatch",
            "Returned bytes do not match expected_content_sha256",
            false,
        ));
    }
    let bytes_read = raw.bytes.len() as u64;
    let next_offset = spec
        .offset
        .checked_add(bytes_read)
        .ok_or_else(|| invalid("Returned file offset cannot be represented"))?;
    let content = match spec.encoding {
        Encoding::Utf8 => String::from_utf8(raw.bytes.into()).map_err(|_| ToolError::new(
            "invalid_encoding",
            "Returned bytes are not complete UTF-8; use encoding base64 for lossless byte ranges",
            false,
        ))?,
        Encoding::Base64 => STANDARD.encode(&raw.bytes),
    };
    Ok(ReadData {
        content,
        content_sha256: hex::encode(digest),
        encoding: spec.encoding,
        bytes_read,
        next_offset,
        eof: raw.eof,
    })
}

pub(crate) async fn read(
    session: &Session,
    spec: ReadSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<ReadData> {
    let outcome = run_sftp(session, context, |sftp| read_sftp(sftp, &spec)).await;
    FileOutcome {
        reply: match outcome.reply.data {
            Some(raw) => match encode(raw, &spec) {
                Ok(data) => ToolReply::success(data),
                Err(error) => ToolReply::failure(error),
            },
            None => ToolReply {
                data: None,
                error: outcome.reply.error,
            },
        },
        check_master: outcome.check_master,
    }
}

pub(crate) async fn stat(
    session: &Session,
    spec: StatSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<StatData> {
    run_sftp(session, context, |sftp| stat_sftp(sftp, spec)).await
}

pub(crate) async fn list(
    session: &Session,
    spec: ListSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<ListData> {
    run_sftp(session, context, |sftp| list_sftp(sftp, spec)).await
}

async fn run_sftp<T, F, Fut>(
    session: &Session,
    context: FileContext<'_>,
    operation: F,
) -> FileOutcome<T>
where
    F: FnOnce(Sftp) -> Fut,
    Fut: Future<Output = Result<T, Failure>>,
{
    let cancel = CancellationToken::new();
    // Also wake library tasks if our caller drops the entire operation future.
    let _cancel_on_drop = cancel.clone().drop_guard();
    let mut child = None;
    let mut dispatched = false;
    let mut released = [None, None];
    let result = {
        let operation = async {
            // Once polled, a channel request may reach the server even if the
            // spawn future is later cancelled before returning its handle.
            dispatched = true;
            child = Some(
                session
                    .subsystem("sftp")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .await
                    .map_err(ssh_failure)?,
            );
            let channel = child.as_mut().ok_or_else(Failure::io)?;
            let stdin = channel.stdin().take().ok_or_else(Failure::io)?;
            let stdout = channel.stdout().take().ok_or_else(Failure::io)?;
            let mut stderr = channel.stderr().take().ok_or_else(Failure::io)?;
            let (stdin, input_released) = ChannelStream::new(stdin, &cancel);
            let (stdout, output_released) = ChannelStream::new(stdout, &cancel);
            released = [Some(input_released), Some(output_released)];
            let protocol = async {
                let sftp = Sftp::new(stdin, stdout, SftpOptions::default())
                    .await
                    .map_err(sftp_failure)?;
                operation(sftp).await
            };
            let drain = async { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await };
            tokio::pin!(protocol, drain);
            let result = tokio::select! {
                result = &mut protocol => {
                    let raw = result?;
                    tokio::time::timeout(CLEANUP_TIMEOUT, &mut drain)
                        .await.map_err(|_| Failure::cleanup())?
                        .map_err(|error| io_failure(&error))?;
                    Ok(raw)
                }
                drained = &mut drain => {
                    drained.map_err(|error| io_failure(&error))?;
                    protocol.await
                }
            };
            let status = tokio::time::timeout(
                CLEANUP_TIMEOUT,
                child.take().ok_or_else(Failure::io)?.wait(),
            )
            .await
            .map_err(|_| Failure::cleanup())?
            .map_err(ssh_failure);
            let closed = match status {
                Ok(status) if status.success() => Ok(()),
                Ok(_) => Err(Failure::io()),
                Err(error) => Err(error),
            };
            combine_close(result, closed)
        };
        tokio::select! {
            biased;
            () = context.ct.cancelled() => Err(Failure {
                error: ToolError::new("cancelled", "SFTP file operation cancelled", false),
                check_master: false,
            }),
            () = context.shutdown.cancelled() => Err(Failure {
                error: ToolError::new("cancelled", "SFTP file operation cancelled", false),
                check_master: false,
            }),
            () = tokio::time::sleep_until(context.deadline) => Err(Failure {
                error: ToolError::new("timeout", "SFTP file operation deadline exceeded", false),
                check_master: false,
            }),
            result = operation => result,
        }
    };
    // Operation futures and every File/Sftp handle have now been dropped. Wake
    // blocked protocol reads before disconnecting ONLY this child, not its master.
    cancel.cancel();
    let cleanup = async {
        if let Some(child) = child.take() {
            let _ = child.disconnect().await;
        }
        for receiver in released.into_iter().flatten() {
            let _ = receiver.await;
        }
    };
    let cleanup_timed_out = tokio::time::timeout(CLEANUP_TIMEOUT, cleanup)
        .await
        .is_err();
    match result {
        Ok(data) if !cleanup_timed_out => FileOutcome {
            reply: ToolReply::success(data),
            check_master: false,
        },
        Ok(_) => FileOutcome {
            reply: ToolReply::failure(Failure::cleanup().error),
            check_master: false,
        },
        Err(mut failure) => {
            if cleanup_timed_out
                || (dispatched
                    && matches!(
                        failure.error.code,
                        "timeout" | "cancelled" | "connection_lost"
                    ))
            {
                failure.error.remote_state_unknown = true;
            }
            FileOutcome {
                reply: ToolReply::failure(failure.error),
                check_master: failure.check_master,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::RequestId;
    use serde_json::json;

    fn request() -> ReadRequest {
        serde_json::from_value(json!({ "host": "target", "path": "relative/file" })).unwrap()
    }

    fn budget() -> ReplyBudget {
        ReplyBudget::new(&RequestId::Number(1)).unwrap()
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
            truncated: false,
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
            assert!(data.push(list_entry(), &mut spec));
            assert_eq!(data.push(list_entry(), &mut spec), extra == 0);
            if extra == 0 {
                assert!(!data.truncated, "exact fit was falsely truncated");
                assert_eq!(spec.remaining_bytes, 0);
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
        assert!(!data.push(list_entry(), &mut spec));
        assert!(data.entries.is_empty() && data.truncated);
    }

    #[test]
    fn absent_metadata_stays_null_and_does_not_imply_a_file_kind() {
        let data = metadata_data(openssh_sftp_client::metadata::MetaDataBuilder::new().create());
        assert_eq!(
            serde_json::to_value(data).unwrap(),
            json!({
                "kind": "unknown",
                "size": null,
                "permissions": null,
                "uid": null,
                "gid": null,
                "modified_unix_secs": null,
            })
        );
    }

    #[test]
    fn explicit_zero_metadata_is_not_treated_as_missing() {
        use openssh_sftp_client::{
            UnixTimeStamp,
            metadata::{MetaDataBuilder, Permissions},
        };
        let metadata = MetaDataBuilder::new()
            .len(0)
            .id((0, 0))
            .permissions(Permissions::from(0u16))
            .time(UnixTimeStamp::unix_epoch(), UnixTimeStamp::unix_epoch())
            .create();
        let data = metadata_data(metadata);
        assert_eq!(data.size, Some(0));
        assert_eq!(data.uid, Some(0));
        assert_eq!(data.gid, Some(0));
        assert_eq!(data.permissions, Some(0));
        assert_eq!(data.modified_unix_secs, Some(0));
    }

    #[test]
    fn metadata_preserves_special_mode_bits_and_unsigned_modification_seconds() {
        use openssh_sftp_client::{
            UnixTimeStamp,
            metadata::{MetaDataBuilder, Permissions},
        };
        for (mode, seconds) in [(0o7777u16, u32::MAX), (0o4750, 2_147_483_648)] {
            let metadata = MetaDataBuilder::new()
                .len(u64::MAX)
                .id((u32::MAX, 0))
                .permissions(Permissions::from(mode))
                .time(
                    UnixTimeStamp::unix_epoch(),
                    UnixTimeStamp::from_raw(seconds).unwrap(),
                )
                .create();
            let data = metadata_data(metadata);
            assert_eq!(data.permissions, Some(u32::from(mode)));
            assert_eq!(data.modified_unix_secs, Some(u64::from(seconds)));
            assert_eq!(data.size, Some(u64::MAX));
            assert_eq!(data.uid, Some(u32::MAX));
            assert_eq!(data.gid, Some(0));
        }
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
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
        request.path = "file".into();
        request.timeout_secs = Some(0);
        assert_eq!(
            request.validate(budget()).unwrap_err().code,
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
        let reservation = ToolReply {
            data: Some(widest),
            error: Some(ToolError::SSH_CONNECT_FAILED),
        };
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
        assert_eq!(error.code, "invalid_argument");
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
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }

    #[test]
    fn digest_budget_reservation_enforces_the_complete_duplicated_frame_boundary() {
        let id = RequestId::String("consumer-id".repeat(50).into());
        let budget = ReplyBudget::new(&id).unwrap();
        for encoding in [Encoding::Utf8, Encoding::Base64] {
            let mut reservation = ToolReply {
                data: Some(ReadData {
                    content: String::new(),
                    content_sha256: ABC_SHA256.into(),
                    encoding,
                    bytes_read: u64::MAX,
                    next_offset: u64::MAX,
                    eof: false,
                }),
                error: Some(ToolError::SSH_CONNECT_FAILED),
            };
            let remaining = budget.remaining(&reservation).unwrap();
            reservation.data.as_mut().unwrap().content_sha256.clear();
            assert_eq!(budget.remaining(&reservation).unwrap(), remaining + 128);
            reservation.data.as_mut().unwrap().content_sha256 = ABC_SHA256.into();
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
                request.validate(u64::MAX, budget).unwrap_err().code,
                "invalid_argument"
            );
            reservation.data.as_mut().unwrap().content = content;
            assert!(budget.remaining(&reservation).is_ok());
            // One additional raw byte costs a full base64 group, or thirteen
            // bytes for this UTF-8 control character, across both wire copies.
            reservation
                .data
                .as_mut()
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
                request.validate(100, budget()).unwrap_err().code,
                "invalid_argument"
            );
        }
        for count in [0, 101, u64::MAX] {
            let mut request = request();
            request.max_bytes = Some(count);
            assert_eq!(
                request.validate(100, budget()).unwrap_err().code,
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
            assert_eq!(error.code, "invalid_encoding");
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

    #[test]
    fn missing_subsystem_executable_is_not_a_missing_remote_file() {
        let failure = ssh_failure(openssh::Error::Remote(io::ErrorKind::NotFound.into()));
        assert_eq!(failure.error.code, "io_error");
        assert!(!failure.check_master);
    }
}
