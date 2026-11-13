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

use bytes::BytesMut;
use futures_util::StreamExt;
use openssh::{Session, Stdio};
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions};
use openssh_sftp_error::SftpErrorKind;
use tokio::{
    io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::{
    filedata::{
        ListData, ListSpec, MkdirData, MkdirSpec, RawRead, ReadData, ReadSpec, RenameData,
        RenameSpec, StatSpec, WriteData, WriteSpec, encode, verify_script,
    },
    filemeta::{ListEntry, StatData, metadata_data},
    reply::{ToolError, ToolReply},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

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
        io::ErrorKind::AlreadyExists => {
            ("already_exists", "Remote destination already exists", false)
        }
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

#[derive(Clone, Copy)]
enum ReadKind {
    Range,
    Script,
}

async fn read_sftp(sftp: Sftp, spec: &ReadSpec<'_>, kind: ReadKind) -> Result<RawRead, Failure> {
    let (result, file) = match sftp.open(spec.path).await {
        Ok(mut file) => {
            let result = async {
                if let ReadKind::Script = kind {
                    let metadata = file.metadata().await.map_err(sftp_failure)?;
                    if !metadata.file_type().is_some_and(|kind| kind.is_file()) {
                        return Err(Failure {
                            error: ToolError::new(
                                "unsupported",
                                "Script source must be a regular file",
                                false,
                            ),
                            check_master: false,
                        });
                    }
                }
                read_handle(&mut file, spec).await
            }
            .await;
            (result, Some(file))
        }
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

async fn write_sftp(
    sftp: Sftp,
    spec: &WriteSpec<'_>,
    mutation_started: &mut bool,
) -> Result<WriteData, Failure> {
    let opened = async {
        if !spec.overwrite {
            // SFTP v3 reports EEXIST as generic FAILURE. Observe existing paths
            // without following symlinks for a truthful already_exists result.
            // This is not the race guard: OPEN below still uses atomic EXCL.
            let metadata = {
                let mut fs = sftp.fs();
                fs.symlink_metadata(spec.path).await
            };
            match metadata {
                Ok(_) => {
                    return Err(Failure {
                        error: ToolError::new(
                            "already_exists",
                            "Remote destination already exists",
                            false,
                        ),
                        check_master: false,
                    });
                }
                Err(SftpError::SftpError(SftpErrorKind::NoSuchFile, _)) => {}
                Err(error) => return Err(sftp_failure(error)),
            }
        }
        let mut options = sftp.options();
        options.write(true);
        if spec.overwrite {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        // OPEN itself can create or truncate, before any WRITE acknowledgement.
        // Set before polling; cancellation can lose the OPEN response.
        *mutation_started = true;
        options.open(spec.path).await.map_err(sftp_failure)
    }
    .await;
    let (result, file) = match opened {
        Ok(mut file) => {
            let result = file
                .write_all(&spec.content)
                .await
                .map_err(sftp_failure)
                .map(|()| WriteData {
                    bytes_written: spec.content.len() as u64,
                });
            (result, Some(file))
        }
        Err(error) => (Err(error), None),
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

async fn mkdir_sftp(
    sftp: Sftp,
    spec: MkdirSpec<'_>,
    mutation_started: &mut bool,
) -> Result<MkdirData, Failure> {
    let result = async {
        let mut fs = sftp.fs();
        // Observe existing entries, including final symlinks, without claiming
        // a race-free no-follow check. MKDIR itself cannot replace an entry.
        match fs.symlink_metadata(spec.path).await {
            Ok(_) => {
                return Err(Failure {
                    error: ToolError::new(
                        "already_exists",
                        "Remote destination already exists",
                        false,
                    ),
                    check_master: false,
                });
            }
            Err(SftpError::SftpError(SftpErrorKind::NoSuchFile, _)) => {}
            Err(error) => return Err(sftp_failure(error)),
        }
        // Set before polling: cancellation may lose the MKDIR acknowledgement.
        *mutation_started = true;
        fs.create_dir(spec.path).await.map_err(sftp_failure)?;
        Ok(MkdirData { created: true })
    }
    .await;
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
    combine_close(result, close)
}

async fn rename_sftp(
    sftp: Sftp,
    spec: RenameSpec<'_>,
    mutation_started: &mut bool,
) -> Result<RenameData, Failure> {
    let result = async {
        // SFTP v3 has no atomic no-replace flag. Its standard RENAME is not
        // equivalent: OpenSSH can fall back to a racy stat-then-rename.
        if !spec.overwrite {
            return Err(Failure {
                error: ToolError::new(
                    "unsupported",
                    "Atomic no-overwrite rename is unavailable on this SFTP backend",
                    false,
                ),
                check_master: false,
            });
        }
        // Fs::rename silently falls back to standard RENAME without this
        // extension; reject before mutation rather than weaken atomicity.
        if !sftp.support_posix_rename() {
            return Err(Failure {
                error: ToolError::new(
                    "unsupported",
                    "Atomic overwrite rename requires the SFTP POSIX-rename extension",
                    false,
                ),
                check_master: false,
            });
        }
        let mut fs = sftp.fs();
        // Set before polling: loss/cancellation may hide the acknowledgement.
        *mutation_started = true;
        fs.rename(spec.source, spec.destination)
            .await
            .map_err(sftp_failure)?;
        Ok(RenameData { renamed: true })
    }
    .await;
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
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
            let entry = ListEntry::from_filename(entry.filename().as_os_str(), entry.metadata());
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

/// Negotiate and close SFTP without issuing any filesystem requests.
pub(crate) async fn probe(session: &Session, context: FileContext<'_>) -> FileOutcome<()> {
    run_sftp(session, context, |sftp| async move {
        tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
            .await
            .map_err(|_| Failure::cleanup())?
            .map_err(sftp_failure)
    })
    .await
}

pub(crate) async fn read(
    session: &Session,
    spec: ReadSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<ReadData> {
    let outcome = run_sftp(session, context, |sftp| {
        read_sftp(sftp, &spec, ReadKind::Range)
    })
    .await;
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

/// Read/close once and retain the exact checked bytes; execution never reopens the path.
pub(crate) async fn read_script(
    session: &Session,
    path: &str,
    expected_content_sha256: &[u8; 32],
    max_bytes: usize,
    context: FileContext<'_>,
) -> FileOutcome<String> {
    let spec = ReadSpec {
        path,
        offset: 0,
        max_bytes,
        encoding: crate::filedata::Encoding::Utf8,
        expected_content_sha256: None,
    };
    let outcome = run_sftp(session, context, |sftp| {
        read_sftp(sftp, &spec, ReadKind::Script)
    })
    .await;
    let mut reply = match outcome.reply.data {
        Some(raw) => match verify_script(
            raw.bytes.into(),
            raw.eof,
            expected_content_sha256,
            max_bytes,
        ) {
            Ok(source) => ToolReply::success(source),
            Err(error) => ToolReply::failure(error),
        },
        None => ToolReply {
            data: None,
            error: outcome.reply.error,
        },
    };
    if let Some(error) = &mut reply.error {
        // SFTP preparation can be incomplete, but no script interpreter was started.
        error.remote_state_unknown = false;
    }
    FileOutcome {
        reply,
        check_master: outcome.check_master,
    }
}

pub(crate) async fn write(
    session: &Session,
    spec: WriteSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<WriteData> {
    let mut mutation_started = false;
    let mut outcome = run_sftp(session, context, |sftp| {
        write_sftp(sftp, &spec, &mut mutation_started)
    })
    .await;
    if let Some(error) = &mut outcome.reply.error {
        // Unlike reads, write uncertainty is specifically about file effects.
        // Handshake/preflight failures cannot have dispatched a mutating OPEN.
        error.remote_state_unknown = mutation_started;
    }
    outcome
}

pub(crate) async fn mkdir(
    session: &Session,
    spec: MkdirSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<MkdirData> {
    let mut mutation_started = false;
    let mut outcome = run_sftp(session, context, |sftp| {
        mkdir_sftp(sftp, spec, &mut mutation_started)
    })
    .await;
    if let Some(error) = &mut outcome.reply.error {
        error.remote_state_unknown = mutation_started;
    }
    outcome
}

pub(crate) async fn rename(
    session: &Session,
    spec: RenameSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<RenameData> {
    let mut mutation_started = false;
    let mut outcome = run_sftp(session, context, |sftp| {
        rename_sftp(sftp, spec, &mut mutation_started)
    })
    .await;
    if let Some(error) = &mut outcome.reply.error {
        error.remote_state_unknown = mutation_started;
    }
    outcome
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

    #[test]
    fn missing_subsystem_executable_is_not_a_missing_remote_file() {
        let failure = ssh_failure(openssh::Error::Remote(io::ErrorKind::NotFound.into()));
        assert_eq!(failure.error.code, "io_error");
        assert!(!failure.check_master);
    }
}
