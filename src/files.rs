//! Lossless, bounded file operations over independently owned ordinary SFTP channels.
//!
//! No remote commands or privilege changes are involved. Cancellation interrupts
//! the local protocol streams as well as disconnecting this channel, so a remote
//! FIFO cannot retain local library tasks or the caller's channel permit.
//!
//! SHA-256 covers only the returned raw byte range, not the lookahead or encoded
//! content. Separate reads are not a snapshot of a concurrently changing file.
//!
//! Atomic replacement uses a new mode-0600 inode, not destination metadata, and
//! promises atomic visibility rather than durability or concurrent-writer safety.
//! The exclusive OPEN creates the sibling stage with mode 0600.
//! Cancellation or uncertain acknowledgements can leave `.estus-replace-*`
//! orphans: never replay replacement or remove an unproven staging pathname.
//!
//! Directory continuations retain one pinned READDIR stream and its native lease.
//! A cursor owner, not a request task, owns bounded close and idle cancellation;
//! request admission is never retained between pages.
use std::{
    collections::HashMap,
    fmt::Write as _,
    future::Future,
    io::{self, SeekFrom},
    os::unix::ffi::OsStrExt,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use futures_util::{FutureExt, StreamExt};
use openssh::{Session, Stdio};
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions, metadata::Permissions};
use openssh_sftp_error::SftpErrorKind;
use tokio::{
    io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::{
    filedata::{
        DIRECTORY_CURSORS_PER_TARGET, DirectoryLimits, ListData, ListSpec, MkdirData, MkdirSpec,
        RawRead, ReadData, ReadSpec, RemoveDirectoryData, RemoveDirectorySpec, RemoveFileData,
        RemoveFileSpec, RenameData, RenameSpec, ReplaceData, ReplaceSpec, StatSpec, WriteData,
        WriteSpec, encode, verify_script,
    },
    filemeta::{ListEntry, StatData, metadata_data},
    reply::{ToolError, ToolReply},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct FileContext<'a> {
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) ct: &'a CancellationToken,
    pub(crate) shutdown: &'a CancellationToken,
    pub(crate) progress: crate::progress::Reporter,
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
    closed: Option<CancellationToken>,
}

impl<T> ChannelStream<T> {
    fn new(inner: T, cancel: &CancellationToken) -> (Self, oneshot::Receiver<()>) {
        let (released, receiver) = oneshot::channel();
        (
            Self {
                inner,
                cancelled: Box::pin(cancel.clone().cancelled_owned()),
                _released: released,
                closed: None,
            },
            receiver,
        )
    }

    fn interrupted(&mut self, cx: &mut Context<'_>) -> bool {
        self.cancelled.as_mut().poll(cx).is_ready()
    }
}

impl<T> Drop for ChannelStream<T> {
    fn drop(&mut self) {
        if let Some(closed) = &self.closed {
            closed.cancel();
        }
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
        let before = buf.filled().len();
        let capacity = buf.remaining();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Err(_)))
            || (matches!(&result, Poll::Ready(Ok(())))
                && capacity != 0
                && buf.filled().len() == before)
        {
            if let Some(closed) = &self.closed {
                closed.cancel();
            }
        }
        result
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

enum ReplacePhase {
    NotStarted,
    Opening,
    Staging,
    Renaming,
    Renamed,
}

fn replacement_stage_path(destination: &str) -> Result<String, Failure> {
    let mut random = [0; 16];
    getrandom::fill(&mut random).map_err(|_| Failure::io())?;
    let prefix = destination
        .rfind('/')
        .map_or("", |index| &destination[..=index]);
    // Reserve the entire raw sibling path once; the basename never grows with
    // the destination basename, and formatting does not allocate an intermediate.
    let mut path = String::with_capacity(prefix.len() + ".estus-replace-".len() + 32);
    write!(
        path,
        "{prefix}.estus-replace-{:032x}",
        u128::from_be_bytes(random)
    )
    .map_err(|_| Failure::io())?;
    Ok(path)
}

async fn replace_sftp(
    sftp: Sftp,
    spec: &ReplaceSpec<'_>,
    phase: &mut ReplacePhase,
) -> Result<ReplaceData, Failure> {
    let result = async {
        // Fs::rename otherwise falls back to standard RENAME. Refuse before
        // OPEN, chmod, WRITE or any other filesystem mutation.
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
        let path = replacement_stage_path(spec.path)?;
        // A nonce collision with the requested name must never stage in-place.
        if path == spec.path {
            return Err(Failure::io());
        }
        let mut options = sftp.options();
        options
            .write(true)
            .create_new(true)
            .create_permissions(Permissions::from(0o600));
        // Only an acknowledged EXCL OPEN establishes ownership. An uncertain
        // OPEN or collision must never cause pathname cleanup.
        *phase = ReplacePhase::Opening;
        let mut file = options.open(&path).await.map_err(sftp_failure)?;
        *phase = ReplacePhase::Staging;
        let written = async {
            // Defensive confirmation only: confidentiality already holds at
            // the exclusive OPEN, even if another user observes the empty stage.
            file.set_permissions(Permissions::from(0o600))
                .await
                .map_err(sftp_failure)?;
            file.write_all(&spec.content).await.map_err(sftp_failure)
        }
        .await;
        let close = tokio::time::timeout(CLEANUP_TIMEOUT, file.close())
            .await
            .map_err(|_| Failure::cleanup())
            .and_then(|result| result.map_err(sftp_failure));
        let staged = combine_close(written, close);
        if let Err(error) = staged {
            // This is the only pathname cleanup: known exclusive ownership,
            // after bounded handle close, before any rename has been polled.
            // Cancellation can drop us before cleanup; leave a possible orphan
            // rather than reconnecting or guessing whether OPEN succeeded.
            let remove = async { sftp.fs().remove_file(&path).await.map_err(sftp_failure) };
            let cleanup = tokio::time::timeout(CLEANUP_TIMEOUT, remove)
                .await
                .unwrap_or_else(|_| Err(Failure::cleanup()));
            return combine_close(Err(error), cleanup);
        }
        // Even a rejected or lost rename response ends staging ownership.
        // Never remove either pathname after polling this request.
        *phase = ReplacePhase::Renaming;
        sftp.fs()
            .rename(&path, spec.path)
            .await
            .map_err(sftp_failure)?;
        *phase = ReplacePhase::Renamed;
        Ok(ReplaceData {
            bytes_written: spec.content.len() as u64,
        })
    }
    .await;
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
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

async fn remove_file_sftp(
    sftp: Sftp,
    spec: RemoveFileSpec<'_>,
    mutation_started: &mut bool,
) -> Result<RemoveFileData, Failure> {
    let result = async {
        let mut fs = sftp.fs();
        // REMOVE unlinks one entry, including a final symlink, not its target.
        // No metadata/canonicalization preflight can strengthen that guarantee.
        // Set before polling: cancellation may hide the REMOVE acknowledgement.
        *mutation_started = true;
        fs.remove_file(spec.path).await.map_err(sftp_failure)?;
        Ok(RemoveFileData { removed: true })
    }
    .await;
    let close = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
        .await
        .map_err(|_| Failure::cleanup())
        .and_then(|result| result.map_err(sftp_failure));
    combine_close(result, close)
}

async fn remove_directory_sftp(
    sftp: Sftp,
    spec: RemoveDirectorySpec<'_>,
    mutation_started: &mut bool,
) -> Result<RemoveDirectoryData, Failure> {
    let result = async {
        let mut fs = sftp.fs();
        // RMDIR itself enforces emptiness; a prior listing cannot replace it.
        // Set before polling: cancellation may hide the acknowledgement.
        *mutation_started = true;
        fs.remove_dir(spec.path).await.map_err(sftp_failure)?;
        Ok(RemoveDirectoryData { removed: true })
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

pub(crate) async fn replace_file(
    session: &Session,
    spec: ReplaceSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<ReplaceData> {
    let mut phase = ReplacePhase::NotStarted;
    let mut outcome = run_sftp(session, context, |sftp| {
        replace_sftp(sftp, &spec, &mut phase)
    })
    .await;
    if let Some(error) = &mut outcome.reply.error {
        // All failures after polling mutating OPEN remain uncertain, including
        // acknowledged pre-rename cleanup or a later local channel-close error.
        error.remote_state_unknown = !matches!(phase, ReplacePhase::NotStarted);
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

pub(crate) async fn remove_file(
    session: &Session,
    spec: RemoveFileSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<RemoveFileData> {
    let mut mutation_started = false;
    let mut outcome = run_sftp(session, context, |sftp| {
        remove_file_sftp(sftp, spec, &mut mutation_started)
    })
    .await;
    if let Some(error) = &mut outcome.reply.error {
        error.remote_state_unknown = mutation_started;
    }
    outcome
}

pub(crate) async fn remove_directory(
    session: &Session,
    spec: RemoveDirectorySpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<RemoveDirectoryData> {
    let mut mutation_started = false;
    let mut outcome = run_sftp(session, context, |sftp| {
        remove_directory_sftp(sftp, spec, &mut mutation_started)
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

/// Session-local, single-use capabilities. The registry owns only dispatch
/// handles; each owner task owns its stream, lease, idle deadline and cleanup.
pub(crate) struct DirectoryStore {
    shared: Arc<DirectoryShared>,
}

struct DirectoryShared {
    limits: DirectoryLimits,
    stopping: CancellationToken,
    registry: Mutex<DirectoryRegistry>,
}

#[derive(Default)]
struct DirectoryRegistry {
    owners: HashMap<String, DirectoryOwner>,
    idle: HashMap<String, IdleDirectory>,
}

struct DirectoryOwner {
    host: String,
    destination: String,
    role: crate::config::IdentityRole,
    path: String,
    retained: bool,
    sender: mpsc::Sender<DirectoryPage>,
    done: CancellationToken,
}

struct IdleDirectory {
    owner: String,
    expires: tokio::time::Instant,
}

struct DirectoryPage {
    max_entries: usize,
    remaining_bytes: usize,
    deadline: tokio::time::Instant,
    cancel: CancellationToken,
    shutdown: CancellationToken,
    progress: crate::progress::Reporter,
    reply: oneshot::Sender<ToolReply<ListData>>,
}

fn directory_lock(shared: &DirectoryShared) -> MutexGuard<'_, DirectoryRegistry> {
    // Recover ownership records on unwind so shutdown can still await cleanup.
    shared
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn directory_missing() -> ToolError {
    ToolError::new("not_found", "Directory continuation was not found", false)
}

fn directory_control(code: &'static str) -> Failure {
    Failure {
        error: match code {
            "timeout" => ToolError::new("timeout", "SFTP file operation deadline exceeded", false),
            _ => ToolError::new("cancelled", "SFTP file operation cancelled", false),
        },
        check_master: false,
    }
}

fn directory_token() -> Result<String, Failure> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| Failure::io())?;
    Ok(format!("{:032x}", u128::from_be_bytes(bytes)))
}

impl DirectoryStore {
    pub(crate) fn new(limits: DirectoryLimits, shutdown: CancellationToken) -> Self {
        Self {
            shared: Arc::new(DirectoryShared {
                limits,
                stopping: shutdown.child_token(),
                registry: Mutex::new(DirectoryRegistry::default()),
            }),
        }
    }

    pub(crate) async fn page(
        &self,
        pool: &Arc<crate::ssh::Pool>,
        target: crate::config::ResolvedTarget<'_>,
        spec: ListSpec<'_>,
        continuation: Option<&str>,
        context: FileContext<'_>,
    ) -> ToolReply<ListData> {
        if context.ct.is_cancelled()
            || context.shutdown.is_cancelled()
            || self.shared.stopping.is_cancelled()
        {
            return ToolReply::failure(directory_control("cancelled").error);
        }
        if tokio::time::Instant::now() >= context.deadline {
            return ToolReply::failure(directory_control("timeout").error);
        }
        // Dropping the caller wakes the owner even if the caller's request
        // cancellation token itself was never cancelled.
        let cancel = context.ct.child_token();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let (reply, response) = oneshot::channel();
        let request = DirectoryPage {
            max_entries: spec.max_entries,
            remaining_bytes: spec.remaining_bytes,
            deadline: context.deadline,
            cancel,
            shutdown: context.shutdown.clone(),
            progress: context.progress,
            reply,
        };
        if let Some(token) = continuation {
            let dispatched = {
                let mut registry = directory_lock(&self.shared);
                let Some(idle) = registry.idle.get(token) else {
                    return ToolReply::failure(directory_missing());
                };
                if idle.expires <= tokio::time::Instant::now() {
                    return ToolReply::failure(directory_missing());
                }
                let Some(owner) = registry.owners.get(&idle.owner) else {
                    return ToolReply::failure(directory_missing());
                };
                if owner.host != target.name
                    || owner.destination != target.destination
                    || owner.role != target.role
                    || owner.path != spec.path
                {
                    return ToolReply::failure(ToolError::new(
                        "invalid_argument",
                        "Directory continuation identity does not match",
                        false,
                    ));
                }
                // No await or second admission boundary between consumption and
                // dispatch. Concurrent users can never dispatch the same token.
                let result = owner.sender.try_send(request);
                registry.idle.remove(token);
                result.is_ok()
            };
            if !dispatched {
                return ToolReply::failure(directory_missing());
            }
        } else {
            let lease = match pool
                .acquire(
                    target.name,
                    target.destination,
                    target.role,
                    context.deadline,
                    &request.cancel,
                )
                .await
            {
                Ok(lease) => lease,
                Err(error) => return ToolReply::failure(error),
            };
            let id = match directory_token() {
                Ok(id) => id,
                Err(failure) => return ToolReply::failure(failure.error),
            };
            let (sender, receiver) = mpsc::channel(1);
            let done = CancellationToken::new();
            let path = spec.path.to_owned();
            {
                let mut registry = directory_lock(&self.shared);
                if self.shared.stopping.is_cancelled() {
                    return ToolReply::failure(directory_control("cancelled").error);
                }
                if registry.owners.contains_key(&id) {
                    return ToolReply::failure(Failure::io().error);
                }
                registry.owners.insert(
                    id.clone(),
                    DirectoryOwner {
                        host: target.name.to_owned(),
                        destination: target.destination.to_owned(),
                        role: target.role,
                        path: path.clone(),
                        retained: false,
                        sender,
                        done: done.clone(),
                    },
                );
            }
            let shared = Arc::clone(&self.shared);
            // This owner is never aborted. In particular it does not inherit
            // the server's ordinary global request-admission permit.
            let recovery_shared = Arc::downgrade(&shared);
            let recovery_id = id.clone();
            let recovery_done = done.clone();
            tokio::spawn(async move {
                let outcome = AssertUnwindSafe(directory_owner(
                    shared, id, path, lease, receiver, request, done,
                ))
                .catch_unwind()
                .await;
                if outcome.is_err() {
                    // The failed future has dropped its channel and lease.
                    // Never leave shutdown waiting on an un-signalled owner.
                    if let Some(shared) = recovery_shared.upgrade() {
                        let mut registry = directory_lock(&shared);
                        registry.idle.retain(|_, idle| idle.owner != recovery_id);
                        registry.owners.remove(&recovery_id);
                    }
                    recovery_done.cancel();
                    crate::audit::emit(&serde_json::json!({
                        "event":"directory_cursor_error",
                        "error_code":"owner_panicked",
                        "remote_state_unknown":true,
                    }));
                }
            });
        }
        response.await.unwrap_or_else(|_| {
            ToolReply::failure(ToolError::new(
                "io_error",
                "Directory owner cleanup was interrupted",
                true,
            ))
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.shared.stopping.cancel();
        let owners: Vec<_> = directory_lock(&self.shared)
            .owners
            .values()
            .map(|owner| owner.done.clone())
            .collect();
        for done in owners {
            done.cancelled().await;
        }
    }
}

impl Drop for DirectoryStore {
    fn drop(&mut self) {
        self.shared.stopping.cancel();
    }
}

struct DirectoryChannel {
    child: Option<openssh::Child<Arc<Session>>>,
    sftp: Option<Sftp>,
    stream: Option<Pin<Box<openssh_sftp_client::fs::ReadDir>>>,
    pending: Option<ListEntry>,
    cancel: CancellationToken,
    closed: CancellationToken,
    released: [Option<oneshot::Receiver<()>>; 2],
    drain: Option<tokio::task::JoinHandle<io::Result<u64>>>,
    pump: Option<tokio::task::JoinHandle<io::Result<u64>>>,
    dispatched: bool,
}

impl DirectoryChannel {
    fn new() -> Self {
        Self {
            child: None,
            sftp: None,
            stream: None,
            pending: None,
            cancel: CancellationToken::new(),
            closed: CancellationToken::new(),
            released: [None, None],
            drain: None,
            pump: None,
            dispatched: false,
        }
    }

    async fn open(
        &mut self,
        lease: &crate::ssh::Lease,
        path: &str,
        progress: &crate::progress::Reporter,
    ) -> Result<(), Failure> {
        self.dispatched = true;
        self.child = Some(
            Session::to_subsystem(lease.owned_session(), "sftp")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .await
                .map_err(ssh_failure)?,
        );
        progress.stage(crate::progress::Stage::SftpOpened);
        let child = self.child.as_mut().ok_or_else(Failure::io)?;
        let stdin = child.stdin().take().ok_or_else(Failure::io)?;
        let mut stdout = child.stdout().take().ok_or_else(Failure::io)?;
        let mut stderr = child.stderr().take().ok_or_else(Failure::io)?;
        let (stdin, input_released) = ChannelStream::new(stdin, &self.cancel);
        // The SFTP library stops polling stdout when it has no outstanding
        // requests. A bounded pump keeps observing real pipe EOF while idle,
        // without issuing another READDIR or probing/reopening the channel.
        let (reader, mut writer) = tokio::io::duplex(64 * 1024);
        let cancel = self.cancel.clone();
        let closed = self.closed.clone();
        self.pump = Some(tokio::spawn(async move {
            let _closed_on_drop = closed.drop_guard();
            tokio::select! {
                biased;
                () = cancel.cancelled() => Ok(0),
                result = tokio::io::copy(&mut stdout, &mut writer) => result,
            }
        }));
        let (mut stdout, output_released) = ChannelStream::new(reader, &self.cancel);
        stdout.closed = Some(self.closed.clone());
        self.released = [Some(input_released), Some(output_released)];
        self.drain = Some(tokio::spawn(async move {
            tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await
        }));
        self.sftp = Some(
            Sftp::new(stdin, stdout, SftpOptions::default())
                .await
                .map_err(sftp_failure)?,
        );
        progress.stage(crate::progress::Stage::SftpReady);
        let dir = self
            .sftp
            .as_ref()
            .ok_or_else(Failure::io)?
            .fs()
            .open_dir(path)
            .await
            .map_err(sftp_failure)?;
        self.stream = Some(Box::pin(dir.read_dir()));
        Ok(())
    }

    async fn page(&mut self, mut spec: ListSpec<'_>) -> Result<ListData, Failure> {
        let mut data = ListData::empty();
        loop {
            let entry = match self.pending.take() {
                Some(entry) => entry,
                None => {
                    let stream = self.stream.as_mut().ok_or_else(Failure::io)?;
                    let Some(entry) = stream.next().await else {
                        return Ok(data);
                    };
                    let entry = entry.map_err(sftp_failure)?;
                    let bytes = entry.filename().as_os_str().as_bytes();
                    if matches!(bytes, b"." | b"..") {
                        continue;
                    }
                    ListEntry::from_filename(entry.filename().as_os_str(), entry.metadata())
                }
            };
            if data.entries.len() == spec.max_entries {
                self.pending = Some(entry);
                data.truncated = true;
                return Ok(data);
            }
            if let Err(entry) = data.push(entry, &mut spec) {
                if data.entries.is_empty()
                    || crate::wire::duplicated_size(&entry)
                        .ok()
                        .is_none_or(|cost| cost > crate::filedata::DIRECTORY_PAGE_BYTES)
                {
                    return Err(Failure {
                        error: ToolError::new(
                            "resource_limit",
                            "Directory entry exceeds the page payload limit",
                            false,
                        ),
                        check_master: false,
                    });
                }
                self.pending = Some(entry);
                return Ok(data);
            }
        }
    }

    async fn close(&mut self, graceful: bool) -> Result<(), Failure> {
        // Dropping ReadDir schedules CLOSE. Sftp::close acknowledges the
        // library's queued work before native child/session ownership is lost.
        self.stream.take();
        self.pending.take();
        let mut result = Ok(());
        if let Some(sftp) = self.sftp.take() {
            if graceful {
                result = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close())
                    .await
                    .map_err(|_| Failure::cleanup())
                    .and_then(|result| result.map_err(sftp_failure));
            } else {
                drop(sftp);
            }
        }
        if graceful && result.is_ok() {
            if let Some(child) = self.child.take() {
                result = tokio::time::timeout(CLEANUP_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| Failure::cleanup())
                    .and_then(|result| result.map_err(ssh_failure))
                    .and_then(|status| {
                        if status.success() {
                            Ok(())
                        } else {
                            Err(Failure::io())
                        }
                    });
            }
        }
        let cleanup = close_channel(
            &self.cancel,
            self.child.take(),
            std::mem::take(&mut self.released),
        )
        .await;
        for mut drain in [self.pump.take(), self.drain.take()].into_iter().flatten() {
            match tokio::time::timeout(CLEANUP_TIMEOUT, &mut drain).await {
                Ok(Ok(Ok(_))) => {}
                Ok(_) => result = combine_close(result, Err(Failure::io())),
                Err(_) => {
                    drain.abort();
                    let _ = drain.await;
                    result = combine_close(result, Err(Failure::cleanup()));
                }
            }
        }
        combine_close(result, cleanup)
    }
}

impl Drop for DirectoryChannel {
    fn drop(&mut self) {
        self.cancel.cancel();
        for drain in [self.pump.take(), self.drain.take()].into_iter().flatten() {
            drain.abort();
        }
    }
}

/// Reserve only after positive lookahead; small exhausted listings need no
/// retained-cursor credit. Busy and closing owners keep their reservation.
fn publish_directory(shared: &DirectoryShared, id: &str) -> Result<String, Failure> {
    let token = directory_token()?;
    let mut registry = directory_lock(shared);
    if shared.stopping.is_cancelled() {
        return Err(directory_control("cancelled"));
    }
    let owner = registry.owners.get(id).ok_or_else(Failure::io)?;
    if !owner.retained {
        let total = registry
            .owners
            .values()
            .filter(|owner| owner.retained)
            .count();
        let target = registry
            .owners
            .values()
            .filter(|other| other.retained && other.host == owner.host && other.role == owner.role)
            .count();
        if total >= shared.limits.max_cursors || target >= DIRECTORY_CURSORS_PER_TARGET {
            return Err(Failure {
                error: ToolError::new("resource_limit", "Directory cursor limit reached", false),
                check_master: false,
            });
        }
    }
    if registry.idle.contains_key(&token) {
        return Err(Failure::io());
    }
    registry
        .owners
        .get_mut(id)
        .ok_or_else(Failure::io)?
        .retained = true;
    registry.idle.insert(
        token.clone(),
        IdleDirectory {
            owner: id.to_owned(),
            expires: tokio::time::Instant::now()
                + Duration::from_secs(shared.limits.idle_timeout_secs),
        },
    );
    Ok(token)
}

async fn directory_owner(
    shared: Arc<DirectoryShared>,
    id: String,
    path: String,
    lease: crate::ssh::Lease,
    mut receiver: mpsc::Receiver<DirectoryPage>,
    first: DirectoryPage,
    done: CancellationToken,
) {
    let mut channel = DirectoryChannel::new();
    let mut request = first;
    let mut initialized = false;
    let mut terminal;
    let final_reply;
    loop {
        let operation = async {
            if !initialized {
                channel.open(&lease, &path, &request.progress).await?;
                initialized = true;
            }
            channel
                .page(ListSpec {
                    path: &path,
                    max_entries: request.max_entries,
                    remaining_bytes: request.remaining_bytes,
                })
                .await
        };
        let result = tokio::select! {
            biased;
            () = request.cancel.cancelled() => Err(directory_control("cancelled")),
            () = request.shutdown.cancelled() => Err(directory_control("cancelled")),
            () = shared.stopping.cancelled() => Err(directory_control("cancelled")),
            () = tokio::time::sleep_until(request.deadline) => Err(directory_control("timeout")),
            result = operation => result,
        };
        let result = if channel.closed.is_cancelled() && result.is_ok() {
            Err(Failure {
                error: ToolError::new("connection_lost", "SFTP channel connection was lost", false),
                check_master: true,
            })
        } else {
            result
        };
        if result.is_ok() {
            request
                .progress
                .stage(crate::progress::Stage::SftpAcknowledged);
        }
        request.progress.stop();
        match result {
            Ok(mut data) if data.truncated => match publish_directory(&shared, &id) {
                Ok(token) => {
                    data.set_continuation(token, shared.limits.idle_timeout_secs);
                    if request.reply.send(ToolReply::success(data)).is_err() {
                        terminal = Ok(None);
                        final_reply = None;
                        break;
                    }
                }
                Err(failure) => {
                    terminal = Err(failure);
                    final_reply = Some(request.reply);
                    break;
                }
            },
            result => {
                terminal = result.map(|data| Some(data));
                final_reply = Some(request.reply);
                break;
            }
        }
        drop(request.cancel);
        drop(request.shutdown);
        drop(request.progress);
        // No request context or admission permit survives this idle wait.
        // The bounded stdout pump observes EOF even when the SFTP library is
        // waiting for another request; there is no polling or reconnection.
        let idle_deadline =
            tokio::time::Instant::now() + Duration::from_secs(shared.limits.idle_timeout_secs);
        let next = tokio::select! {
            biased;
            () = shared.stopping.cancelled() => None,
            () = channel.closed.cancelled() => None,
            next = receiver.recv() => next,
            () = tokio::time::sleep_until(idle_deadline) => None,
        };
        match next {
            Some(next) => request = next,
            None => {
                terminal = if channel.closed.is_cancelled() {
                    Err(Failure {
                        error: ToolError::new(
                            "connection_lost",
                            "SFTP channel connection was lost",
                            false,
                        ),
                        check_master: true,
                    })
                } else {
                    Ok(None)
                };
                final_reply = None;
                break;
            }
        }
    }
    // Invalidate capabilities before any potentially slow close, but keep the
    // credit and lease until acknowledged/bounded cleanup has completed.
    directory_lock(&shared)
        .idle
        .retain(|_, idle| idle.owner != id);
    let graceful = terminal.is_ok() && !channel.closed.is_cancelled();
    let cleanup = channel.close(graceful).await;
    terminal = combine_close(terminal, cleanup);
    let reply = match terminal {
        Ok(data) => data.map(ToolReply::success),
        Err(mut failure) => {
            if channel.dispatched
                && matches!(
                    failure.error.code,
                    "timeout" | "cancelled" | "connection_lost"
                )
            {
                failure.error.remote_state_unknown = true;
            }
            if failure.check_master
                && matches!(lease.check_health().await, crate::ssh::MasterHealth::Lost)
            {
                lease.invalidate();
            }
            Some(ToolReply::failure(failure.error))
        }
    };
    drop(channel);
    drop(lease);
    directory_lock(&shared).owners.remove(&id);
    done.cancel();
    if final_reply.is_none()
        && let Some(error) = reply.as_ref().and_then(|reply| reply.error.as_ref())
    {
        crate::audit::emit(&serde_json::json!({
            "event":"directory_cursor_error",
            "error_code":error.code,
            "remote_state_unknown":error.remote_state_unknown,
        }));
    }
    if let (Some(sender), Some(reply)) = (final_reply, reply) {
        let _ = sender.send(reply);
    }
}

async fn close_channel<S>(
    cancel: &CancellationToken,
    child: Option<openssh::Child<S>>,
    released: [Option<oneshot::Receiver<()>>; 2],
) -> Result<(), Failure> {
    cancel.cancel();
    tokio::time::timeout(CLEANUP_TIMEOUT, async {
        if let Some(child) = child {
            let _ = child.disconnect().await;
        }
        for receiver in released.into_iter().flatten() {
            let _ = receiver.await;
        }
    })
    .await
    .map_err(|_| Failure::cleanup())
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
            context.progress.stage(crate::progress::Stage::SftpOpened);
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
                context.progress.stage(crate::progress::Stage::SftpReady);
                let result = operation(sftp).await;
                if result.is_ok() {
                    context
                        .progress
                        .stage(crate::progress::Stage::SftpAcknowledged);
                }
                result
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
    context.progress.stop();
    // Operation futures and every File/Sftp handle have now been dropped. Wake
    // blocked protocol reads before disconnecting ONLY this child, not its master.
    let cleanup_timed_out = close_channel(&cancel, child.take(), released)
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
