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
//! The exclusive OPEN creates the sibling stage with the server's creation
//! default; the first handle chmod reaches mode 0600 before any content.
//! Cancellation or uncertain acknowledgements can leave `.estus-replace-*`
//! orphans: never replay replacement or remove an unproven staging pathname.
//!
//! Directory enumeration is a single bounded page per request; a truncated
//! result is not an error and never implies a consistent snapshot.
use std::{
    fmt::Write as _,
    future::Future,
    io::{self, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::ssh::{Child, Session, SshError, Stdio};
use bytes::BytesMut;
use futures_util::StreamExt;
use openssh_sftp_client::{Error as SftpError, Sftp, SftpOptions, metadata::Permissions};
use openssh_sftp_error::SftpErrorKind;
use tokio::{
    io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf},
    sync::oneshot,
};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::{
    data::{
        ListData, ListSpec, MkdirData, MkdirSpec, RawRead, ReadData, ReadSpec, RemoveDirectoryData,
        RemoveDirectorySpec, RemoveFileData, RemoveFileSpec, RenameData, RenameSpec, ReplaceData,
        ReplaceSpec, StatSpec, WriteData, WriteSpec, encode,
    },
    metadata::{ListEntry, StatData, metadata_data},
};
use crate::reply::{ErrorCode, ToolError, ToolReply};

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
    pub(crate) lost_ack: bool,
}

struct Failure {
    error: ToolError,
    check_master: bool,
}

impl Failure {
    fn io() -> Self {
        Self {
            error: ToolError::new(ErrorCode::IoError, "SFTP file operation failed", false),
            check_master: false,
        }
    }

    fn cleanup() -> Self {
        Self {
            error: ToolError::new(
                ErrorCode::IoError,
                "SFTP channel cleanup did not complete within its deadline",
                true,
            ),
            check_master: false,
        }
    }
}

fn io_failure(error: &io::Error) -> Failure {
    let (error, check_master) = match error.kind() {
        io::ErrorKind::NotFound => (
            ToolError::new(ErrorCode::NotFound, "Remote file was not found", false),
            false,
        ),
        io::ErrorKind::AlreadyExists => (
            ToolError::new(
                ErrorCode::AlreadyExists,
                "Remote destination already exists",
                false,
            ),
            false,
        ),
        io::ErrorKind::PermissionDenied => (
            ToolError::new(
                ErrorCode::PermissionDenied,
                "Remote file access was denied",
                false,
            ),
            false,
        ),
        io::ErrorKind::Unsupported => (
            ToolError::new(
                ErrorCode::Unsupported,
                "SFTP operation is not supported",
                false,
            ),
            false,
        ),
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::NotConnected => (
            ToolError::new(
                ErrorCode::ConnectionLost,
                "SFTP channel connection was lost",
                false,
            ),
            true,
        ),
        _ => return Failure::io(),
    };
    Failure {
        error,
        check_master,
    }
}

fn sftp_failure(error: SftpError) -> Failure {
    let error = match error {
        SftpError::SftpError(SftpErrorKind::NoSuchFile, _) => {
            ToolError::new(ErrorCode::NotFound, "Remote file was not found", false)
        }
        SftpError::SftpError(SftpErrorKind::PermDenied, _) => ToolError::new(
            ErrorCode::PermissionDenied,
            "Remote file access was denied",
            false,
        ),
        SftpError::SftpError(SftpErrorKind::OpUnsupported, _)
        | SftpError::UnsupportedSftpProtocol { .. }
        | SftpError::UnsupportedExtension(_) => ToolError::new(
            ErrorCode::Unsupported,
            "SFTP operation is not supported",
            false,
        ),
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
                error: ToolError::new(
                    ErrorCode::ConnectionLost,
                    "SFTP channel connection was lost",
                    false,
                ),
                check_master: true,
            };
        }
        _ => return Failure::io(),
    };
    Failure {
        error,
        check_master: false,
    }
}

fn ssh_failure(error: SshError) -> Failure {
    match error {
        SshError::Remote(error) if error.kind() == io::ErrorKind::NotFound => Failure::io(),
        SshError::Remote(error) | SshError::ChildIo(error) => io_failure(&error),
        SshError::Master(_)
        | SshError::Connect(_)
        | SshError::SshMux(_)
        | SshError::Disconnected
        | SshError::RemoteProcessTerminated => Failure {
            error: ToolError::new(
                ErrorCode::ConnectionLost,
                "SFTP channel could not be opened or was lost",
                false,
            ),
            check_master: true,
        },
        #[allow(unreachable_patterns)]
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
        if (matches!(&result, Poll::Ready(Err(_)))
            || (matches!(&result, Poll::Ready(Ok(())))
                && capacity != 0
                && buf.filled().len() == before))
            && let Some(closed) = &self.closed
        {
            closed.cancel();
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
                            ErrorCode::AlreadyExists,
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
                    ErrorCode::Unsupported,
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
        options.write(true).create_new(true);
        // Only an acknowledged EXCL OPEN establishes ownership. An uncertain
        // OPEN or collision must never cause pathname cleanup.
        *phase = ReplacePhase::Opening;
        let mut file = options.open(&path).await.map_err(sftp_failure)?;
        *phase = ReplacePhase::Staging;
        let written = async {
            // The exclusive empty stage briefly has the server's creation
            // default before this chmod; no content is written until after it.
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
                        ErrorCode::AlreadyExists,
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
                    ErrorCode::Unsupported,
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
                    ErrorCode::Unsupported,
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
    let outcome = run_sftp(session, context, |sftp| read_sftp(sftp, &spec)).await;
    FileOutcome {
        reply: outcome.reply.map_ok(|raw| encode(raw, &spec)),
        check_master: outcome.check_master,
        lost_ack: false,
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
    if let Some(error) = outcome.reply.error_mut() {
        // Unlike reads, write uncertainty is specifically about file effects.
        // Handshake/preflight failures cannot have dispatched a mutating OPEN.
        error.remote_state_unknown = mutation_started;
    }
    outcome.lost_ack &= mutation_started;
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
    if let Some(error) = outcome.reply.error_mut() {
        // All failures after polling mutating OPEN remain uncertain, including
        // acknowledged pre-rename cleanup or a later local channel-close error.
        error.remote_state_unknown = !matches!(phase, ReplacePhase::NotStarted);
    }
    outcome.lost_ack &= !matches!(phase, ReplacePhase::NotStarted);
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
    if let Some(error) = outcome.reply.error_mut() {
        error.remote_state_unknown = mutation_started;
    }
    outcome.lost_ack &= mutation_started;
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
    if let Some(error) = outcome.reply.error_mut() {
        error.remote_state_unknown = mutation_started;
    }
    outcome.lost_ack &= mutation_started;
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
    if let Some(error) = outcome.reply.error_mut() {
        error.remote_state_unknown = mutation_started;
    }
    outcome.lost_ack &= mutation_started;
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
    if let Some(error) = outcome.reply.error_mut() {
        error.remote_state_unknown = mutation_started;
    }
    outcome.lost_ack &= mutation_started;
    outcome
}

pub(crate) async fn stat(
    session: &Session,
    spec: StatSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<StatData> {
    run_sftp(session, context, |sftp| stat_sftp(sftp, spec)).await
}

async fn list_sftp(sftp: Sftp, mut spec: ListSpec<'_>) -> Result<ListData, Failure> {
    let mut data = ListData::empty();
    let dir = sftp.fs().open_dir(spec.path).await.map_err(sftp_failure)?;
    let mut stream = Box::pin(dir.read_dir());
    loop {
        let entry = match stream.next().await {
            None => return Ok(data),
            Some(result) => result.map_err(sftp_failure)?,
        };
        let bytes = entry.filename().as_os_str().as_encoded_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let entry = ListEntry::from_filename(entry.filename().as_os_str(), entry.metadata());
        if data.entries.len() == spec.max_entries {
            data.truncated = true;
            return Ok(data);
        }
        if let Err(entry) = data.push(entry, &mut spec) {
            if data.entries.is_empty()
                || crate::wire::duplicated_size(&entry)
                    .ok()
                    .is_none_or(|cost| cost > super::data::DIRECTORY_PAGE_BYTES)
            {
                return Err(Failure {
                    error: ToolError::new(
                        ErrorCode::ResourceLimit,
                        "Directory entry exceeds the page payload limit",
                        false,
                    ),
                    check_master: false,
                });
            }
            return Ok(data);
        }
    }
}

pub(crate) async fn list(
    session: &Session,
    spec: ListSpec<'_>,
    context: FileContext<'_>,
) -> FileOutcome<ListData> {
    run_sftp(session, context, |sftp| list_sftp(sftp, spec)).await
}

async fn close_channel(
    cancel: &CancellationToken,
    child: Option<Child<'_>>,
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
                error: ToolError::new(ErrorCode::Cancelled, "SFTP file operation cancelled", false),
                check_master: false,
            }),
            () = context.shutdown.cancelled() => Err(Failure {
                error: ToolError::new(ErrorCode::Cancelled, "SFTP file operation cancelled", false),
                check_master: false,
            }),
            () = tokio::time::sleep_until(context.deadline) => Err(Failure {
                error: ToolError::new(ErrorCode::Timeout, "SFTP file operation deadline exceeded", false),
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
        // A slow child cleanup after an acknowledged result must not rewrite
        // that result or quarantine the target; the acknowledgement already
        // proves the remote operation completed.
        Ok(data) => {
            if cleanup_timed_out {
                crate::audit::emit(&serde_json::json!({
                    "event": "sftp_cleanup_timeout",
                    "remote_state_unknown": false,
                }));
            }
            FileOutcome {
                reply: ToolReply::success(data),
                check_master: false,
                lost_ack: false,
            }
        }
        Err(mut failure) => {
            let lost_ack = cleanup_timed_out
                || failure.error.remote_state_unknown
                || (dispatched
                    && matches!(
                        failure.error.code(),
                        ErrorCode::Timeout | ErrorCode::Cancelled | ErrorCode::ConnectionLost
                    ));
            if lost_ack {
                failure.error.remote_state_unknown = true;
            }
            FileOutcome {
                reply: ToolReply::failure(failure.error),
                check_master: failure.check_master,
                lost_ack,
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
        assert_eq!(failure.error.code(), ErrorCode::IoError);
        assert!(!failure.check_master);
    }
}
