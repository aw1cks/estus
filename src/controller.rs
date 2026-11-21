//! Explicit local execution with private file input and retained cleanup ownership.
//!
//! Process groups are not containment: descendants may escape with setsid/setpgid.
//! Completion certifies the final anchored-group signal and direct-child reaping,
//! not descendant disappearance, rollback, or bounded shutdown on a broken OS.
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::bindings::{ControllerPlan, PreparedController};
use crate::capture::{Capture, drain};
use crate::config::CleanupDiagnostics;
use crate::process::Children;
use crate::progress::Reporter;
use crate::reply::{
    ControllerData, ControllerError, ControllerReply, ControllerTermination, ErrorCode,
    GroupCleanup,
};
const GRACE: Duration = Duration::from_millis(250);
const POLL: Duration = Duration::from_millis(10);
pub(crate) const QUARANTINE_CAPACITY: usize = 16;
const REPAIR_DEPTH_LIMIT: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum QuarantinePhase {
    ChildReap,
    WorkspaceRemove,
}

#[derive(Default)]
struct QuarantineCounts {
    reserved: usize,
    child_reap: usize,
    workspace_remove: usize,
}

pub(crate) struct CleanupQuarantine {
    counts: Mutex<QuarantineCounts>,
}

impl Default for CleanupQuarantine {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_quarantine(mutex: &Mutex<QuarantineCounts>) -> MutexGuard<'_, QuarantineCounts> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl CleanupQuarantine {
    pub(crate) fn new() -> Self {
        Self {
            counts: Mutex::new(QuarantineCounts::default()),
        }
    }

    pub(crate) fn snapshot(&self) -> CleanupDiagnostics {
        let counts = lock_quarantine(&self.counts);
        CleanupDiagnostics {
            capacity: QUARANTINE_CAPACITY,
            child_reap: counts.child_reap,
            workspace_remove: counts.workspace_remove,
        }
    }

    pub(crate) fn try_reserve(self: &Arc<Self>) -> Option<CleanupReservation> {
        let mut counts = lock_quarantine(&self.counts);
        if counts.reserved >= QUARANTINE_CAPACITY {
            return None;
        }
        counts.reserved += 1;
        Some(CleanupReservation {
            quarantine: Arc::clone(self),
            phase: None,
        })
    }
}

pub(crate) struct CleanupReservation {
    quarantine: Arc<CleanupQuarantine>,
    phase: Option<QuarantinePhase>,
}

impl CleanupReservation {
    fn enter_child_reap(&mut self) {
        let emit = {
            let mut counts = lock_quarantine(&self.quarantine.counts);
            if self.phase == Some(QuarantinePhase::ChildReap) {
                None
            } else {
                if self.phase == Some(QuarantinePhase::WorkspaceRemove) {
                    counts.workspace_remove -= 1;
                }
                self.phase = Some(QuarantinePhase::ChildReap);
                counts.child_reap += 1;
                Some((counts.child_reap, counts.workspace_remove))
            }
        };
        if let Some((child_reap, workspace_remove)) = emit {
            audit::cleanup_quarantine(
                "child_reap",
                child_reap,
                workspace_remove,
                QUARANTINE_CAPACITY,
            );
        }
    }

    fn enter_workspace_remove(&mut self) {
        let emit = {
            let mut counts = lock_quarantine(&self.quarantine.counts);
            if self.phase == Some(QuarantinePhase::WorkspaceRemove) {
                None
            } else {
                if self.phase == Some(QuarantinePhase::ChildReap) {
                    counts.child_reap -= 1;
                }
                self.phase = Some(QuarantinePhase::WorkspaceRemove);
                counts.workspace_remove += 1;
                Some((counts.child_reap, counts.workspace_remove))
            }
        };
        if let Some((child_reap, workspace_remove)) = emit {
            audit::cleanup_quarantine(
                "workspace_remove",
                child_reap,
                workspace_remove,
                QUARANTINE_CAPACITY,
            );
        }
    }
}

impl Drop for CleanupReservation {
    fn drop(&mut self) {
        let mut counts = lock_quarantine(&self.quarantine.counts);
        counts.reserved -= 1;
        match self.phase {
            Some(QuarantinePhase::ChildReap) => counts.child_reap -= 1,
            Some(QuarantinePhase::WorkspaceRemove) => counts.workspace_remove -= 1,
            None => {}
        }
    }
}

pub(crate) struct ControllerContext<'a> {
    pub deadline: tokio::time::Instant,
    pub ct: &'a CancellationToken,
    pub shutdown: &'a CancellationToken,
    pub started: Instant,
    pub capture_limit: u64,
    pub retention: Option<crate::output::Session>,
    pub progress: Reporter,
}

pub(crate) struct ControllerRun {
    pub reply: ControllerReply,
    pub pending: Option<PendingCleanup>,
}

struct Setup {
    workspace: Option<PathBuf>,
    root_identity: Option<(nix::libc::dev_t, nix::libc::ino_t)>,
    ready: bool,
}

/// Owned by the server's tracked local task, including after its receiver drops.
/// Never abort this owner or release its admission permit before finish returns.
pub(crate) struct PendingCleanup {
    setup: Option<JoinHandle<Setup>>,
    workspace: Option<PathBuf>,
    root_identity: Option<(nix::libc::dev_t, nix::libc::ino_t)>,
    cleanup: Option<JoinHandle<io::Result<()>>>,
    children: Children,
}

impl PendingCleanup {
    fn new() -> Self {
        Self {
            setup: None,
            workspace: None,
            root_identity: None,
            cleanup: None,
            children: Children::default(),
        }
    }

    fn start_workspace_cleanup(&mut self) {
        if self.cleanup.is_none()
            && let Some(path) = self.workspace.as_ref()
        {
            let path = path.clone();
            let identity = self.root_identity;
            self.cleanup = Some(tokio::task::spawn_blocking(move || {
                remove_workspace(&path, identity)
            }));
        }
    }

    pub(crate) async fn finish_with(
        mut self,
        mut permit: Option<OwnedSemaphorePermit>,
        mut slot: Option<CleanupReservation>,
    ) {
        if let Some(setup) = self.setup.take()
            && let Ok(setup) = setup.await
        {
            self.workspace = setup.workspace;
            self.root_identity = setup.root_identity;
        }
        self.children.signal_final();
        let mut reaped = self.children.reap();
        if !reaped && let Some(reservation) = slot.as_mut() {
            reservation.enter_child_reap();
        }
        let mut backoff = POLL;
        let mut total_wait = Duration::ZERO;
        let mut warned = false;
        while !reaped {
            tokio::time::sleep(backoff).await;
            total_wait = total_wait.saturating_add(backoff);
            if !warned && total_wait >= Duration::from_secs(2) {
                warned = true;
                crate::audit::emit(&serde_json::json!({
                    "event": "controller_reap_delayed",
                    "elapsed_ms": u64::try_from(total_wait.as_millis()).unwrap_or(u64::MAX),
                }));
            }
            backoff = (backoff * 2).min(GRACE);
            reaped = self.children.reap();
        }
        while self.workspace.is_some() {
            self.start_workspace_cleanup();
            if let Some(cleanup) = self.cleanup.take() {
                if matches!(cleanup.await, Ok(Ok(()))) {
                    self.workspace = None;
                    break;
                }
                if let Some(reservation) = slot.as_mut() {
                    reservation.enter_workspace_remove();
                }
                if slot.is_some() {
                    permit.take();
                }
                tokio::time::sleep(GRACE).await;
            }
        }
        drop(permit);
        drop(slot);
    }
}

fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    openat(
        nix::fcntl::AT_FDCWD,
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
}

fn clean_dir_fd(dir_fd: std::os::fd::BorrowedFd<'_>, uid: u32, depth: usize) -> io::Result<()> {
    if depth > REPAIR_DEPTH_LIMIT {
        return Err(io::Error::other("controller workspace repair depth limit"));
    }
    let dir_stat = fstat(dir_fd).map_err(io::Error::from)?;
    if !SFlag::from_bits_truncate(dir_stat.st_mode).contains(SFlag::S_IFDIR)
        || dir_stat.st_uid != uid
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "controller workspace directory is not owned",
        ));
    }
    if !Mode::from_bits_truncate(dir_stat.st_mode).contains(Mode::S_IRWXU) {
        fchmod(dir_fd, Mode::S_IRWXU).map_err(io::Error::from)?;
    }
    let mut stream = Dir::openat(
        dir_fd,
        c".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut names: Vec<CString> = Vec::new();
    for entry in stream.iter() {
        let entry = entry.map_err(io::Error::from)?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(entry.file_name().to_owned());
    }
    drop(stream);
    for name in names {
        clean_entry(dir_fd, name.as_c_str(), uid, depth)?;
    }
    Ok(())
}

fn clean_entry(
    dir_fd: std::os::fd::BorrowedFd<'_>,
    name: &CStr,
    uid: u32,
    depth: usize,
) -> io::Result<()> {
    let entry_stat = match fstatat(dir_fd, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(()),
        Err(error) => return Err(io::Error::from(error)),
    };
    if SFlag::from_bits_truncate(entry_stat.st_mode).contains(SFlag::S_IFDIR) {
        if entry_stat.st_uid != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controller subdirectory is not owned",
            ));
        }
        let child_fd = match openat(
            dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::ENOENT) => return Ok(()),
            Err(error) => return Err(io::Error::from(error)),
        };
        let opened_stat = fstat(&child_fd).map_err(io::Error::from)?;
        if !SFlag::from_bits_truncate(opened_stat.st_mode).contains(SFlag::S_IFDIR)
            || opened_stat.st_uid != uid
            || opened_stat.st_dev != entry_stat.st_dev
            || opened_stat.st_ino != entry_stat.st_ino
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "controller subdirectory identity changed",
            ));
        }
        clean_dir_fd(child_fd.as_fd(), uid, depth + 1)?;
        drop(child_fd);
        match unlinkat(dir_fd, name, UnlinkatFlags::RemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    } else {
        match unlinkat(dir_fd, name, UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(error) => Err(io::Error::from(error)),
        }
    }
}

fn repair_and_remove_workspace(
    root: &Path,
    root_identity: Option<(nix::libc::dev_t, nix::libc::ino_t)>,
) -> io::Result<()> {
    let root_fd = match open_dir_nofollow(root) {
        Ok(fd) => fd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let uid = nix::unistd::geteuid().as_raw();
    let st = fstat(&root_fd).map_err(io::Error::from)?;
    if !SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFDIR) || st.st_uid != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "controller workspace root ownership mismatch",
        ));
    }
    if let Some((dev, ino)) = root_identity
        && (st.st_dev != dev || st.st_ino != ino)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "controller workspace root identity changed",
        ));
    }
    clean_dir_fd(root_fd.as_fd(), uid, 0)?;
    drop(root_fd);
    match fs::remove_dir_all(root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn remove_workspace(
    root: &Path,
    root_identity: Option<(nix::libc::dev_t, nix::libc::ino_t)>,
) -> io::Result<()> {
    match fs::remove_dir_all(root) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            repair_and_remove_workspace(root, root_identity)
        }
        Err(error) => Err(error),
    }
}

fn prepare_workspace(plan: Arc<ControllerPlan>, input: Vec<u8>) -> Setup {
    let mut workspace = None;
    let mut root_identity = None;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
        let directory = tempfile::Builder::new()
            .prefix("controller-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(plan.workspace_root.as_ref())?;
        workspace = Some(directory.keep());
        let path = workspace
            .as_ref()
            .ok_or_else(|| io::Error::other("controller setup failed"))?;
        fs::set_permissions(path, Permissions::from_mode(0o700))?;
        let root_fd = open_dir_nofollow(path)?;
        let root_stat = fstat(&root_fd).map_err(io::Error::from)?;
        root_identity = Some((root_stat.st_dev, root_stat.st_ino));
        for (name, bytes) in [
            ("source", plan.source.as_bytes()),
            ("input.json", input.as_slice()),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))?;
            file.set_permissions(Permissions::from_mode(0o600))?;
            file.write_all(bytes)?;
            file.flush()?;
        }
        Ok(())
    }));
    Setup {
        workspace,
        root_identity,
        ready: matches!(result, Ok(Ok(()))),
    }
}

fn spawn_script_blocking(
    plan: &ControllerPlan,
    workspace: &Path,
) -> (
    Children,
    io::Result<(std::process::ChildStdout, std::process::ChildStderr)>,
) {
    let mut owner = Children::default();
    let result = (|| {
        let group = owner.start_anchor()?;
        let group =
            i32::try_from(group).map_err(|_| io::Error::other("controller spawn failed"))?;
        let mut command = Command::new(&plan.interpreter);
        command
            .args(&plan.interpreter_argv)
            .arg(workspace.join("source"))
            .arg(workspace.join("input.json"))
            .current_dir(plan.cwd.as_deref().unwrap_or(workspace))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .envs(&plan.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(group);
        for name in [
            "HOME",
            "TMPDIR",
            "TMP",
            "TEMP",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
        ] {
            command.env(name, workspace);
        }
        owner.install_script(command.spawn()?);
        let child = owner
            .script
            .as_mut()
            .ok_or_else(|| io::Error::other("controller spawn failed"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("controller pipe failed"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("controller pipe failed"))?;
        Ok((stdout, stderr))
    })();
    (owner, result)
}

enum Outcome {
    Completed(ExitStatus),
    Timeout,
    Cancelled,
    Io,
    Spawn,
    Setup,
}

async fn read_pipe<R: AsyncRead + Unpin>(
    pipe: &mut Option<R>,
    buffer: &mut [u8],
) -> io::Result<usize> {
    match pipe {
        Some(pipe) => pipe.read(buffer).await,
        None => std::future::pending().await,
    }
}

async fn monitor(
    owner: &mut PendingCleanup,
    stdout: &mut Option<ChildStdout>,
    stderr: &mut Option<ChildStderr>,
    output: &mut Capture,
    errors: &mut Capture,
    context: &ControllerContext<'_>,
) -> Outcome {
    let mut out_buffer = [0; 8192];
    let mut err_buffer = [0; 8192];
    loop {
        match owner.children.script_status() {
            Ok(Some(status)) => return Outcome::Completed(status),
            Err(_) => return Outcome::Io,
            Ok(None) => {}
        }
        tokio::select! {
            () = context.ct.cancelled() => return Outcome::Cancelled,
            () = context.shutdown.cancelled() => return Outcome::Cancelled,
            () = tokio::time::sleep_until(context.deadline) => return Outcome::Timeout,
            () = tokio::time::sleep(POLL) => {},
            result = read_pipe(stdout, &mut out_buffer) => match result {
                Ok(0) => { stdout.take(); },
                Ok(count) => output.retain(&out_buffer[..count]),
                Err(_) => { output.incomplete(); stdout.take(); return Outcome::Io; },
            },
            result = read_pipe(stderr, &mut err_buffer) => match result {
                Ok(0) => { stderr.take(); },
                Ok(count) => errors.retain(&err_buffer[..count]),
                Err(_) => { errors.incomplete(); stderr.take(); return Outcome::Io; },
            },
        }
    }
}

async fn finish_drain<R: AsyncRead + Unpin>(pipe: Option<R>, capture: &mut Capture) -> bool {
    let Some(pipe) = pipe else {
        return true;
    };
    match tokio::time::timeout(GRACE, drain(pipe, capture)).await {
        Ok(Ok(())) => true,
        _ => {
            capture.incomplete();
            false
        }
    }
}

pub(crate) async fn run(
    prepared: PreparedController,
    mut context: ControllerContext<'_>,
) -> ControllerRun {
    context.deadline = context
        .deadline
        .min(tokio::time::Instant::now() + prepared.duration);
    let mut owner = PendingCleanup::new();
    let plan = prepared.plan;
    let setup_plan = Arc::clone(&plan);
    owner.setup = Some(tokio::task::spawn_blocking(move || {
        prepare_workspace(setup_plan, prepared.input_json)
    }));
    let limit = context.capture_limit.min(prepared.max_output_bytes);
    let capture = || match context.retention.as_ref() {
        Some(retention) => Capture::with_retention(limit, retention.capture_limit()),
        None => Capture::new(limit),
    };
    let mut output = capture();
    let mut errors = capture();
    output.report_to(context.progress.clone());
    errors.report_to(context.progress.clone());
    let mut stdout = None;
    let mut stderr = None;

    let operation = AssertUnwindSafe(async {
        let setup = match owner.setup.as_mut() {
            Some(setup) => tokio::select! {
                biased;
                () = context.ct.cancelled() => return Outcome::Cancelled,
                () = context.shutdown.cancelled() => return Outcome::Cancelled,
                () = tokio::time::sleep_until(context.deadline) => return Outcome::Timeout,
                result = setup => result,
            },
            None => return Outcome::Setup,
        };
        owner.setup.take();
        let setup = match setup {
            Ok(setup) => setup,
            Err(_) => return Outcome::Setup,
        };
        owner.workspace = setup.workspace;
        owner.root_identity = setup.root_identity;
        if !setup.ready {
            return Outcome::Setup;
        }
        if context.ct.is_cancelled() || context.shutdown.is_cancelled() {
            return Outcome::Cancelled;
        }
        if tokio::time::Instant::now() >= context.deadline {
            return Outcome::Timeout;
        }
        let Some(workspace) = owner.workspace.clone() else {
            return Outcome::Setup;
        };
        let spawn_plan = Arc::clone(&plan);
        let Ok((children, spawned)) =
            tokio::task::spawn_blocking(move || spawn_script_blocking(&spawn_plan, &workspace))
                .await
        else {
            return Outcome::Spawn;
        };
        owner.children = children;
        match spawned
            .and_then(|(out, err)| Ok((ChildStdout::from_std(out)?, ChildStderr::from_std(err)?)))
        {
            Ok((out, err)) => {
                stdout = Some(out);
                stderr = Some(err);
                context.progress.output_started();
            }
            Err(_) if owner.children.script.is_some() => return Outcome::Io,
            Err(_) => return Outcome::Spawn,
        }
        monitor(
            &mut owner,
            &mut stdout,
            &mut stderr,
            &mut output,
            &mut errors,
            &context,
        )
        .await
    })
    .catch_unwind()
    .await;
    context.progress.stop();
    let outcome = operation.unwrap_or(Outcome::Io);
    let started = owner.children.started();
    owner.children.signal_final();
    let cleanup_deadline = tokio::time::Instant::now() + GRACE;
    let (out_complete, err_complete) = tokio::join!(
        finish_drain(stdout.take(), &mut output),
        finish_drain(stderr.take(), &mut errors),
    );
    let mut reaped = owner.children.reap();
    while !reaped && tokio::time::Instant::now() < cleanup_deadline {
        tokio::time::sleep(POLL).await;
        reaped = owner.children.reap();
    }
    let mut cleanup_ok = true;
    if reaped && owner.setup.is_none() {
        owner.start_workspace_cleanup();
        if let Some(cleanup) = owner.cleanup.as_mut() {
            match tokio::time::timeout_at(cleanup_deadline, cleanup).await {
                Ok(Ok(Ok(()))) => {
                    owner.cleanup.take();
                    owner.workspace = None;
                }
                Ok(_) => {
                    owner.cleanup.take();
                    cleanup_ok = false;
                }
                Err(_) => cleanup_ok = false,
            }
        }
    } else {
        cleanup_ok = false;
    }
    let group_cleanup = if !started {
        GroupCleanup::NotStarted
    } else if reaped && owner.children.clean() && cleanup_ok && out_complete && err_complete {
        GroupCleanup::SignalledAndReaped
    } else {
        GroupCleanup::Incomplete
    };
    let cancelled = matches!(outcome, Outcome::Cancelled) || context.ct.is_cancelled();
    let (exit_code, signal, termination, mut failure) = match outcome {
        Outcome::Completed(status) => (
            status.code(),
            status.signal(),
            if status.signal().is_some() {
                ControllerTermination::Signalled
            } else {
                ControllerTermination::Exited
            },
            if status.success() {
                None
            } else {
                Some(ControllerError::new(
                    ErrorCode::CommandFailed,
                    "Controller command failed",
                ))
            },
        ),
        Outcome::Timeout => (
            None,
            None,
            ControllerTermination::Timeout,
            Some(ControllerError::new(
                ErrorCode::Timeout,
                "Controller command deadline exceeded",
            )),
        ),
        Outcome::Cancelled => (
            None,
            None,
            ControllerTermination::Cancelled,
            Some(ControllerError::new(
                ErrorCode::Cancelled,
                "Controller command cancelled",
            )),
        ),
        Outcome::Io => (
            None,
            None,
            ControllerTermination::IoError,
            Some(ControllerError::new(
                ErrorCode::IoError,
                "Controller command I/O failed",
            )),
        ),
        Outcome::Spawn => (
            None,
            None,
            ControllerTermination::IoError,
            Some(ControllerError::new(
                ErrorCode::SpawnFailed,
                "Controller command could not start",
            )),
        ),
        Outcome::Setup => (
            None,
            None,
            ControllerTermination::IoError,
            Some(ControllerError::new(
                ErrorCode::ResourceUnavailable,
                "Controller private workspace preparation failed",
            )),
        ),
    };
    if failure.is_none()
        && (!cleanup_ok || (started && !owner.children.clean()) || !out_complete || !err_complete)
    {
        failure = Some(ControllerError::new(
            ErrorCode::CleanupIncomplete,
            "Controller cleanup is incomplete",
        ));
    }
    let (stdout, stdout_truncated, stdout_lossy, retained_stdout) = output.finish();
    let (stderr, stderr_truncated, stderr_lossy, retained_stderr) = errors.finish();
    let duration_ms = u64::try_from(context.started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let output = if cancelled {
        drop(context.retention);
        None
    } else {
        match context.retention {
            Some(retention) => {
                retention
                    .finish(
                        retained_stdout.unwrap_or_default(),
                        retained_stderr.unwrap_or_default(),
                        context.ct,
                    )
                    .await
            }
            None => None,
        }
    };
    let data = ControllerData {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        stdout_lossy,
        stderr_lossy,
        exit_code,
        signal,
        termination,
        duration_ms,
        owned_group_cleanup: group_cleanup,
        output,
    };
    let pending =
        if owner.setup.is_some() || !reaped || owner.workspace.is_some() || owner.cleanup.is_some()
        {
            Some(owner)
        } else {
            None
        };
    ControllerRun {
        reply: ControllerReply::with_optional_error(data, failure),
        pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_removes_private_0555_workspace_without_following_symlinks() {
        let base = tempfile::tempdir().unwrap();
        let external = base.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("keep"), b"untouched").unwrap();
        fs::set_permissions(&external, Permissions::from_mode(0o555)).unwrap();

        let workspace = base.path().join("controller-ws");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, Permissions::from_mode(0o700)).unwrap();
        let root_stat = fstat(open_dir_nofollow(&workspace).unwrap()).unwrap();
        let sub = workspace.join("sub");
        fs::create_dir(&sub).unwrap();
        let nested = sub.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("data"), b"bytes").unwrap();
        std::os::unix::fs::symlink(&external, sub.join("link")).unwrap();
        fs::set_permissions(&nested, Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&sub, Permissions::from_mode(0o555)).unwrap();

        remove_workspace(&workspace, Some((root_stat.st_dev, root_stat.st_ino))).unwrap();
        assert!(!workspace.exists());
        assert_eq!(
            fs::metadata(&external).unwrap().permissions().mode() & 0o777,
            0o555
        );
        assert_eq!(fs::read(external.join("keep")).unwrap(), b"untouched");
        fs::set_permissions(&external, Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn quarantine_tracks_phases_and_saturates_at_capacity() {
        let quarantine = Arc::new(CleanupQuarantine::new());
        let mut slots = Vec::new();
        for _ in 0..QUARANTINE_CAPACITY {
            slots.push(quarantine.try_reserve().unwrap());
        }
        assert!(quarantine.try_reserve().is_none());
        slots[0].enter_child_reap();
        slots[1].enter_workspace_remove();
        slots[0].enter_workspace_remove();
        let snap = quarantine.snapshot();
        assert_eq!(snap.capacity, QUARANTINE_CAPACITY);
        assert_eq!(snap.child_reap, 0);
        assert_eq!(snap.workspace_remove, 2);
        slots.pop();
        assert!(quarantine.try_reserve().is_some());
    }
}
