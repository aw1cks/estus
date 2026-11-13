//! Explicit local execution with private file input and retained cleanup ownership.
//!
//! Process groups are not containment: descendants may escape with setsid/setpgid.
//! Completion certifies the final anchored-group signal and direct-child reaping,
//! not descendant disappearance, rollback, or bounded shutdown on a broken OS.
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::FutureExt;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::bindings::{ControllerPlan, PreparedController};
use crate::capture::{Capture, drain};
use crate::process::Children;
use crate::reply::{
    ControllerData, ControllerError, ControllerReply, ControllerTermination, GroupCleanup,
};

const GRACE: Duration = Duration::from_millis(250);
const POLL: Duration = Duration::from_millis(10);

/// Concrete child protocols; native controller scripts retain their existing mode.
#[derive(Debug)]
pub(crate) enum ControllerSupervision {
    Script,
    Automation {
        invocation_id: String,
        mode: crate::automation_exec::ExecutionMode,
        scratch_bytes: u64,
        scratch_files: usize,
    },
}

pub(crate) struct ControllerContext<'a> {
    pub deadline: tokio::time::Instant,
    pub ct: &'a CancellationToken,
    pub shutdown: &'a CancellationToken,
    pub started: Instant,
    pub capture_limit: u64,
}

pub(crate) struct ControllerRun {
    pub reply: ControllerReply,
    pub pending: Option<PendingCleanup>,
    pub automation: Option<crate::automation_exec::Evidence>,
}

struct Setup {
    workspace: Option<PathBuf>,
    ready: bool,
}

enum LeaseStage {
    Waiting,
    Running,
    Finished { clean: bool },
    Closed { clean: bool },
}

/// The CLI wrapper alone holds the writer until process exit. Its own child
/// never inherits it, so EOF cannot precede wrapper exit and child reaping.
struct CliLease {
    reader: fs::File,
    startup_writer: Option<fs::File>,
    stage: LeaseStage,
    invalid: bool,
}

impl CliLease {
    fn open(path: &Path) -> io::Result<Self> {
        let flags = nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW;
        let reader = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?;
        if !reader.metadata()?.file_type().is_fifo() {
            return Err(io::Error::other("invalid CLI lifetime pipe"));
        }
        let writer = OpenOptions::new()
            .write(true)
            .custom_flags(flags)
            .open(path)?;
        Ok(Self {
            reader,
            startup_writer: Some(writer),
            stage: LeaseStage::Waiting,
            invalid: false,
        })
    }

    fn poll(&mut self) -> io::Result<()> {
        if matches!(self.stage, LeaseStage::Closed { .. }) {
            return Ok(());
        }
        let mut bytes = [0; 8];
        loop {
            let count = match self.reader.read(&mut bytes) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if count == 0 {
                let clean =
                    matches!(self.stage, LeaseStage::Finished { clean: true }) && !self.invalid;
                self.stage = LeaseStage::Closed { clean };
                return Ok(());
            }
            for &byte in &bytes[..count] {
                match (&self.stage, byte) {
                    (LeaseStage::Waiting, b'R') => {
                        self.startup_writer.take();
                        self.stage = LeaseStage::Running;
                    }
                    (LeaseStage::Running, b'C' | b'F') => {
                        self.stage = LeaseStage::Finished {
                            clean: byte == b'C',
                        };
                    }
                    _ => {
                        self.invalid = true;
                        self.startup_writer.take();
                        if matches!(self.stage, LeaseStage::Waiting) {
                            self.stage = LeaseStage::Running;
                        }
                    }
                }
            }
        }
    }

    fn active(&self) -> bool {
        matches!(
            self.stage,
            LeaseStage::Running | LeaseStage::Finished { .. }
        )
    }

    fn clean(&self) -> bool {
        !self.invalid
            && matches!(
                self.stage,
                LeaseStage::Waiting | LeaseStage::Closed { clean: true }
            )
    }
}

/// Owned by the server's tracked local task, including after its receiver drops.
/// Never abort this owner or release its admission permit before finish returns.
pub(crate) struct PendingCleanup {
    setup: Option<JoinHandle<Setup>>,
    workspace: Option<PathBuf>,
    cleanup: Option<JoinHandle<io::Result<()>>>,
    children: Children,
    control: Option<ChildStdin>,
    scratch: Option<JoinHandle<io::Result<bool>>>,
    lease: Option<CliLease>,
}

impl PendingCleanup {
    fn new() -> Self {
        Self {
            setup: None,
            workspace: None,
            cleanup: None,
            children: Children::default(),
            control: None,
            scratch: None,
            lease: None,
        }
    }

    fn start_workspace_cleanup(&mut self) {
        if self.cleanup.is_none()
            && let Some(path) = self.workspace.as_ref()
        {
            let path = path.clone();
            self.cleanup = Some(tokio::task::spawn_blocking(
                move || match fs::remove_dir_all(path) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    result => result,
                },
            ));
        }
    }

    /// An unkillable direct child or persistently failing filesystem can keep
    /// this owner alive indefinitely. No numeric process-group polling occurs.
    pub(crate) async fn finish(mut self) {
        if let Some(setup) = self.setup.take()
            && let Ok(setup) = setup.await
        {
            self.workspace = setup.workspace;
        }
        self.control.take();
        self.children.signal_final();
        if let Some(scratch) = self.scratch.take() {
            let _ = scratch.await;
        }
        while !self.children.reap() {
            tokio::time::sleep(POLL).await;
        }
        loop {
            if let Some(lease) = self.lease.as_mut() {
                let _ = lease.poll();
                if lease.active() {
                    tokio::time::sleep(POLL).await;
                    continue;
                }
            }
            break;
        }
        while self.workspace.is_some() {
            self.start_workspace_cleanup();
            if let Some(cleanup) = self.cleanup.take() {
                if matches!(cleanup.await, Ok(Ok(()))) {
                    self.workspace = None;
                } else {
                    tokio::time::sleep(GRACE).await;
                }
            }
        }
    }
}

fn prepare_workspace(plan: Arc<ControllerPlan>, input: Vec<u8>, automation: bool) -> Setup {
    let mut workspace = None;
    // The path owner is outside the unwind boundary so partial private files
    // survive a setup panic as an explicitly owned cleanup obligation.
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
        if automation {
            nix::unistd::mkfifo(
                &path.join("runner.lease"),
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )?;
        }
        Ok(())
    }));
    Setup {
        workspace,
        ready: matches!(result, Ok(Ok(()))),
    }
}

fn spawn_script(
    owner: &mut Children,
    control: &mut Option<ChildStdin>,
    plan: &ControllerPlan,
    workspace: &Path,
    automation: bool,
) -> io::Result<(ChildStdout, ChildStderr)> {
    let group = owner.start_anchor()?;
    let group = i32::try_from(group).map_err(|_| io::Error::other("controller spawn failed"))?;
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
        .stdin(if automation {
            Stdio::piped()
        } else {
            Stdio::null()
        })
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
    // Both std Child handles are owned before either fallible Tokio conversion.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("controller pipe failed"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("controller pipe failed"))?;
    *control = child.stdin.take();
    Ok((
        ChildStdout::from_std(stdout)?,
        ChildStderr::from_std(stderr)?,
    ))
}

enum Outcome {
    Completed(ExitStatus),
    Timeout,
    Cancelled,
    Io,
    Spawn,
    Setup,
    Protocol,
    Resource,
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

struct Monitoring {
    automation: Option<crate::automation_exec::Evidence>,
    scratch: Option<(u64, usize)>,
}

fn scratch_within_limit(root: &Path, mut bytes: u64, mut files: usize) -> io::Result<bool> {
    fn visit(path: &Path, depth: usize, bytes: &mut u64, files: &mut usize) -> io::Result<bool> {
        if depth > 16 {
            return Ok(false);
        }
        let entries = match fs::read_dir(path) {
            Err(error) if depth > 0 && error.kind() == io::ErrorKind::NotFound => return Ok(true),
            result => result?,
        };
        for entry in entries {
            let entry = entry?;
            if *files == 0 {
                return Ok(false);
            }
            *files -= 1;
            let metadata = match entry.path().symlink_metadata() {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                result => result?,
            };
            if metadata.is_dir() {
                if !visit(&entry.path(), depth + 1, bytes, files)? {
                    return Ok(false);
                }
            } else if metadata.is_file() {
                if metadata.len() > *bytes {
                    return Ok(false);
                }
                *bytes -= metadata.len();
            } else if !(depth == 0
                && entry.file_name() == "runner.lease"
                && metadata.file_type().is_fifo())
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    visit(root, 0, &mut bytes, &mut files)
}

async fn monitor(
    owner: &mut PendingCleanup,
    stdout: &mut Option<ChildStdout>,
    stderr: &mut Option<ChildStderr>,
    output: &mut Capture,
    errors: &mut Capture,
    context: &ControllerContext<'_>,
    monitoring: &mut Monitoring,
) -> Outcome {
    let mut out_buffer = [0; 8192];
    let mut err_buffer = [0; 8192];
    let mut next_scratch = tokio::time::Instant::now();
    loop {
        // Status wins over a late cancellation, including when no pipes remain.
        match owner.children.script_status() {
            Ok(Some(status)) => return Outcome::Completed(status),
            Err(_) => return Outcome::Io,
            Ok(None) => {}
        }
        if let Some(lease) = owner.lease.as_mut() {
            if lease.poll().is_err() {
                return Outcome::Io;
            }
            if lease.invalid {
                return Outcome::Protocol;
            }
        }
        if let Some((bytes, files)) = monitoring.scratch {
            if owner.scratch.as_ref().is_some_and(JoinHandle::is_finished) {
                let Some(scan) = owner.scratch.take() else {
                    return Outcome::Io;
                };
                match scan.await {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => return Outcome::Resource,
                    _ => return Outcome::Io,
                }
            }
            if owner.scratch.is_none() && tokio::time::Instant::now() >= next_scratch {
                let Some(path) = owner.workspace.as_ref() else {
                    return Outcome::Io;
                };
                let path = path.clone();
                owner.scratch = Some(tokio::task::spawn_blocking(move || {
                    scratch_within_limit(&path, bytes, files)
                }));
                next_scratch = tokio::time::Instant::now() + Duration::from_millis(100);
            }
        }
        tokio::select! {
            () = context.ct.cancelled() => return Outcome::Cancelled,
            () = context.shutdown.cancelled() => return Outcome::Cancelled,
            () = tokio::time::sleep_until(context.deadline) => return Outcome::Timeout,
            () = tokio::time::sleep(POLL) => {},
            result = read_pipe(stdout, &mut out_buffer) => match result {
                Ok(0) => { stdout.take(); },
                Ok(count) => if let Some(evidence) = monitoring.automation.as_mut() {
                    evidence.feed(&out_buffer[..count]);
                    if evidence.failed() {
                        return if evidence.resource_limited() { Outcome::Resource } else { Outcome::Protocol };
                    }
                } else { output.retain(&out_buffer[..count]); },
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

async fn finish_protocol(
    mut pipe: Option<ChildStdout>,
    capture: &mut Capture,
    evidence: &mut Option<crate::automation_exec::Evidence>,
) -> bool {
    if evidence.is_none() {
        return finish_drain(pipe, capture).await;
    }
    let result = tokio::time::timeout(GRACE, async {
        let mut buffer = [0; 8192];
        while let Some(stream) = pipe.as_mut() {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if let Some(evidence) = evidence.as_mut() {
                evidence.feed(&buffer[..count]);
            }
        }
        Ok::<_, io::Error>(())
    })
    .await;
    if let Some(evidence) = evidence.as_mut() {
        evidence.finish();
    }
    matches!(result, Ok(Ok(())))
}

async fn cooperative_finish(
    owner: &mut PendingCleanup,
    stdout: &mut Option<ChildStdout>,
    stderr: &mut Option<ChildStderr>,
    evidence: &mut crate::automation_exec::Evidence,
) {
    owner.control.take();
    if owner.children.script.is_none() {
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut output = [0; 8192];
    let mut errors = [0; 8192];
    while tokio::time::Instant::now() < deadline {
        let cli_done = owner.lease.as_mut().is_none_or(|lease| {
            let _ = lease.poll();
            !lease.active()
        });
        if !matches!(owner.children.script_status(), Ok(None)) && cli_done {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(POLL) => {},
            result = read_pipe(stdout, &mut output) => match result {
                Ok(0) | Err(_) => { stdout.take(); },
                Ok(count) => evidence.feed(&output[..count]),
            },
            result = read_pipe(stderr, &mut errors) => {
                if !matches!(result, Ok(1..)) { stderr.take(); }
            },
        }
    }
}

fn error(code: &'static str, message: &'static str) -> ControllerError {
    ControllerError::new(code, message)
}

pub(crate) async fn run(
    prepared: PreparedController,
    mut context: ControllerContext<'_>,
) -> ControllerRun {
    context.deadline = context
        .deadline
        .min(tokio::time::Instant::now() + prepared.duration);
    let mut monitoring = match prepared.supervision {
        ControllerSupervision::Script => Monitoring {
            automation: None,
            scratch: None,
        },
        ControllerSupervision::Automation {
            invocation_id,
            mode,
            scratch_bytes,
            scratch_files,
        } => Monitoring {
            automation: Some(crate::automation_exec::Evidence::new(invocation_id, mode)),
            scratch: Some((scratch_bytes, scratch_files)),
        },
    };
    let mut owner = PendingCleanup::new();
    let plan = prepared.plan;
    let setup_plan = Arc::clone(&plan);
    let automation = monitoring.automation.is_some();
    owner.setup = Some(tokio::task::spawn_blocking(move || {
        prepare_workspace(setup_plan, prepared.input_json, automation)
    }));
    let limit = if monitoring.automation.is_some() {
        0
    } else {
        context.capture_limit.min(prepared.max_output_bytes)
    };
    let mut output = Capture::new(limit);
    let mut errors = Capture::new(limit);
    let mut stdout = None;
    let mut stderr = None;

    // All direct-child/workspace/capture ownership lives outside catch_unwind.
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
        if !setup.ready {
            return Outcome::Setup;
        }
        // Cancellation after blocking setup cannot dispatch a new child.
        if context.ct.is_cancelled() || context.shutdown.is_cancelled() {
            return Outcome::Cancelled;
        }
        if tokio::time::Instant::now() >= context.deadline {
            return Outcome::Timeout;
        }
        let Some(workspace) = owner.workspace.as_ref() else {
            return Outcome::Setup;
        };
        if monitoring.automation.is_some() {
            owner.lease = match CliLease::open(&workspace.join("runner.lease")) {
                Ok(lease) => Some(lease),
                Err(_) => return Outcome::Setup,
            };
        }
        match spawn_script(
            &mut owner.children,
            &mut owner.control,
            &plan,
            workspace,
            monitoring.automation.is_some(),
        ) {
            Ok((out, err)) => {
                stdout = Some(out);
                stderr = Some(err);
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
            &mut monitoring,
        )
        .await
    })
    .catch_unwind()
    .await;
    let mut outcome = operation.unwrap_or(Outcome::Io);
    let started = owner.children.started();
    if let Some(evidence) = monitoring.automation.as_mut() {
        evidence.stop();
        cooperative_finish(&mut owner, &mut stdout, &mut stderr, evidence).await;
    }
    owner.children.signal_final();
    let cleanup_deadline = tokio::time::Instant::now() + GRACE;
    let (out_complete, err_complete) = tokio::join!(
        finish_protocol(stdout.take(), &mut output, &mut monitoring.automation),
        finish_drain(stderr.take(), &mut errors),
    );
    let mut reaped = owner.children.reap();
    while !reaped && tokio::time::Instant::now() < cleanup_deadline {
        tokio::time::sleep(POLL).await;
        reaped = owner.children.reap();
    }
    let mut cleanup_ok = true;
    if let Some(scan) = owner.scratch.as_mut() {
        match tokio::time::timeout_at(cleanup_deadline, scan).await {
            Ok(Ok(Ok(true))) => {
                owner.scratch.take();
            }
            Ok(Ok(Ok(false))) => {
                owner.scratch.take();
                outcome = Outcome::Resource;
            }
            Ok(_) => {
                owner.scratch.take();
                outcome = Outcome::Io;
            }
            Err(_) => cleanup_ok = false,
        }
    }
    let lease_done = owner.lease.as_mut().is_none_or(|lease| {
        if lease.poll().is_err() {
            return false;
        }
        !lease.active()
    });
    cleanup_ok &= owner.lease.as_ref().is_none_or(CliLease::clean);
    if reaped && owner.setup.is_none() && owner.scratch.is_none() && lease_done {
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
                Some(error("command_failed", "Controller command failed"))
            },
        ),
        Outcome::Timeout => (
            None,
            None,
            ControllerTermination::Timeout,
            Some(error("timeout", "Controller command deadline exceeded")),
        ),
        Outcome::Cancelled => (
            None,
            None,
            ControllerTermination::Cancelled,
            Some(error("cancelled", "Controller command cancelled")),
        ),
        Outcome::Protocol => (
            None,
            None,
            ControllerTermination::IoError,
            Some(error("invalid_result", "Controller protocol was invalid")),
        ),
        Outcome::Resource => (
            None,
            None,
            ControllerTermination::IoError,
            Some(error(
                "resource_limit",
                "Controller workspace or protocol limit exceeded",
            )),
        ),
        Outcome::Io => (
            None,
            None,
            ControllerTermination::IoError,
            Some(error("io_error", "Controller command I/O failed")),
        ),
        Outcome::Spawn => (
            None,
            None,
            ControllerTermination::IoError,
            Some(error("spawn_failed", "Controller command could not start")),
        ),
        Outcome::Setup => (
            None,
            None,
            ControllerTermination::IoError,
            Some(error(
                "resource_unavailable",
                "Controller private workspace preparation failed",
            )),
        ),
    };
    if failure.is_none()
        && (!cleanup_ok || (started && !owner.children.clean()) || !out_complete || !err_complete)
    {
        failure = Some(error(
            "cleanup_incomplete",
            "Controller cleanup is incomplete",
        ));
    }
    let (stdout, stdout_truncated, stdout_lossy) = output.decode();
    let (stderr, stderr_truncated, stderr_lossy) = errors.decode();
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
        duration_ms: u64::try_from(context.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        owned_group_cleanup: group_cleanup,
    };
    let pending = if owner.setup.is_some()
        || !reaped
        || owner.workspace.is_some()
        || owner.cleanup.is_some()
        || owner.scratch.is_some()
        || owner.lease.as_ref().is_some_and(CliLease::active)
    {
        Some(owner)
    } else {
        None
    };
    ControllerRun {
        reply: match failure {
            Some(error) => ControllerReply {
                data: Some(data),
                error: Some(error),
            },
            None => ControllerReply::success(data),
        },
        pending,
        automation: monitoring.automation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_completion_does_not_release_ownership_before_writer_exit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("runner.lease");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let mut lease = CliLease::open(&path).unwrap();
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"RC").unwrap();
        lease.poll().unwrap();
        assert!(
            lease.active(),
            "a completion byte is not process-exit evidence"
        );
        drop(writer);
        lease.poll().unwrap();
        assert!(!lease.active());
        assert!(lease.clean());
        lease.poll().unwrap();
        assert!(
            lease.clean(),
            "later polls must retain accepted exit evidence"
        );
    }

    #[test]
    fn forced_or_missing_cli_cleanup_acknowledgment_is_not_clean() {
        for bytes in [b"RF".as_slice(), b"R", b"RX"] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("runner.lease");
            nix::unistd::mkfifo(
                &path,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            let mut lease = CliLease::open(&path).unwrap();
            let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
            writer.write_all(bytes).unwrap();
            drop(writer);
            lease.poll().unwrap();
            assert!(!lease.active());
            assert!(!lease.clean());
        }
    }
}
