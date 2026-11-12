//! Explicit local execution with private file input and retained cleanup ownership.
//!
//! Process groups are not containment: descendants may escape with setsid/setpgid.
//! Completion certifies the final anchored-group signal and direct-child reaping,
//! not descendant disappearance, rollback, or bounded shutdown on a broken OS.
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
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
}

struct Setup {
    workspace: Option<PathBuf>,
    ready: bool,
}

/// Owned by the server's tracked local task, including after its receiver drops.
/// Never abort this owner or release its admission permit before finish returns.
pub(crate) struct PendingCleanup {
    setup: Option<JoinHandle<Setup>>,
    workspace: Option<PathBuf>,
    cleanup: Option<JoinHandle<io::Result<()>>>,
    children: Children,
}

impl PendingCleanup {
    fn new() -> Self {
        Self {
            setup: None,
            workspace: None,
            cleanup: None,
            children: Children::default(),
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
        self.children.signal_final();
        while !self.children.reap() {
            tokio::time::sleep(POLL).await;
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

fn prepare_workspace(plan: Arc<ControllerPlan>, input: Vec<u8>) -> Setup {
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
        Ok(())
    }));
    Setup {
        workspace,
        ready: matches!(result, Ok(Ok(()))),
    }
}

fn spawn_script(
    owner: &mut Children,
    plan: &ControllerPlan,
    workspace: &Path,
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
    // Both std Child handles are owned before either fallible Tokio conversion.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("controller pipe failed"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("controller pipe failed"))?;
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
    children: &mut Children,
    stdout: &mut Option<ChildStdout>,
    stderr: &mut Option<ChildStderr>,
    output: &mut Capture,
    errors: &mut Capture,
    context: &ControllerContext<'_>,
) -> Outcome {
    let mut out_buffer = [0; 8192];
    let mut err_buffer = [0; 8192];
    loop {
        // Status wins over a late cancellation, including when no pipes remain.
        match children.script_status() {
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
    let mut owner = PendingCleanup::new();
    let plan = prepared.plan;
    let setup_plan = Arc::clone(&plan);
    owner.setup = Some(tokio::task::spawn_blocking(move || {
        prepare_workspace(setup_plan, prepared.input_json)
    }));
    let limit = context.capture_limit.min(prepared.max_output_bytes);
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
        match spawn_script(&mut owner.children, &plan, workspace) {
            Ok((out, err)) => {
                stdout = Some(out);
                stderr = Some(err);
            }
            Err(_) if owner.children.script.is_some() => return Outcome::Io,
            Err(_) => return Outcome::Spawn,
        }
        monitor(
            &mut owner.children,
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
    let pending =
        if owner.setup.is_some() || !reaped || owner.workspace.is_some() || owner.cleanup.is_some()
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
    }
}
