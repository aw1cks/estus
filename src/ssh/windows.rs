//! Per-invocation OpenSSH subprocess transport for Windows.
//!
//! Windows OpenSSH does not support `ControlMaster` Unix domain sockets or
//! `SCM_RIGHTS` FD passing, so each command or SFTP subsystem spawns `ssh.exe`
//! directly while preserving Estus's OpenSSH delegation, hardening options,
//! concurrency bounds, and cancellation semantics.
use crate::{
    config::IdentityRole,
    reply::{ErrorCode, ToolError},
};
use shell_escape::unix::escape as posix_escape;
use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::OsString,
    io,
    marker::PhantomData,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    process::{Child as TokioChild, ChildStderr, ChildStdin, ChildStdout, Command as TokioCommand},
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const CHANNELS: usize = 4;

type Key = (String, String, IdentityRole);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Native,
    Headless,
    Diagnostic,
}

impl Policy {
    fn hardening(self) -> &'static [&'static str] {
        match self {
            Self::Native => &[],
            Self::Headless | Self::Diagnostic => &[
                "StrictHostKeyChecking=yes",
                "UpdateHostKeys=no",
                "AddKeysToAgent=no",
            ],
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum SshError {
    #[error("remote command error: {0}")]
    #[allow(dead_code)]
    Remote(#[source] io::Error),
    #[error("child I/O error: {0}")]
    ChildIo(#[source] io::Error),
    #[error("ssh connection error: {0}")]
    Connect(#[source] io::Error),
    #[error("ssh master error: {0}")]
    #[allow(dead_code)]
    Master(#[source] io::Error),
    #[error("ssh mux error: {0}")]
    #[allow(dead_code)]
    SshMux(#[source] io::Error),
    #[error("ssh session disconnected")]
    Disconnected,
    #[error("remote process terminated")]
    RemoteProcessTerminated,
}

pub(crate) struct Session {
    executable: PathBuf,
    ssh_config: Option<PathBuf>,
    destination: String,
    hardening: &'static [&'static str],
    connect_timeout: Duration,
    agent: Option<Option<OsString>>,
}

impl Session {
    pub(crate) fn command(&self, program: impl AsRef<str>) -> Command<'_> {
        let mut cmd = Command::new(self, false);
        cmd.arg(program);
        cmd
    }

    pub(crate) fn subsystem(&self, name: impl AsRef<str>) -> Command<'_> {
        let mut cmd = Command::new(self, true);
        cmd.raw_arg(name);
        cmd
    }
}

pub(crate) struct Command<'s> {
    session: &'s Session,
    subsystem: bool,
    remote_parts: Vec<String>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl<'s> Command<'s> {
    fn new(session: &'s Session, subsystem: bool) -> Self {
        Self {
            session,
            subsystem,
            remote_parts: Vec::new(),
            stdin: Stdio::null(),
            stdout: Stdio::null(),
            stderr: Stdio::null(),
        }
    }

    pub(crate) fn arg(&mut self, arg: impl AsRef<str>) -> &mut Self {
        self.remote_parts
            .push(posix_escape(Cow::Borrowed(arg.as_ref())).into_owned());
        self
    }

    pub(crate) fn raw_arg(&mut self, arg: impl AsRef<str>) -> &mut Self {
        self.remote_parts.push(arg.as_ref().to_owned());
        self
    }

    pub(crate) fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.arg(arg);
        }
        self
    }

    pub(crate) fn stdin(&mut self, cfg: Stdio) -> &mut Self {
        self.stdin = cfg;
        self
    }

    pub(crate) fn stdout(&mut self, cfg: Stdio) -> &mut Self {
        self.stdout = cfg;
        self
    }

    pub(crate) fn stderr(&mut self, cfg: Stdio) -> &mut Self {
        self.stderr = cfg;
        self
    }

    pub(crate) async fn spawn(&mut self) -> Result<Child<'s>, SshError> {
        let mut cmd = TokioCommand::new(&self.session.executable);
        cmd.arg("-T")
            .arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg(format!(
                "ConnectTimeout={}",
                self.session.connect_timeout.as_secs().max(1)
            ))
            .arg("-o")
            .arg("ControlMaster=no")
            .arg("-o")
            .arg("ControlPath=none");
        for option in self.session.hardening {
            cmd.arg("-o").arg(option);
        }
        if let Some(config) = &self.session.ssh_config {
            cmd.arg("-F").arg(config);
        }
        if let Some(agent) = &self.session.agent {
            match agent {
                Some(sock) => {
                    cmd.env("SSH_AUTH_SOCK", sock);
                }
                None => {
                    cmd.env_remove("SSH_AUTH_SOCK");
                }
            }
        }
        if self.subsystem {
            cmd.arg("-s");
        }
        cmd.arg("--").arg(&self.session.destination);
        let remote = self.remote_parts.join(" ");
        if !remote.is_empty() {
            cmd.arg(remote);
        }
        let stdin = std::mem::replace(&mut self.stdin, Stdio::null());
        let stdout = std::mem::replace(&mut self.stdout, Stdio::null());
        let stderr = std::mem::replace(&mut self.stderr, Stdio::null());
        cmd.stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            .kill_on_drop(true);
        let inner = cmd.spawn().map_err(SshError::Connect)?;
        Ok(Child {
            inner,
            _session: PhantomData,
        })
    }
}

pub(crate) struct Child<'s> {
    inner: TokioChild,
    _session: PhantomData<&'s Session>,
}

impl Child<'_> {
    pub(crate) fn stdin(&mut self) -> &mut Option<ChildStdin> {
        &mut self.inner.stdin
    }

    pub(crate) fn stdout(&mut self) -> &mut Option<ChildStdout> {
        &mut self.inner.stdout
    }

    pub(crate) fn stderr(&mut self) -> &mut Option<ChildStderr> {
        &mut self.inner.stderr
    }

    pub(crate) async fn wait(mut self) -> Result<ExitStatus, SshError> {
        let status = self.inner.wait().await.map_err(SshError::ChildIo)?;
        if status.code() == Some(255) {
            return Err(SshError::Disconnected);
        }
        Ok(status)
    }

    pub(crate) async fn disconnect(mut self) -> Result<(), SshError> {
        let _ = self.inner.kill().await;
        let _ = self.inner.wait().await;
        Ok(())
    }
}

/// Master availability is independent of whether a remote operation completed.
pub(crate) enum MasterHealth {
    Available,
    #[allow(dead_code)]
    Lost,
    #[allow(dead_code)]
    Unknown,
}

pub(crate) struct Lease {
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
}

impl Lease {
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }

    pub(crate) async fn check_health(&self) -> MasterHealth {
        MasterHealth::Available
    }

    pub(crate) fn invalidate(&self) {}
}

pub(crate) struct Pool {
    channels: Mutex<HashMap<Key, Arc<Semaphore>>>,
    executable: PathBuf,
    agent: Option<Option<OsString>>,
    ssh_config: Option<PathBuf>,
    policy: Policy,
    connect_timeout: Duration,
    shutdown: CancellationToken,
    stopping: CancellationToken,
}

impl Pool {
    pub(crate) fn automation(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
        agent: Option<OsString>,
        headless: bool,
    ) -> Arc<Self> {
        let mut pool = Self::with_policy(
            executable,
            ssh_config,
            connect_timeout,
            shutdown,
            if headless {
                Policy::Headless
            } else {
                Policy::Native
            },
        );
        if let Some(inner) = Arc::get_mut(&mut pool) {
            inner.agent = Some(agent);
        }
        pool
    }

    pub(crate) fn new(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::with_policy(
            executable,
            ssh_config,
            connect_timeout,
            shutdown,
            Policy::Native,
        )
    }

    pub(crate) fn headless(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::with_policy(
            executable,
            ssh_config,
            connect_timeout,
            shutdown,
            Policy::Headless,
        )
    }

    pub(crate) fn diagnostic(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Self::with_policy(
            executable,
            ssh_config,
            connect_timeout,
            shutdown,
            Policy::Diagnostic,
        )
    }

    pub(crate) fn matches_native_transport(
        &self,
        executable: &Path,
        ssh_config: Option<&Path>,
    ) -> bool {
        matches!(self.policy, Policy::Native | Policy::Headless)
            && self.agent.is_none()
            && self.executable == executable
            && self.ssh_config.as_deref() == ssh_config
    }

    fn with_policy(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
        policy: Policy,
    ) -> Arc<Self> {
        Arc::new(Self {
            channels: Mutex::new(HashMap::new()),
            executable,
            agent: None,
            ssh_config,
            policy,
            connect_timeout,
            shutdown,
            stopping: CancellationToken::new(),
        })
    }

    pub(crate) async fn acquire(
        self: &Arc<Self>,
        target: &str,
        destination: &str,
        role: IdentityRole,
        deadline: Instant,
        ct: &CancellationToken,
    ) -> Result<Lease, ToolError> {
        if ct.is_cancelled() || self.shutdown.is_cancelled() || self.stopping.is_cancelled() {
            return Err(ToolError::new(
                ErrorCode::Cancelled,
                "SSH connection cancelled",
                false,
            ));
        }
        if Instant::now() >= deadline {
            return Err(ToolError::new(
                ErrorCode::Timeout,
                "SSH connection deadline expired",
                false,
            ));
        }
        let key = (target.to_owned(), destination.to_owned(), role);
        let semaphore = {
            let mut map = self
                .channels
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                map.entry(key)
                    .or_insert_with(|| Arc::new(Semaphore::new(CHANNELS))),
            )
        };
        let permit = tokio::select! {
            biased;
            () = ct.cancelled() => {
                return Err(ToolError::new(
                    ErrorCode::Cancelled,
                    "SSH connection cancelled",
                    false,
                ));
            }
            () = self.shutdown.cancelled() => {
                return Err(ToolError::new(
                    ErrorCode::Cancelled,
                    "SSH connection cancelled",
                    false,
                ));
            }
            () = self.stopping.cancelled() => {
                return Err(ToolError::new(
                    ErrorCode::Cancelled,
                    "SSH connection cancelled",
                    false,
                ));
            }
            result = timeout_at(deadline, semaphore.acquire_owned()) => match result {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => {
                    return Err(ToolError::new(
                        ErrorCode::ConnectionLost,
                        "SSH connection is unavailable",
                        false,
                    ));
                }
                Err(_) => {
                    return Err(ToolError::new(
                        ErrorCode::Timeout,
                        "SSH connection deadline expired",
                        false,
                    ));
                }
            }
        };
        let session = Arc::new(Session {
            executable: self.executable.clone(),
            ssh_config: self.ssh_config.clone(),
            destination: destination.to_owned(),
            hardening: self.policy.hardening(),
            connect_timeout: self.connect_timeout,
            agent: self.agent.clone(),
        });
        Ok(Lease {
            session,
            _permit: permit,
        })
    }

    pub(crate) async fn shutdown(&self) {
        self.stopping.cancel();
    }
}
