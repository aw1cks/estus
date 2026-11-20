//! Owned foreground OpenSSH masters; native mux channels never fall back to ssh.
use crate::{audit, config::IdentityRole, reply::ToolError};
use futures_util::FutureExt;
use openssh::Session;
use std::{
    collections::HashMap,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAX_MASTERS: usize = 16;
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
const CHANNELS: usize = 4;
const IDLE: Duration = Duration::from_secs(60);
const CLEANUP: Duration = Duration::from_secs(2);
const SOCKET_POLL: Duration = Duration::from_millis(5);
const READINESS_POLL: Duration = Duration::from_millis(25);
const MAX_SOCKET_BYTES: usize = 100;
const SOCKET_ENTRY_RESERVE_BYTES: usize = 12;

type Key = (String, String, IdentityRole);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    /// Operator/user OpenSSH configuration applies exactly as written.
    Native,
    /// Headless service: pins trust updates and agent loading off.
    Headless,
    Diagnostic,
}

impl Policy {
    /// Hardening options that must not be relaxed by a host stanza.
    ///
    /// Command-line `-o` values precede config parsing, so a `Host *` block can
    /// never grant trust updates or agent loading in a managed deployment.
    fn hardening(self) -> &'static [&'static str] {
        match self {
            // Workstation mode honors the operator's OpenSSH configuration.
            Self::Native => &[],
            Self::Headless | Self::Diagnostic => &[
                "StrictHostKeyChecking=yes",
                "UpdateHostKeys=no",
                "AddKeysToAgent=no",
            ],
        }
    }
}

pub(crate) struct Pool {
    entries: Mutex<HashMap<Key, Arc<Entry>>>,
    executable: PathBuf,
    agent: Option<Option<std::ffi::OsString>>,
    ssh_config: Option<PathBuf>,
    policy: Policy,
    connect_timeout: Duration,
    shutdown: CancellationToken,
    stopping: CancellationToken,
}

struct Entry {
    // Labels one owned master generation. Production no longer compares
    // generations; the pool teardown tests use it to prove a fresh master.
    #[cfg_attr(not(test), allow(dead_code))]
    generation: u64,
    state: Mutex<State>,
    channels: Arc<Semaphore>,
    ready: CancellationToken,
    stop: CancellationToken,
    done: CancellationToken,
    zero_interests: Notify,
}

struct State {
    session: Option<Arc<Session>>,
    interests: usize,
    idle_since: Instant,
    failure: Option<Failure>,
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Launch,
    Connect,
    Timeout,
    Cancelled,
    Lost,
}

impl Failure {
    fn error(self) -> ToolError {
        match self {
            Self::Launch => ToolError::ssh_spawn_failed(
                "Local SSH process failed to start; run `estus doctor --target <host>` for diagnostics",
                false,
            ),
            Self::Connect => ToolError::SSH_CONNECT_FAILED,
            Self::Timeout => ToolError::timeout("SSH connection deadline expired", false),
            Self::Cancelled => ToolError::cancelled("SSH connection cancelled", false),
            Self::Lost => ToolError::connection_lost("SSH connection is unavailable", false),
        }
    }
}

// Poison is only possible after an internal panic. Recover the ownership records
// so shutdown can still reap children rather than abandoning their resources.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An interest exists before launching and through the last use of a channel.
/// Dropping an acquire future therefore cancels an otherwise unneeded launch.
struct Interest(Arc<Entry>);

impl Drop for Interest {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        state.interests -= 1;
        if state.interests == 0 {
            state.idle_since = Instant::now();
            if state.session.is_none() {
                self.0.stop.cancel();
            }
            self.0.zero_interests.notify_waiters();
        }
    }
}

/// Master availability is independent of whether a remote operation completed.
pub(crate) enum MasterHealth {
    Available,
    Lost,
    Unknown,
}

pub(crate) struct Lease {
    // Drop session before the interest tells cleanup that the last lease is gone.
    session: Arc<Session>,
    _permit: OwnedSemaphorePermit,
    interest: Interest,
}

impl Lease {
    pub(crate) fn session(&self) -> &Session {
        &self.session
    }

    pub(crate) async fn check_health(&self) -> MasterHealth {
        match timeout_at(Instant::now() + CLEANUP, self.session.check()).await {
            Ok(Ok(())) => MasterHealth::Available,
            Ok(Err(_)) => MasterHealth::Lost,
            // An unresponsive check does not establish loss. The supervisor
            // still owns process-exit detection and idle/shutdown cleanup.
            Err(_) => MasterHealth::Unknown,
        }
    }

    pub(crate) fn invalidate(&self) {
        self.interest.0.stop.cancel();
    }
}

impl Pool {
    /// Automation pool in the mode-appropriate policy.
    ///
    /// Headless deployments pin trust; workstation deployments leave the
    /// operator's trust and agent configuration untouched.
    pub(crate) fn automation(
        executable: PathBuf,
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
        agent: Option<std::ffi::OsString>,
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
        Arc::get_mut(&mut pool)
            .expect("new pool is uniquely owned")
            .agent = Some(agent);
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

    /// Headless service pool: pinned trust, no host-key updates, no agent loading.
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

    /// Negotiate with configured credentials and trust, without changing either.
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
        // Both workstation and headless pools carry the operator's trust
        // configuration; reuse keeps one warm master per authority identity.
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
            entries: Mutex::new(HashMap::new()),
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
        let check_control = || {
            if ct.is_cancelled() || self.shutdown.is_cancelled() || self.stopping.is_cancelled() {
                Err(Failure::Cancelled.error())
            } else if Instant::now() >= deadline {
                Err(Failure::Timeout.error())
            } else {
                Ok(())
            }
        };
        check_control()?;
        let key = (target.to_owned(), destination.to_owned(), role);
        enum AcquireStep {
            Existing(Arc<Entry>),
            Launch {
                entry: Arc<Entry>,
                permit: OwnedSemaphorePermit,
            },
            Wait(CancellationToken),
        }
        loop {
            check_control()?;
            let step = {
                let mut entries = lock(&self.entries);
                check_control()?;
                if let Some(entry) = entries.get(&key) {
                    if entry.stop.is_cancelled() {
                        AcquireStep::Wait(entry.done.clone())
                    } else {
                        let mut state = lock(&entry.state);
                        if entry.stop.is_cancelled() {
                            AcquireStep::Wait(entry.done.clone())
                        } else {
                            state.interests += 1;
                            AcquireStep::Existing(Arc::clone(entry))
                        }
                    }
                } else if entries.len() >= MAX_MASTERS {
                    let mut victim: Option<(bool, Instant, Arc<Entry>)> = None;
                    for candidate in entries.values() {
                        let stopped = candidate.stop.is_cancelled();
                        let idle = {
                            let state = lock(&candidate.state);
                            if state.interests != 0 {
                                continue;
                            }
                            state.idle_since
                        };
                        let replace = match &victim {
                            None => true,
                            Some((best_stopped, best_idle, _)) => {
                                (stopped && !*best_stopped)
                                    || (stopped == *best_stopped && idle < *best_idle)
                            }
                        };
                        if replace {
                            victim = Some((stopped, idle, Arc::clone(candidate)));
                        }
                    }
                    let Some((_, _, victim)) = victim else {
                        return Err(ToolError::resource_limit("SSH master limit reached", false));
                    };
                    let done = {
                        let state = lock(&victim.state);
                        if state.interests == 0 {
                            victim.stop.cancel();
                        }
                        victim.done.clone()
                    };
                    AcquireStep::Wait(done)
                } else {
                    let entry = Arc::new(Entry {
                        generation: GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                        state: Mutex::new(State {
                            session: None,
                            interests: 1,
                            idle_since: Instant::now(),
                            failure: None,
                        }),
                        channels: Arc::new(Semaphore::new(CHANNELS)),
                        ready: CancellationToken::new(),
                        stop: CancellationToken::new(),
                        done: CancellationToken::new(),
                        zero_interests: Notify::new(),
                    });
                    // Reserve the creator's channel before publishing the entry.
                    // Followers cannot consume its slot and strand an unowned launch.
                    let permit = Arc::clone(&entry.channels)
                        .try_acquire_owned()
                        .map_err(|_| {
                            ToolError::resource_limit("SSH channel limit reached", false)
                        })?;
                    entries.insert(key.clone(), Arc::clone(&entry));
                    AcquireStep::Launch { entry, permit }
                }
            };
            let (entry, launch, interest, permit) = match step {
                AcquireStep::Wait(done) => {
                    tokio::select! {
                        biased;
                        _ = ct.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.shutdown.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.stopping.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = sleep_until(deadline) => return Err(Failure::Timeout.error()),
                        _ = done.cancelled() => {}
                    }
                    continue;
                }
                AcquireStep::Launch { entry, permit } => {
                    let interest = Interest(Arc::clone(&entry));
                    (entry, true, interest, permit)
                }
                AcquireStep::Existing(entry) => {
                    let interest = Interest(Arc::clone(&entry));
                    let channels = Arc::clone(&entry.channels);
                    let acquired = tokio::select! {
                        biased;
                        _ = ct.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.shutdown.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.stopping.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = sleep_until(deadline) => return Err(Failure::Timeout.error()),
                        _ = entry.stop.cancelled() => None,
                        res = channels.acquire_owned() => res.ok(),
                    };
                    let Some(permit) = acquired else {
                        let done = entry.done.clone();
                        drop(interest);
                        drop(entry);
                        tokio::select! {
                            biased;
                            _ = ct.cancelled() => return Err(Failure::Cancelled.error()),
                            _ = self.shutdown.cancelled() => return Err(Failure::Cancelled.error()),
                            _ = self.stopping.cancelled() => return Err(Failure::Cancelled.error()),
                            _ = sleep_until(deadline) => return Err(Failure::Timeout.error()),
                            _ = done.cancelled() => {}
                        }
                        continue;
                    };
                    (entry, false, interest, permit)
                }
            };
            if launch {
                let owner = Arc::downgrade(self);
                let executable = self.executable.clone();
                let agent = self.agent.clone();
                let config = self.ssh_config.clone();
                let policy = self.policy;
                let destination = destination.to_owned();
                // The shared launch has its own timeout. Each interested request
                // enforces its deadline independently; the last one cancels launch.
                let connection_deadline = Instant::now().checked_add(self.connect_timeout);
                let worker_entry = Arc::clone(&entry);
                let shutdown = self.shutdown.clone();
                let stopping = self.stopping.clone();
                let worker_key = key.clone();
                // This task is never aborted: it owns initialization and cleanup even
                // if the request future is dropped at the very next await point.
                tokio::spawn(async move {
                    let control = EntryControl {
                        executable,
                        policy,
                        agent,
                        deadline: connection_deadline,
                        shutdown,
                        stopping,
                    };
                    run_entry(
                        owner,
                        worker_key,
                        worker_entry,
                        config,
                        destination,
                        control,
                    )
                    .await;
                });
            }
            tokio::select! {
                biased;
                _ = ct.cancelled() => return Err(Failure::Cancelled.error()),
                _ = self.shutdown.cancelled() => return Err(Failure::Cancelled.error()),
                _ = self.stopping.cancelled() => return Err(Failure::Cancelled.error()),
                _ = sleep_until(deadline) => return Err(Failure::Timeout.error()),
                _ = entry.ready.cancelled() => {}
            }
            check_control()?;
            enum ReadyOutcome {
                Connected(Arc<Session>),
                Retired,
            }
            let ready_outcome = {
                let state = lock(&entry.state);
                if let Some(failure) = state.failure {
                    if !launch && entry.stop.is_cancelled() && matches!(failure, Failure::Lost) {
                        ReadyOutcome::Retired
                    } else {
                        return Err(failure.error());
                    }
                } else if entry.stop.is_cancelled() {
                    ReadyOutcome::Retired
                } else {
                    ReadyOutcome::Connected(
                        state
                            .session
                            .as_ref()
                            .map(Arc::clone)
                            .ok_or_else(|| Failure::Connect.error())?,
                    )
                }
            };
            let session = match ready_outcome {
                ReadyOutcome::Connected(session) => session,
                ReadyOutcome::Retired => {
                    let done = entry.done.clone();
                    drop(permit);
                    drop(interest);
                    drop(entry);
                    tokio::select! {
                        biased;
                        _ = ct.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.shutdown.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = self.stopping.cancelled() => return Err(Failure::Cancelled.error()),
                        _ = sleep_until(deadline) => return Err(Failure::Timeout.error()),
                        _ = done.cancelled() => {}
                    }
                    continue;
                }
            };
            return Ok(Lease {
                session,
                _permit: permit,
                interest,
            });
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.stopping.cancel();
        let entries: Vec<_> = lock(&self.entries).values().cloned().collect();
        // Each supervisor cleans independently; waiting sequentially here does
        // not serialize network close operations or multiply cleanup deadlines.
        for entry in entries {
            entry.done.cancelled().await;
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stopping.cancel();
    }
}

struct Master {
    child: Option<Child>,
    directory: Option<TempDir>,
    drain: Option<JoinHandle<()>>,
    finalizer: Option<EntryFinalizer>,
}

fn validated_xdg_socket_parent(
    xdg_runtime_dir: Option<&std::ffi::OsStr>,
    current_uid: u32,
) -> Option<PathBuf> {
    let raw = xdg_runtime_dir?;
    if raw.is_empty() || raw.as_bytes().contains(&0) {
        return None;
    }
    let runtime_dir = Path::new(raw);
    if !runtime_dir.is_absolute() {
        return None;
    }
    let runtime_meta = std::fs::symlink_metadata(runtime_dir).ok()?;
    if runtime_meta.file_type().is_symlink()
        || !runtime_meta.is_dir()
        || runtime_meta.uid() != current_uid
        || (runtime_meta.mode() & 0o077) != 0
    {
        return None;
    }
    let estus_dir = runtime_dir.join("estus");
    if estus_dir.as_os_str().as_bytes().len() + SOCKET_ENTRY_RESERVE_BYTES > MAX_SOCKET_BYTES {
        return None;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(&estus_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&estus_dir)
        .ok()?;
    let estus_meta = opened.metadata().ok()?;
    if !estus_meta.is_dir()
        || estus_meta.uid() != current_uid
        || (estus_meta.mode() & 0o777) != 0o700
    {
        return None;
    }
    Some(estus_dir)
}

fn create_socket_directory(
    xdg_runtime_dir: Option<&std::ffi::OsStr>,
    current_uid: u32,
) -> Result<TempDir, Failure> {
    if let Some(parent) = validated_xdg_socket_parent(xdg_runtime_dir, current_uid)
        && let Ok(directory) = tempfile::Builder::new()
            .prefix("sm-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(&parent)
    {
        let socket = directory.path().join("c");
        if socket.as_os_str().as_bytes().len() <= MAX_SOCKET_BYTES {
            return Ok(directory);
        }
    }
    let directory = tempfile::Builder::new()
        .prefix("sm-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(|_| Failure::Launch)?;
    // Request owner-only permissions at creation; never inherit TMPDIR or a
    // destination-derived pathname for the control socket.
    let socket = directory.path().join("c");
    if socket.as_os_str().as_bytes().len() > MAX_SOCKET_BYTES {
        return Err(Failure::Launch);
    }
    Ok(directory)
}

impl Master {
    fn launch(
        executable: &Path,
        config: Option<&PathBuf>,
        destination: &str,
        policy: Policy,
        agent: &Option<Option<std::ffi::OsString>>,
    ) -> Result<(Self, Session), Failure> {
        let directory = create_socket_directory(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            nix::unistd::Uid::current().as_raw(),
        )?;
        let socket = directory.path().join("c");
        let mut command = Command::new(executable);
        if let Some(agent) = agent {
            command.env_remove("SSH_AUTH_SOCK");
            if let Some(socket) = agent {
                command.env("SSH_AUTH_SOCK", socket);
            }
        }
        command.args(["-M", "-N", "-T", "-S"]).arg(&socket);
        for option in [
            "ControlMaster=yes",
            "ControlPersist=no",
            "ForkAfterAuthentication=no",
            "BatchMode=yes",
            "RequestTTY=no",
            "SessionType=none",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "RemoteCommand=none",
            // SetEnv uses the first active list: replace operator-configured values.
            "SetEnv=ESTUS=1",
        ] {
            command.arg("-o").arg(option);
        }
        // Command-line values precede config parsing and cannot be relaxed by a
        // host stanza. Keep configured known-host paths and proxies.
        for option in policy.hardening() {
            command.arg("-o").arg(option);
        }
        if let Some(config) = config {
            command.arg("-F").arg(config);
        }
        command
            .arg("--")
            .arg(destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| Failure::Launch)?;
        let drain = child.stderr.take().map(|mut stderr| {
            tokio::spawn(async move {
                let mut discard = [0_u8; 8192];
                loop {
                    match stderr.read(&mut discard).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            })
        });
        let session = Session::resume_mux(socket.into_boxed_path(), None);
        Ok((
            Self {
                child: Some(child),
                directory: Some(directory),
                drain,
                finalizer: None,
            },
            session,
        ))
    }

    async fn cleanup(&mut self, session: Option<Arc<Session>>, entry: &Entry) -> Option<i32> {
        let until = Instant::now() + CLEANUP;
        // Stop admitting leases before taking the session from shared state.
        // Existing leases get the grace period to release their channel handles.
        if let Some(session) = session {
            let _ = timeout_at(until, async {
                loop {
                    let notified = entry.zero_interests.notified();
                    if lock(&entry.state).interests == 0 {
                        break;
                    }
                    notified.await;
                }
                match Arc::try_unwrap(session) {
                    Ok(session) => {
                        if session.close().await.is_err() {
                            diagnostic("master_close_failed");
                        }
                    }
                    Err(_) => diagnostic("master_session_ownership_mismatch"),
                }
            })
            .await;
        }
        let mut status = None;
        if let Some(child) = self.child.as_mut() {
            status = match timeout_at(until, child.wait()).await {
                Ok(Ok(status)) => status.code(),
                _ => {
                    if child.start_kill().is_err() {
                        diagnostic("master_kill_failed");
                    }
                    match child.wait().await {
                        Ok(status) => status.code(),
                        Err(_) => {
                            diagnostic("master_reap_failed");
                            None
                        }
                    }
                }
            };
        } else {
            diagnostic("master_child_ownership_mismatch");
        }
        self.child.take();
        self.finish_drain().await;
        // The owned process has been reaped before unlinking its socket.
        if let Some(directory) = self.directory.take()
            && directory.close().is_err()
        {
            diagnostic("master_socket_cleanup_failed");
        }
        status
    }

    async fn finish_drain(&mut self) {
        if let Some(mut drain) = self.drain.take() {
            // A configured proxy descendant may inherit stderr after ssh exits.
            match timeout_at(Instant::now() + Duration::from_millis(100), &mut drain).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => diagnostic("master_drain_failed"),
                Err(_) => {
                    drain.abort();
                    if drain.await.is_err_and(|error| !error.is_cancelled()) {
                        diagnostic("master_drain_failed");
                    }
                }
            }
        }
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        let child = self.child.take();
        let directory = self.directory.take();
        let drain = self.drain.take();
        if child.is_none() && directory.is_none() && drain.is_none() {
            return;
        }
        let finalizer = self.finalizer.take();
        if let Some(finalizer) = &finalizer {
            unavailable(&finalizer.entry);
        }
        // On an unexpected unwind, keep finalization with the owned reaper:
        // shutdown must not observe done before process/socket cleanup.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Some(mut child) = child {
                    if child.start_kill().is_err() {
                        diagnostic("master_kill_failed");
                    }
                    if child.wait().await.is_err() {
                        diagnostic("master_reap_failed");
                    }
                }
                if let Some(drain) = drain {
                    drain.abort();
                    let _ = drain.await;
                }
                if let Some(directory) = directory
                    && directory.close().is_err()
                {
                    diagnostic("master_socket_cleanup_failed");
                }
                drop(finalizer);
            });
        } else {
            if let Some(mut child) = child
                && child.start_kill().is_err()
            {
                diagnostic("master_kill_failed");
            }
            if let Some(drain) = drain {
                drain.abort();
            }
            if let Some(directory) = directory
                && directory.close().is_err()
            {
                diagnostic("master_socket_cleanup_failed");
            }
            drop(finalizer);
        }
    }
}

struct EntryControl {
    executable: PathBuf,
    agent: Option<Option<std::ffi::OsString>>,
    policy: Policy,
    deadline: Option<Instant>,
    shutdown: CancellationToken,
    stopping: CancellationToken,
}

async fn connect_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

async fn ready(
    master: &mut Master,
    session: &Session,
    entry: &Entry,
    control: &EntryControl,
) -> Result<(), Failure> {
    let socket = master
        .directory
        .as_ref()
        .map(|dir| dir.path().join("c"))
        .ok_or(Failure::Connect)?;
    let child = master.child.as_mut().ok_or(Failure::Connect)?;
    // Wait for OpenSSH to bind the Unix control socket before spawning `ssh -O check`.
    while tokio::fs::symlink_metadata(&socket).await.is_err() {
        tokio::select! {
            biased;
            _ = entry.stop.cancelled() => return Err(Failure::Cancelled),
            _ = control.shutdown.cancelled() => return Err(Failure::Cancelled),
            _ = control.stopping.cancelled() => return Err(Failure::Cancelled),
            _ = connect_deadline(control.deadline) => return Err(Failure::Timeout),
            _ = child.wait() => return Err(Failure::Connect),
            _ = sleep(SOCKET_POLL) => {}
        }
    }
    loop {
        tokio::select! {
            biased;
            _ = entry.stop.cancelled() => return Err(Failure::Cancelled),
            _ = control.shutdown.cancelled() => return Err(Failure::Cancelled),
            _ = control.stopping.cancelled() => return Err(Failure::Cancelled),
            _ = connect_deadline(control.deadline) => return Err(Failure::Timeout),
            _ = child.wait() => return Err(Failure::Connect),
            result = session.check() => if result.is_ok() { return Ok(()) }
        }
        tokio::select! {
            biased;
            _ = entry.stop.cancelled() => return Err(Failure::Cancelled),
            _ = control.shutdown.cancelled() => return Err(Failure::Cancelled),
            _ = control.stopping.cancelled() => return Err(Failure::Cancelled),
            _ = connect_deadline(control.deadline) => return Err(Failure::Timeout),
            _ = child.wait() => return Err(Failure::Connect),
            _ = sleep(READINESS_POLL) => {}
        }
    }
}

async fn supervise(master: &mut Master, entry: &Entry, control: &EntryControl) {
    let Some(child) = master.child.as_mut() else {
        diagnostic("master_child_ownership_mismatch");
        return;
    };
    loop {
        let idle_deadline = {
            let state = lock(&entry.state);
            if state.interests == 0 {
                state.idle_since + IDLE
            } else {
                Instant::now() + IDLE
            }
        };
        tokio::select! {
            biased;
            _ = entry.stop.cancelled() => break,
            _ = control.shutdown.cancelled() => break,
            _ = control.stopping.cancelled() => break,
            _ = child.wait() => break,
            _ = sleep_until(idle_deadline) => {
                // Coordinate the idle decision with acquire's interest count.
                let state = lock(&entry.state);
                if state.interests == 0 && Instant::now() >= state.idle_since + IDLE {
                    entry.stop.cancel();
                    break;
                }
            }
        }
    }
}

/// Finalization follows the master into its fallback reaper on unwind.
struct EntryFinalizer {
    owner: Weak<Pool>,
    key: Key,
    entry: Arc<Entry>,
    completed: bool,
}

fn unavailable(entry: &Entry) {
    entry.stop.cancel();
    {
        let mut state = lock(&entry.state);
        state.session.take();
        if state.failure.is_none() {
            state.failure = Some(Failure::Lost);
        }
    }
    entry.ready.cancel();
}

impl Drop for EntryFinalizer {
    fn drop(&mut self) {
        unavailable(&self.entry);
        let misplaced = if let Some(owner) = self.owner.upgrade() {
            let mut entries = lock(&owner.entries);
            let matches = entries
                .get(&self.key)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry));
            if matches {
                entries.remove(&self.key);
            }
            !matches
        } else {
            false
        };
        // Signal before reporting: even an unexpected diagnostic failure must
        // not strand shutdown. Normal completion follows awaited cleanup.
        self.entry.done.cancel();
        if misplaced {
            diagnostic("master_entry_ownership_mismatch");
        }
        if !self.completed {
            diagnostic("master_finalization_interrupted");
        }
    }
}

async fn run_entry(
    owner: Weak<Pool>,
    key: Key,
    entry: Arc<Entry>,
    config: Option<PathBuf>,
    destination: String,
    control: EntryControl,
) {
    let role = key.2;
    let mut finalizer = Some(EntryFinalizer {
        owner,
        key,
        entry: Arc::clone(&entry),
        completed: false,
    });
    // Keep process ownership outside the unwind boundary. Dropping the inner
    // future must not drop the only handle before awaited cleanup can run.
    let mut resources = None;
    let result = AssertUnwindSafe(async {
        let cancelled = entry.stop.is_cancelled()
            || control.shutdown.is_cancelled()
            || control.stopping.is_cancelled();
        if cancelled
            || control
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            lock(&entry.state).failure = Some(if cancelled {
                Failure::Cancelled
            } else {
                Failure::Timeout
            });
            return;
        }
        let (mut master, session) = match Master::launch(
            &control.executable,
            config.as_ref(),
            &destination,
            control.policy,
            &control.agent,
        ) {
            Ok(resources) => resources,
            Err(failure) => {
                lock(&entry.state).failure = Some(failure);
                return;
            }
        };
        master.finalizer = finalizer.take();
        let (master, session) = resources.insert((master, Arc::new(session)));
        let pid = master.child.as_ref().and_then(Child::id);
        let socket = master
            .directory
            .as_ref()
            .map(|directory| directory.path().join("c"));
        lifecycle("master_start", pid, socket.as_ref(), role, None);
        let result = ready(master, session, &entry, &control).await;
        {
            let mut state = lock(&entry.state);
            if let Err(failure) = result {
                state.failure = Some(failure);
            } else {
                state.session = Some(Arc::clone(session));
            }
        }
        entry.ready.cancel();
        if result.is_ok() {
            supervise(master, &entry, &control).await;
        }
    })
    .catch_unwind()
    .await;
    if result.is_err() {
        // Never include panic payloads, backend errors, or destinations.
        diagnostic("master_supervisor_panicked");
    }
    unavailable(&entry);
    if let Some((mut master, session)) = resources {
        let pid = master.child.as_ref().and_then(Child::id);
        let socket = master
            .directory
            .as_ref()
            .map(|directory| directory.path().join("c"));
        let status = master.cleanup(Some(session), &entry).await;
        lifecycle("master_finish", pid, socket.as_ref(), role, status);
        if let Some(finalizer) = master.finalizer.as_mut() {
            finalizer.completed = true;
        } else {
            diagnostic("master_finalizer_ownership_mismatch");
        }
    }
    if let Some(finalizer) = finalizer.as_mut() {
        finalizer.completed = true;
    }
}

fn lifecycle(
    event: &str,
    pid: Option<u32>,
    socket: Option<&PathBuf>,
    role: IdentityRole,
    status: Option<i32>,
) {
    // No destination, backend error, or stderr payload may enter this record.
    audit::emit(&serde_json::json!({
        "event": event, "pid": pid, "socket": socket, "role": role, "status": status,
    }));
}

fn diagnostic(code: &'static str) {
    audit::emit(&serde_json::json!({
        "event": "master_error",
        "error_code": code,
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply::ErrorCode;
    use nix::{errno::Errno, sys::signal::kill, unistd::Pid};

    #[test]
    fn headless_policy_pins_trust_and_agent_options() {
        assert_eq!(
            Policy::Headless.hardening(),
            &[
                "StrictHostKeyChecking=yes",
                "UpdateHostKeys=no",
                "AddKeysToAgent=no",
            ]
        );
        // Workstation mode must not override the operator's OpenSSH config.
        assert!(Policy::Native.hardening().is_empty());
        assert_eq!(Policy::Diagnostic.hardening(), Policy::Headless.hardening());
    }

    #[test]
    fn matches_native_transport_accepts_native_and_headless_for_shared_reuse() {
        let executable = PathBuf::from("/usr/bin/ssh");
        let config = PathBuf::from("/etc/estus/ssh.conf");
        let shutdown = || CancellationToken::new();
        let (exe, cfg) = (executable.as_path(), Some(config.as_path()));

        let native = Pool::new(
            executable.clone(),
            Some(config.clone()),
            Duration::from_secs(1),
            shutdown(),
        );
        assert!(native.matches_native_transport(exe, cfg));

        let headless = Pool::headless(
            executable.clone(),
            Some(config.clone()),
            Duration::from_secs(1),
            shutdown(),
        );
        assert!(
            headless.matches_native_transport(exe, cfg),
            "headless pool must share the warm master with native transport"
        );

        // A diagnostic pool intentionally negotiates a distinct trust state.
        let diagnostic = Pool::diagnostic(
            executable.clone(),
            Some(config.clone()),
            Duration::from_secs(1),
            shutdown(),
        );
        assert!(!diagnostic.matches_native_transport(exe, cfg));

        // Identity differences never share a master.
        assert!(!headless.matches_native_transport(Path::new("/usr/bin/other"), cfg));
        assert!(!headless.matches_native_transport(exe, None));

        let automated = Pool::automation(
            executable.clone(),
            Some(config.clone()),
            Duration::from_secs(1),
            shutdown(),
            None,
            true,
        );
        assert_eq!(
            automated.policy,
            Policy::Headless,
            "headless automation must pin trust"
        );
        assert!(!automated.matches_native_transport(exe, cfg));

        // Workstation automation must honor the operator's OpenSSH config.
        let workstation = Pool::automation(
            executable.clone(),
            Some(config.clone()),
            Duration::from_secs(1),
            shutdown(),
            None,
            false,
        );
        assert_eq!(
            workstation.policy,
            Policy::Native,
            "workstation automation must not pin trust options"
        );
        assert!(workstation.policy.hardening().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unwound_master_reaps_before_pool_completion() {
        let pool = Pool::new(
            PathBuf::from("/unused-ssh"),
            None,
            Duration::from_secs(1),
            CancellationToken::new(),
        );
        let key = (
            "unwind-owned".to_owned(),
            "unwind-owned".to_owned(),
            IdentityRole::Ordinary,
        );
        let entry = Arc::new(Entry {
            generation: GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            state: Mutex::new(State {
                session: None,
                interests: 0,
                idle_since: Instant::now(),
                failure: None,
            }),
            channels: Arc::new(Semaphore::new(CHANNELS)),
            ready: CancellationToken::new(),
            stop: CancellationToken::new(),
            done: CancellationToken::new(),
            zero_interests: Notify::new(),
        });
        lock(&pool.entries).insert(key.clone(), Arc::clone(&entry));
        let directory = tempfile::tempdir().unwrap();
        let owned_path = directory.path().to_owned();
        // This tests OS-process ownership, not SSH behavior. No SSH/network
        // prerequisites enter the default suite; native tests use real masters.
        let child = Command::new("sleep")
            .arg("10")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap());
        let master = Master {
            child: Some(child),
            directory: Some(directory),
            drain: None,
            finalizer: Some(EntryFinalizer {
                owner: Arc::downgrade(&pool),
                key: key.clone(),
                entry: Arc::clone(&entry),
                completed: false,
            }),
        };
        let task = tokio::spawn(async move {
            let _owned = master;
            panic!("test supervisor unwind");
        });
        assert!(task.await.unwrap_err().is_panic());
        timeout_at(
            Instant::now() + Duration::from_secs(5),
            entry.done.cancelled(),
        )
        .await
        .unwrap();
        // Completion is not merely a notification: the process must already
        // be reaped, the private tree gone, and the capacity slot removed.
        assert!(matches!(kill(pid, None), Err(Errno::ESRCH)));
        assert!(!owned_path.exists());
        assert!(!lock(&pool.entries).contains_key(&key));
    }

    fn test_entry(interests: usize, idle_since: Instant) -> Arc<Entry> {
        Arc::new(Entry {
            generation: GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            state: Mutex::new(State {
                session: None,
                interests,
                idle_since,
                failure: None,
            }),
            channels: Arc::new(Semaphore::new(CHANNELS)),
            ready: CancellationToken::new(),
            stop: CancellationToken::new(),
            done: CancellationToken::new(),
            zero_interests: Notify::new(),
        })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acquire_waits_for_teardown_then_launches_fresh_generation() {
        let pool = Pool::new(
            PathBuf::from("/nonexistent-ssh"),
            None,
            Duration::from_secs(1),
            CancellationToken::new(),
        );
        let key = (
            "reacquire-target".to_owned(),
            "reacquire-target".to_owned(),
            IdentityRole::Ordinary,
        );
        let old = test_entry(0, Instant::now());
        let old_gen = old.generation;
        old.stop.cancel();
        lock(&pool.entries).insert(key.clone(), Arc::clone(&old));

        let pool_clone = Arc::clone(&pool);
        let key_clone = key.clone();
        let old_clone = Arc::clone(&old);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            lock(&pool_clone.entries).remove(&key_clone);
            old_clone.done.cancel();
        });

        let err = pool
            .acquire(
                "reacquire-target",
                "reacquire-target",
                IdentityRole::Ordinary,
                Instant::now() + Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await
            .err()
            .expect("nonexistent ssh fails launch");
        // Must not return connection_lost from the invalidated generation;
        // wait for teardown and attempt launch of a new generation.
        assert_eq!(err.code(), ErrorCode::SshSpawnFailed);
        assert!(
            lock(&pool.entries)
                .get(&key)
                .is_none_or(|e| e.generation > old_gen)
        );
        pool.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acquire_evicts_idle_victim_at_max_masters_and_rejects_when_all_busy() {
        let pool = Pool::new(
            PathBuf::from("/nonexistent-ssh"),
            None,
            Duration::from_secs(1),
            CancellationToken::new(),
        );
        let now = Instant::now();
        let mut entries_list = Vec::new();
        for i in 0..MAX_MASTERS {
            let key = (
                format!("host-{i:02}"),
                format!("host-{i:02}"),
                IdentityRole::Ordinary,
            );
            let idle_at = now - Duration::from_secs((MAX_MASTERS - i) as u64);
            let entry = test_entry(0, idle_at);
            if i == 5 {
                entry.stop.cancel();
            }
            lock(&pool.entries).insert(key.clone(), Arc::clone(&entry));
            entries_list.push((key, entry));
        }
        // Victim #5 is already stop-cancelled, so it must be chosen before #0 (oldest idle_since).
        let victim_key = entries_list[5].0.clone();
        let victim = Arc::clone(&entries_list[5].1);
        let pool_clone = Arc::clone(&pool);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            lock(&pool_clone.entries).remove(&victim_key);
            victim.done.cancel();
        });

        let err = pool
            .acquire(
                "host-new",
                "host-new",
                IdentityRole::Ordinary,
                Instant::now() + Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await
            .err()
            .expect("nonexistent ssh fails launch after eviction");
        assert_eq!(err.code(), ErrorCode::SshSpawnFailed);
        assert!(!entries_list[0].1.stop.is_cancelled());
        for (key, entry) in entries_list {
            lock(&pool.entries).remove(&key);
            entry.done.cancel();
        }
        pool.shutdown().await;

        // When every master has active interest > 0, return resource_limit immediately.
        let busy_pool = Pool::new(
            PathBuf::from("/nonexistent-ssh"),
            None,
            Duration::from_secs(1),
            CancellationToken::new(),
        );
        for i in 0..MAX_MASTERS {
            let key = (
                format!("busy-{i:02}"),
                format!("busy-{i:02}"),
                IdentityRole::Ordinary,
            );
            lock(&busy_pool.entries).insert(key, test_entry(1, Instant::now()));
        }
        let err = busy_pool
            .acquire(
                "busy-new",
                "busy-new",
                IdentityRole::Ordinary,
                Instant::now() + Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await
            .err()
            .expect("busy pool must reject");
        assert_eq!(err.code(), ErrorCode::ResourceLimit);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn acquire_retries_when_master_retires_at_ready_wakeup() {
        let pool = Pool::new(
            PathBuf::from("/nonexistent-ssh"),
            None,
            Duration::from_secs(1),
            CancellationToken::new(),
        );
        let key = (
            "race-target".to_owned(),
            "race-target".to_owned(),
            IdentityRole::Ordinary,
        );
        let old = test_entry(0, Instant::now());
        lock(&pool.entries).insert(key.clone(), Arc::clone(&old));

        let pool_clone = Arc::clone(&pool);
        let old_clone = Arc::clone(&old);
        let key_clone = key.clone();
        tokio::spawn(async move {
            // Wait for follower to register interest.
            while lock(&old_clone.state).interests == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Retire the entry right as ready wakes without populating failure.
            old_clone.stop.cancel();
            old_clone.ready.cancel();
            // Wait until follower drops its interest, then finalize entry.
            let notified = old_clone.zero_interests.notified();
            if lock(&old_clone.state).interests != 0 {
                notified.await;
            }
            lock(&pool_clone.entries).remove(&key_clone);
            old_clone.done.cancel();
        });

        let err = pool
            .acquire(
                "race-target",
                "race-target",
                IdentityRole::Ordinary,
                Instant::now() + Duration::from_secs(2),
                &CancellationToken::new(),
            )
            .await
            .err()
            .expect("fresh launch fails on nonexistent ssh");
        assert_eq!(err.code(), ErrorCode::SshSpawnFailed);
        pool.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_interests_notify_wakes_waiter_without_polling_delay() {
        let entry = test_entry(1, Instant::now());
        let interest = Interest(Arc::clone(&entry));
        let waiter_entry = Arc::clone(&entry);
        let waiter = tokio::spawn(async move {
            loop {
                let notified = waiter_entry.zero_interests.notified();
                if lock(&waiter_entry.state).interests == 0 {
                    break;
                }
                notified.await;
            }
        });
        tokio::task::yield_now().await;
        drop(interest);
        timeout_at(Instant::now() + Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn xdg_runtime_socket_directory_requires_private_owner_mode_length_and_cleans_up() {
        let uid = nix::unistd::Uid::current().as_raw();
        let scratch = tempfile::Builder::new()
            .prefix("xdg-")
            .tempdir_in("/tmp")
            .unwrap();

        // Valid private $XDG_RUNTIME_DIR creates a private `estus` subdirectory and cleans up sm-*.
        let valid = scratch.path().join("rt");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&valid)
            .unwrap();
        let dir = create_socket_directory(Some(valid.as_os_str()), uid).unwrap();
        let created_path = dir.path().to_path_buf();
        let estus_subdir = valid.join("estus");
        assert_eq!(created_path.parent(), Some(estus_subdir.as_path()));
        assert_eq!(
            std::fs::metadata(&estus_subdir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&created_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(created_path.join("c").as_os_str().as_bytes().len() <= MAX_SOCKET_BYTES);
        drop(dir);
        assert!(!created_path.exists());

        // Invalid owner falls back to /tmp without creating `estus` inside unowned runtime dir.
        let unowned = scratch.path().join("other-uid");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&unowned)
            .unwrap();
        let dir =
            create_socket_directory(Some(unowned.as_os_str()), uid.saturating_add(1)).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        assert!(!unowned.join("estus").exists());
        drop(dir);

        // Permissive mode (group/other bits set) falls back to /tmp.
        let permissive = scratch.path().join("loose");
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&permissive)
            .unwrap();
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o750)).unwrap();
        let dir = create_socket_directory(Some(permissive.as_os_str()), uid).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        assert!(!permissive.join("estus").exists());
        drop(dir);

        // Symlink runtime dir or relative path falls back to /tmp.
        let linked = scratch.path().join("sym");
        std::os::unix::fs::symlink(&valid, &linked).unwrap();
        let dir = create_socket_directory(Some(linked.as_os_str()), uid).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        drop(dir);
        let dir =
            create_socket_directory(Some(std::ffi::OsStr::new("relative/runtime")), uid).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        drop(dir);

        // Long $XDG_RUNTIME_DIR exceeding socket bound falls back to /tmp without creating estus/.
        let deep = scratch.path().join("a".repeat(80));
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            deep.join("estus").as_os_str().as_bytes().len() + SOCKET_ENTRY_RESERVE_BYTES
                > MAX_SOCKET_BYTES
        );
        let dir = create_socket_directory(Some(deep.as_os_str()), uid).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        assert!(!deep.join("estus").exists());
        drop(dir);

        // Pre-existing permissive `estus` child falls back to /tmp.
        let poisoned_parent = scratch.path().join("poison");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&poisoned_parent)
            .unwrap();
        let poisoned_child = poisoned_parent.join("estus");
        std::fs::DirBuilder::new()
            .mode(0o755)
            .create(&poisoned_child)
            .unwrap();
        std::fs::set_permissions(&poisoned_child, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = create_socket_directory(Some(poisoned_parent.as_os_str()), uid).unwrap();
        assert_eq!(dir.path().parent(), Some(Path::new("/tmp")));
        drop(dir);
    }
}
