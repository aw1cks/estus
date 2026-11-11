//! Owned foreground OpenSSH masters; native mux channels never fall back to ssh.
use crate::{config::IdentityRole, server::ToolError};
use openssh::Session;
use std::{
    collections::HashMap,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAX_MASTERS: usize = 16;
const CHANNELS: usize = 4;
const IDLE: Duration = Duration::from_secs(60);
const CLEANUP: Duration = Duration::from_secs(2);
const READINESS_POLL: Duration = Duration::from_millis(25);

type Key = (String, IdentityRole);

pub(crate) struct Pool {
    entries: Mutex<HashMap<Key, Arc<Entry>>>,
    ssh_config: Option<PathBuf>,
    connect_timeout: Duration,
    shutdown: CancellationToken,
    stopping: CancellationToken,
}

struct Entry {
    state: Mutex<State>,
    channels: Arc<Semaphore>,
    ready: CancellationToken,
    stop: CancellationToken,
    done: CancellationToken,
}

struct State {
    session: Option<Arc<Session>>,
    interests: usize,
    idle_since: Instant,
    failure: Option<Failure>,
}

#[derive(Clone, Copy)]
enum Failure {
    Connect,
    Timeout,
    Cancelled,
    Lost,
}

impl Failure {
    fn error(self) -> ToolError {
        match self {
            Self::Connect => ToolError::new(
                "ssh_connect_failed",
                "SSH connection failed; verify the configured alias, authentication and known hosts with your SSH client outside MCP",
                false,
            ),
            Self::Timeout => ToolError::new("timeout", "SSH connection deadline expired", false),
            Self::Cancelled => ToolError::new("cancelled", "SSH connection cancelled", false),
            Self::Lost => ToolError::new("connection_lost", "SSH connection is unavailable", false),
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
    pub(crate) fn new(
        ssh_config: Option<PathBuf>,
        connect_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(HashMap::new()),
            ssh_config,
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
        let key = (target.to_owned(), role);
        let (entry, launch, permit) = {
            let mut entries = lock(&self.entries);
            check_control()?;
            if let Some(entry) = entries.get(&key) {
                if entry.stop.is_cancelled() {
                    return Err(Failure::Lost.error());
                }
                let permit = Arc::clone(&entry.channels)
                    .try_acquire_owned()
                    .map_err(|_| {
                        ToolError::new("resource_limit", "SSH channel limit reached", false)
                    })?;
                lock(&entry.state).interests += 1;
                (Arc::clone(entry), false, permit)
            } else {
                if entries.len() >= MAX_MASTERS {
                    return Err(ToolError::new(
                        "resource_limit",
                        "SSH master limit reached",
                        false,
                    ));
                }
                let entry = Arc::new(Entry {
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
                });
                // Reserve the creator's channel before publishing the entry.
                // Followers cannot consume its slot and strand an unowned launch.
                let permit = Arc::clone(&entry.channels)
                    .try_acquire_owned()
                    .map_err(|_| {
                        ToolError::new("resource_limit", "SSH channel limit reached", false)
                    })?;
                entries.insert(key.clone(), Arc::clone(&entry));
                (entry, true, permit)
            }
        };
        let interest = Interest(Arc::clone(&entry));
        if launch {
            let owner = Arc::downgrade(self);
            let config = self.ssh_config.clone();
            let destination = destination.to_owned();
            // The shared launch has its own timeout. Each interested request
            // enforces its deadline independently; the last one cancels launch.
            let connection_deadline = Instant::now().checked_add(self.connect_timeout);
            let worker_entry = Arc::clone(&entry);
            let shutdown = self.shutdown.clone();
            let stopping = self.stopping.clone();
            // This task is never aborted: it owns initialization and cleanup even
            // if the request future is dropped at the very next await point.
            tokio::spawn(async move {
                let control = EntryControl {
                    deadline: connection_deadline,
                    shutdown,
                    stopping,
                };
                run_entry(owner, key, worker_entry, config, destination, control).await;
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
        let session = {
            let state = lock(&entry.state);
            if let Some(failure) = state.failure {
                return Err(failure.error());
            }
            if entry.stop.is_cancelled() {
                return Err(Failure::Lost.error());
            }
            state
                .session
                .as_ref()
                .map(Arc::clone)
                .ok_or_else(|| Failure::Connect.error())?
        };
        Ok(Lease {
            session,
            _permit: permit,
            interest,
        })
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
}

impl Master {
    fn launch(config: Option<&PathBuf>, destination: &str) -> Result<(Self, Session), Failure> {
        let directory = tempfile::Builder::new()
            .prefix("sm-")
            .tempdir_in("/tmp")
            .map_err(|_| Failure::Connect)?;
        // tempfile creates mode 0700 directories; never inherit TMPDIR or a
        // destination-derived pathname for the control socket.
        let socket = directory.path().join("c");
        if socket.as_os_str().as_bytes().len() > 100 {
            return Err(Failure::Connect);
        }
        let mut command = Command::new("ssh");
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
        ] {
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
        let mut child = command.spawn().map_err(|_| Failure::Connect)?;
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
                    if lock(&entry.state).interests == 0 {
                        break;
                    }
                    sleep(READINESS_POLL).await;
                }
                if let Ok(session) = Arc::try_unwrap(session) {
                    let _ = session.close().await;
                }
            })
            .await;
        }
        let mut status = None;
        if let Some(child) = self.child.as_mut() {
            status = match timeout_at(until, child.wait()).await {
                Ok(Ok(status)) => status.code(),
                _ => {
                    let _ = child.start_kill();
                    child.wait().await.ok().and_then(|status| status.code())
                }
            };
        }
        self.child.take();
        self.finish_drain().await;
        // The owned process has been reaped before unlinking its socket.
        if let Some(directory) = self.directory.take() {
            let _ = directory.close();
        }
        status
    }

    async fn finish_drain(&mut self) {
        if let Some(mut drain) = self.drain.take() {
            // A configured proxy descendant may inherit stderr after ssh exits.
            if timeout_at(Instant::now() + Duration::from_millis(100), &mut drain)
                .await
                .is_err()
            {
                drain.abort();
                let _ = drain.await;
            }
        }
    }
}

impl Drop for Master {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let directory = self.directory.take();
        let drain = self.drain.take();
        // Launch/cleanup cancellation guard. The process and directory move
        // together to an owned reaper; kill_on_drop remains the last backstop.
        let _ = child.start_kill();
        tokio::spawn(async move {
            let _ = child.wait().await;
            if let Some(drain) = drain {
                drain.abort();
                let _ = drain.await;
            }
            if let Some(directory) = directory {
                let _ = directory.close();
            }
        });
    }
}

struct EntryControl {
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
    let child = master.child.as_mut().ok_or(Failure::Connect)?;
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

async fn run_entry(
    owner: Weak<Pool>,
    key: Key,
    entry: Arc<Entry>,
    config: Option<PathBuf>,
    destination: String,
    control: EntryControl,
) {
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
        entry.stop.cancel();
        entry.ready.cancel();
    } else if let Ok((mut master, session)) = Master::launch(config.as_ref(), &destination) {
        let pid = master.child.as_ref().and_then(Child::id);
        let socket = master
            .directory
            .as_ref()
            .map(|directory| directory.path().join("c"));
        lifecycle("master_start", pid, socket.as_ref(), key.1, None);
        let result = ready(&mut master, &session, &entry, &control).await;
        let session = Arc::new(session);
        {
            let mut state = lock(&entry.state);
            if let Err(failure) = result {
                state.failure = Some(failure);
            } else {
                state.session = Some(Arc::clone(&session));
            }
        }
        entry.ready.cancel();
        if result.is_ok() {
            supervise(&mut master, &entry, &control).await;
        }
        entry.stop.cancel();
        {
            let mut state = lock(&entry.state);
            state.session.take();
            if state.failure.is_none() {
                state.failure = Some(Failure::Lost);
            }
        }
        let status = master.cleanup(Some(session), &entry).await;
        lifecycle("master_finish", pid, socket.as_ref(), key.1, status);
    } else {
        lock(&entry.state).failure = Some(Failure::Connect);
        entry.stop.cancel();
        entry.ready.cancel();
    }
    if let Some(owner) = owner.upgrade() {
        lock(&owner.entries).remove(&key);
    }
    entry.done.cancel();
}

fn lifecycle(
    event: &str,
    pid: Option<u32>,
    socket: Option<&PathBuf>,
    role: IdentityRole,
    status: Option<i32>,
) {
    // No destination, backend error, or stderr payload may enter this record.
    eprintln!(
        "{}",
        serde_json::json!({
            "event": event, "pid": pid, "socket": socket, "role": role, "status": status,
        })
    );
}
