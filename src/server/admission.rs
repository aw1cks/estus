use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    os::fd::AsFd,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use nix::{
    dir::Dir,
    errno::Errno,
    fcntl::{OFlag, openat, renameat},
    sys::stat::{Mode, SFlag, fstat},
    unistd::{UnlinkatFlags, unlinkat},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit, RwLock, Semaphore},
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{
    audit,
    config::ConfigError,
    reply::{ErrorCode, ToolError},
    strict_json,
};

const READ_SLOTS: usize = 4;
const MAX_DYNAMIC_GATES: usize = 256;
const MAX_PERSISTED_RECORD_BYTES: usize = 4096;
static PERSIST_NONCE: AtomicU64 = AtomicU64::new(1);

const KNOWN_EXECUTORS: &[&str] = &[
    "native_sftp",
    "native_shell",
    "native_argv",
    "native_sudo",
    "native_payload",
    "ansible_module",
    "unknown",
];

/// Closed set of quarantine causes; persisted and audited by wire string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QuarantineCause {
    AlreadyExists,
    AutomationFailed,
    Cancelled,
    ChecksumMismatch,
    CleanupIncomplete,
    CommandFailed,
    ConnectionLost,
    ControllerResourceLimit,
    DiscoveryFailed,
    InvalidArgument,
    InvalidEncoding,
    InvalidProjection,
    InvalidResult,
    IoError,
    NotFound,
    PayloadFailed,
    PayloadRejected,
    PermissionDenied,
    PolicyDenied,
    PreviewRequired,
    ResourceLimit,
    ResourceUnavailable,
    Shutdown,
    SpawnFailed,
    SshConnectFailed,
    SshSpawnFailed,
    TargetQuarantined,
    Timeout,
    Unsupported,
    UnsupportedWorkspaceEntry,
    WorkerLost,
}

impl QuarantineCause {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyExists => "already_exists",
            Self::AutomationFailed => "automation_failed",
            Self::Cancelled => "cancelled",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::CleanupIncomplete => "cleanup_incomplete",
            Self::CommandFailed => "command_failed",
            Self::ConnectionLost => "connection_lost",
            Self::ControllerResourceLimit => "controller_resource_limit",
            Self::DiscoveryFailed => "discovery_failed",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidProjection => "invalid_projection",
            Self::InvalidResult => "invalid_result",
            Self::IoError => "io_error",
            Self::NotFound => "not_found",
            Self::PayloadFailed => "payload_failed",
            Self::PayloadRejected => "payload_rejected",
            Self::PermissionDenied => "permission_denied",
            Self::PolicyDenied => "policy_denied",
            Self::PreviewRequired => "preview_required",
            Self::ResourceLimit => "resource_limit",
            Self::ResourceUnavailable => "resource_unavailable",
            Self::Shutdown => "shutdown",
            Self::SpawnFailed => "spawn_failed",
            Self::SshConnectFailed => "ssh_connect_failed",
            Self::SshSpawnFailed => "ssh_spawn_failed",
            Self::TargetQuarantined => "target_quarantined",
            Self::Timeout => "timeout",
            Self::Unsupported => "unsupported",
            Self::UnsupportedWorkspaceEntry => "unsupported_workspace_entry",
            Self::WorkerLost => "worker_lost",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "already_exists" => Some(Self::AlreadyExists),
            "automation_failed" => Some(Self::AutomationFailed),
            "cancelled" => Some(Self::Cancelled),
            "checksum_mismatch" => Some(Self::ChecksumMismatch),
            "cleanup_incomplete" => Some(Self::CleanupIncomplete),
            "command_failed" => Some(Self::CommandFailed),
            "connection_lost" => Some(Self::ConnectionLost),
            "controller_resource_limit" => Some(Self::ControllerResourceLimit),
            "discovery_failed" => Some(Self::DiscoveryFailed),
            "invalid_argument" => Some(Self::InvalidArgument),
            "invalid_encoding" => Some(Self::InvalidEncoding),
            "invalid_projection" => Some(Self::InvalidProjection),
            "invalid_result" => Some(Self::InvalidResult),
            "io_error" => Some(Self::IoError),
            "not_found" => Some(Self::NotFound),
            "payload_failed" => Some(Self::PayloadFailed),
            "payload_rejected" => Some(Self::PayloadRejected),
            "permission_denied" => Some(Self::PermissionDenied),
            "policy_denied" => Some(Self::PolicyDenied),
            "preview_required" => Some(Self::PreviewRequired),
            "resource_limit" => Some(Self::ResourceLimit),
            "resource_unavailable" => Some(Self::ResourceUnavailable),
            "shutdown" => Some(Self::Shutdown),
            "spawn_failed" => Some(Self::SpawnFailed),
            "ssh_connect_failed" => Some(Self::SshConnectFailed),
            "ssh_spawn_failed" => Some(Self::SshSpawnFailed),
            "target_quarantined" => Some(Self::TargetQuarantined),
            "timeout" => Some(Self::Timeout),
            "unsupported" => Some(Self::Unsupported),
            "unsupported_workspace_entry" => Some(Self::UnsupportedWorkspaceEntry),
            "worker_lost" => Some(Self::WorkerLost),
            _ => None,
        }
    }

    fn from_error_code(code: ErrorCode) -> Self {
        match code {
            ErrorCode::AlreadyExists => Self::AlreadyExists,
            ErrorCode::AutomationFailed => Self::AutomationFailed,
            ErrorCode::Cancelled => Self::Cancelled,
            ErrorCode::ChecksumMismatch => Self::ChecksumMismatch,
            ErrorCode::CleanupIncomplete => Self::CleanupIncomplete,
            ErrorCode::CommandFailed => Self::CommandFailed,
            ErrorCode::ConnectionLost => Self::ConnectionLost,
            ErrorCode::ControllerResourceLimit => Self::ControllerResourceLimit,
            ErrorCode::DiscoveryFailed => Self::DiscoveryFailed,
            ErrorCode::InvalidArgument => Self::InvalidArgument,
            ErrorCode::InvalidEncoding => Self::InvalidEncoding,
            ErrorCode::InvalidProjection => Self::InvalidProjection,
            ErrorCode::InvalidResult => Self::InvalidResult,
            ErrorCode::IoError => Self::IoError,
            ErrorCode::NotFound => Self::NotFound,
            ErrorCode::PayloadFailed => Self::PayloadFailed,
            ErrorCode::PayloadRejected => Self::PayloadRejected,
            ErrorCode::PermissionDenied => Self::PermissionDenied,
            ErrorCode::PolicyDenied => Self::PolicyDenied,
            ErrorCode::PreviewRequired => Self::PreviewRequired,
            ErrorCode::ResourceLimit => Self::ResourceLimit,
            ErrorCode::ResourceUnavailable => Self::ResourceUnavailable,
            ErrorCode::Shutdown => Self::Shutdown,
            ErrorCode::SpawnFailed => Self::SpawnFailed,
            ErrorCode::SshConnectFailed => Self::SshConnectFailed,
            ErrorCode::SshSpawnFailed => Self::SshSpawnFailed,
            ErrorCode::TargetQuarantined => Self::TargetQuarantined,
            ErrorCode::Timeout => Self::Timeout,
            ErrorCode::Unsupported => Self::Unsupported,
            #[cfg(test)]
            // Test-only code; controller errors never quarantine targets.
            ErrorCode::ControllerTimeout => Self::CommandFailed,
        }
    }
}

fn intern_known(table: &[&'static str], value: &str) -> Option<&'static str> {
    table.iter().copied().find(|candidate| *candidate == value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionMode {
    /// Shared 4-slot read; allowed while quarantined; never quarantines target.
    SharedRead,
    /// Exclusive non-mutating probe; allowed while quarantined; never quarantines target.
    ExclusiveProbe,
    /// Multiplexed channel execution; blocked while quarantined; quarantines target on lost ack/owner.
    MultiplexedExec,
    /// Exclusive target mutation; blocked while quarantined; quarantines target on lost ack/owner.
    ExclusiveWrite,
}

#[derive(Clone)]
struct QuarantineState {
    authority: String,
    executor: &'static str,
    cause: QuarantineCause,
}

pub(super) struct ClearedQuarantine {
    pub(super) authority: String,
    pub(super) executor: &'static str,
    pub(super) cause: &'static str,
}

struct DispatchContext {
    host: String,
    authority: String,
    executor: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRecord {
    schema: u32,
    host: String,
    authority: String,
    executor: String,
    cause: String,
}

struct Persistence {
    dir: File,
}

fn record_stem(host: &str) -> String {
    hex::encode(Sha256::digest(host.as_bytes()))
}

impl Persistence {
    fn open(path: &Path) -> Result<(Self, BTreeMap<String, QuarantineState>), ConfigError> {
        let invalid = |reason: &'static str| ConfigError::new("quarantine.state_dir", reason);
        let dir = File::from(
            openat(
                nix::fcntl::AT_FDCWD,
                path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| invalid("cannot open private quarantine state directory"))?,
        );
        let st = fstat(&dir).map_err(|_| invalid("cannot inspect quarantine state directory"))?;
        if !SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFDIR)
            || st.st_uid != nix::unistd::geteuid().as_raw()
            || (st.st_mode & 0o077) != 0
        {
            return Err(invalid(
                "quarantine state directory must be owned by the current UID with mode 0700",
            ));
        }
        let mut stream = Dir::openat(
            &dir,
            c".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| invalid("cannot enumerate quarantine state directory"))?;
        let mut restored = BTreeMap::new();
        for entry in stream.iter() {
            let entry = entry.map_err(|_| invalid("cannot read quarantine state entry"))?;
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." || name_bytes.starts_with(b".tmp-") {
                continue;
            }
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| invalid("invalid entry in quarantine state directory"))?;
            let Some(stem) = name.strip_suffix(".json") else {
                return Err(invalid("unexpected entry in quarantine state directory"));
            };
            if stem.len() != 64 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("invalid quarantine state filename"));
            }
            if restored.len() >= MAX_DYNAMIC_GATES {
                return Err(invalid("quarantine state directory exceeds entry bound"));
            }
            let file = File::from(
                openat(
                    &dir,
                    entry.file_name(),
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|_| invalid("cannot open quarantine state record"))?,
            );
            let meta = fstat(&file).map_err(|_| invalid("cannot stat quarantine state record"))?;
            if !SFlag::from_bits_truncate(meta.st_mode).contains(SFlag::S_IFREG)
                || meta.st_uid != nix::unistd::geteuid().as_raw()
            {
                return Err(invalid(
                    "quarantine state record must be an owned regular file",
                ));
            }
            let mut bytes = Vec::new();
            file.take(MAX_PERSISTED_RECORD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid("cannot read quarantine state record"))?;
            if bytes.len() > MAX_PERSISTED_RECORD_BYTES {
                return Err(invalid("quarantine state record exceeds size bound"));
            }
            let record: PersistedRecord = strict_json::parse(&bytes)
                .and_then(serde_json::from_value)
                .map_err(|_| invalid("malformed quarantine state record"))?;
            if record.schema != 1
                || record.host.is_empty()
                || record.host.len() > 256
                || record.host.chars().any(char::is_control)
                || record.authority.is_empty()
                || record.authority.len() > 128
                || record_stem(&record.host) != stem
            {
                return Err(invalid("invalid quarantine state record identity"));
            }
            let executor = intern_known(KNOWN_EXECUTORS, &record.executor)
                .ok_or_else(|| invalid("unknown executor in quarantine state record"))?;
            let cause = QuarantineCause::from_str(&record.cause)
                .ok_or_else(|| invalid("unknown cause in quarantine state record"))?;
            restored.insert(
                record.host,
                QuarantineState {
                    authority: record.authority,
                    executor,
                    cause,
                },
            );
        }
        Ok((Self { dir }, restored))
    }

    fn save(&self, host: &str, state: &QuarantineState) -> std::io::Result<()> {
        let stem = record_stem(host);
        let final_name = std::ffi::CString::new(format!("{stem}.json"))
            .map_err(|_| std::io::Error::other("invalid cstring"))?;
        let nonce = PERSIST_NONCE.fetch_add(1, Ordering::Relaxed);
        let tmp_name = std::ffi::CString::new(format!(".tmp-{stem}-{nonce}"))
            .map_err(|_| std::io::Error::other("invalid cstring"))?;
        let payload = serde_json::to_vec(&PersistedRecord {
            schema: 1,
            host: host.to_owned(),
            authority: state.authority.clone(),
            executor: state.executor.to_owned(),
            cause: state.cause.as_str().to_owned(),
        })
        .map_err(std::io::Error::other)?;
        let mut file = File::from(
            openat(
                &self.dir,
                tmp_name.as_c_str(),
                OFlag::O_WRONLY
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map_err(std::io::Error::from)?,
        );
        if let Err(err) = file.write_all(&payload).and_then(|()| file.sync_data()) {
            let _ = unlinkat(&self.dir, tmp_name.as_c_str(), UnlinkatFlags::NoRemoveDir);
            return Err(err);
        }
        drop(file);
        if let Err(err) = renameat(
            self.dir.as_fd(),
            tmp_name.as_c_str(),
            self.dir.as_fd(),
            final_name.as_c_str(),
        ) {
            let _ = unlinkat(&self.dir, tmp_name.as_c_str(), UnlinkatFlags::NoRemoveDir);
            return Err(std::io::Error::from(err));
        }
        Ok(())
    }

    fn remove(&self, host: &str) -> std::io::Result<()> {
        let stem = record_stem(host);
        let final_name = std::ffi::CString::new(format!("{stem}.json"))
            .map_err(|_| std::io::Error::other("invalid cstring"))?;
        match unlinkat(&self.dir, final_name.as_c_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(err) => Err(std::io::Error::from(err)),
        }
    }
}

struct TargetGate {
    rw: Arc<RwLock<()>>,
    reads: Arc<Semaphore>,
    quarantine: Mutex<Option<QuarantineState>>,
}

impl TargetGate {
    fn new() -> Arc<Self> {
        Self::with_quarantine(None)
    }

    fn with_quarantine(initial: Option<QuarantineState>) -> Arc<Self> {
        Arc::new(Self {
            rw: Arc::new(RwLock::new(())),
            reads: Arc::new(Semaphore::new(READ_SLOTS)),
            quarantine: Mutex::new(initial),
        })
    }

    fn set_quarantine(
        &self,
        persistence: Option<&Persistence>,
        host: &str,
        authority: String,
        executor: &'static str,
        cause: QuarantineCause,
    ) {
        let state = QuarantineState {
            authority: authority.clone(),
            executor,
            cause,
        };
        let mut guard = self
            .quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(persistence) = persistence
            && persistence.save(host, &state).is_err()
        {
            audit::emit(&serde_json::json!({
                "event": "quarantine_persist_failed",
                "target": host,
            }));
        }
        *guard = Some(state);
        drop(guard);
        audit::target_quarantine(
            "quarantined",
            host,
            Some(&authority),
            Some(executor),
            cause.as_str(),
        );
    }

    fn is_quarantined(&self) -> bool {
        self.quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    fn clear_quarantine(
        &self,
        persistence: Option<&Persistence>,
        host: &str,
    ) -> Result<Option<ClearedQuarantine>, ToolError> {
        let mut guard = self
            .quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            return Ok(None);
        }
        if let Some(persistence) = persistence {
            persistence.remove(host).map_err(|_| {
                ToolError::io_error(
                    "Persistent target quarantine state could not be cleared",
                    false,
                )
            })?;
        }
        let previous = guard.take().expect("checked quarantine is_some");
        Ok(Some(ClearedQuarantine {
            authority: previous.authority,
            executor: previous.executor,
            cause: previous.cause.as_str(),
        }))
    }
}

struct GateEntry {
    gate: Arc<TargetGate>,
    last_used: u64,
}

struct AdmissionState {
    gates: BTreeMap<String, GateEntry>,
    seq: u64,
}

pub(super) struct TargetAdmission {
    dynamic_hosts: bool,
    persistence: Option<Arc<Persistence>>,
    state: Mutex<AdmissionState>,
}

impl TargetAdmission {
    #[cfg(test)]
    pub(super) fn new<'a>(hosts: impl Iterator<Item = &'a String>, dynamic_hosts: bool) -> Self {
        Self::new_with_persistence(hosts, dynamic_hosts, None)
            .expect("in-memory target admission cannot fail")
    }

    pub(super) fn new_with_persistence<'a>(
        hosts: impl Iterator<Item = &'a String>,
        dynamic_hosts: bool,
        state_dir: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let (persistence, mut restored) = match state_dir {
            Some(path) => {
                let (p, map) = Persistence::open(path)?;
                (Some(Arc::new(p)), map)
            }
            None => (None, BTreeMap::new()),
        };
        let mut seq = 0u64;
        let mut gates: BTreeMap<String, GateEntry> = hosts
            .map(|host| {
                seq += 1;
                let initial = restored.remove(host);
                (
                    host.clone(),
                    GateEntry {
                        gate: TargetGate::with_quarantine(initial),
                        last_used: seq,
                    },
                )
            })
            .collect();
        if dynamic_hosts {
            for (host, initial) in restored {
                if gates.len() >= MAX_DYNAMIC_GATES {
                    break;
                }
                seq += 1;
                gates.insert(
                    host,
                    GateEntry {
                        gate: TargetGate::with_quarantine(Some(initial)),
                        last_used: seq,
                    },
                );
            }
        }
        Ok(Self {
            dynamic_hosts,
            persistence,
            state: Mutex::new(AdmissionState { gates, seq }),
        })
    }

    pub(super) fn contains(&self, host: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gates
            .contains_key(host)
    }

    pub(super) fn quarantine_info(
        &self,
        host: &str,
    ) -> Option<(String, &'static str, &'static str)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let gate = state.gates.get(host)?;
        let q = gate
            .gate
            .quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        q.as_ref()
            .map(|item| (item.authority.clone(), item.executor, item.cause.as_str()))
    }

    pub(super) async fn acquire(
        &self,
        host: &str,
        mode: AdmissionMode,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<TargetLease, ToolError> {
        match mode {
            AdmissionMode::SharedRead => self
                .acquire_read(host, deadline, ct, shutdown)
                .await
                .map(TargetLease::Read),
            AdmissionMode::ExclusiveProbe => self
                .acquire_probe(host, deadline, ct, shutdown)
                .await
                .map(TargetLease::Probe),
            AdmissionMode::MultiplexedExec => self
                .acquire_exec(host, deadline, ct, shutdown)
                .map(TargetLease::Exec),
            AdmissionMode::ExclusiveWrite => self
                .acquire_write(host, deadline, ct, shutdown)
                .await
                .map(TargetLease::Write),
        }
    }

    pub(super) async fn acquire_read(
        &self,
        host: &str,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<ReadLease, ToolError> {
        let gate = self.gate(host)?;
        let permit = wait_for(
            deadline,
            ct,
            shutdown,
            Arc::clone(&gate.reads).acquire_owned(),
        )
        .await?
        .map_err(|_| ToolError::cancelled("Target gate closed before dispatch", false))?;
        let guard = wait_for(deadline, ct, shutdown, Arc::clone(&gate.rw).read_owned()).await?;
        Ok(ReadLease {
            _guard: guard,
            _permit: permit,
        })
    }

    async fn acquire_probe(
        &self,
        host: &str,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<ProbeLease, ToolError> {
        let gate = self.gate(host)?;
        let guard = wait_for(deadline, ct, shutdown, Arc::clone(&gate.rw).write_owned()).await?;
        Ok(ProbeLease { _guard: guard })
    }

    fn acquire_exec(
        &self,
        host: &str,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<ExecLease, ToolError> {
        if ct.is_cancelled() || shutdown.is_cancelled() {
            return Err(ToolError::cancelled(
                "Request cancelled before dispatch",
                false,
            ));
        }
        if Instant::now() >= deadline {
            return Err(ToolError::timeout(
                "Operation deadline expired waiting for target gate",
                false,
            ));
        }
        let gate = self.gate(host)?;
        if gate.is_quarantined() {
            return Err(quarantined_error());
        }
        Ok(ExecLease {
            gate,
            persistence: self.persistence.clone(),
            dispatched: None,
        })
    }

    pub(super) async fn acquire_write(
        &self,
        host: &str,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<WriteLease, ToolError> {
        let gate = self.gate(host)?;
        let guard = wait_for(deadline, ct, shutdown, Arc::clone(&gate.rw).write_owned()).await?;
        if gate.is_quarantined() {
            return Err(quarantined_error());
        }
        Ok(WriteLease {
            gate,
            persistence: self.persistence.clone(),
            _guard: guard,
            dispatched: None,
        })
    }

    pub(super) fn clear_quarantine(
        &self,
        host: &str,
    ) -> Result<Option<ClearedQuarantine>, ToolError> {
        let Some(gate) = ({
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.gates.get(host).map(|entry| Arc::clone(&entry.gate))
        }) else {
            return Ok(None);
        };
        gate.clear_quarantine(self.persistence.as_deref(), host)
    }

    fn gate(&self, host: &str) -> Result<Arc<TargetGate>, ToolError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.seq = state.seq.saturating_add(1);
        let seq = state.seq;
        if let Some(entry) = state.gates.get_mut(host) {
            entry.last_used = seq;
            return Ok(Arc::clone(&entry.gate));
        }
        if !self.dynamic_hosts {
            return Err(ToolError::policy_denied(
                "Operation is not authorized",
                false,
            ));
        }
        if state.gates.len() >= MAX_DYNAMIC_GATES {
            let victim = state
                .gates
                .iter()
                .filter(|(_, entry)| {
                    Arc::strong_count(&entry.gate) == 1
                        && !entry.gate.is_quarantined()
                        && entry.gate.reads.available_permits() == READ_SLOTS
                        && entry.gate.rw.try_write().is_ok()
                })
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(name, _)| name.clone());
            let Some(victim) = victim else {
                return Err(ToolError::resource_limit(
                    "Dynamic target gate capacity reached",
                    false,
                ));
            };
            state.gates.remove(&victim);
        }
        let gate = TargetGate::new();
        state.gates.insert(
            host.to_owned(),
            GateEntry {
                gate: Arc::clone(&gate),
                last_used: seq,
            },
        );
        Ok(gate)
    }
}

fn quarantined_error() -> ToolError {
    ToolError::target_quarantined(
        "Target is quarantined after an uncertain remote mutation; inspect target state and run change_target_quarantine_clear after independent reconciliation",
        false,
    )
}

async fn wait_for<F>(
    deadline: Instant,
    ct: &CancellationToken,
    shutdown: &CancellationToken,
    future: F,
) -> Result<F::Output, ToolError>
where
    F: Future,
{
    if ct.is_cancelled() || shutdown.is_cancelled() {
        return Err(ToolError::cancelled(
            "Request cancelled before dispatch",
            false,
        ));
    }
    if Instant::now() >= deadline {
        return Err(ToolError::timeout(
            "Operation deadline expired waiting for target gate",
            false,
        ));
    }
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(ToolError::cancelled(
            "Request cancelled before dispatch",
            false,
        )),
        _ = shutdown.cancelled() => Err(ToolError::cancelled(
            "Server shutting down before dispatch",
            false,
        )),
        _ = sleep_until(deadline) => Err(ToolError::timeout(
            "Operation deadline expired waiting for target gate",
            false,
        )),
        output = future => Ok(output),
    }
}

pub(super) struct ReadLease {
    _guard: OwnedRwLockReadGuard<()>,
    _permit: OwnedSemaphorePermit,
}

pub(super) struct ProbeLease {
    _guard: OwnedRwLockWriteGuard<()>,
}

pub(super) struct ExecLease {
    gate: Arc<TargetGate>,
    persistence: Option<Arc<Persistence>>,
    dispatched: Option<DispatchContext>,
}

impl ExecLease {
    fn mark_dispatched(&mut self, host: String, authority: String, executor: &'static str) {
        self.dispatched = Some(DispatchContext {
            host,
            authority,
            executor,
        });
    }

    fn finish(&mut self, quarantine_target: bool, cause: Option<ErrorCode>) {
        if let Some(ctx) = self.dispatched.take()
            && quarantine_target
            && let Some(cause) = cause.map(QuarantineCause::from_error_code)
        {
            self.gate.set_quarantine(
                self.persistence.as_deref(),
                &ctx.host,
                ctx.authority,
                ctx.executor,
                cause,
            );
        }
    }
}

impl Drop for ExecLease {
    fn drop(&mut self) {
        if let Some(ctx) = self.dispatched.take() {
            self.gate.set_quarantine(
                self.persistence.as_deref(),
                &ctx.host,
                ctx.authority,
                ctx.executor,
                QuarantineCause::WorkerLost,
            );
        }
    }
}

pub(super) struct WriteLease {
    gate: Arc<TargetGate>,
    persistence: Option<Arc<Persistence>>,
    _guard: OwnedRwLockWriteGuard<()>,
    dispatched: Option<DispatchContext>,
}

impl WriteLease {
    pub(super) fn mark_dispatched(
        &mut self,
        host: String,
        authority: String,
        executor: &'static str,
    ) {
        self.dispatched = Some(DispatchContext {
            host,
            authority,
            executor,
        });
    }

    pub(super) fn finish(&mut self, quarantine_target: bool, cause: Option<ErrorCode>) {
        if let Some(ctx) = self.dispatched.take()
            && quarantine_target
            && let Some(cause) = cause.map(QuarantineCause::from_error_code)
        {
            self.gate.set_quarantine(
                self.persistence.as_deref(),
                &ctx.host,
                ctx.authority,
                ctx.executor,
                cause,
            );
        }
    }
}

impl Drop for WriteLease {
    fn drop(&mut self) {
        if let Some(ctx) = self.dispatched.take() {
            self.gate.set_quarantine(
                self.persistence.as_deref(),
                &ctx.host,
                ctx.authority,
                ctx.executor,
                QuarantineCause::WorkerLost,
            );
        }
    }
}

pub(super) enum TargetLease {
    Read(#[allow(dead_code)] ReadLease),
    Probe(#[allow(dead_code)] ProbeLease),
    Exec(ExecLease),
    Write(WriteLease),
}

impl TargetLease {
    pub(super) fn mark_dispatched(
        &mut self,
        host: String,
        authority: String,
        executor: &'static str,
    ) {
        match self {
            Self::Read(_) | Self::Probe(_) => {}
            Self::Exec(lease) => lease.mark_dispatched(host, authority, executor),
            Self::Write(lease) => lease.mark_dispatched(host, authority, executor),
        }
    }

    pub(super) fn finish(&mut self, quarantine_target: bool, cause: Option<ErrorCode>) {
        match self {
            Self::Read(_) | Self::Probe(_) => {}
            Self::Exec(lease) => lease.finish(quarantine_target, cause),
            Self::Write(lease) => lease.finish(quarantine_target, cause),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use super::*;
    use crate::reply::ErrorCode;

    fn admission_with(hosts: &[&str]) -> TargetAdmission {
        let owned: Vec<String> = hosts.iter().map(|h| (*h).to_owned()).collect();
        TargetAdmission::new(owned.iter(), false)
    }

    #[tokio::test]
    async fn four_reads_overlap_fifth_waits_and_write_serializes() {
        let admission = Arc::new(admission_with(&["alpha"]));
        let ct = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        let r1 = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        let r2 = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        let r3 = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        let r4 = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();

        let fifth_acquired = Arc::new(AtomicUsize::new(0));
        let fifth_flag = Arc::clone(&fifth_acquired);
        let adm5 = Arc::clone(&admission);
        let ct5 = ct.clone();
        let sd5 = shutdown.clone();
        let fifth = tokio::spawn(async move {
            let _r5 = adm5
                .acquire_read("alpha", deadline, &ct5, &sd5)
                .await
                .unwrap();
            fifth_flag.store(1, Ordering::Release);
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(fifth_acquired.load(Ordering::Acquire), 0);

        drop(r1);
        fifth.await.unwrap();
        assert_eq!(fifth_acquired.load(Ordering::Acquire), 1);

        // A pending write must wait until active reads finish.
        let write_acquired = Arc::new(AtomicUsize::new(0));
        let write_flag = Arc::clone(&write_acquired);
        let adm_w = Arc::clone(&admission);
        let ct_w = ct.clone();
        let sd_w = shutdown.clone();
        let writer = tokio::spawn(async move {
            let mut w = adm_w
                .acquire_write("alpha", deadline, &ct_w, &sd_w)
                .await
                .unwrap();
            write_flag.store(1, Ordering::Release);
            w.finish(false, None);
        });

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(write_acquired.load(Ordering::Acquire), 0);

        drop((r2, r3, r4));
        writer.await.unwrap();
        assert_eq!(write_acquired.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancellation_at_each_wait_point_releases_ownership() {
        let admission = Arc::new(admission_with(&["alpha"]));
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        // Saturate 4 read slots so 5th read waits at semaphore.
        let ct_ok = CancellationToken::new();
        let r1 = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let r2 = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let r3 = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let r4 = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();

        let ct_wait_sem = CancellationToken::new();
        let ct_wait_sem_trigger = ct_wait_sem.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            ct_wait_sem_trigger.cancel();
        });
        let err = admission
            .acquire_read("alpha", deadline, &ct_wait_sem, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(!err.remote_state_unknown);

        drop((r1, r2, r3, r4));

        // Hold exclusive write lock so both read (at rw.read_owned) and write (at rw.write_owned) wait.
        let mut w = admission
            .acquire_write("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let ct_wait_rw_read = CancellationToken::new();
        let ct_wait_rw_read_trigger = ct_wait_rw_read.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            ct_wait_rw_read_trigger.cancel();
        });
        let err = admission
            .acquire_read("alpha", deadline, &ct_wait_rw_read, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(!err.remote_state_unknown);

        // Partial read_permit MUST have been released when rw.read_owned cancelled.
        let ct_wait_rw_write = CancellationToken::new();
        let ct_wait_rw_write_trigger = ct_wait_rw_write.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            ct_wait_rw_write_trigger.cancel();
        });
        let err = admission
            .acquire_write("alpha", deadline, &ct_wait_rw_write, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(!err.remote_state_unknown);

        w.finish(false, None);
        drop(w);

        // All 4 read slots remain available after cancelled waits.
        let _a = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let _b = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let _c = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
        let _d = admission
            .acquire_read("alpha", deadline, &ct_ok, &shutdown)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn uncertain_write_and_owner_loss_quarantine_writes_while_reads_remain_open() {
        let admission = admission_with(&["alpha"]);
        let ct = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        let mut w1 = admission
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        w1.mark_dispatched("alpha".into(), "ordinary".into(), "native_payload");
        w1.finish(true, Some(ErrorCode::Timeout));
        drop(w1);

        let blocked = admission
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked.code(), ErrorCode::TargetQuarantined);
        assert!(!blocked.remote_state_unknown);

        // Reads still succeed while quarantined.
        let _r = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        drop(_r);

        // Exclusive probes also remain open while quarantined and never quarantine on failure.
        let mut p = admission
            .acquire(
                "alpha",
                AdmissionMode::ExclusiveProbe,
                deadline,
                &ct,
                &shutdown,
            )
            .await
            .unwrap();
        p.mark_dispatched("alpha".into(), "ordinary".into(), "native_payload");
        p.finish(true, Some(ErrorCode::Timeout));
        drop(p);

        // Multiplexed exec is blocked while quarantined.
        let blocked_exec = admission
            .acquire(
                "alpha",
                AdmissionMode::MultiplexedExec,
                deadline,
                &ct,
                &shutdown,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(blocked_exec.code(), ErrorCode::TargetQuarantined);

        // Unknown or non-quarantined targets return None.
        assert!(admission.clear_quarantine("missing").unwrap().is_none());
        let cleared = admission.clear_quarantine("alpha").unwrap().unwrap();
        assert_eq!(cleared.cause, "timeout");
        assert!(admission.clear_quarantine("alpha").unwrap().is_none());

        // Multiplexed exec overlaps concurrently and quarantines on uncertain completion.
        let mut e1 = admission
            .acquire(
                "alpha",
                AdmissionMode::MultiplexedExec,
                deadline,
                &ct,
                &shutdown,
            )
            .await
            .unwrap();
        let mut e2 = admission
            .acquire(
                "alpha",
                AdmissionMode::MultiplexedExec,
                deadline,
                &ct,
                &shutdown,
            )
            .await
            .unwrap();
        e1.mark_dispatched("alpha".into(), "ordinary".into(), "native_shell");
        e2.mark_dispatched("alpha".into(), "ordinary".into(), "native_shell");
        e1.finish(false, None);
        e2.finish(true, Some(ErrorCode::Timeout));
        drop((e1, e2));
        assert_eq!(
            admission
                .acquire_write("alpha", deadline, &ct, &shutdown)
                .await
                .err()
                .unwrap()
                .code(),
            ErrorCode::TargetQuarantined
        );
        let cleared = admission.clear_quarantine("alpha").unwrap().unwrap();
        assert_eq!(cleared.executor, "native_shell");
        assert_eq!(cleared.cause, "timeout");

        // Owner lost after dispatch without finish() also quarantines atomically on Drop.
        let mut w2 = admission
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        w2.mark_dispatched("alpha".into(), "ordinary".into(), "native_payload");
        drop(w2);

        let blocked = admission
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked.code(), ErrorCode::TargetQuarantined);
        let cleared = admission.clear_quarantine("alpha").unwrap().unwrap();
        assert_eq!(cleared.cause, "worker_lost");
    }

    #[tokio::test]
    async fn dynamic_host_gates_cap_at_256_evict_idle_non_quarantined_and_preserve_quarantine() {
        let admission = TargetAdmission::new(std::iter::empty(), true);
        let ct = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);

        // Saturate 256 dynamic gates with active read leases.
        let mut active_reads = Vec::new();
        for idx in 0..256 {
            let host = format!("host-{idx:03}");
            active_reads.push(
                admission
                    .acquire_read(&host, deadline, &ct, &shutdown)
                    .await
                    .unwrap(),
            );
        }
        // 257th distinct host must reject with resource_limit while all 256 are active.
        let overflow = admission
            .acquire_read("host-256", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(overflow.code(), ErrorCode::ResourceLimit);

        // Quarantine host-000, drop its active lease, and verify it cannot be evicted.
        let first_read = active_reads.remove(0);
        drop(first_read);
        let mut w0 = admission
            .acquire_write("host-000", deadline, &ct, &shutdown)
            .await
            .unwrap();
        w0.mark_dispatched("host-000".into(), "ordinary".into(), "native_payload");
        w0.finish(true, Some(ErrorCode::Timeout));

        // host-000 is idle but quarantined: 257th host still cannot evict it while 255 others remain active.
        let blocked_evict = admission
            .acquire_read("host-256", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked_evict.code(), ErrorCode::ResourceLimit);

        // Drop idle non-quarantined host-001: now 257th host succeeds by evicting host-001 while host-000 stays quarantined.
        let second_read = active_reads.remove(0);
        drop(second_read);
        let r256 = admission
            .acquire_read("host-256", deadline, &ct, &shutdown)
            .await
            .unwrap();
        assert!(!admission.contains("host-001"));
        assert!(admission.contains("host-000"));
        assert!(
            admission
                .acquire_write("host-000", deadline, &ct, &shutdown)
                .await
                .is_err()
        );
        drop(r256);
        drop(active_reads);
    }

    #[tokio::test]
    async fn persistent_quarantine_survives_restart_and_rejects_unsafe_state_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("quarantine");
        std::fs::create_dir(&state_dir).unwrap();

        // World/group-accessible directory fails closed.
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hosts = ["alpha".to_owned()];
        assert!(
            TargetAdmission::new_with_persistence(hosts.iter(), false, Some(&state_dir)).is_err()
        );

        // Private 0700 directory loads, persists across restarts, and unlinks on clear.
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ct = CancellationToken::new();
        let shutdown = CancellationToken::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        {
            let adm1 = TargetAdmission::new_with_persistence(hosts.iter(), false, Some(&state_dir))
                .unwrap();
            let mut w = adm1
                .acquire_write("alpha", deadline, &ct, &shutdown)
                .await
                .unwrap();
            w.mark_dispatched("alpha".into(), "ordinary".into(), "native_sftp");
            w.finish(true, Some(ErrorCode::Timeout));
        }
        let adm2 =
            TargetAdmission::new_with_persistence(hosts.iter(), false, Some(&state_dir)).unwrap();
        assert_eq!(
            adm2.quarantine_info("alpha"),
            Some(("ordinary".into(), "native_sftp", "timeout"))
        );
        let blocked = adm2
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked.code(), ErrorCode::TargetQuarantined);
        let cleared = adm2.clear_quarantine("alpha").unwrap().unwrap();
        assert_eq!(cleared.executor, "native_sftp");
        assert_eq!(cleared.cause, "timeout");
        drop(adm2);

        let adm3 =
            TargetAdmission::new_with_persistence(hosts.iter(), false, Some(&state_dir)).unwrap();
        assert!(adm3.quarantine_info("alpha").is_none());
    }
}
