use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use tokio::{
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit, RwLock, Semaphore},
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{audit, reply::ToolError};

const READ_SLOTS: usize = 4;
const MAX_DYNAMIC_GATES: usize = 256;

#[derive(Clone)]
struct QuarantineState {
    authority: String,
    executor: &'static str,
    cause: &'static str,
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

struct TargetGate {
    rw: Arc<RwLock<()>>,
    reads: Arc<Semaphore>,
    quarantine: Mutex<Option<QuarantineState>>,
}

impl TargetGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            rw: Arc::new(RwLock::new(())),
            reads: Arc::new(Semaphore::new(READ_SLOTS)),
            quarantine: Mutex::new(None),
        })
    }

    fn set_quarantine(
        &self,
        host: &str,
        authority: String,
        executor: &'static str,
        cause: &'static str,
    ) {
        let mut guard = self
            .quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(QuarantineState {
            authority: authority.clone(),
            executor,
            cause,
        });
        drop(guard);
        audit::target_quarantine("quarantined", host, Some(&authority), Some(executor), cause);
    }

    fn is_quarantined(&self) -> bool {
        self.quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    fn clear_quarantine(&self) -> Option<ClearedQuarantine> {
        let previous = self
            .quarantine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()?;
        Some(ClearedQuarantine {
            authority: previous.authority,
            executor: previous.executor,
            cause: previous.cause,
        })
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
    state: Mutex<AdmissionState>,
}

impl TargetAdmission {
    pub(super) fn new<'a>(hosts: impl Iterator<Item = &'a String>, dynamic_hosts: bool) -> Self {
        let mut seq = 0u64;
        let gates = hosts
            .map(|host| {
                seq += 1;
                (
                    host.clone(),
                    GateEntry {
                        gate: TargetGate::new(),
                        last_used: seq,
                    },
                )
            })
            .collect();
        Self {
            dynamic_hosts,
            state: Mutex::new(AdmissionState { gates, seq }),
        }
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
            .map(|item| (item.authority.clone(), item.executor, item.cause))
    }

    pub(super) async fn acquire(
        &self,
        host: &str,
        shared_read: bool,
        deadline: Instant,
        ct: &CancellationToken,
        shutdown: &CancellationToken,
    ) -> Result<TargetLease, ToolError> {
        if shared_read {
            self.acquire_read(host, deadline, ct, shutdown)
                .await
                .map(TargetLease::Read)
        } else {
            self.acquire_write(host, deadline, ct, shutdown)
                .await
                .map(TargetLease::Write)
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
        .map_err(|_| ToolError::new("cancelled", "Target gate closed before dispatch", false))?;
        let guard = wait_for(deadline, ct, shutdown, Arc::clone(&gate.rw).read_owned()).await?;
        Ok(ReadLease {
            _guard: guard,
            _permit: permit,
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
            return Err(ToolError::new(
                "target_quarantined",
                "Target is quarantined after an uncertain remote mutation; inspect target state and run change_target_quarantine_clear after independent reconciliation",
                false,
            ));
        }
        Ok(WriteLease {
            gate,
            _guard: guard,
            dispatched: None,
        })
    }

    pub(super) fn clear_quarantine(&self, host: &str) -> Option<ClearedQuarantine> {
        let gate = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.gates.get(host).map(|entry| Arc::clone(&entry.gate))
        }?;
        gate.clear_quarantine()
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
            return Err(ToolError::new(
                "policy_denied",
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
                return Err(ToolError::new(
                    "resource_limit",
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
        return Err(ToolError::new(
            "cancelled",
            "Request cancelled before dispatch",
            false,
        ));
    }
    if Instant::now() >= deadline {
        return Err(ToolError::new(
            "timeout",
            "Operation deadline expired waiting for target gate",
            false,
        ));
    }
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(ToolError::new(
            "cancelled",
            "Request cancelled before dispatch",
            false,
        )),
        _ = shutdown.cancelled() => Err(ToolError::new(
            "cancelled",
            "Server shutting down before dispatch",
            false,
        )),
        _ = sleep_until(deadline) => Err(ToolError::new(
            "timeout",
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

pub(super) struct WriteLease {
    gate: Arc<TargetGate>,
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

    pub(super) fn finish(&mut self, remote_state_unknown: bool, cause: &'static str) {
        if let Some(ctx) = self.dispatched.take()
            && remote_state_unknown
        {
            self.gate
                .set_quarantine(&ctx.host, ctx.authority, ctx.executor, cause);
        }
    }
}

impl Drop for WriteLease {
    fn drop(&mut self) {
        if let Some(ctx) = self.dispatched.take() {
            self.gate
                .set_quarantine(&ctx.host, ctx.authority, ctx.executor, "worker_lost");
        }
    }
}

pub(super) enum TargetLease {
    Read(#[allow(dead_code)] ReadLease),
    Write(WriteLease),
}

impl TargetLease {
    pub(super) fn mark_dispatched(
        &mut self,
        host: String,
        authority: String,
        executor: &'static str,
    ) {
        if let Self::Write(lease) = self {
            lease.mark_dispatched(host, authority, executor);
        }
    }

    pub(super) fn finish(&mut self, remote_state_unknown: bool, cause: &'static str) {
        if let Self::Write(lease) = self {
            lease.finish(remote_state_unknown, cause);
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
            w.finish(false, "ok");
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
        assert_eq!(err.code, "cancelled");
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
        assert_eq!(err.code, "cancelled");
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
        assert_eq!(err.code, "cancelled");
        assert!(!err.remote_state_unknown);

        w.finish(false, "ok");
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
        w1.finish(true, "timeout");
        drop(w1);

        let blocked = admission
            .acquire_write("alpha", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked.code, "target_quarantined");
        assert!(!blocked.remote_state_unknown);

        // Reads still succeed while quarantined.
        let _r = admission
            .acquire_read("alpha", deadline, &ct, &shutdown)
            .await
            .unwrap();
        drop(_r);

        // Unknown or non-quarantined targets return None.
        assert!(admission.clear_quarantine("missing").is_none());
        let cleared = admission.clear_quarantine("alpha").unwrap();
        assert_eq!(cleared.cause, "timeout");
        assert!(admission.clear_quarantine("alpha").is_none());

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
        assert_eq!(blocked.code, "target_quarantined");
        let cleared = admission.clear_quarantine("alpha").unwrap();
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
        assert_eq!(overflow.code, "resource_limit");

        // Quarantine host-000, drop its active lease, and verify it cannot be evicted.
        let first_read = active_reads.remove(0);
        drop(first_read);
        let mut w0 = admission
            .acquire_write("host-000", deadline, &ct, &shutdown)
            .await
            .unwrap();
        w0.mark_dispatched("host-000".into(), "ordinary".into(), "native_payload");
        w0.finish(true, "timeout");

        // host-000 is idle but quarantined: 257th host still cannot evict it while 255 others remain active.
        let blocked_evict = admission
            .acquire_read("host-256", deadline, &ct, &shutdown)
            .await
            .err()
            .unwrap();
        assert_eq!(blocked_evict.code, "resource_limit");

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
}
