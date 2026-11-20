use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use openssh::{Session, Stdio};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use super::{MAX_INPUT, PayloadPlan, digest};
use crate::{
    config::{AutomationAgent, AutomationBecome, ResolvedAutomation},
    reply::{
        AutomationData, AutomationStatus, AutomationTasks, GroupCleanup, ModuleProjection,
        ToolError, ToolReply,
    },
    ssh::{Lease, Pool},
    strict_json::parse,
};

const BOOTSTRAP: &str = include_str!("bootstrap.py");
const PRESTATE: &str = include_str!("prestate.py");
const PROBE_LIMIT: usize = 65_536;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy)]
struct Failure {
    make: fn(&'static str, bool) -> ToolError,
    message: &'static str,
    unknown: bool,
}

impl Failure {
    fn tool(self) -> ToolError {
        (self.make)(self.message, self.unknown)
    }
}

fn failed(
    make: fn(&'static str, bool) -> ToolError,
    message: &'static str,
    unknown: bool,
) -> Failure {
    Failure {
        make,
        message,
        unknown,
    }
}

struct Probe {
    result: Mutex<Option<Result<Value, Failure>>>,
    ready: CancellationToken,
    stop: CancellationToken,
    owners: AtomicUsize,
}

struct Interest(Arc<Probe>);

impl Drop for Interest {
    fn drop(&mut self) {
        if self.0.owners.fetch_sub(1, Ordering::AcqRel) == 1 && !self.0.ready.is_cancelled() {
            self.0.stop.cancel();
        }
    }
}

struct ProbeCompletion(Arc<Probe>);

impl Drop for ProbeCompletion {
    fn drop(&mut self) {
        let mut result = lock(&self.0.result);
        if result.is_none() {
            *result = Some(Err(failed(
                ToolError::discovery_failed,
                "Discovery owner was lost",
                false,
            )));
        }
        self.0.ready.cancel();
    }
}

/// One engine belongs to one activated config generation, never a process-global pool.
pub(crate) struct Engine {
    pools: Mutex<HashMap<String, Arc<Pool>>>,
    probes: Mutex<HashMap<String, Arc<Probe>>>,
    shutdown: CancellationToken,
}

impl Engine {
    pub(crate) fn new(shutdown: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            pools: Mutex::new(HashMap::new()),
            probes: Mutex::new(HashMap::new()),
            shutdown,
        })
    }

    pub(crate) async fn shutdown(&self) {
        let pools: Vec<_> = lock(&self.pools).values().cloned().collect();
        let probes: Vec<_> = lock(&self.probes).values().cloned().collect();
        for probe in &probes {
            probe.stop.cancel();
        }
        for probe in probes {
            probe.ready.cancelled().await;
        }
        for pool in pools {
            pool.shutdown().await;
        }
    }

    fn pool(
        &self,
        host: &str,
        authority: &str,
        target: &ResolvedAutomation<'_>,
        connect_timeout: Duration,
    ) -> Result<(String, Arc<Pool>), ToolError> {
        let agent = match target.agent {
            AutomationAgent::Inherit => std::env::var_os("SSH_AUTH_SOCK"),
            AutomationAgent::Disabled => None,
            AutomationAgent::Fixed(path) => Some(path.as_os_str().to_owned()),
        };
        let key = serde_json::to_string(&json!({
            "host": host,
            "authority": authority,
            "destination": target.target.destination,
            "config": target.ssh_config,
            "executable": target.ssh_executable,
            "agent": agent.as_ref().map(|socket| socket.to_string_lossy()),
            "become": target.r#become,
            "python": target.target.python,
        }))
        .map_err(|_| ToolError::invalid_argument("Invalid transport identity", false))?;
        let mut pools = lock(&self.pools);
        if let Some(pool) = pools.get(&key) {
            return Ok((key, Arc::clone(pool)));
        }
        if pools.len() >= 16 {
            return Err(ToolError::resource_limit(
                "Native authority pool limit reached",
                false,
            ));
        }
        let pool = Pool::automation(
            target.ssh_executable.to_owned(),
            target.ssh_config.map(ToOwned::to_owned),
            connect_timeout,
            self.shutdown.clone(),
            agent,
        );
        pools.insert(key.clone(), Arc::clone(&pool));
        Ok((key, pool))
    }

    fn probe_cell(&self, key: &str) -> Result<(Arc<Probe>, bool), ToolError> {
        let mut probes = lock(&self.probes);
        let expired = probes.get(key).is_some_and(|probe| {
            probe.stop.is_cancelled() || lock(&probe.result).as_ref().is_some_and(Result::is_err)
        });
        if expired {
            probes.remove(key);
        }
        if let Some(probe) = probes.get(key) {
            probe.owners.fetch_add(1, Ordering::AcqRel);
            return Ok((Arc::clone(probe), false));
        }
        if probes.len() >= 128 {
            probes.retain(|_, probe| probe.owners.load(Ordering::Acquire) > 0);
        }
        if probes.len() >= 128 {
            return Err(ToolError::resource_limit(
                "Native discovery cache limit reached",
                false,
            ));
        }
        let probe = Arc::new(Probe {
            result: Mutex::new(None),
            ready: CancellationToken::new(),
            stop: CancellationToken::new(),
            owners: AtomicUsize::new(1),
        });
        probes.insert(key.to_owned(), Arc::clone(&probe));
        Ok((probe, true))
    }

    async fn discover(
        &self,
        request: DiscoverRequest<'_>,
    ) -> Result<(Value, String, u64), ToolError> {
        let DiscoverRequest {
            key,
            lease,
            python,
            r#become,
            requirements,
            deadline,
            ct,
        } = request;
        let generation = lease.generation();
        let requirement_bytes = serde_json::to_vec(&requirements)
            .map_err(|_| ToolError::invalid_argument("Invalid requirements", false))?;
        let key = format!(
            "{}:{}:{}:{}",
            key,
            generation,
            python,
            digest(&requirement_bytes)
        );
        let (probe, launch) = self.probe_cell(&key)?;
        let _interest = Interest(Arc::clone(&probe));
        if launch {
            let worker = Arc::clone(&probe);
            let shutdown = self.shutdown.clone();
            let r#become = r#become.cloned();
            // A cancelled waiter cannot drop another waiter's owned probe/channel.
            tokio::spawn(async move {
                let _completion = ProbeCompletion(Arc::clone(&worker));
                let lease = lease;
                let id = crate::automation::execution::invocation_id();
                let spec = json!({
                    "schema": 1, "operation": "discover", "id": id,
                    "requirements": requirements,
                });
                let result = match frame(&spec, &[]) {
                    Ok(frame) => channel(ChannelRequest {
                        session: lease.session(),
                        python: &python,
                        r#become: r#become.as_ref(),
                        input: &frame,
                        limit: PROBE_LIMIT,
                        deadline: Instant::now() + Duration::from_secs(30),
                        ct: &worker.stop,
                        shutdown: &shutdown,
                    })
                    .await
                    .and_then(|out| discovery_identity(out, &id)),
                    Err(error) => Err(error),
                }
                .map_err(|mut error| {
                    // Discovery carries no payload source and cannot dispatch a mutation.
                    error.unknown = false;
                    error
                });
                drop(lease);
                *lock(&worker.result) = Some(result);
                worker.ready.cancel();
            });
        } else {
            drop(lease);
        }
        tokio::select! {
            biased;
            _ = ct.cancelled() => Err(ToolError::cancelled("Request cancelled before payload dispatch", false)),
            _ = self.shutdown.cancelled() => Err(ToolError::cancelled("Server shutting down", false)),
            _ = sleep_until(deadline) => Err(ToolError::timeout("Payload request deadline expired before dispatch", false)),
            _ = probe.ready.cancelled() => {
                match lock(&probe.result).as_ref() {
                    Some(Ok(value)) => Ok((value.clone(), key, generation)),
                    Some(Err(error)) => Err(error.tool()),
                    None => Err(ToolError::discovery_failed("Discovery evidence unavailable", false)),
                }
            }
        }
    }

    pub(crate) async fn run(&self, request: PayloadRun<'_>) -> ToolReply<AutomationData> {
        let PayloadRun {
            plan,
            host,
            authority,
            target,
            argv,
            connect_timeout,
            output_limit,
            deadline,
            ct,
            started,
        } = request;
        let operation = async {
            let (key, pool) = self.pool(host, authority, &target, connect_timeout)?;
            let candidates = interpreters(plan, &target.target.python, target.dynamic_python)?;
            let r#become = target.r#become;
            let role = if r#become.is_some() {
                crate::config::IdentityRole::Automation
            } else {
                crate::config::IdentityRole::Ordinary
            };
            let requirements = serde_json::to_value(&plan.manifest.requirements)
                .map_err(|_| ToolError::invalid_argument("Invalid requirements", false))?;
            let mut discovered = None;
            for python in candidates {
                let probe_lease = pool
                    .acquire(host, &target.target.destination, role, deadline, ct)
                    .await?;
                match self
                    .discover(DiscoverRequest {
                        key: key.clone(),
                        lease: probe_lease,
                        python: python.to_owned(),
                        r#become,
                        requirements: requirements.clone(),
                        deadline,
                        ct,
                    })
                    .await
                {
                    Ok((identity, cache_key, discovery_generation)) => {
                        discovered = Some((python, identity, cache_key, discovery_generation));
                        break;
                    }
                    Err(error)
                        if matches!(
                            error.code(),
                            "discovery_failed" | "io_error" | "connection_lost"
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            let (python, identity, cache_key, discovery_generation) =
                discovered.ok_or_else(|| {
                    ToolError::discovery_failed(
                        "Approved target interpreters or requirements are unavailable",
                        false,
                    )
                })?;
            let lease = pool
                .acquire(host, &target.target.destination, role, deadline, ct)
                .await?;
            if lease.generation() != discovery_generation {
                return Err(ToolError::discovery_failed(
                    "SSH generation changed before dispatch",
                    false,
                ));
            }
            let id = crate::automation::execution::invocation_id();
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64();
            if remaining <= 0.0 {
                return Err(ToolError::timeout(
                    "Payload deadline expired before dispatch",
                    false,
                ));
            }
            let spec = json!({
                "schema": 1, "operation": "execute", "id": id,
                "requirements": requirements, "identity": identity,
                "sha256": plan.manifest.source_sha256, "argv": argv,
                "timeout": remaining.min(600.0), "output_limit": output_limit,
            });
            let input = frame(&spec, &plan.source).map_err(Failure::tool)?;
            let out = channel(ChannelRequest {
                session: lease.session(),
                python,
                r#become,
                input: &input,
                limit: output_limit.saturating_mul(6).saturating_add(PROBE_LIMIT),
                deadline,
                ct,
                shutdown: &self.shutdown,
            })
            .await
            .map_err(Failure::tool)?;
            let decoded = terminal(out, &id);
            if decoded
                .as_ref()
                .err()
                .is_some_and(|error| error.code() == "payload_rejected")
            {
                // A requirements lookup can fail before identity comparison is possible.
                lock(&self.probes).remove(&cache_key);
            }
            decoded
        }
        .await;

        match operation {
            Err(error) => {
                let status = match error.code() {
                    "cancelled" => AutomationStatus::Cancelled,
                    "timeout" => AutomationStatus::Timeout,
                    "invalid_result" => AutomationStatus::InvalidResult,
                    _ if error.remote_state_unknown => AutomationStatus::WorkerLost,
                    _ => AutomationStatus::NotStarted,
                };
                let data = AutomationData {
                    host: host.to_owned(),
                    status,
                    runner_rc: None,
                    changed: None,
                    tasks: AutomationTasks::default(),
                    censored: plan.no_log,
                    complete: false,
                    duration_ms: elapsed(started),
                    owned_group_cleanup: GroupCleanup::NotApplicable,
                    projection: None,
                };
                ToolReply::partial(data, error)
            }
            Ok((rc, value, output_status)) => complete_reply(
                host,
                plan.no_log,
                &plan.manifest.change_policy,
                plan.projection.as_deref(),
                rc,
                &value,
                output_status,
                started,
            ),
        }
    }

    pub(crate) async fn observe_preview_prestate(
        &self,
        request: PreviewPrestateRequest<'_>,
    ) -> Result<[u8; 32], ToolError> {
        let PreviewPrestateRequest {
            host,
            authority,
            target,
            module,
            arguments,
            connect_timeout,
            deadline,
            ct,
        } = request;
        let (_, pool) = self.pool(host, authority, target, connect_timeout)?;
        let role = if target.r#become.is_some() {
            crate::config::IdentityRole::Automation
        } else {
            crate::config::IdentityRole::Ordinary
        };
        let lease = pool
            .acquire(host, &target.target.destination, role, deadline, ct)
            .await?;
        let python = if !target.target.python.is_empty() {
            target.target.python.as_str()
        } else if target.dynamic_python {
            "python3"
        } else {
            return Err(ToolError::preview_required(
                "Independent pre-state probe interpreter is unavailable",
                false,
            ));
        };
        let payload = serde_json::to_vec(&json!({
            "module": module,
            "arguments": arguments,
        }))
        .map_err(|_| ToolError::preview_required("Invalid pre-state request", false))?;
        let r#become = target.r#become;
        let shutdown = &self.shutdown;
        let operation = async {
            let mut command = if let Some(AutomationBecome::Sudo { user, executable }) = r#become {
                let mut command = lease.session().command(executable);
                command.args(["-H", "-n", "-k", "-u", user, "--", python]);
                command
            } else {
                lease.session().command(python)
            };
            command
                .args(["-I", "-c", PRESTATE])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().await.map_err(|_| {
                ToolError::preview_required("Independent pre-state probe could not spawn", false)
            })?;
            let mut stdin = child.stdin().take().ok_or_else(|| {
                ToolError::preview_required("Independent pre-state probe pipe unavailable", false)
            })?;
            let stdout = child.stdout().take().ok_or_else(|| {
                ToolError::preview_required("Independent pre-state probe output unavailable", false)
            })?;
            let stderr = child.stderr().take().ok_or_else(|| {
                ToolError::preview_required(
                    "Independent pre-state probe error pipe unavailable",
                    false,
                )
            })?;
            let (out, err, write) = tokio::join!(
                bounded(stdout, PROBE_LIMIT),
                bounded(stderr, 0),
                async move {
                    stdin.write_all(&payload).await?;
                    stdin.shutdown().await
                }
            );
            let (stdout, overflow) = out.map_err(|_| {
                ToolError::preview_required("Independent pre-state probe read failed", false)
            })?;
            let _ = err;
            write.map_err(|_| {
                ToolError::preview_required("Independent pre-state probe input failed", false)
            })?;
            let status = child.wait().await.map_err(|_| {
                ToolError::preview_required("Independent pre-state probe exit failed", false)
            })?;
            if !status.success() || overflow || parse(&stdout).is_err() {
                return Err(ToolError::preview_required(
                    "Independent pre-state digest could not be obtained",
                    false,
                ));
            }
            Ok(<sha2::Sha256 as sha2::Digest>::digest(&stdout).into())
        };
        tokio::select! {
            biased;
            _ = ct.cancelled() => Err(ToolError::cancelled("Request cancelled before preview pre-state probe", false)),
            _ = shutdown.cancelled() => Err(ToolError::cancelled("Server shutting down", false)),
            _ = sleep_until(deadline) => Err(ToolError::timeout("Request deadline exceeded during preview pre-state probe", false)),
            result = operation => result,
        }
    }
}

fn interpreters<'a>(
    plan: &'a PayloadPlan,
    configured: &'a str,
    dynamic_python: bool,
) -> Result<Vec<&'a str>, ToolError> {
    if !configured.is_empty() {
        if !configured.starts_with('/') || configured.contains('\0') {
            return Err(ToolError::discovery_failed(
                "An approved absolute target interpreter is required",
                false,
            ));
        }
        return Ok(vec![configured]);
    }
    let fixed = plan
        .manifest
        .approval
        .overlay
        .get("fixed_args")
        .and_then(|arguments| arguments.get("target_python"));
    let mut candidates: Vec<&str> = Vec::new();
    if let Some(fixed) = fixed {
        let fixed = fixed.as_str().ok_or_else(|| {
            ToolError::discovery_failed("Invalid approved collector interpreter", false)
        })?;
        candidates.push(fixed);
    }
    if dynamic_python || fixed.is_none() {
        for interpreter in &plan.manifest.requirements.interpreters {
            if !candidates.contains(&interpreter.as_str()) {
                candidates.push(interpreter.as_str());
            }
        }
    }
    if dynamic_python {
        for fallback in [
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/run/current-system/sw/bin/python3",
            "python3",
        ] {
            if !candidates.contains(&fallback) {
                candidates.push(fallback);
            }
        }
    }
    if candidates.is_empty()
        || candidates.iter().any(|path| {
            path.is_empty()
                || path.contains('\0')
                || (!path.starts_with('/') && !(dynamic_python && *path == "python3"))
        })
    {
        return Err(ToolError::discovery_failed(
            "An approved absolute target interpreter is required",
            false,
        ));
    }
    Ok(candidates)
}

fn discovery_identity(out: Output, id: &str) -> Result<Value, Failure> {
    if out.rc != 0 || out.overflow {
        return Err(failed(
            ToolError::discovery_failed,
            "Target requirements are unavailable",
            false,
        ));
    }
    let value = parse(&out.stdout).map_err(|_| {
        failed(
            ToolError::discovery_failed,
            "Invalid discovery evidence",
            false,
        )
    })?;
    if value.get("schema").and_then(Value::as_u64) != Some(1)
        || value.get("id").and_then(Value::as_str) != Some(id)
        || value.get("phase").and_then(Value::as_str) != Some("discovered")
    {
        return Err(failed(
            ToolError::discovery_failed,
            "Invalid discovery evidence",
            false,
        ));
    }
    value
        .get("identity")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            failed(
                ToolError::discovery_failed,
                "Missing discovery identity",
                false,
            )
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputStatus {
    Complete,
    Overflow,
    InvalidUtf8,
}

#[allow(clippy::too_many_arguments)]
fn complete_reply(
    host: &str,
    no_log: bool,
    change_policy: &crate::native_payload::ChangePolicy,
    projection_plan: Option<&crate::contracts::projection::Plan>,
    rc: i32,
    value: &Value,
    output_status: OutputStatus,
    started: std::time::Instant,
) -> ToolReply<AutomationData> {
    // Censor before domain parsing/publication, including changed evidence.
    let domain = if !no_log && output_status == OutputStatus::Complete {
        value
            .get("stdout")
            .and_then(Value::as_str)
            .and_then(|stdout| parse(stdout.as_bytes()).ok())
    } else {
        None
    };
    let failure_reason = if !no_log && rc != 0 {
        domain
            .as_ref()
            .and_then(|doc| doc.get("estus_error"))
            .and_then(|err| err.get("code"))
            .and_then(Value::as_str)
            .and_then(crate::reply::PayloadFailureReason::from_code)
            .or_else(|| {
                value
                    .get("error_reason")
                    .and_then(Value::as_str)
                    .and_then(crate::reply::PayloadFailureReason::from_code)
            })
    } else {
        None
    };
    let mut error = (rc != 0).then(|| match failure_reason {
        Some(reason) => ToolError::payload_failed_with_reason(reason, false),
        None => ToolError::payload_failed("Payload operation completed with failure", false),
    });
    let changed = if no_log {
        None
    } else {
        change_policy.evidence(rc, domain.as_ref())
    };
    if !no_log && error.is_none() {
        match output_status {
            OutputStatus::Overflow => {
                error = Some(crate::reply::ToolError::resource_limit(
                    "Payload output exceeded retention limit",
                    false,
                ));
            }
            OutputStatus::InvalidUtf8 => {
                error = Some(crate::reply::ToolError::invalid_projection(
                    "Payload output was not valid UTF-8",
                    false,
                ));
            }
            OutputStatus::Complete => {}
        }
    }
    let projection = projection_plan.map(|projection| {
        if no_log {
            return ModuleProjection::Censored;
        }
        match output_status {
            OutputStatus::Overflow => ModuleProjection::Unavailable,
            OutputStatus::InvalidUtf8 => ModuleProjection::Invalid,
            OutputStatus::Complete => {
                if rc != 0 {
                    return ModuleProjection::Unavailable;
                }
                match domain
                    .as_ref()
                    .and_then(|result| project(projection, result))
                {
                    Some(value) => ModuleProjection::Complete { value },
                    None => {
                        if error.is_none() {
                            error = Some(crate::reply::ToolError::invalid_projection(
                                "Payload output violates approved projection",
                                false,
                            ));
                        }
                        ModuleProjection::Invalid
                    }
                }
            }
        }
    });
    let data = AutomationData {
        host: host.to_owned(),
        status: if rc == 0 {
            AutomationStatus::Successful
        } else {
            AutomationStatus::Failed
        },
        runner_rc: Some(rc),
        changed,
        tasks: AutomationTasks {
            ok: u32::from(rc == 0),
            failed: u32::from(rc != 0),
            ..Default::default()
        },
        censored: no_log,
        complete: true,
        duration_ms: elapsed(started),
        owned_group_cleanup: GroupCleanup::NotApplicable,
        projection,
    };
    ToolReply::with_optional_error(data, error)
}

/// A bootstrap terminal record and its SSH exit status must agree independently.
fn terminal(out: Output, id: &str) -> Result<(i32, Value, OutputStatus), ToolError> {
    let invalid = || {
        ToolError::invalid_result(
            "Payload terminal evidence is invalid; remote state is unknown",
            true,
        )
    };
    let value = parse(&out.stdout).map_err(|_| invalid())?;
    if out.overflow
        || value.get("schema").and_then(Value::as_u64) != Some(1)
        || value.get("id").and_then(Value::as_str) != Some(id)
    {
        return Err(invalid());
    }
    match (value.get("phase").and_then(Value::as_str), out.rc) {
        (Some("rejected"), 70) => {
            return Err(ToolError::payload_rejected(
                "Payload rejected before execution; identity or requirements changed",
                false,
            ));
        }
        (Some("timeout"), 124) => {
            return Err(ToolError::timeout(
                "Payload deadline exceeded; remote descendants may continue",
                true,
            ));
        }
        (Some("cancelled"), 125) => {
            return Err(ToolError::cancelled(
                "Payload cancelled; remote descendants may continue",
                true,
            ));
        }
        (Some("complete"), _) => (),
        _ => return Err(invalid()),
    }
    let rc = value
        .get("rc")
        .and_then(Value::as_i64)
        .and_then(|rc| i32::try_from(rc).ok())
        .ok_or_else(invalid)?;
    if out.rc != if rc == 0 { 0 } else { 1 } {
        return Err(invalid());
    }
    let overflow = value
        .get("overflow")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    let output_status = match value.get("output_status").and_then(Value::as_str) {
        Some("complete") if !overflow && value.get("stdout").and_then(Value::as_str).is_some() => {
            OutputStatus::Complete
        }
        Some("overflow") if overflow => OutputStatus::Overflow,
        Some("invalid_utf8") if !overflow => OutputStatus::InvalidUtf8,
        _ => return Err(invalid()),
    };
    Ok((rc, value, output_status))
}

fn elapsed(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn project(plan: &crate::contracts::projection::Plan, result: &Value) -> Option<Value> {
    let mut selected = serde_json::Map::new();
    for (name, path) in &plan.fields {
        // Existing catalog contracts use the role's virtual mcp_result envelope.
        // Native collectors emit that domain object directly; no clone is needed.
        let path = if path.first().map(String::as_str) == Some("mcp_result") {
            &path[1..]
        } else {
            path.as_slice()
        };
        let mut value = Some(result);
        for segment in path {
            value = value.and_then(|value| value.get(segment));
        }
        if let Some(value) = value {
            selected.insert(name.clone(), value.clone());
        }
    }
    let value = Value::Object(selected);
    plan.validate_value(&value).ok()?;
    Some(value)
}

struct Frame<'a> {
    header: Vec<u8>,
    source: &'a [u8],
}

fn frame<'a>(spec: &Value, source: &'a [u8]) -> Result<Frame<'a>, Failure> {
    let data = serde_json::to_vec(spec)
        .map_err(|_| failed(ToolError::invalid_argument, "Invalid payload frame", false))?;
    if data.len() > MAX_INPUT || source.len() > super::MAX_SOURCE {
        return Err(failed(
            ToolError::resource_limit,
            "Payload frame exceeds bounds",
            false,
        ));
    }
    let mut header = Vec::with_capacity(16 + data.len());
    header.extend_from_slice(b"ESTUSNP1");
    header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    header.extend_from_slice(&(source.len() as u32).to_be_bytes());
    header.extend_from_slice(&data);
    Ok(Frame { header, source })
}

struct Output {
    stdout: Vec<u8>,
    overflow: bool,
    rc: i32,
}

async fn bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let keep = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..keep]);
        overflow |= count > keep;
    }
    Ok((bytes, overflow))
}

pub(crate) struct PayloadRun<'a> {
    pub(crate) plan: &'a PayloadPlan,
    pub(crate) host: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) target: ResolvedAutomation<'a>,
    pub(crate) argv: Vec<String>,
    pub(crate) connect_timeout: Duration,
    pub(crate) output_limit: usize,
    pub(crate) deadline: Instant,
    pub(crate) ct: &'a CancellationToken,
    pub(crate) started: std::time::Instant,
}

pub(crate) struct PreviewPrestateRequest<'a> {
    pub(crate) host: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) target: &'a ResolvedAutomation<'a>,
    pub(crate) module: &'a str,
    pub(crate) arguments: &'a Value,
    pub(crate) connect_timeout: Duration,
    pub(crate) deadline: Instant,
    pub(crate) ct: &'a CancellationToken,
}

struct DiscoverRequest<'a> {
    key: String,
    lease: Lease,
    python: String,
    r#become: Option<&'a AutomationBecome>,
    requirements: Value,
    deadline: Instant,
    ct: &'a CancellationToken,
}

struct ChannelRequest<'a> {
    session: &'a Session,
    python: &'a str,
    r#become: Option<&'a AutomationBecome>,
    input: &'a Frame<'a>,
    limit: usize,
    deadline: Instant,
    ct: &'a CancellationToken,
    shutdown: &'a CancellationToken,
}

async fn channel(request: ChannelRequest<'_>) -> Result<Output, Failure> {
    let ChannelRequest {
        session,
        python,
        r#become,
        input,
        limit,
        deadline,
        ct,
        shutdown,
    } = request;
    let operation = async {
        let mut command = if let Some(AutomationBecome::Sudo { user, executable }) = r#become {
            let mut command = session.command(executable);
            command.args(["-H", "-n", "-k", "-u", user, "--", python]);
            command
        } else {
            session.command(python)
        };
        command
            .args(["-I", "-c", BOOTSTRAP])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().await.map_err(|_| {
            failed(
                ToolError::connection_lost,
                "Payload channel failed; remote state is unknown",
                true,
            )
        })?;
        let mut stdin = child
            .stdin()
            .take()
            .ok_or_else(|| failed(ToolError::io_error, "Missing payload input pipe", true))?;
        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| failed(ToolError::io_error, "Missing payload output pipe", true))?;
        let stderr = child
            .stderr()
            .take()
            .ok_or_else(|| failed(ToolError::io_error, "Missing payload error pipe", true))?;
        let (out, err, write) =
            tokio::join!(bounded(stdout, limit), bounded(stderr, 0), async move {
                stdin.write_all(&input.header).await?;
                stdin.write_all(input.source).await?;
                stdin.shutdown().await
            },);
        let (stdout, overflow) = out.map_err(|_| {
            failed(
                ToolError::io_error,
                "Payload output failed; remote state is unknown",
                true,
            )
        })?;
        err.map_err(|_| {
            failed(
                ToolError::io_error,
                "Payload error stream failed; remote state is unknown",
                true,
            )
        })?;
        write.map_err(|_| {
            failed(
                ToolError::io_error,
                "Payload input failed; remote state is unknown",
                true,
            )
        })?;
        let status = child.wait().await.map_err(|_| {
            failed(
                ToolError::connection_lost,
                "Payload channel lost; remote state is unknown",
                true,
            )
        })?;
        let rc = status.code().ok_or_else(|| {
            failed(
                ToolError::connection_lost,
                "Payload exit unavailable; remote state is unknown",
                true,
            )
        })?;
        Ok(Output {
            stdout,
            overflow,
            rc,
        })
    };
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(failed(ToolError::cancelled, "Payload cancelled; remote execution may continue", true)),
        _ = shutdown.cancelled() => Err(failed(ToolError::cancelled, "Server stopped; remote execution may continue", true)),
        _ = sleep_until(deadline) => Err(failed(ToolError::timeout, "Payload deadline exceeded; remote execution may continue", true)),
        result = operation => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_preserves_source_and_data() {
        let source = b"print('immutable')\n";
        let frame = frame(&json!({"literal":"{{ x }};\n"}), source)
            .unwrap_or_else(|_| panic!("frame rejected"));
        assert_eq!(&frame.header[..8], b"ESTUSNP1");
        assert_eq!(frame.source, source);
        assert_eq!(frame.source.as_ptr(), source.as_ptr());
        assert!(super::frame(&json!({}), &vec![0; super::super::MAX_SOURCE + 1]).is_err());
    }

    #[test]
    fn last_waiter_owns_probe_cancellation() {
        let probe = Arc::new(Probe {
            result: Mutex::new(None),
            ready: CancellationToken::new(),
            stop: CancellationToken::new(),
            owners: AtomicUsize::new(2),
        });
        let first = Interest(probe.clone());
        let second = Interest(probe.clone());
        drop(first);
        assert!(!probe.stop.is_cancelled());
        drop(second);
        assert!(probe.stop.is_cancelled());
    }

    #[tokio::test]
    async fn overflow_drains_without_accepting_prefix() {
        let (out, overflow) = bounded(b"{\"ok\":true}trailing".as_slice(), 11)
            .await
            .unwrap();
        assert!(overflow);
        assert_eq!(out, b"{\"ok\":true}");
    }

    #[test]
    fn shared_probe_positive_only_and_generation_separation() {
        let engine = Engine::new(CancellationToken::new());
        let (first, launch) = engine
            .probe_cell("host:authority:generation1:python:requirements")
            .unwrap();
        assert!(launch);
        let (second, launch) = engine
            .probe_cell("host:authority:generation1:python:requirements")
            .unwrap();
        assert!(!launch);
        assert!(Arc::ptr_eq(&first, &second));
        *lock(&first.result) = Some(Ok(json!({"uid":0})));
        first.ready.cancel();
        drop(Interest(first.clone()));
        drop(Interest(second));
        let (cached, launch) = engine
            .probe_cell("host:authority:generation1:python:requirements")
            .unwrap();
        assert!(!launch);
        assert!(Arc::ptr_eq(&first, &cached));
        let (different, launch) = engine
            .probe_cell("host:authority:generation2:python:requirements")
            .unwrap();
        assert!(launch);
        assert!(!Arc::ptr_eq(&first, &different));
        *lock(&different.result) = Some(Err(failed(
            ToolError::discovery_failed,
            "Unavailable",
            false,
        )));
        different.ready.cancel();
        drop(Interest(different.clone()));
        let (retry, launch) = engine
            .probe_cell("host:authority:generation2:python:requirements")
            .unwrap();
        assert!(launch);
        assert!(!Arc::ptr_eq(&different, &retry));
        drop(Interest(cached));
        drop(Interest(retry));
    }

    #[test]
    fn authority_destination_and_host_have_distinct_pools() {
        let engine = Engine::new(CancellationToken::new());
        let target = crate::config::AutomationTarget {
            destination: "approved-automation-destination".into(),
            python: "/usr/bin/python3".into(),
        };
        let resolved = crate::config::ResolvedAutomation {
            target: std::borrow::Cow::Borrowed(&target),
            ssh_config: None,
            ssh_executable: std::path::Path::new("/usr/bin/ssh"),
            r#become: None,
            agent: crate::config::AutomationAgent::Disabled,
            dynamic_python: false,
        };
        let (_, first) = engine
            .pool("logical-a", "automation", &resolved, Duration::from_secs(1))
            .unwrap();
        let (_, same) = engine
            .pool("logical-a", "automation", &resolved, Duration::from_secs(1))
            .unwrap();
        let (_, other) = engine
            .pool(
                "logical-a",
                "automation:catalog",
                &resolved,
                Duration::from_secs(1),
            )
            .unwrap();
        let (_, host) = engine
            .pool("logical-b", "automation", &resolved, Duration::from_secs(1))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));
        assert!(!Arc::ptr_eq(&first, &host));
    }

    #[test]
    fn optional_projection_members_and_virtual_wrapper() {
        let mut plan = crate::contracts::projection::Plan {
            fields: std::collections::BTreeMap::from([
                ("required".into(), vec!["present".into()]),
                ("optional".into(), vec!["absent".into()]),
            ]),
            schema: json!({
                "type":"object", "additionalProperties":false, "required":["required"],
                "properties":{"required":{"type":"boolean"},"optional":{"type":"boolean"}},
            }),
            max_bytes: 1024,
            max_items: 16,
            max_depth: 4,
        };
        assert_eq!(
            project(&plan, &json!({"present":true})),
            Some(json!({"required":true}))
        );
        assert!(project(&plan, &json!({})).is_none());
        plan.fields
            .get_mut("required")
            .unwrap()
            .insert(0, "mcp_result".into());
        assert_eq!(
            project(&plan, &json!({"present":true})),
            Some(json!({"required":true}))
        );
    }

    #[test]
    fn interruption_terminals_remain_unknown_and_require_matching_exit() {
        for (phase, rc, code) in [("timeout", 124, "timeout"), ("cancelled", 125, "cancelled")] {
            let stdout =
                serde_json::to_vec(&json!({"schema":1,"id":"owned","phase":phase})).unwrap();
            let error = terminal(
                Output {
                    stdout: stdout.clone(),
                    overflow: false,
                    rc,
                },
                "owned",
            )
            .unwrap_err();
            assert_eq!(error.code(), code);
            assert!(error.remote_state_unknown);
            let error = terminal(
                Output {
                    stdout,
                    overflow: false,
                    rc: 1,
                },
                "owned",
            )
            .unwrap_err();
            assert_eq!(error.code(), "invalid_result");
        }
    }
    #[test]
    fn overflow_and_invalid_utf8_preserve_completion_without_remote_state_unknown() {
        let plan = crate::contracts::projection::compile(json!({
            "fields": {"ok": ["ok"]},
            "schema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["ok"],
                "properties": {"ok": {"type": "boolean"}}
            },
            "max_bytes": 1024,
            "max_items": 16,
            "max_depth": 4
        }))
        .unwrap();
        for (status_str, overflow, expected_status, expected_code, expected_proj) in [
            (
                "overflow",
                true,
                OutputStatus::Overflow,
                "resource_limit",
                "unavailable",
            ),
            (
                "invalid_utf8",
                false,
                OutputStatus::InvalidUtf8,
                "invalid_projection",
                "invalid",
            ),
        ] {
            for (rc, ssh_rc) in [(0, 0), (3, 1)] {
                let stdout = serde_json::to_vec(&json!({
                    "schema": 1,
                    "id": "owned",
                    "phase": "complete",
                    "rc": rc,
                    "overflow": overflow,
                    "output_status": status_str,
                }))
                .unwrap();
                let (parsed_rc, value, parsed_status) = terminal(
                    Output {
                        stdout,
                        overflow: false,
                        rc: ssh_rc,
                    },
                    "owned",
                )
                .unwrap();
                assert_eq!(parsed_rc, rc);
                assert_eq!(parsed_status, expected_status);

                let reply = complete_reply(
                    "host-a",
                    false,
                    &crate::native_payload::ChangePolicy::ReportedChanged,
                    Some(&plan),
                    parsed_rc,
                    &value,
                    parsed_status,
                    std::time::Instant::now(),
                );
                let data = reply.data().unwrap();
                assert!(data.complete);
                assert_eq!(data.runner_rc, Some(rc));
                assert_eq!(data.changed, None);
                let proj_json = serde_json::to_value(&data.projection).unwrap();
                assert_eq!(proj_json["status"], expected_proj);
                let err = reply.error().unwrap();
                assert!(!err.remote_state_unknown);
                assert_eq!(
                    err.code(),
                    if rc == 0 {
                        expected_code
                    } else {
                        "payload_failed"
                    }
                );
            }
        }
        let censored = complete_reply(
            "host-a",
            true,
            &crate::native_payload::ChangePolicy::MutationSuccess,
            Some(&plan),
            0,
            &json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": true, "output_status": "overflow"}),
            OutputStatus::Overflow,
            std::time::Instant::now(),
        );
        assert!(censored.error().is_none());
        let censored_data = censored.data().unwrap();
        assert!(censored_data.complete);
        assert_eq!(censored_data.runner_rc, Some(0));
        assert_eq!(censored_data.changed, None);
        assert_eq!(
            serde_json::to_value(&censored_data.projection).unwrap()["status"],
            "censored"
        );
    }

    #[test]
    fn terminal_rejects_mismatched_overflow_or_unknown_output_status() {
        for bad in [
            json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": false}),
            json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": false, "output_status": "complete"}),
            json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": false, "output_status": "overflow"}),
            json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": true, "output_status": "invalid_utf8"}),
            json!({"schema": 1, "id": "owned", "phase": "complete", "rc": 0, "overflow": false, "output_status": "unknown"}),
        ] {
            let err = terminal(
                Output {
                    stdout: serde_json::to_vec(&bad).unwrap(),
                    overflow: false,
                    rc: 0,
                },
                "owned",
            )
            .unwrap_err();
            assert_eq!(err.code(), "invalid_result");
        }
    }

    #[test]
    fn configured_target_python_takes_precedence_over_template_default() {
        let mut manifest = super::super::Manifest {
            approved: true,
            manifest_sha256: String::new(),
            schema: 1,
            protocol: 1,
            adapter_version: 1,
            change_policy: super::super::ChangePolicy::ReadOnly,
            source_sha256: "0".repeat(64),
            max_source_bytes: 4096,
            argv: Vec::new(),
            requirements: super::super::Requirements {
                python_min: [3, 8],
                interpreters: vec!["/usr/local/bin/python3".into()],
                modules: Vec::new(),
                executables: Vec::new(),
                paths: Vec::new(),
                executable_candidates: Default::default(),
            },
            contract: json!({
                "schema": {
                    "type": "object",
                    "properties": {"target_python": {"type": "string"}},
                    "required": ["target_python"],
                    "additionalProperties": false
                },
                "aliases": {"aliases": {}, "properties": {"target_python": {"aliases": {}, "properties": {}}}},
                "defaults": {},
                "review_required": ["test"]
            }),
            approval: super::super::Approval {
                overlay: json!({"fixed_args": {"target_python": "/usr/bin/python3"}}),
                result: json!({"kind": "capability_projection"}),
                authority: "automation".into(),
                no_log: false,
                revision: "1".into(),
            },
        };
        manifest.manifest_sha256 = "0".repeat(64);
        let plan = PayloadPlan {
            manifest,
            source: Arc::from(b"# empty\n".as_slice()),
            binding: crate::contracts::module_schema::compile_binding(
                &json!({
                    "schema": {
                        "type": "object",
                        "properties": {"target_python": {"type": "string"}},
                        "required": ["target_python"],
                        "additionalProperties": false
                    },
                    "aliases": {"aliases": {}, "properties": {"target_python": {"aliases": {}, "properties": {}}}},
                    "defaults": {},
                    "review_required": ["test"]
                }),
                &json!({"input_schema":{"type":"object","properties":{},"required":[],"additionalProperties":false},"fixed_args":{"target_python":"/usr/bin/python3"},"input_map":{}}),
            )
            .unwrap(),
            no_log: false,
            projection: None,
        };
        assert_eq!(
            interpreters(&plan, "/opt/site/bin/python3", false).unwrap(),
            vec!["/opt/site/bin/python3"]
        );
        assert_eq!(
            interpreters(&plan, "", false).unwrap(),
            vec!["/usr/bin/python3"]
        );
        let dynamic = interpreters(&plan, "", true).unwrap();
        assert_eq!(dynamic[0], "/usr/bin/python3");
        assert!(dynamic.contains(&"/usr/local/bin/python3"));
        assert!(dynamic.contains(&"python3"));
    }

    #[test]
    fn structured_failure_reason_maps_closed_codes_and_respects_no_log() {
        let explicit = complete_reply(
            "host-a",
            false,
            &crate::native_payload::ChangePolicy::ReadOnly,
            None,
            1,
            &json!({"stdout": "{\"estus_error\":{\"code\":\"verification_failed\"}}"}),
            OutputStatus::Complete,
            std::time::Instant::now(),
        );
        let err = explicit.error().unwrap();
        assert_eq!(err.code(), "payload_failed");
        assert_eq!(
            err.reason,
            Some(crate::reply::PayloadFailureReason::VerificationFailed)
        );
        assert_eq!(
            err.message,
            "Payload operation failed: post-mutation verification failed"
        );

        let classified = complete_reply(
            "host-a",
            false,
            &crate::native_payload::ChangePolicy::ReadOnly,
            None,
            1,
            &json!({"stdout": "", "error_reason": "permission_denied"}),
            OutputStatus::Complete,
            std::time::Instant::now(),
        );
        assert_eq!(
            classified.error().unwrap().reason,
            Some(crate::reply::PayloadFailureReason::PermissionDenied)
        );

        let censored = complete_reply(
            "host-a",
            true,
            &crate::native_payload::ChangePolicy::ReadOnly,
            None,
            1,
            &json!({"stdout": "{\"estus_error\":{\"code\":\"verification_failed\"}}", "error_reason": "permission_denied"}),
            OutputStatus::Complete,
            std::time::Instant::now(),
        );
        assert_eq!(censored.error().unwrap().reason, None);
        assert_eq!(
            censored.error().unwrap().message,
            "Payload operation completed with failure"
        );
    }
}
