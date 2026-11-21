use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use openssh::{Session, Stdio};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use super::{MAX_INPUT, PayloadPlan};
use crate::{
    config::{AutomationAgent, AutomationBecome, ResolvedAutomation},
    reply::{
        AutomationData, AutomationStatus, AutomationTasks, ErrorCode, GroupCleanup,
        ModuleProjection, ToolError, ToolReply,
    },
    ssh::Pool,
    strict_json::parse,
};

const BOOTSTRAP: &str = include_str!("bootstrap.py");
const PRESTATE: &str = include_str!("prestate.py");
const STAGE0_LOADER: &str = "import struct,sys;b=sys.stdin.buffer;h=b.read(4);n,=struct.unpack('!I',h);s=b.read(n);assert len(s)==n;exec(compile(s,'<estus>','exec'),{'__name__':'__main__'})";
const OUTPUT_HEADROOM: usize = 65_536;
/// Prints only the package manager family a bundle router needs. Self-contained so
/// it needs no frame, no request values and no imports from the payload protocol.
const PKG_MGR: &str = r#"import os,sys
p='unknown'
if os.path.exists('/run/ostree-booted'):
    p='atomic_container'
else:
    r=''
    try:
        r=open('/etc/os-release',encoding='utf-8',errors='replace').read(8192).lower()
    except OSError:
        pass
    if ('id=debian' in r or 'id=ubuntu' in r) and os.path.exists('/usr/bin/apt-get'):
        p='apt'
    elif os.path.exists('/usr/bin/dnf') or os.path.exists('/usr/bin/microdnf'):
        p='dnf5' if os.path.realpath('/usr/bin/dnf').endswith('/dnf5') else 'dnf'
    else:
        for path,mgr in (('/usr/bin/apt-get','apt'),('/usr/bin/yum','dnf'),('/usr/bin/zypper','zypper'),('/sbin/apk','apk'),('/usr/bin/apk','apk'),('/usr/bin/pacman','pacman')):
            if os.path.exists(path):
                p=mgr
                break
sys.stdout.write(p)
"#;
const MAX_BUNDLE_FRAME: usize = 4 * 1024 * 1024;

pub(crate) fn invocation_id() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::fill(&mut bytes);
    hex::encode(bytes)
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy)]
struct Failure {
    code: ErrorCode,
    message: &'static str,
    unknown: bool,
}

impl Failure {
    fn into_tool(self) -> ToolError {
        ToolError::new(self.code, self.message, self.unknown)
    }

    fn into_code(self) -> ErrorCode {
        self.code
    }
}

/// One engine belongs to one activated config generation, never a process-global pool.
pub(crate) struct Engine {
    shared_pool: Option<Arc<Pool>>,
    pools: Mutex<HashMap<String, Arc<Pool>>>,
    shutdown: CancellationToken,
    // Headless deployments pin SSH trust; workstation mode leaves it to the operator.
    headless: bool,
}

impl Engine {
    #[cfg(test)]
    pub(crate) fn new(shutdown: CancellationToken) -> Arc<Self> {
        Self::new_with_shared_pool(shutdown, None, false)
    }

    pub(crate) fn new_with_shared_pool(
        shutdown: CancellationToken,
        shared_pool: Option<Arc<Pool>>,
        headless: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            shared_pool,
            pools: Mutex::new(HashMap::new()),
            shutdown,
            headless,
        })
    }
    pub(crate) async fn shutdown(&self) {
        let pools: Vec<_> = lock(&self.pools).values().cloned().collect();
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
    ) -> Result<Arc<Pool>, ToolError> {
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
        .map_err(|_| {
            ToolError::new(
                ErrorCode::InvalidArgument,
                "Invalid transport identity",
                false,
            )
        })?;
        if matches!(target.agent, AutomationAgent::Inherit)
            && let Some(shared) = &self.shared_pool
            && shared.matches_native_transport(target.ssh_executable, target.ssh_config)
        {
            return Ok(Arc::clone(shared));
        }
        let mut pools = lock(&self.pools);
        if let Some(pool) = pools.get(&key) {
            return Ok(Arc::clone(pool));
        }
        if pools.len() >= 16 {
            return Err(ToolError::new(
                ErrorCode::ResourceLimit,
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
            self.headless,
        );
        pools.insert(key, Arc::clone(&pool));
        Ok(pool)
    }

    /// Resolve the target package manager for a router module.
    ///
    /// This is deliberately uncached: it runs immediately before dispatch and
    /// nothing about the answer survives the call, so a rebuilt target image is
    /// observed by the very next request.
    #[allow(clippy::too_many_arguments)]
    async fn package_manager(
        &self,
        pool: &Arc<Pool>,
        host: &str,
        destination: &str,
        role: crate::config::IdentityRole,
        candidates: &[&str],
        r#become: Option<&AutomationBecome>,
        deadline: Instant,
        ct: &CancellationToken,
    ) -> Result<String, ToolError> {
        let lease = pool.acquire(host, destination, role, deadline, ct).await?;
        let operation = async {
            let mut last = None;
            for python in candidates {
                let mut command =
                    if let Some(AutomationBecome::Sudo { user, executable }) = r#become {
                        let mut command = lease.session().command(executable);
                        command.args(["-H", "-n", "-k", "-u", user, "--", python]);
                        command
                    } else {
                        lease.session().command(*python)
                    };
                command
                    .args(["-I", "-c", PKG_MGR])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let Ok(mut child) = command.spawn().await else {
                    continue;
                };
                let Some(stdout) = child.stdout().take() else {
                    continue;
                };
                let Some(stderr) = child.stderr().take() else {
                    continue;
                };
                let (out, err) = tokio::join!(bounded(stdout, 64), bounded(stderr, 0));
                let (stdout, overflow) = out.map_err(|_| {
                    ToolError::new(
                        ErrorCode::ResourceUnavailable,
                        "Package manager probe failed",
                        false,
                    )
                })?;
                let _ = err;
                let status = child.wait().await.map_err(|_| {
                    ToolError::new(
                        ErrorCode::ResourceUnavailable,
                        "Package manager probe failed",
                        false,
                    )
                })?;
                if !status.success() || overflow {
                    last = Some(ToolError::new(
                        ErrorCode::ResourceUnavailable,
                        "Target package manager is unavailable",
                        false,
                    ));
                    continue;
                }
                let name = String::from_utf8_lossy(&stdout);
                let name = name.trim();
                if name.is_empty() || name.len() > 32 {
                    last = Some(ToolError::new(
                        ErrorCode::ResourceUnavailable,
                        "Target package manager is unavailable",
                        false,
                    ));
                    continue;
                }
                return Ok(name.to_owned());
            }
            Err(last.unwrap_or_else(|| {
                ToolError::new(
                    ErrorCode::ResourceUnavailable,
                    "Target package manager is unavailable",
                    false,
                )
            }))
        };
        tokio::select! {
            biased;
            _ = ct.cancelled() => Err(ToolError::new(ErrorCode::Cancelled, "Request cancelled before package manager probe", false)),
            _ = self.shutdown.cancelled() => Err(ToolError::new(ErrorCode::Cancelled, "Server shutting down", false)),
            _ = sleep_until(deadline) => Err(ToolError::new(ErrorCode::Timeout, "Request deadline exceeded during package manager probe", false)),
            result = operation => result,
        }
    }

    pub(crate) async fn run(&self, request: PayloadRun<'_>) -> ToolReply<AutomationData> {
        let PayloadRun {
            plan,
            host,
            authority,
            target,
            request,
            connect_timeout,
            output_limit,
            deadline,
            ct,
            started,
        } = request;
        let operation = async {
            let pool = self.pool(host, authority, &target, connect_timeout)?;
            let candidates = interpreters(
                plan,
                &target.target.python,
                target.dynamic_python,
                target.r#become.is_some(),
            )?;
            let r#become = target.r#become;
            let role = if r#become.is_some() {
                crate::config::IdentityRole::Automation
            } else {
                crate::config::IdentityRole::Ordinary
            };
            let requirements = serde_json::to_value(&plan.manifest.requirements).map_err(|_| {
                ToolError::new(ErrorCode::InvalidArgument, "Invalid requirements", false)
            })?;
            let mut last = None;
            for python in &candidates {
                let lease = pool
                    .acquire(host, &target.target.destination, role, deadline, ct)
                    .await?;
                let id = invocation_id();
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs_f64();
                if remaining <= 0.0 {
                    return Err(ToolError::new(
                        ErrorCode::Timeout,
                        "Payload deadline expired before dispatch",
                        false,
                    ));
                }
                // The target re-checks interpreter, modules and executables in the
                // same round trip that runs the collector; source is re-shipped.
                let spec = json!({
                    "schema": 1, "operation": "execute", "id": id,
                    "requirements": requirements,
                    "sha256": plan.manifest.source_sha256, "request": request,
                    "timeout": remaining.min(600.0), "output_limit": output_limit,
                });
                let input = frame(&spec, &plan.source).map_err(Failure::into_tool)?;
                let out = match channel(ChannelRequest {
                    session: lease.session(),
                    python,
                    r#become,
                    input: &input,
                    limit: output_limit
                        .saturating_mul(6)
                        .saturating_add(OUTPUT_HEADROOM),
                    deadline,
                    ct,
                    shutdown: &self.shutdown,
                })
                .await
                {
                    Ok(out) => out,
                    // Only a spawn/transport failure moves to the next approved
                    // interpreter; a collector outcome is final for this call.
                    Err(error)
                        if matches!(
                            error.into_code(),
                            ErrorCode::IoError | ErrorCode::ConnectionLost | ErrorCode::SpawnFailed
                        ) =>
                    {
                        last = Some(error.into_tool());
                        continue;
                    }
                    Err(error) => return Err(error.into_tool()),
                };
                return terminal(out, &id);
            }
            Err(last.unwrap_or_else(|| {
                ToolError::new(
                    ErrorCode::ResourceUnavailable,
                    "No approved target interpreter could be started",
                    false,
                )
            }))
        }
        .await;

        match operation {
            Err(error) => {
                let status = match error.code() {
                    ErrorCode::Cancelled => AutomationStatus::Cancelled,
                    ErrorCode::Timeout => AutomationStatus::Timeout,
                    ErrorCode::InvalidResult => AutomationStatus::InvalidResult,
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

    pub(crate) async fn run_bundle(&self, request: BundleRun<'_>) -> ToolReply<AutomationData> {
        let BundleRun {
            pack,
            module,
            arguments,
            no_log,
            check_mode,
            diff,
            projection,
            host,
            authority,
            target,
            connect_timeout,
            output_limit,
            deadline,
            ct,
            started,
        } = request;
        let operation = async {
            let pool = self.pool(host, authority, &target, connect_timeout)?;
            let candidates = bundle_interpreters(
                &target.target.python,
                target.dynamic_python,
                target.r#become.is_some(),
            )?;
            let r#become = target.r#become;
            let role = if r#become.is_some() {
                crate::config::IdentityRole::Automation
            } else {
                crate::config::IdentityRole::Ordinary
            };
            let requirements = json!({
                "python_min": pack.target_python_floor,
                "modules": [],
                "executables": [],
                "paths": [],
            });
            // Router modules need the target's package manager to pick the bundled
            // implementation. This is one minimal, uncached round trip: nothing
            // about it is remembered across calls.
            let pkg_mgr = if pack.routers.contains_key(module) {
                self.package_manager(
                    &pool,
                    host,
                    &target.target.destination,
                    role,
                    &candidates,
                    r#become,
                    deadline,
                    ct,
                )
                .await?
            } else {
                "unknown".to_owned()
            };
            let (bundled, dispatched_args) = pack.resolve_dispatch(module, &pkg_mgr, arguments)?;
            let mut last = None;
            for python in &candidates {
                let lease = pool
                    .acquire(host, &target.target.destination, role, deadline, ct)
                    .await?;
                let id = invocation_id();
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs_f64();
                if remaining <= 0.0 {
                    return Err(ToolError::new(
                        ErrorCode::Timeout,
                        "Bundle deadline expired before dispatch",
                        false,
                    ));
                }
                let mut module_args = dispatched_args.as_object().cloned().unwrap_or_default();
                module_args.insert("_ansible_check_mode".into(), Value::Bool(check_mode));
                module_args.insert("_ansible_diff".into(), Value::Bool(diff));
                module_args.insert("_ansible_no_log".into(), Value::Bool(no_log));
                module_args.insert("_ansible_verbosity".into(), json!(0));
                module_args.insert(
                    "_ansible_version".into(),
                    Value::String(pack.ansible_core_version.clone()),
                );
                module_args.insert(
                    "_ansible_module_name".into(),
                    Value::String(bundled.fqcn.clone()),
                );
                module_args.insert("_ansible_syslog_facility".into(), json!("LOG_USER"));
                module_args.insert(
                    "_ansible_selinux_special_fs".into(),
                    json!(["fuse", "nfs", "vboxsf", "ramfs", "9p", "vfat"]),
                );
                module_args.insert("_ansible_socket".into(), Value::Null);
                module_args.insert("_ansible_keep_remote_files".into(), Value::Bool(false));
                module_args.insert("_ansible_remote_tmp".into(), json!("/tmp"));
                let mut combined =
                    Vec::with_capacity(pack.wrapper_bytes.len() + bundled.zip_bytes.len());
                combined.extend_from_slice(&pack.wrapper_bytes);
                combined.extend_from_slice(&bundled.zip_bytes);
                let spec = json!({
                    "schema": 1,
                    "operation": "ansiballz",
                    "id": id,
                    "requirements": requirements,
                    "wrapper_len": pack.wrapper_bytes.len(),
                    "wrapper_sha256": pack.wrapper_sha256,
                    "zip_sha256": bundled.zip_sha256,
                    "ansible_module": bundled.ansible_module,
                    "module_fqn": bundled.module_fqn,
                    "serialization_profile": bundled.serialization_profile,
                    "params": { "ANSIBLE_MODULE_ARGS": module_args },
                    "timeout": remaining.min(600.0),
                    "output_limit": output_limit,
                });
                let input = frame_bounded(&spec, &combined, MAX_BUNDLE_FRAME)
                    .map_err(Failure::into_tool)?;
                let out = match channel(ChannelRequest {
                    session: lease.session(),
                    python,
                    r#become,
                    input: &input,
                    limit: output_limit
                        .saturating_mul(6)
                        .saturating_add(OUTPUT_HEADROOM),
                    deadline,
                    ct,
                    shutdown: &self.shutdown,
                })
                .await
                {
                    Ok(out) => out,
                    Err(error)
                        if matches!(
                            error.into_code(),
                            ErrorCode::IoError | ErrorCode::ConnectionLost | ErrorCode::SpawnFailed
                        ) =>
                    {
                        last = Some(error.into_tool());
                        continue;
                    }
                    Err(error) => return Err(error.into_tool()),
                };
                return terminal(out, &id);
            }
            Err(last.unwrap_or_else(|| {
                ToolError::new(
                    ErrorCode::ResourceUnavailable,
                    "No approved target interpreter could be started",
                    false,
                )
            }))
        }
        .await;
        match operation {
            Err(error) => {
                let status = match error.code() {
                    ErrorCode::Cancelled => AutomationStatus::Cancelled,
                    ErrorCode::Timeout => AutomationStatus::Timeout,
                    ErrorCode::InvalidResult => AutomationStatus::InvalidResult,
                    _ if error.remote_state_unknown => AutomationStatus::WorkerLost,
                    _ => AutomationStatus::NotStarted,
                };
                ToolReply::partial(
                    AutomationData {
                        host: host.to_owned(),
                        status,
                        runner_rc: None,
                        changed: None,
                        tasks: AutomationTasks::default(),
                        censored: no_log,
                        complete: false,
                        duration_ms: elapsed(started),
                        owned_group_cleanup: GroupCleanup::NotApplicable,
                        projection: None,
                    },
                    error,
                )
            }
            Ok((rc, value, output_status)) => {
                complete_bundle_reply(host, no_log, projection, rc, &value, output_status, started)
            }
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
        let pool = self.pool(host, authority, target, connect_timeout)?;
        let role = if target.r#become.is_some() {
            crate::config::IdentityRole::Automation
        } else {
            crate::config::IdentityRole::Ordinary
        };
        let lease = pool
            .acquire(host, &target.target.destination, role, deadline, ct)
            .await?;
        // Under sudo a bare name would be resolved through root's PATH, so an
        // elevated probe must use an absolute interpreter only.
        let candidates: Vec<&str> = if !target.target.python.is_empty() {
            vec![target.target.python.as_str()]
        } else if target.dynamic_python {
            if target.r#become.is_some() {
                vec![
                    "/usr/bin/python3",
                    "/usr/local/bin/python3",
                    "/run/current-system/sw/bin/python3",
                ]
            } else {
                vec!["python3"]
            }
        } else {
            return Err(ToolError::new(
                ErrorCode::PreviewRequired,
                "Independent pre-state probe interpreter is unavailable",
                false,
            ));
        };
        let payload = serde_json::to_vec(&json!({
            "module": module,
            "arguments": arguments,
        }))
        .map_err(|_| {
            ToolError::new(
                ErrorCode::PreviewRequired,
                "Invalid pre-state request",
                false,
            )
        })?;
        let r#become = target.r#become;
        let shutdown = &self.shutdown;
        let operation = async {
            let unavailable = || {
                ToolError::new(
                    ErrorCode::PreviewRequired,
                    "Independent pre-state digest could not be obtained",
                    false,
                )
            };
            // Each absolute candidate is tried in order; a spawn failure moves to
            // the next one, exactly as bundle dispatch does.
            for python in candidates {
                let mut command =
                    if let Some(AutomationBecome::Sudo { user, executable }) = r#become {
                        let mut command = lease.session().command(executable);
                        command.args(["-H", "-n", "-k", "-u", user, "--", python]);
                        command
                    } else {
                        lease.session().command(python)
                    };
                command
                    .args(["-I", "-c", STAGE0_LOADER])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let Ok(mut child) = command.spawn().await else {
                    continue;
                };
                let Some(mut stdin) = child.stdin().take() else {
                    continue;
                };
                let Some(stdout) = child.stdout().take() else {
                    continue;
                };
                let Some(stderr) = child.stderr().take() else {
                    continue;
                };
                let probe = payload.clone();
                let (out, err, write) = tokio::join!(
                    bounded(stdout, OUTPUT_HEADROOM),
                    bounded(stderr, 0),
                    async move {
                        let script = PRESTATE.as_bytes();
                        stdin
                            .write_all(&(script.len() as u32).to_be_bytes())
                            .await?;
                        stdin.write_all(script).await?;
                        stdin.write_all(&probe).await?;
                        stdin.shutdown().await
                    }
                );
                let (stdout, overflow) = out.map_err(|_| unavailable())?;
                let _ = err;
                write.map_err(|_| unavailable())?;
                let status = child.wait().await.map_err(|_| unavailable())?;
                if !status.success() || overflow || parse(&stdout).is_err() {
                    continue;
                }
                return Ok(<sha2::Sha256 as sha2::Digest>::digest(&stdout).into());
            }
            Err(unavailable())
        };
        tokio::select! {
            biased;
            _ = ct.cancelled() => Err(ToolError::new(ErrorCode::Cancelled, "Request cancelled before preview pre-state probe", false)),
            _ = shutdown.cancelled() => Err(ToolError::new(ErrorCode::Cancelled, "Server shutting down", false)),
            _ = sleep_until(deadline) => Err(ToolError::new(ErrorCode::Timeout, "Request deadline exceeded during preview pre-state probe", false)),
            result = operation => result,
        }
    }
}

fn interpreters<'a>(
    plan: &'a PayloadPlan,
    configured: &'a str,
    dynamic_python: bool,
    elevated: bool,
) -> Result<Vec<&'a str>, ToolError> {
    if !configured.is_empty() {
        if !configured.starts_with('/') || configured.contains('\0') {
            return Err(ToolError::new(
                ErrorCode::ResourceUnavailable,
                "An approved absolute target interpreter is required",
                false,
            ));
        }
        return Ok(vec![configured]);
    }
    let fixed = plan.target_python();
    let mut candidates: Vec<&str> = Vec::new();
    if let Some(fixed) = fixed {
        candidates.push(fixed);
    }
    if dynamic_python || fixed.is_none() {
        for interpreter in &plan.manifest.requirements.interpreters {
            // A relative name resolves through sudo's PATH, not the caller's.
            if elevated && !interpreter.starts_with('/') {
                continue;
            }
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
        ] {
            if !candidates.contains(&fallback) {
                candidates.push(fallback);
            }
        }
        // Under sudo a bare name would be resolved by root's PATH, so only an
        // absolute interpreter is ever spawned there.
        if !elevated && !candidates.contains(&"python3") {
            candidates.push("python3");
        }
    }
    if candidates.is_empty()
        || candidates.iter().any(|path| {
            path.is_empty()
                || path.contains('\0')
                || !(path.starts_with('/') || !elevated && dynamic_python && *path == "python3")
        })
    {
        return Err(ToolError::new(
            ErrorCode::ResourceUnavailable,
            "An approved absolute target interpreter is required",
            false,
        ));
    }
    Ok(candidates)
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
        None => ToolError::new(
            ErrorCode::PayloadFailed,
            "Payload operation completed with failure",
            false,
        ),
    });
    let changed = if no_log {
        None
    } else {
        change_policy.evidence(rc, domain.as_ref())
    };
    if !no_log && error.is_none() {
        match output_status {
            OutputStatus::Overflow => {
                error = Some(crate::reply::ToolError::new(
                    ErrorCode::ResourceLimit,
                    "Payload output exceeded retention limit",
                    false,
                ));
            }
            OutputStatus::InvalidUtf8 => {
                error = Some(crate::reply::ToolError::new(
                    ErrorCode::InvalidProjection,
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
                match domain {
                    Some(ref result) => match project(projection, result) {
                        Ok(value) => ModuleProjection::Complete { value },
                        Err(violation) => {
                            if error.is_none() {
                                error = Some(crate::reply::ToolError::invalid_projection_at(
                                    violation.schema_path,
                                    violation.constraint,
                                ));
                            }
                            ModuleProjection::Invalid
                        }
                    },
                    None => {
                        if error.is_none() {
                            error = Some(crate::reply::ToolError::new(
                                ErrorCode::InvalidProjection,
                                "Payload output is not valid strict JSON",
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

fn bundle_interpreters(
    configured: &str,
    dynamic_python: bool,
    elevated: bool,
) -> Result<Vec<&str>, ToolError> {
    if !configured.is_empty() {
        if !configured.starts_with('/') || configured.contains('\0') {
            return Err(ToolError::new(
                ErrorCode::ResourceUnavailable,
                "An approved absolute target interpreter is required",
                false,
            ));
        }
        return Ok(vec![configured]);
    }
    if dynamic_python {
        let mut candidates = vec![
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/run/current-system/sw/bin/python3",
        ];
        // Under sudo a bare name would be resolved by root's PATH.
        if !elevated {
            candidates.push("python3");
        }
        Ok(candidates)
    } else {
        Ok(vec!["/usr/bin/python3"])
    }
}

fn complete_bundle_reply(
    host: &str,
    no_log: bool,
    projection_plan: Option<&crate::contracts::projection::Plan>,
    rc: i32,
    value: &Value,
    output_status: OutputStatus,
    started: std::time::Instant,
) -> ToolReply<AutomationData> {
    let parsed = if output_status == OutputStatus::Complete {
        value
            .get("stdout")
            .and_then(Value::as_str)
            .and_then(|stdout| parse(stdout.as_bytes()).ok())
    } else {
        None
    };
    let module_censored = parsed.as_ref().is_some_and(|doc| {
        doc.get("_ansible_no_log") == Some(&Value::Bool(true)) || doc.get("censored").is_some()
    });
    let censored = no_log || module_censored;
    let skipped = parsed
        .as_ref()
        .and_then(|doc| doc.get("skipped"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let module_failed = parsed
        .as_ref()
        .and_then(|doc| doc.get("failed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let failed = rc != 0 || module_failed;

    let failure_reason = if !censored && failed {
        value
            .get("error_reason")
            .and_then(Value::as_str)
            .and_then(crate::reply::PayloadFailureReason::from_code)
    } else {
        None
    };
    let mut error = failed.then(|| match failure_reason {
        Some(reason) => ToolError::payload_failed_with_reason(reason, false),
        None => ToolError::new(
            ErrorCode::AutomationFailed,
            "Ansible module execution failed",
            false,
        ),
    });
    if !censored && error.is_none() {
        match output_status {
            OutputStatus::Overflow => {
                error = Some(ToolError::new(
                    ErrorCode::ResourceLimit,
                    "Module output exceeded retention limit",
                    false,
                ));
            }
            OutputStatus::InvalidUtf8 => {
                error = Some(ToolError::new(
                    ErrorCode::InvalidProjection,
                    "Module output was not valid UTF-8",
                    false,
                ));
            }
            OutputStatus::Complete if parsed.is_none() => {
                error = Some(ToolError::new(
                    ErrorCode::InvalidResult,
                    "Module output was not valid JSON",
                    false,
                ));
            }
            OutputStatus::Complete => {}
        }
    }
    let changed = if censored {
        None
    } else if failed {
        parsed
            .as_ref()
            .and_then(|doc| doc.get("changed"))
            .and_then(Value::as_bool)
            .filter(|&c| c)
    } else if skipped {
        Some(false)
    } else {
        parsed
            .as_ref()
            .and_then(|doc| doc.get("changed"))
            .and_then(Value::as_bool)
            .or(Some(false))
    };
    let projection = projection_plan.map(|plan| {
        if censored {
            return ModuleProjection::Censored;
        }
        match output_status {
            OutputStatus::Overflow => ModuleProjection::Unavailable,
            OutputStatus::InvalidUtf8 => ModuleProjection::Invalid,
            OutputStatus::Complete => {
                if failed || skipped {
                    return ModuleProjection::Unavailable;
                }
                match parsed.as_ref() {
                    Some(doc) => match project(plan, doc) {
                        Ok(val) => ModuleProjection::Complete { value: val },
                        Err(violation) => {
                            if error.is_none() {
                                error = Some(ToolError::invalid_projection_at(
                                    violation.schema_path,
                                    violation.constraint,
                                ));
                            }
                            ModuleProjection::Invalid
                        }
                    },
                    None => ModuleProjection::Invalid,
                }
            }
        }
    });
    let tasks = AutomationTasks {
        ok: u32::from(!failed && !skipped),
        failed: u32::from(failed),
        skipped: u32::from(!failed && skipped),
        ..Default::default()
    };
    let data = AutomationData {
        host: host.to_owned(),
        status: if failed {
            AutomationStatus::Failed
        } else {
            AutomationStatus::Successful
        },
        runner_rc: Some(if failed {
            if rc == 0 { 1 } else { rc }
        } else {
            0
        }),
        changed,
        tasks,
        censored,
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
        ToolError::new(
            ErrorCode::InvalidResult,
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
            // A declared prerequisite failed, so the collector never ran and no
            // mutation is possible. Distinguish that from a frame/protocol rejection.
            return Err(match value.get("error_reason").and_then(Value::as_str) {
                Some("unsupported_platform") => ToolError::new(
                    ErrorCode::ResourceUnavailable,
                    "Target interpreter does not meet the approved minimum version",
                    false,
                ),
                Some("dependency_unavailable") => ToolError::new(
                    ErrorCode::ResourceUnavailable,
                    "A declared target module or executable is unavailable",
                    false,
                ),
                _ => ToolError::new(
                    ErrorCode::PayloadRejected,
                    "Payload rejected before execution; frame or source drift",
                    false,
                ),
            });
        }
        (Some("timeout"), 124) => {
            return Err(ToolError::new(
                ErrorCode::Timeout,
                "Payload deadline exceeded; remote descendants may continue",
                true,
            ));
        }
        (Some("cancelled"), 125) => {
            return Err(ToolError::new(
                ErrorCode::Cancelled,
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

fn project(
    plan: &crate::contracts::projection::Plan,
    result: &Value,
) -> Result<Value, crate::contracts::projection::ProjectionViolation> {
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
    plan.validate_value_detailed(&value)?;
    Ok(value)
}

struct Frame<'a> {
    header: Vec<u8>,
    source: &'a [u8],
}

fn frame<'a>(spec: &Value, source: &'a [u8]) -> Result<Frame<'a>, Failure> {
    frame_bounded(spec, source, super::MAX_SOURCE)
}

fn frame_bounded<'a>(
    spec: &Value,
    source: &'a [u8],
    max_source: usize,
) -> Result<Frame<'a>, Failure> {
    let data = serde_json::to_vec(spec).map_err(|_| Failure {
        code: ErrorCode::InvalidArgument,
        message: "Invalid payload frame",
        unknown: false,
    })?;
    if data.len() > MAX_INPUT || source.len() > max_source {
        return Err(Failure {
            code: ErrorCode::ResourceLimit,
            message: "Payload frame exceeds bounds",
            unknown: false,
        });
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
    pub(crate) request: Vec<Value>,
    pub(crate) connect_timeout: Duration,
    pub(crate) output_limit: usize,
    pub(crate) deadline: Instant,
    pub(crate) ct: &'a CancellationToken,
    pub(crate) started: std::time::Instant,
}
pub(crate) struct BundleRun<'a> {
    pub(crate) pack: &'a crate::bundle::BundlePack,
    pub(crate) module: &'a str,
    pub(crate) arguments: &'a Value,
    pub(crate) no_log: bool,
    pub(crate) check_mode: bool,
    pub(crate) diff: bool,
    pub(crate) projection: Option<&'a crate::contracts::projection::Plan>,
    pub(crate) host: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) target: ResolvedAutomation<'a>,
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
            .args(["-I", "-c", STAGE0_LOADER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().await.map_err(|_| Failure {
            code: ErrorCode::ConnectionLost,
            message: "Payload channel failed; remote state is unknown",
            unknown: true,
        })?;
        let mut stdin = child.stdin().take().ok_or(Failure {
            code: ErrorCode::IoError,
            message: "Missing payload input pipe",
            unknown: true,
        })?;
        let stdout = child.stdout().take().ok_or(Failure {
            code: ErrorCode::IoError,
            message: "Missing payload output pipe",
            unknown: true,
        })?;
        let stderr = child.stderr().take().ok_or(Failure {
            code: ErrorCode::IoError,
            message: "Missing payload error pipe",
            unknown: true,
        })?;
        let (out, err, write) =
            tokio::join!(bounded(stdout, limit), bounded(stderr, 0), async move {
                let script = BOOTSTRAP.as_bytes();
                stdin
                    .write_all(&(script.len() as u32).to_be_bytes())
                    .await?;
                stdin.write_all(script).await?;
                stdin.write_all(&input.header).await?;
                stdin.write_all(input.source).await?;
                stdin.shutdown().await
            },);
        let (stdout, overflow) = out.map_err(|_| Failure {
            code: ErrorCode::IoError,
            message: "Payload output failed; remote state is unknown",
            unknown: true,
        })?;
        err.map_err(|_| Failure {
            code: ErrorCode::IoError,
            message: "Payload error stream failed; remote state is unknown",
            unknown: true,
        })?;
        write.map_err(|_| Failure {
            code: ErrorCode::IoError,
            message: "Payload input failed; remote state is unknown",
            unknown: true,
        })?;
        let status = child.wait().await.map_err(|_| Failure {
            code: ErrorCode::ConnectionLost,
            message: "Payload channel lost; remote state is unknown",
            unknown: true,
        })?;
        let rc = status.code().ok_or(Failure {
            code: ErrorCode::ConnectionLost,
            message: "Payload exit unavailable; remote state is unknown",
            unknown: true,
        })?;
        Ok(Output {
            stdout,
            overflow,
            rc,
        })
    };
    tokio::select! {
        biased;
        _ = ct.cancelled() => Err(Failure { code: ErrorCode::Cancelled, message: "Payload cancelled; remote execution may continue", unknown: true }),
        _ = shutdown.cancelled() => Err(Failure { code: ErrorCode::Cancelled, message: "Server stopped; remote execution may continue", unknown: true }),
        _ = sleep_until(deadline) => Err(Failure { code: ErrorCode::Timeout, message: "Payload deadline exceeded; remote execution may continue", unknown: true }),
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

    #[tokio::test]
    async fn overflow_drains_without_accepting_prefix() {
        let (out, overflow) = bounded(b"{\"ok\":true}trailing".as_slice(), 11)
            .await
            .unwrap();
        assert!(overflow);
        assert_eq!(out, b"{\"ok\":true}");
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
        let first = engine
            .pool("logical-a", "automation", &resolved, Duration::from_secs(1))
            .unwrap();
        let same = engine
            .pool("logical-a", "automation", &resolved, Duration::from_secs(1))
            .unwrap();
        let other = engine
            .pool(
                "logical-a",
                "automation:catalog",
                &resolved,
                Duration::from_secs(1),
            )
            .unwrap();
        let host = engine
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
            ..Default::default()
        };
        assert_eq!(
            project(&plan, &json!({"present":true})),
            Ok(json!({"required":true}))
        );
        let missing = project(&plan, &json!({})).unwrap_err();
        assert_eq!(missing.schema_path, "result.required");
        assert_eq!(missing.constraint, "missing_field");
        plan.fields
            .get_mut("required")
            .unwrap()
            .insert(0, "mcp_result".into());
        assert_eq!(
            project(&plan, &json!({"present":true})),
            Ok(json!({"required":true}))
        );
    }

    #[test]
    fn interruption_terminals_remain_unknown_and_require_matching_exit() {
        for (phase, rc, code) in [
            ("timeout", 124, ErrorCode::Timeout),
            ("cancelled", 125, ErrorCode::Cancelled),
        ] {
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
            assert_eq!(error.code(), ErrorCode::InvalidResult);
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
                ErrorCode::ResourceLimit,
                "unavailable",
            ),
            (
                "invalid_utf8",
                false,
                OutputStatus::InvalidUtf8,
                ErrorCode::InvalidProjection,
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
                        ErrorCode::PayloadFailed
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
            assert_eq!(err.code(), ErrorCode::InvalidResult);
        }
    }

    #[test]
    fn configured_target_python_takes_precedence_over_template_default() {
        let manifest = super::super::Manifest {
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
        };
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
            interpreters(&plan, "/opt/site/bin/python3", false, false).unwrap(),
            vec!["/opt/site/bin/python3"]
        );
        assert_eq!(
            interpreters(&plan, "", false, false).unwrap(),
            vec!["/usr/bin/python3"]
        );
        let dynamic = interpreters(&plan, "", true, false).unwrap();
        assert_eq!(dynamic[0], "/usr/bin/python3");
        assert!(dynamic.contains(&"/usr/local/bin/python3"));
        assert!(dynamic.contains(&"python3"));

        // Elevation must never resolve a bare name through root's PATH.
        let elevated = interpreters(&plan, "", true, true).unwrap();
        assert!(!elevated.contains(&"python3"));
        assert!(elevated.iter().all(|path| path.starts_with('/')));
        assert_eq!(
            bundle_interpreters("", true, false).unwrap(),
            vec![
                "/usr/bin/python3",
                "/usr/local/bin/python3",
                "/run/current-system/sw/bin/python3",
                "python3",
            ]
        );
        let bundle_elevated = bundle_interpreters("", true, true).unwrap();
        assert!(!bundle_elevated.contains(&"python3"));
        assert!(bundle_elevated.iter().all(|path| path.starts_with('/')));
        assert_eq!(
            bundle_interpreters("/opt/site/bin/python3", true, true).unwrap(),
            vec!["/opt/site/bin/python3"]
        );
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
        assert_eq!(err.code(), ErrorCode::PayloadFailed);
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
