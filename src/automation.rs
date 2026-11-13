//! Optional, explicitly requested import/identity health for a private runtime.
//! This does not attest execution compatibility or run automation workloads.
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions, Permissions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::bindings::{ControllerPlan, PreparedController};
use crate::config::RuntimeKind;
use crate::controller::{self, ControllerContext};
use crate::reply::{ControllerReply, ControllerTermination, GroupCleanup};

const HEALTH: &str = include_str!("automation_health.py");
const MANIFEST_LIMIT: usize = 16 * 1024;
const REPORT_LIMIT: u64 = 16 * 1024;
const PATH_LIMIT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCollection {
    pub name: String,
    pub version: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeIdentity {
    pub runtime_id: String,
    pub platform: String,
    pub python: String,
    pub ansible_core: String,
    pub ansible_runner: String,
    pub collection_bundle: String,
    pub collections: Vec<RuntimeCollection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeStatus {
    Passed,
    Failed,
    NotTested,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeCheck {
    pub kind: RuntimeKind,
    pub status: RuntimeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<RuntimeIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

impl RuntimeCheck {
    pub(crate) fn failed(code: &'static str) -> Self {
        Self {
            kind: RuntimeKind::Ansible,
            status: RuntimeStatus::Failed,
            identity: None,
            error_code: Some(code),
        }
    }

    pub(crate) fn not_tested(code: &'static str) -> Self {
        Self {
            kind: RuntimeKind::Ansible,
            status: RuntimeStatus::NotTested,
            identity: None,
            error_code: Some(code),
        }
    }

    pub(crate) fn is_passed(&self) -> bool {
        self.status == RuntimeStatus::Passed
    }
}

pub(crate) struct RuntimeContext<'a> {
    pub deadline: tokio::time::Instant,
    pub ct: &'a CancellationToken,
    pub shutdown: &'a CancellationToken,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    health_sha256: String,
    site_packages: String,
    identity: RuntimeIdentity,
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum HealthReport {
    Passed {
        schema: u32,
        identity: RuntimeIdentity,
    },
    Failed {
        schema: u32,
        error_code: HealthError,
    },
}

#[derive(Deserialize)]
enum HealthError {
    #[serde(rename = "runtime_import_failed")]
    ImportFailed,
    #[serde(rename = "runtime_version_mismatch")]
    VersionMismatch,
    #[serde(rename = "runtime_collection_mismatch")]
    CollectionMismatch,
    #[serde(rename = "runtime_check_failed")]
    CheckFailed,
}

impl HealthError {
    fn code(self) -> &'static str {
        match self {
            Self::ImportFailed => "runtime_import_failed",
            Self::VersionMismatch => "runtime_version_mismatch",
            Self::CollectionMismatch => "runtime_collection_mismatch",
            Self::CheckFailed => "runtime_check_failed",
        }
    }
}

struct Loaded {
    root: PathBuf,
    interpreter: String,
    identity: RuntimeIdentity,
}

fn lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn public_token(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn valid_identity(identity: &RuntimeIdentity) -> bool {
    lower_hash(&identity.runtime_id)
        && public_token(&identity.platform, 64)
        && [
            &identity.python,
            &identity.ansible_core,
            &identity.ansible_runner,
            &identity.collection_bundle,
        ]
        .iter()
        .all(|value| public_token(value, 64))
        && (2..=16).contains(&identity.collections.len())
        && identity.collections.iter().all(|collection| {
            let mut parts = collection.name.split('.');
            let namespace = parts.next().unwrap_or_default();
            let name = parts.next().unwrap_or_default();
            parts.next().is_none()
                && [namespace, name].iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 64
                        && part.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
                && public_token(&collection.version, 64)
                && lower_hash(&collection.manifest_sha256)
        })
        && identity
            .collections
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        && ["ansible.posix", "community.general"].iter().all(|name| {
            identity
                .collections
                .iter()
                .any(|collection| collection.name == *name)
        })
}

fn parse_manifest(bytes: &[u8]) -> Result<Manifest, &'static str> {
    let invalid = "invalid_runtime_manifest";
    if bytes.len() > MANIFEST_LIMIT {
        return Err(invalid);
    }
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| invalid)?;
    let site = Path::new(&manifest.site_packages);
    let platform_os = if std::env::consts::OS == "macos" {
        "darwin"
    } else {
        std::env::consts::OS
    };
    let platform = format!("{}-{platform_os}", std::env::consts::ARCH);
    if manifest.schema != 1
        || !lower_hash(&manifest.health_sha256)
        || manifest.health_sha256 != hex::encode(Sha256::digest(HEALTH.as_bytes()))
        || manifest.site_packages.is_empty()
        || manifest.site_packages.len() > PATH_LIMIT
        || manifest.site_packages.contains('\0')
        || !site
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        || !valid_identity(&manifest.identity)
        || manifest.identity.platform != platform
    {
        return Err(invalid);
    }
    Ok(manifest)
}

fn load(runtime: PathBuf) -> Result<Loaded, &'static str> {
    let invalid = "invalid_runtime_manifest";
    if !runtime.is_absolute() || runtime.as_os_str().len() > PATH_LIMIT {
        return Err(invalid);
    }
    let root = fs::canonicalize(runtime).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "runtime_unavailable"
        } else {
            invalid
        }
    })?;
    let root_text = root.to_str().ok_or(invalid)?;
    if root_text.len() > PATH_LIMIT || root_text.contains('\0') || !root.is_dir() {
        return Err(invalid);
    }
    // Nonblocking open plus the regular-file check prevents FIFO/device input
    // from turning the bounded manifest read into an unbounded streaming read.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(root.join("runtime.json"))
        .map_err(|_| invalid)?;
    if !file.metadata().map_err(|_| invalid)?.is_file() {
        return Err(invalid);
    }
    let mut bytes = Vec::with_capacity(MANIFEST_LIMIT + 1);
    file.take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid)?;
    let manifest = parse_manifest(&bytes)?;
    let interpreter = root.join("bin/python3");
    let metadata = fs::metadata(&interpreter).map_err(|_| invalid)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(invalid);
    }
    Ok(Loaded {
        interpreter: interpreter.to_str().ok_or(invalid)?.to_owned(),
        root,
        identity: manifest.identity,
    })
}

fn interrupted(ctx: &RuntimeContext<'_>) -> Option<&'static str> {
    if ctx.ct.is_cancelled() || ctx.shutdown.is_cancelled() {
        Some("runtime_cancelled")
    } else if tokio::time::Instant::now() >= ctx.deadline {
        Some("runtime_timeout")
    } else {
        None
    }
}

fn report(stdout: &str, expected: &RuntimeIdentity) -> RuntimeCheck {
    let parsed = if stdout.len() <= REPORT_LIMIT as usize {
        serde_json::from_str::<HealthReport>(stdout).ok()
    } else {
        None
    };
    match parsed {
        Some(HealthReport::Passed {
            schema: 1,
            identity,
        }) if valid_identity(&identity) => {
            if &identity == expected {
                RuntimeCheck {
                    kind: RuntimeKind::Ansible,
                    status: RuntimeStatus::Passed,
                    identity: Some(identity),
                    error_code: None,
                }
            } else {
                RuntimeCheck::failed("runtime_identity_mismatch")
            }
        }
        Some(HealthReport::Failed {
            schema: 1,
            error_code,
        }) => RuntimeCheck::failed(error_code.code()),
        _ => RuntimeCheck::failed("runtime_protocol_error"),
    }
}

fn observed(reply: ControllerReply, expected: &RuntimeIdentity) -> RuntimeCheck {
    let Some(data) = reply.data else {
        return RuntimeCheck::failed("runtime_check_failed");
    };
    match data.termination {
        ControllerTermination::Cancelled => return RuntimeCheck::failed("runtime_cancelled"),
        ControllerTermination::Timeout => return RuntimeCheck::failed("runtime_timeout"),
        _ => {}
    }
    if data.owned_group_cleanup == GroupCleanup::Incomplete
        || reply
            .error
            .as_ref()
            .is_some_and(|error| error.code == "cleanup_incomplete")
    {
        return RuntimeCheck::failed("runtime_cleanup_failed");
    }
    if reply.error.is_some()
        || data.termination != ControllerTermination::Exited
        || data.exit_code != Some(0)
        || data.signal.is_some()
    {
        return RuntimeCheck::failed("runtime_check_failed");
    }
    if data.owned_group_cleanup != GroupCleanup::SignalledAndReaped {
        return RuntimeCheck::failed("runtime_cleanup_failed");
    }
    if data.stdout_truncated || data.stdout_lossy || data.stderr_truncated || data.stderr_lossy {
        return RuntimeCheck::failed("runtime_protocol_error");
    }
    report(&data.stdout, expected)
}

pub(crate) async fn check(runtime: Option<PathBuf>, ctx: RuntimeContext<'_>) -> RuntimeCheck {
    let Some(runtime) = runtime else {
        return RuntimeCheck::failed("runtime_unavailable");
    };
    if let Some(code) = interrupted(&ctx) {
        return RuntimeCheck::not_tested(code);
    }
    // Never select away from started blocking I/O: join it before observing
    // cancellation. As with the controller owner, a broken OS may delay return.
    let loaded = tokio::task::spawn_blocking(move || load(runtime)).await;
    if let Some(code) = interrupted(&ctx) {
        return RuntimeCheck::not_tested(code);
    }
    let loaded = match loaded {
        Ok(Ok(loaded)) => loaded,
        Ok(Err(code)) => return RuntimeCheck::failed(code),
        Err(_) => return RuntimeCheck::failed("runtime_check_failed"),
    };
    let root = match tokio::task::spawn_blocking(|| {
        tempfile::Builder::new()
            .prefix("ssh-mcp-runtime-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
    })
    .await
    {
        Ok(Ok(root)) => root,
        _ => return RuntimeCheck::failed("runtime_check_failed"),
    };
    let result = if let Some(code) = interrupted(&ctx) {
        RuntimeCheck::not_tested(code)
    } else {
        check_loaded(loaded, root.path(), &ctx).await
    };
    // Retain the private root until the controller's pending owner has finished;
    // explicit close makes removal failure observable rather than Drop-only.
    if !matches!(
        tokio::task::spawn_blocking(move || root.close()).await,
        Ok(Ok(()))
    ) {
        return RuntimeCheck::failed("runtime_cleanup_failed");
    }
    result
}

async fn check_loaded(loaded: Loaded, workspace: &Path, ctx: &RuntimeContext<'_>) -> RuntimeCheck {
    #[derive(Serialize)]
    struct Input<'a> {
        runtime_root: &'a Path,
    }
    let input_json = match serde_json::to_vec(&Input {
        runtime_root: &loaded.root,
    }) {
        Ok(input) => input,
        Err(_) => return RuntimeCheck::failed("invalid_runtime_manifest"),
    };
    let prepared = PreparedController {
        plan: Arc::new(ControllerPlan {
            source: Cow::Borrowed(HEALTH),
            interpreter: loaded.interpreter,
            interpreter_argv: vec!["-I".to_owned(), "-B".to_owned()],
            cwd: None,
            environment: BTreeMap::new(),
            workspace_root: Arc::from(workspace),
        }),
        input_json,
        duration: ctx
            .deadline
            .saturating_duration_since(tokio::time::Instant::now()),
        max_output_bytes: REPORT_LIMIT,
    };
    let run = controller::run(
        prepared,
        ControllerContext {
            deadline: ctx.deadline,
            ct: ctx.ct,
            shutdown: ctx.shutdown,
            started: Instant::now(),
            capture_limit: REPORT_LIMIT,
        },
    )
    .await;
    if let Some(pending) = run.pending {
        pending.finish().await;
    }
    observed(run.reply, &loaded.identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn manifest() -> Value {
        let os = if std::env::consts::OS == "macos" {
            "darwin"
        } else {
            std::env::consts::OS
        };
        json!({
            "schema": 1,
            "health_sha256": hex::encode(Sha256::digest(HEALTH.as_bytes())),
            "site_packages": "python/lib/python3.14/site-packages",
            "identity": {
                "runtime_id": "a".repeat(64),
                "platform": format!("{}-{os}", std::env::consts::ARCH),
                "python": "3.14.8", "ansible_core": "2.21.5",
                "ansible_runner": "2.4.3", "collection_bundle": "14.4.0",
                "collections": [
                    {"name": "ansible.posix", "version": "2.1.0", "manifest_sha256": "b".repeat(64)},
                    {"name": "community.general", "version": "12.0.0", "manifest_sha256": "c".repeat(64)}
                ]
            }
        })
    }

    #[test]
    fn rejects_manifest_shape_path_hash_and_collection_drift() {
        let base = manifest();
        let mut cases = Vec::new();
        for path in [
            "../site-packages",
            "/site-packages",
            "",
            "python/../../site-packages",
        ] {
            let mut value = base.clone();
            value["site_packages"] = json!(path);
            cases.push(value);
        }
        let mut value = base.clone();
        value["health_sha256"] = json!("0".repeat(64));
        cases.push(value);
        let mut value = base.clone();
        value["extra"] = json!(true);
        cases.push(value);
        let mut value = base.clone();
        value["identity"]["collections"][1] = value["identity"]["collections"][0].clone();
        cases.push(value);
        let mut value = base;
        value["identity"]["runtime_id"] = json!("A".repeat(64));
        cases.push(value);
        for value in cases {
            assert!(matches!(
                parse_manifest(&serde_json::to_vec(&value).unwrap()),
                Err("invalid_runtime_manifest")
            ));
        }
    }

    #[test]
    fn bounded_manifest_read_rejects_oversized_regular_file() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("bin")).unwrap();
        std::os::unix::fs::symlink(
            std::env::current_exe().unwrap(),
            root.path().join("bin/python3"),
        )
        .unwrap();
        let mut bytes = serde_json::to_vec(&manifest()).unwrap();
        bytes.resize(MANIFEST_LIMIT, b' ');
        fs::write(root.path().join("runtime.json"), &bytes).unwrap();
        let exact = load(root.path().to_owned()).unwrap();
        assert_eq!(exact.identity.runtime_id, "a".repeat(64));
        bytes.push(b' ');
        fs::write(root.path().join("runtime.json"), &bytes).unwrap();
        assert!(matches!(
            load(root.path().to_owned()),
            Err("invalid_runtime_manifest")
        ));
        assert!(matches!(
            parse_manifest(&bytes),
            Err("invalid_runtime_manifest")
        ));
    }

    #[test]
    fn report_rejects_ambiguous_unknown_trailing_and_changed_identity() {
        let expected = parse_manifest(&serde_json::to_vec(&manifest()).unwrap())
            .unwrap()
            .identity;
        for text in [
            "{\"schema\":1,\"status\":\"failed\",\"error_code\":\"unknown\"}",
            "{\"schema\":1,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\",\"identity\":null}",
            "{\"schema\":2,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\"}",
            "{\"schema\":1,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\"} {}",
        ] {
            assert_eq!(
                report(text, &expected).error_code,
                Some("runtime_protocol_error")
            );
        }
        let mut changed = expected.clone();
        changed.python = "3.14.9".to_owned();
        let text = json!({"schema": 1, "status": "passed", "identity": changed}).to_string();
        assert_eq!(
            report(&text, &expected).error_code,
            Some("runtime_identity_mismatch")
        );
        assert_eq!(
            report(&" ".repeat(REPORT_LIMIT as usize + 1), &expected).error_code,
            Some("runtime_protocol_error")
        );
    }
}
