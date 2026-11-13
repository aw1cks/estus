//! Optional, explicitly requested import/identity health for a private runtime.
//! This does not attest execution compatibility or run automation workloads.
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
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
const DESCRIPTOR_LIMIT: usize = 65_536;

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
    pub provenance: RuntimeProvenance,
    pub platform: String,
    pub python: String,
    pub ansible_core: String,
    pub ansible_runner: String,
    pub collection_bundle: String,
    pub collections: Vec<RuntimeCollection>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RuntimeProvenance {
    NixBundle { runtime_id: String },
    PythonEnvironment {},
}

// The immutable Nix manifest retains its schema-1 wire layout.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleIdentity {
    runtime_id: String,
    platform: String,
    python: String,
    ansible_core: String,
    ansible_runner: String,
    collection_bundle: String,
    collections: Vec<RuntimeCollection>,
}

fn bundle_identity<'de, D>(deserializer: D) -> Result<RuntimeIdentity, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let identity = BundleIdentity::deserialize(deserializer)?;
    Ok(RuntimeIdentity {
        provenance: RuntimeProvenance::NixBundle {
            runtime_id: identity.runtime_id,
        },
        platform: identity.platform,
        python: identity.python,
        ansible_core: identity.ansible_core,
        ansible_runner: identity.ansible_runner,
        collection_bundle: identity.collection_bundle,
        collections: identity.collections,
    })
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
    #[serde(deserialize_with = "bundle_identity")]
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
    interpreter: String,
    source: Source,
}

enum Source {
    Bundle {
        root: PathBuf,
        identity: RuntimeIdentity,
    },
    PythonEnvironment {
        prefix: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonDescriptor {
    schema: u32,
    interpreter: String,
    prefix: String,
}

fn valid_private_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PATH_LIMIT
        && !value.contains('\0')
        && Path::new(value).is_absolute()
}

fn parse_descriptor(raw: &OsStr) -> Result<PythonDescriptor, &'static str> {
    let invalid = "invalid_runtime_manifest";
    if raw.len() > DESCRIPTOR_LIMIT {
        return Err(invalid);
    }
    let descriptor: PythonDescriptor =
        serde_json::from_str(raw.to_str().ok_or(invalid)?).map_err(|_| invalid)?;
    if descriptor.schema != 1
        || !valid_private_path(&descriptor.interpreter)
        || !valid_private_path(&descriptor.prefix)
    {
        return Err(invalid);
    }
    Ok(descriptor)
}

fn load_selected(
    runtime: Option<PathBuf>,
    descriptor: impl FnOnce() -> Option<OsString>,
) -> Result<Loaded, &'static str> {
    if let Some(runtime) = runtime {
        return load(runtime);
    }
    let raw = descriptor().ok_or("runtime_unavailable")?;
    let descriptor = parse_descriptor(&raw)?;
    // Follow the symlink for validation only; executing its original pathname
    // is essential to Python's virtual-environment discovery.
    let metadata = fs::metadata(&descriptor.interpreter).map_err(|_| "runtime_unavailable")?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("runtime_unavailable");
    }
    Ok(Loaded {
        interpreter: descriptor.interpreter,
        source: Source::PythonEnvironment {
            prefix: descriptor.prefix,
        },
    })
}

fn current_platform() -> String {
    let os = if std::env::consts::OS == "macos" {
        "darwin"
    } else {
        std::env::consts::OS
    };
    format!("{}-{os}", std::env::consts::ARCH)
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
    (match &identity.provenance {
        RuntimeProvenance::NixBundle { runtime_id } => lower_hash(runtime_id),
        RuntimeProvenance::PythonEnvironment {} => true,
    }) && public_token(&identity.platform, 64)
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
        || manifest.identity.platform != current_platform()
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
        source: Source::Bundle {
            root,
            identity: manifest.identity,
        },
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

fn report(stdout: &str, source: &Source) -> RuntimeCheck {
    let parsed = if stdout.len() <= REPORT_LIMIT as usize {
        serde_json::from_str::<HealthReport>(stdout).ok()
    } else {
        None
    };
    match parsed {
        Some(HealthReport::Passed {
            schema: 2,
            identity,
        }) if valid_identity(&identity) => {
            let matches_source = match source {
                Source::Bundle {
                    identity: expected, ..
                } => &identity == expected,
                Source::PythonEnvironment { .. } => {
                    identity.provenance == RuntimeProvenance::PythonEnvironment {}
                        && identity.platform == current_platform()
                }
            };
            if matches_source {
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
            schema: 2,
            error_code,
        }) => RuntimeCheck::failed(error_code.code()),
        _ => RuntimeCheck::failed("runtime_protocol_error"),
    }
}

fn observed(reply: ControllerReply, source: &Source) -> RuntimeCheck {
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
    report(&data.stdout, source)
}

pub(crate) async fn check(runtime: Option<PathBuf>, ctx: RuntimeContext<'_>) -> RuntimeCheck {
    if let Some(code) = interrupted(&ctx) {
        return RuntimeCheck::not_tested(code);
    }
    // Never select away from started blocking I/O: join it before observing
    // cancellation. As with the controller owner, a broken OS may delay return.
    let loaded = tokio::task::spawn_blocking(move || {
        load_selected(runtime, || std::env::var_os("SSH_MCP_PYTHON_RUNTIME"))
    })
    .await;
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
    let input_json = match request(&loaded) {
        Ok(input) => input,
        Err(code) => return RuntimeCheck::failed(code),
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
    observed(run.reply, &loaded.source)
}

fn request(loaded: &Loaded) -> Result<Vec<u8>, &'static str> {
    #[derive(Serialize)]
    #[serde(tag = "source", rename_all = "snake_case")]
    enum Input<'a> {
        Bundle {
            schema: u32,
            runtime_root: &'a Path,
        },
        PythonEnvironment {
            schema: u32,
            interpreter: &'a str,
            prefix: &'a str,
        },
    }
    let input = match &loaded.source {
        Source::Bundle { root, .. } => Input::Bundle {
            schema: 1,
            runtime_root: root,
        },
        Source::PythonEnvironment { prefix } => Input::PythonEnvironment {
            schema: 1,
            interpreter: &loaded.interpreter,
            prefix,
        },
    };
    let bytes = serde_json::to_vec(&input).map_err(|_| "invalid_runtime_manifest")?;
    if bytes.len() > MANIFEST_LIMIT {
        return Err("invalid_runtime_manifest");
    }
    Ok(bytes)
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
        let Source::Bundle { identity, .. } = exact.source else {
            panic!("bundle source expected");
        };
        assert_eq!(
            identity.provenance,
            RuntimeProvenance::NixBundle {
                runtime_id: "a".repeat(64)
            }
        );
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
        let source = Source::Bundle {
            root: PathBuf::from("/private/bundle"),
            identity: expected.clone(),
        };
        for text in [
            "{\"schema\":2,\"status\":\"failed\",\"error_code\":\"unknown\"}",
            "{\"schema\":2,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\",\"identity\":null}",
            "{\"schema\":1,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\"}",
            "{\"schema\":2,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\"} {}",
            "{\"schema\":2,\"schema\":2,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\"}",
            "{\"schema\":2,\"status\":\"failed\",\"error_code\":\"runtime_import_failed\",\"source\":\"bundle\"}",
        ] {
            assert_eq!(
                report(text, &source).error_code,
                Some("runtime_protocol_error")
            );
        }
        let mut changed = expected.clone();
        changed.python = "3.14.9".to_owned();
        let text = json!({"schema": 2, "status": "passed", "identity": changed}).to_string();
        assert_eq!(
            report(&text, &source).error_code,
            Some("runtime_identity_mismatch")
        );
        assert_eq!(
            report(&" ".repeat(REPORT_LIMIT as usize + 1), &source).error_code,
            Some("runtime_protocol_error")
        );
    }

    fn descriptor(interpreter: &str, prefix: &str) -> OsString {
        json!({"schema": 1, "interpreter": interpreter, "prefix": prefix})
            .to_string()
            .into()
    }

    #[test]
    fn descriptor_rejects_unknown_duplicate_schema_and_invalid_paths() {
        let invalid = [
            r#"{"schema":1,"interpreter":"/python","prefix":"/venv","extra":true}"#,
            r#"{"schema":1,"schema":1,"interpreter":"/python","prefix":"/venv"}"#,
            r#"{"schema":1,"interpreter":"/python","interpreter":"/other","prefix":"/venv"}"#,
            r#"{"schema":1,"interpreter":"/python","prefix":"/venv","prefix":"/other"}"#,
            r#"{"schema":2,"interpreter":"/python","prefix":"/venv"}"#,
            r#"{"schema":true,"interpreter":"/python","prefix":"/venv"}"#,
            r#"{"schema":1,"interpreter":"/python"}"#,
            r#"{"schema":1,"interpreter":"/python","prefix":"/venv"} {}"#,
        ];
        for raw in invalid {
            assert!(
                matches!(
                    parse_descriptor(OsStr::new(raw)),
                    Err("invalid_runtime_manifest")
                ),
                "{raw}"
            );
        }
        for path in ["", "relative", "/bad\0path"] {
            assert!(
                parse_descriptor(&descriptor(path, "/venv")).is_err(),
                "{path:?}"
            );
            assert!(
                parse_descriptor(&descriptor("/python", path)).is_err(),
                "{path:?}"
            );
        }
        use std::os::unix::ffi::OsStringExt;
        assert!(parse_descriptor(&OsString::from_vec(vec![0xff])).is_err());
    }

    #[test]
    fn descriptor_enforces_exact_raw_and_utf8_path_bounds() {
        let path = format!("/{}", "x".repeat(PATH_LIMIT - 1));
        assert!(parse_descriptor(&descriptor(&path, &path)).is_ok());
        let too_long = format!("{path}x");
        assert!(parse_descriptor(&descriptor(&too_long, "/venv")).is_err());
        assert!(parse_descriptor(&descriptor("/python", &too_long)).is_err());
        let multibyte = format!("/{}", "é".repeat(PATH_LIMIT / 2));
        assert!(parse_descriptor(&descriptor(&multibyte, "/venv")).is_err());
        let mut raw = descriptor("/python", "/venv").into_string().unwrap();
        raw.extend(std::iter::repeat_n(' ', DESCRIPTOR_LIMIT - raw.len()));
        assert!(parse_descriptor(OsStr::new(&raw)).is_ok());
        raw.push(' ');
        assert!(parse_descriptor(OsStr::new(&raw)).is_err());
    }

    #[test]
    fn explicit_bundle_never_consults_environment_even_if_broken() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            load_selected(Some(root.path().join("missing")), || panic!(
                "descriptor consulted"
            )),
            Err("runtime_unavailable")
        ));
        assert!(matches!(
            load_selected(Some(root.path().to_owned()), || panic!(
                "descriptor consulted"
            )),
            Err("invalid_runtime_manifest")
        ));
        assert!(matches!(
            load_selected(None, || None),
            Err("runtime_unavailable")
        ));
    }

    #[test]
    fn environment_selection_preserves_symlink_and_tags_bounded_request() {
        let root = tempfile::tempdir().unwrap();
        let interpreter = root.path().join("python");
        std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &interpreter).unwrap();
        let raw = descriptor(interpreter.to_str().unwrap(), root.path().to_str().unwrap());
        let loaded = load_selected(None, || Some(raw)).unwrap();
        assert_eq!(loaded.interpreter, interpreter.to_str().unwrap());
        fs::remove_file(&interpreter).unwrap();
        fs::write(&interpreter, b"not executable").unwrap();
        fs::set_permissions(&interpreter, Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            load_selected(None, || Some(descriptor(
                interpreter.to_str().unwrap(),
                "/venv"
            ))),
            Err("runtime_unavailable")
        ));
        assert!(matches!(
            load_selected(None, || Some(descriptor(
                root.path().to_str().unwrap(),
                "/venv"
            ))),
            Err("runtime_unavailable")
        ));
        let escaped = format!("/{}", "\u{1}".repeat(PATH_LIMIT - 1));
        let loaded = Loaded {
            interpreter: escaped.clone(),
            source: Source::PythonEnvironment { prefix: escaped },
        };
        assert!(matches!(request(&loaded), Err("invalid_runtime_manifest")));
    }

    #[test]
    fn reports_bind_source_and_reject_provenance_spoofing() {
        let bundle_identity = parse_manifest(&serde_json::to_vec(&manifest()).unwrap())
            .unwrap()
            .identity;
        let bundle = Source::Bundle {
            root: PathBuf::from("/private/bundle"),
            identity: bundle_identity.clone(),
        };
        let environment = Source::PythonEnvironment {
            prefix: "/private/venv".to_owned(),
        };
        let mut observed_identity = bundle_identity.clone();
        observed_identity.provenance = RuntimeProvenance::PythonEnvironment {};
        // Environment Python patch versions are observations, not Nix pins.
        observed_identity.python = "3.14.9".to_owned();
        let environment_report =
            json!({"schema": 2, "status": "passed", "identity": observed_identity});
        let passed = report(&environment_report.to_string(), &environment);
        assert!(passed.is_passed());
        let public = serde_json::to_value(passed).unwrap();
        assert_eq!(
            public["identity"]["provenance"],
            json!({"kind": "python_environment"})
        );
        assert!(!public.to_string().contains("/private"));
        assert_eq!(
            report(&environment_report.to_string(), &bundle).error_code,
            Some("runtime_identity_mismatch")
        );
        let bundle_report = json!({"schema": 2, "status": "passed", "identity": bundle_identity});
        assert!(report(&bundle_report.to_string(), &bundle).is_passed());
        assert_eq!(
            report(&bundle_report.to_string(), &environment).error_code,
            Some("runtime_identity_mismatch")
        );
        for provenance in [
            json!({"kind": "python_environment", "runtime_id": "a".repeat(64)}),
            json!({"kind": "python_environment", "prefix": "/private/venv"}),
            json!({"kind": "nix_bundle"}),
            json!({"kind": "nix_bundle", "runtime_id": "A".repeat(64)}),
            json!({"kind": "unknown"}),
        ] {
            let mut invalid = environment_report.clone();
            invalid["identity"]["provenance"] = provenance;
            assert_eq!(
                report(&invalid.to_string(), &environment).error_code,
                Some("runtime_protocol_error")
            );
        }
        for provenance in [
            r#"{"kind":"python_environment","kind":"nix_bundle","runtime_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
            r#"{"kind":"nix_bundle","runtime_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","runtime_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ] {
            let identity_json = environment_report["identity"]
                .to_string()
                .replace(r#"{"kind":"python_environment"}"#, provenance);
            let text = format!(r#"{{"schema":2,"status":"passed","identity":{identity_json}}}"#);
            assert_eq!(
                report(&text, &environment).error_code,
                Some("runtime_protocol_error")
            );
        }
        let mut wrong_platform = environment_report.clone();
        wrong_platform["identity"]["platform"] = json!("wrong-platform");
        assert_eq!(
            report(&wrong_platform.to_string(), &environment).error_code,
            Some("runtime_identity_mismatch")
        );
        let mut leaked_path = environment_report;
        leaked_path["identity"]["python"] = json!("/private/python");
        assert_eq!(
            report(&leaked_path.to_string(), &environment).error_code,
            Some("runtime_protocol_error")
        );
        let failure = r#"{"schema":2,"status":"failed","error_code":"runtime_import_failed"}"#;
        assert_eq!(
            report(failure, &environment).error_code,
            Some("runtime_import_failed")
        );
    }
}
