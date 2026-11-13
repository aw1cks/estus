//! Optional selected-runtime health and explicit public module documentation import.
//! Neither path executes automation workloads or attests execution compatibility.
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
const MODULE_REPORT_LIMIT: u64 = 2 * 1024 * 1024 + REPORT_LIMIT;
const PATH_LIMIT: usize = 4096;
const DESCRIPTOR_LIMIT: usize = 65_536;
// A selected descriptor may contain four full paths. Leave bounded room for
// the source tag instead of applying the smaller immutable-manifest budget.
const REQUEST_LIMIT: usize = DESCRIPTOR_LIMIT + 1024;

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

pub(crate) struct ModuleImport {
    pub identity: RuntimeIdentity,
    pub document: serde_json::Value,
    pub content_sha256: String,
    pub collection: Option<RuntimeCollection>,
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
#[serde(deny_unknown_fields)]
struct ModuleReport {
    schema: u32,
    status: ModuleStatus,
    #[serde(default, deserialize_with = "present_field")]
    identity: Option<RuntimeIdentity>,
    #[serde(default, deserialize_with = "present_field")]
    document: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "present_field")]
    content_sha256: Option<String>,
    #[serde(default, deserialize_with = "present_field")]
    collection: Option<Option<RuntimeCollection>>,
    #[serde(default, deserialize_with = "present_field")]
    error_code: Option<ModuleError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModuleStatus {
    Passed,
    Failed,
}

// Missing fields are None, but explicitly present null is not absence.
fn present_field<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

enum RuntimeFailure {
    NotTested(&'static str),
    Failed(&'static str),
}

impl RuntimeFailure {
    fn code(self) -> &'static str {
        match self {
            Self::NotTested(code) | Self::Failed(code) => code,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ModuleError {
    InvalidModuleIdentifier,
    ModuleOutputLimit,
    ModuleContentLimit,
    ModuleContentFailed,
    ModuleContentSymlink,
    ModuleNotFound,
    ModuleDocumentationFailed,
    ModuleIdentifierMismatch,
    #[serde(untagged)]
    Health(HealthError),
}

impl ModuleError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidModuleIdentifier => "invalid_module_identifier",
            Self::ModuleOutputLimit => "module_output_limit",
            Self::ModuleContentLimit => "module_content_limit",
            Self::ModuleContentFailed => "module_content_failed",
            Self::ModuleContentSymlink => "module_content_symlink",
            Self::ModuleNotFound => "module_not_found",
            Self::ModuleDocumentationFailed => "module_documentation_failed",
            Self::ModuleIdentifierMismatch => "module_identifier_mismatch",
            Self::Health(error) => error.code(),
        }
    }
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
        package_root: String,
        scripts: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PythonDescriptor {
    schema: u32,
    interpreter: String,
    prefix: String,
    package_root: String,
    scripts: String,
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
    if descriptor.schema != 2
        || !valid_private_path(&descriptor.interpreter)
        || !valid_private_path(&descriptor.prefix)
        || !valid_private_path(&descriptor.package_root)
        || !valid_private_path(&descriptor.scripts)
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
            package_root: descriptor.package_root,
            scripts: descriptor.scripts,
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

pub(crate) fn valid_collection(collection: &RuntimeCollection) -> bool {
    let mut parts = collection.name.split('.');
    let namespace = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    parts.next().is_none()
        && [namespace, name].iter().all(|part| {
            !part.is_empty()
                && part.len() <= 64
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && public_token(&collection.version, 64)
        && lower_hash(&collection.manifest_sha256)
}

pub(crate) fn valid_identity(identity: &RuntimeIdentity) -> bool {
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
        && identity.collections.iter().all(valid_collection)
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

fn matches_source(identity: &RuntimeIdentity, source: &Source) -> bool {
    match source {
        Source::Bundle {
            identity: expected, ..
        } => identity == expected,
        Source::PythonEnvironment { .. } => {
            identity.provenance == RuntimeProvenance::PythonEnvironment {}
                && identity.platform == current_platform()
        }
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
            if matches_source(&identity, source) {
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

fn observed_stdout(reply: ControllerReply) -> Result<String, &'static str> {
    let Some(data) = reply.data else {
        return Err("runtime_check_failed");
    };
    match data.termination {
        ControllerTermination::Cancelled => return Err("runtime_cancelled"),
        ControllerTermination::Timeout => return Err("runtime_timeout"),
        _ => {}
    }
    if data.owned_group_cleanup == GroupCleanup::Incomplete
        || reply
            .error
            .as_ref()
            .is_some_and(|error| error.code == "cleanup_incomplete")
    {
        return Err("runtime_cleanup_failed");
    }
    if reply.error.is_some()
        || data.termination != ControllerTermination::Exited
        || data.exit_code != Some(0)
        || data.signal.is_some()
    {
        return Err("runtime_check_failed");
    }
    if data.owned_group_cleanup != GroupCleanup::SignalledAndReaped {
        return Err("runtime_cleanup_failed");
    }
    if data.stdout_truncated || data.stdout_lossy || data.stderr_truncated || data.stderr_lossy {
        return Err("runtime_protocol_error");
    }
    Ok(data.stdout)
}

fn observed(reply: ControllerReply, source: &Source) -> RuntimeCheck {
    match observed_stdout(reply) {
        Ok(stdout) => report(&stdout, source),
        Err(code) => RuntimeCheck::failed(code),
    }
}

pub(crate) async fn check(runtime: Option<PathBuf>, ctx: RuntimeContext<'_>) -> RuntimeCheck {
    match run_selected(runtime, &ctx, None).await {
        Ok((reply, source)) => observed(reply, &source),
        Err(RuntimeFailure::NotTested(code)) => RuntimeCheck::not_tested(code),
        Err(RuntimeFailure::Failed(code)) => RuntimeCheck::failed(code),
    }
}

pub(crate) async fn import_module(
    runtime: Option<PathBuf>,
    module: &str,
    ctx: RuntimeContext<'_>,
) -> Result<ModuleImport, &'static str> {
    if !crate::module_schema::valid_fqcn(module) {
        return Err("invalid_module_identifier");
    }
    let (reply, source) = run_selected(runtime, &ctx, Some(module))
        .await
        .map_err(RuntimeFailure::code)?;
    module_report(&observed_stdout(reply)?, &source, module)
}

fn module_report(
    stdout: &str,
    source: &Source,
    module: &str,
) -> Result<ModuleImport, &'static str> {
    if stdout.len() > MODULE_REPORT_LIMIT as usize {
        return Err("runtime_protocol_error");
    }
    match serde_json::from_str::<ModuleReport>(stdout).map_err(|_| "runtime_protocol_error")? {
        ModuleReport {
            schema: 2,
            status: ModuleStatus::Passed,
            identity: Some(identity),
            document: Some(document),
            content_sha256: Some(content_sha256),
            collection: Some(collection),
            error_code: None,
        } if valid_identity(&identity) && lower_hash(&content_sha256) => {
            if !matches_source(&identity, source) {
                return Err("runtime_identity_mismatch");
            }
            let collection_name = module
                .match_indices('.')
                .nth(1)
                .map(|(index, _)| &module[..index])
                .ok_or("runtime_protocol_error")?;
            match &collection {
                None if collection_name == "ansible.builtin" => {}
                Some(selected)
                    if collection_name != "ansible.builtin"
                        && selected.name == collection_name
                        && valid_collection(selected) =>
                {
                    if identity
                        .collections
                        .iter()
                        .any(|baseline| baseline.name == selected.name && baseline != selected)
                    {
                        return Err("runtime_collection_mismatch");
                    }
                }
                _ => return Err("runtime_collection_mismatch"),
            }
            let doc = document
                .get("doc")
                .and_then(serde_json::Value::as_object)
                .ok_or("runtime_protocol_error")?;
            if doc.get("plugin_name").and_then(serde_json::Value::as_str) != Some(module) {
                return Err("module_identifier_mismatch");
            }
            Ok(ModuleImport {
                identity,
                document,
                content_sha256,
                collection,
            })
        }
        ModuleReport {
            schema: 2,
            status: ModuleStatus::Failed,
            identity: None,
            document: None,
            content_sha256: None,
            collection: None,
            error_code: Some(error_code),
        } => Err(error_code.code()),
        _ => Err("runtime_protocol_error"),
    }
}

async fn run_selected(
    runtime: Option<PathBuf>,
    ctx: &RuntimeContext<'_>,
    module: Option<&str>,
) -> Result<(ControllerReply, Source), RuntimeFailure> {
    if let Some(code) = interrupted(ctx) {
        return Err(RuntimeFailure::NotTested(code));
    }
    // Retain started blocking I/O ownership even during cancellation.
    let loaded = tokio::task::spawn_blocking(move || {
        load_selected(runtime, || std::env::var_os("SSH_MCP_PYTHON_RUNTIME"))
    })
    .await;
    if let Some(code) = interrupted(ctx) {
        return Err(RuntimeFailure::NotTested(code));
    }
    let loaded = match loaded {
        Ok(Ok(loaded)) => loaded,
        Ok(Err(code)) => return Err(RuntimeFailure::Failed(code)),
        Err(_) => return Err(RuntimeFailure::Failed("runtime_check_failed")),
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
        _ => return Err(RuntimeFailure::Failed("runtime_check_failed")),
    };
    let result = if let Some(code) = interrupted(ctx) {
        Err(RuntimeFailure::NotTested(code))
    } else {
        run_loaded(loaded, root.path(), ctx, module).await
    };
    // The private root outlives the controller's pending process-group owner.
    if !matches!(
        tokio::task::spawn_blocking(move || root.close()).await,
        Ok(Ok(()))
    ) {
        return Err(RuntimeFailure::Failed("runtime_cleanup_failed"));
    }
    result
}

async fn run_loaded(
    loaded: Loaded,
    workspace: &Path,
    ctx: &RuntimeContext<'_>,
    module: Option<&str>,
) -> Result<(ControllerReply, Source), RuntimeFailure> {
    let mut input_json = request(&loaded).map_err(RuntimeFailure::Failed)?;
    if let Some(module) = module {
        let mut input: serde_json::Value = serde_json::from_slice(&input_json)
            .map_err(|_| RuntimeFailure::Failed("invalid_runtime_manifest"))?;
        input["module"] = serde_json::Value::String(module.to_owned());
        input_json = serde_json::to_vec(&input)
            .map_err(|_| RuntimeFailure::Failed("invalid_runtime_manifest"))?;
        if input_json.len() > REQUEST_LIMIT {
            return Err(RuntimeFailure::Failed("invalid_runtime_manifest"));
        }
    }
    let limit = if module.is_some() {
        MODULE_REPORT_LIMIT
    } else {
        REPORT_LIMIT
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
        max_output_bytes: limit,
        supervision: controller::ControllerSupervision::Script,
    };
    let run = controller::run(
        prepared,
        ControllerContext {
            deadline: ctx.deadline,
            ct: ctx.ct,
            shutdown: ctx.shutdown,
            started: Instant::now(),
            capture_limit: limit,
        },
    )
    .await;
    if let Some(pending) = run.pending {
        pending.finish().await;
    }
    Ok((run.reply, loaded.source))
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
            package_root: &'a str,
            scripts: &'a str,
        },
    }
    let input = match &loaded.source {
        Source::Bundle { root, .. } => Input::Bundle {
            schema: 2,
            runtime_root: root,
        },
        Source::PythonEnvironment {
            prefix,
            package_root,
            scripts,
        } => Input::PythonEnvironment {
            schema: 2,
            interpreter: &loaded.interpreter,
            prefix,
            package_root,
            scripts,
        },
    };
    let bytes = serde_json::to_vec(&input).map_err(|_| "invalid_runtime_manifest")?;
    if bytes.len() > REQUEST_LIMIT {
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
        json!({"schema": 2, "interpreter": interpreter, "prefix": prefix,
            "package_root": prefix, "scripts": prefix})
        .to_string()
        .into()
    }

    #[test]
    fn descriptor_rejects_unknown_duplicate_schema_and_invalid_paths() {
        let raw = descriptor("/python", "/venv").into_string().unwrap();
        let base: Value = serde_json::from_str(&raw).unwrap();
        let mut invalid = vec![format!("{raw} {{}}")];
        for field in ["schema", "interpreter", "prefix", "package_root", "scripts"] {
            invalid.push(format!(
                "{},\"{field}\":{}}}",
                raw.strip_suffix('}').unwrap(),
                base[field]
            ));
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove(field);
            invalid.push(missing.to_string());
        }
        for schema in [json!(1), json!(3), json!(true), json!("2")] {
            let mut value = base.clone();
            value["schema"] = schema;
            invalid.push(value.to_string());
        }
        let mut unknown = base.clone();
        unknown["extra"] = json!(true);
        invalid.push(unknown.to_string());
        for raw in invalid {
            assert!(
                matches!(
                    parse_descriptor(OsStr::new(&raw)),
                    Err("invalid_runtime_manifest")
                ),
                "{raw}"
            );
        }
        for field in ["interpreter", "prefix", "package_root", "scripts"] {
            for path in ["", "relative", "/bad\0path"] {
                let mut value = base.clone();
                value[field] = json!(path);
                assert!(
                    parse_descriptor(OsStr::new(&value.to_string())).is_err(),
                    "{field}={path:?}"
                );
            }
        }
        use std::os::unix::ffi::OsStringExt;
        assert!(parse_descriptor(&OsString::from_vec(vec![0xff])).is_err());
    }

    #[test]
    fn descriptor_enforces_exact_raw_and_utf8_path_bounds() {
        let path = format!("/{}", "x".repeat(PATH_LIMIT - 1));
        assert!(parse_descriptor(&descriptor(&path, &path)).is_ok());
        let too_long = format!("{path}x");
        let multibyte = format!("/{}", "é".repeat(PATH_LIMIT / 2));
        for field in ["interpreter", "prefix", "package_root", "scripts"] {
            for path in [&too_long, &multibyte] {
                let mut value: Value =
                    serde_json::from_str(descriptor("/python", "/venv").to_str().unwrap()).unwrap();
                value[field] = json!(path);
                assert!(
                    parse_descriptor(OsStr::new(&value.to_string())).is_err(),
                    "{field} exceeded path bound"
                );
            }
        }
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
        let path = format!("/{}", "x".repeat(PATH_LIMIT - 1));
        let full_paths = Loaded {
            interpreter: path.clone(),
            source: Source::PythonEnvironment {
                prefix: path.clone(),
                package_root: path.clone(),
                scripts: path,
            },
        };
        assert!(
            request(&full_paths).is_ok(),
            "four valid maximum-length paths must fit"
        );
        let escaped = format!("/{}", "\u{1}".repeat(PATH_LIMIT - 1));
        let loaded = Loaded {
            interpreter: escaped.clone(),
            source: Source::PythonEnvironment {
                prefix: escaped.clone(),
                package_root: escaped.clone(),
                scripts: escaped,
            },
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
        let bundle_request: Value = serde_json::from_slice(
            &request(&Loaded {
                interpreter: "/private/bundle/bin/python3".to_owned(),
                source: Source::Bundle {
                    root: PathBuf::from("/private/bundle"),
                    identity: bundle_identity.clone(),
                },
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            bundle_request,
            json!({"schema":2,"source":"bundle","runtime_root":"/private/bundle"})
        );
        let environment = Source::PythonEnvironment {
            prefix: "/private/venv".to_owned(),
            package_root: "/private/venv/lib/python3.14/site-packages/ssh_mcp".to_owned(),
            scripts: "/private/venv/bin".to_owned(),
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

#[cfg(test)]
mod module_import_tests {
    use super::*;
    use serde_json::json;

    fn identity() -> RuntimeIdentity {
        RuntimeIdentity {
            provenance: RuntimeProvenance::PythonEnvironment {},
            platform: current_platform(),
            python: "3.14.8".to_owned(),
            ansible_core: "2.21.5".to_owned(),
            ansible_runner: "2.4.3".to_owned(),
            collection_bundle: "14.4.0".to_owned(),
            collections: ["ansible.posix", "community.general"]
                .into_iter()
                .map(|name| RuntimeCollection {
                    name: name.to_owned(),
                    version: "1.0.0".to_owned(),
                    manifest_sha256: "a".repeat(64),
                })
                .collect(),
        }
    }

    fn source() -> Source {
        Source::PythonEnvironment {
            prefix: "/private/selected".to_owned(),
            package_root: "/private/selected/site/ssh_mcp".to_owned(),
            scripts: "/private/selected/bin".to_owned(),
        }
    }

    #[test]
    fn module_protocol_binds_identity_document_and_content() {
        let document = json!({"doc": {
            "plugin_name": "ansible.builtin.copy", "collection": "ansible.builtin",
            "filename": "ansible/modules/copy.py", "options": {}
        }, "examples": "", "return": {}});
        let base = json!({"schema": 2, "status": "passed", "identity": identity(),
            "document": document, "content_sha256": "b".repeat(64), "collection": null});
        let imported = module_report(&base.to_string(), &source(), "ansible.builtin.copy").unwrap();
        assert_eq!(imported.identity, identity());
        assert_eq!(imported.document, document);
        assert_eq!(imported.content_sha256, "b".repeat(64));
        assert_eq!(imported.collection, None);
        assert!(!imported.document.to_string().contains("/private"));
        assert!(matches!(
            module_report(&base.to_string(), &source(), "ansible.builtin.file"),
            Err("module_identifier_mismatch")
        ));
        let mut changed = base.clone();
        changed["identity"]["platform"] = json!("wrong-platform");
        assert!(matches!(
            module_report(&changed.to_string(), &source(), "ansible.builtin.copy"),
            Err("runtime_identity_mismatch")
        ));
        for field in ["content_sha256", "identity", "document"] {
            let mut changed = base.clone();
            changed[field] = json!(null);
            assert!(
                module_report(&changed.to_string(), &source(), "ansible.builtin.copy").is_err()
            );
        }
        for error_code in [json!(null), json!("module_not_found")] {
            let mut changed = base.clone();
            changed["error_code"] = error_code;
            assert!(
                module_report(&changed.to_string(), &source(), "ansible.builtin.copy").is_err()
            );
        }
        for field in ["identity", "document", "content_sha256", "collection"] {
            for value in [json!(null), base[field].clone()] {
                let mut changed = json!({"schema": 2, "status": "failed",
                    "error_code": "module_not_found"});
                changed[field] = value;
                assert!(
                    module_report(&changed.to_string(), &source(), "ansible.builtin.copy").is_err()
                );
            }
        }
        let mut changed = base.clone();
        changed["content_sha256"] = json!("B".repeat(64));
        assert!(module_report(&changed.to_string(), &source(), "ansible.builtin.copy").is_err());
        let mut changed = base.clone();
        changed["private_path"] = json!("/private/selected");
        assert!(module_report(&changed.to_string(), &source(), "ansible.builtin.copy").is_err());
        assert!(module_report(&format!("{base} {{}}"), &source(), "ansible.builtin.copy").is_err());
        assert!(
            module_report(
                &" ".repeat(MODULE_REPORT_LIMIT as usize + 1),
                &source(),
                "ansible.builtin.copy"
            )
            .is_err()
        );
    }

    #[test]
    fn selected_collection_provenance_is_required_and_bound() {
        for name in ["community.general", "other.collection"] {
            let selected = RuntimeCollection {
                name: name.to_owned(),
                version: "1.0.0".to_owned(),
                manifest_sha256: "a".repeat(64),
            };
            let module = format!("{name}.nested.module");
            let base = json!({"schema": 2, "status": "passed", "identity": identity(),
                "document": {"doc": {"plugin_name": module}}, "content_sha256": "b".repeat(64),
                "collection": selected});
            let imported = module_report(&base.to_string(), &source(), &module).unwrap();
            assert_eq!(imported.collection, Some(selected));
            let mut missing = base.clone();
            missing.as_object_mut().unwrap().remove("collection");
            assert!(module_report(&missing.to_string(), &source(), &module).is_err());
            for changed in [
                json!(null),
                json!({"name": "wrong.collection", "version": "1.0.0", "manifest_sha256": "a".repeat(64)}),
                json!({"name": name, "version": "/private/version", "manifest_sha256": "a".repeat(64)}),
                json!({"name": name, "version": "1.0.0", "manifest_sha256": "A".repeat(64)}),
            ] {
                let mut report = base.clone();
                report["collection"] = changed;
                assert!(matches!(
                    module_report(&report.to_string(), &source(), &module),
                    Err("runtime_collection_mismatch")
                ));
            }
            if name == "community.general" {
                let mut drift = base;
                drift["collection"]["version"] = json!("2.0.0");
                assert!(matches!(
                    module_report(&drift.to_string(), &source(), &module),
                    Err("runtime_collection_mismatch")
                ));
            }
        }
        let report = json!({"schema": 2, "status": "passed", "identity": identity(),
            "document": {"doc": {"plugin_name": "ansible.builtin.copy"}},
            "content_sha256": "b".repeat(64),
            "collection": {"name": "ansible.builtin", "version": "1.0.0",
                "manifest_sha256": "a".repeat(64)}});
        assert!(matches!(
            module_report(&report.to_string(), &source(), "ansible.builtin.copy"),
            Err("runtime_collection_mismatch")
        ));
    }

    #[test]
    fn module_failure_codes_are_closed_and_privacy_safe() {
        for code in [
            "module_not_found",
            "module_identifier_mismatch",
            "module_output_limit",
            "module_content_limit",
            "module_content_failed",
            "module_content_symlink",
            "module_documentation_failed",
            "runtime_import_failed",
            "runtime_check_failed",
        ] {
            let report = json!({"schema": 2, "status": "failed", "error_code": code});
            assert_eq!(
                module_report(&report.to_string(), &source(), "ansible.builtin.copy").err(),
                Some(code)
            );
        }
        let report = json!({"schema": 2, "status": "failed", "error_code": "/private/selected"});
        assert_eq!(
            module_report(&report.to_string(), &source(), "ansible.builtin.copy").err(),
            Some("runtime_protocol_error")
        );
    }
}
