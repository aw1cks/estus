use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rmcp::{ErrorData, model::JsonObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    command::Invocation,
    config::{ConfigError, Limits, account_name},
    reply::{ControllerError, ToolError},
};
pub(crate) const EXECUTOR_KIND: &str = "native_argv";
pub(crate) const RESULT_KIND: &str = "command";

const MAX_SCHEMA_BYTES: usize = 16 * 1024;
const RESERVED: &[&str] = &[
    "host",
    "timeout_secs",
    "argv",
    "program",
    "cwd",
    "stdin",
    "user",
    "role",
    "authority",
    "execution",
    "profile",
    "env",
    "shell",
    "sudo",
    "command",
    "revision",
    "effects",
    "result",
    "input_schema",
    "enabled_tools",
];

struct SchemaCounter(usize);
impl io::Write for SchemaCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_SCHEMA_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "schema exceeds limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn schema_fits(value: &impl Serialize) -> bool {
    serde_json::to_writer(SchemaCounter(0), value).is_ok()
}

fn integral_number(value: &Value) -> bool {
    value.as_number().is_some_and(|number| {
        number.as_i64().is_some()
            || number.as_u64().is_some()
            || number
                .as_f64()
                .is_some_and(|value| value.is_finite() && value.fract() == 0.0)
    })
}
fn canonical_integer(value: Value) -> Value {
    let integer = value.as_i64().or_else(|| {
        let number = value.as_f64()?;
        // Strict upper bound avoids saturating i64::MAX after float rounding.
        (number.is_finite()
            && number.fract() == 0.0
            && number >= i64::MIN as f64
            && number < -(i64::MIN as f64))
            .then_some(number as i64)
    });
    integer.map(Value::from).unwrap_or(value)
}
fn unsigned_integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let number = value.as_f64()?;
        (number.is_finite() && number.fract() == 0.0 && number >= 0.0 && number < u64::MAX as f64)
            .then_some(number as u64)
    })
}

fn invalid(reason: &'static str) -> ConfigError {
    ConfigError::new("tools", reason)
}
fn bound(reason: &'static str) -> ToolError {
    ToolError::new("invalid_argument", reason, false)
}
fn shape() -> ErrorData {
    ErrorData::invalid_params("Invalid named tool argument shape", None)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !RESERVED.contains(&value)
}
fn absolute(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 4096 && !value.contains('\0')
}

pub(crate) fn controller_root(root: Option<&str>) -> Result<Arc<Path>, ConfigError> {
    let root = root.ok_or_else(|| invalid("Active controller tools require workspace_root"))?;
    let root =
        fs::canonicalize(root).map_err(|_| invalid("Controller workspace is unavailable"))?;
    let metadata =
        fs::metadata(&root).map_err(|_| invalid("Controller workspace is unavailable"))?;
    if root.as_os_str().as_bytes().len() > 1024
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "Controller workspace must be an owned private directory",
        ));
    }
    Ok(Arc::from(root))
}

fn controller_environment(
    configured: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut bytes = 0usize;
    if configured.len() > 32 {
        return Err(invalid("Controller environment exceeds entry bound"));
    }
    for (name, value) in &configured {
        let application = name.strip_prefix("MCP_").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        });
        bytes += name.len() + value.len();
        if name.len() > 64
            || (!application && !matches!(name.as_str(), "PATH" | "LANG" | "LC_ALL" | "TZ"))
            || value.len() > 4096
            || value.contains('\0')
            || bytes > 8192
        {
            return Err(invalid("Invalid controller environment"));
        }
    }
    let mut environment = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("TZ".into(), "UTC".into()),
    ]);
    environment.extend(configured);
    Ok(environment)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BindingId(pub(crate) usize);

#[derive(Debug)]
pub(crate) struct Bindings {
    entries: Vec<CompiledBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBinding {
    description: String,
    revision: String,
    targets: Option<Vec<String>>,
    authority: toml::Value,
    effects: Vec<Effect>,
    execution: RawExecution,
    input_schema: toml::Value,
    fixed_args: Option<toml::Value>,
    input_map: Option<BTreeMap<String, String>>,
    result: RawResult,
    limits: Option<RawLimits>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawExecution {
    NativeArgv {
        program: String,
        argv: Vec<RawSlot>,
        cwd: Option<String>,
    },
    RemoteScript {
        source: RawScriptSource,
        interpreter: RawInterpreter,
        argv: Vec<RawSlot>,
        cwd: Option<String>,
    },
    ControllerScript {
        source: RawScriptSource,
        interpreter: RawInterpreter,
        environment: Option<BTreeMap<String, String>>,
        cwd: Option<String>,
    },
    AnsibleModule {
        snapshot: String,
        #[serde(default)]
        no_log: bool,
    },
    AnsibleRole {
        snapshot: String,
        role_path: Option<String>,
        #[serde(default)]
        no_log: bool,
    },
    AnsiblePlaybook {
        snapshot: String,
        project_root: String,
        #[serde(default)]
        no_log: bool,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScriptSource {
    path: String,
    content_sha256: String,
    max_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterpreter {
    program: String,
    argv: Vec<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum RawSlot {
    Fixed(String),
    Input(InputSlot),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSlot {
    input: String,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawResult {
    // Empty struct variants keep unknown-option rejection for tagged records.
    Command {},
    ControllerCommand {},
    AnsibleSummary {},
    AnsibleProjection {
        fields: BTreeMap<String, Vec<String>>,
        schema: toml::Value,
        max_bytes: usize,
        max_items: usize,
        max_depth: usize,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    timeout_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchema {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
    required: Vec<String>,
    properties: BTreeMap<String, RawProperty>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawProperty {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    min_length: Option<u64>,
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    max_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maximum: Option<i64>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    choices: Option<Vec<Value>>,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Effect {
    Read,
    SensitiveRead,
    Probe,
    RuntimeWrite,
    PersistentWrite,
    Availability,
    Unknown,
}
#[derive(Debug)]
enum Domain {
    String { minimum: u64, maximum: u64 },
    Integer { minimum: i64, maximum: i64 },
    Boolean,
}
#[derive(Debug)]
struct Input {
    name: String,
    domain: Domain,
    choices: Option<Vec<Value>>,
}
impl Input {
    fn matches_type(&self, value: &Value) -> bool {
        match self.domain {
            Domain::String { .. } => value.is_string(),
            Domain::Integer { .. } => integral_number(value),
            Domain::Boolean => value.is_boolean(),
        }
    }
    fn validate(&self, value: &Value) -> Result<(), ToolError> {
        let valid = match self.domain {
            Domain::String { minimum, maximum } => value.as_str().is_some_and(|v| {
                !v.contains('\0') && (minimum..=maximum).contains(&(v.chars().count() as u64))
            }),
            Domain::Integer { minimum, maximum } => value
                .as_i64()
                .is_some_and(|v| (minimum..=maximum).contains(&v)),
            Domain::Boolean => value.is_boolean(),
        };
        if !valid
            || self
                .choices
                .as_ref()
                .is_some_and(|choices| !choices.contains(value))
        {
            return Err(bound("Named tool input violates its declared bounds"));
        }
        Ok(())
    }
    fn option_safe(&self) -> bool {
        self.choices.is_some()
            || matches!(
                self.domain,
                Domain::Boolean | Domain::Integer { minimum: 0.., .. }
            )
    }
}
#[derive(Debug)]
enum Slot {
    Fixed(String),
    Input(usize),
}
#[derive(Debug)]
enum Authority {
    Ordinary,
    Sudo(String),
    Controller,
}

#[derive(Debug)]
pub(crate) struct ScriptSource {
    pub(crate) path: String,
    pub(crate) content_sha256: [u8; 32],
    pub(crate) max_bytes: usize,
}

#[derive(Debug)]
enum Execution {
    NativeArgv {
        program: String,
        cwd: Option<String>,
        authority: Authority,
    },
    RemoteScript {
        source: ScriptSource,
        program: String,
        prefix: Vec<String>,
        cwd: Option<String>,
    },
    ControllerScript {
        plan: Option<Arc<ControllerPlan>>,
    },
    Ansible {
        snapshot: PathBuf,
        source: AnsibleSource,
        authority: AutomationAuthority,
        overlay: Value,
        no_log: bool,
        projection: Option<Arc<crate::projection::Plan>>,
        // One startup allocation keeps native bindings from reserving the large plan.
        plan: Option<Box<AutomationPlan>>,
    },
}

#[derive(Clone, Debug)]
enum AnsibleSource {
    Module,
    Role { path: Option<PathBuf> },
    Playbook { project_root: PathBuf },
}

#[derive(Debug)]
pub(crate) enum AutomationAuthority {
    Ordinary,
    Named(String),
}

impl AutomationAuthority {
    fn parse(value: &toml::Value) -> Result<Self, ConfigError> {
        match value.as_str() {
            Some("automation") => Ok(Self::Ordinary),
            Some(value) => {
                let name = value
                    .strip_prefix("automation:")
                    .ok_or_else(|| invalid("Invalid automation authority"))?;
                if name.is_empty()
                    || name.len() > 64
                    || !name.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphabetic()
                            || byte == b'_'
                            || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
                    })
                {
                    return Err(invalid("Invalid automation authority"));
                }
                Ok(Self::Named(name.to_owned()))
            }
            None => Err(invalid("Invalid automation authority")),
        }
    }

    pub(crate) fn identity_role(&self) -> crate::config::IdentityRole {
        match self {
            Self::Ordinary => crate::config::IdentityRole::Ordinary,
            Self::Named(_) => crate::config::IdentityRole::Automation,
        }
    }
}

impl Serialize for AutomationAuthority {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Ordinary => serializer.serialize_str("automation"),
            Self::Named(name) => serializer.collect_str(&format_args!("automation:{name}")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledBinding {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) revision: String,
    pub(crate) targets: Vec<String>,
    pub(crate) input_schema: Arc<JsonObject>,
    enabled: bool,
    effects: Vec<Effect>,
    inputs: Vec<Input>,
    execution: Execution,
    argv: Vec<Slot>,
    timeout_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}
pub(crate) struct BindingRequest {
    pub(crate) host: String,
    pub(crate) timeout_secs: Option<u64>,
    values: Vec<Value>,
}
pub(crate) struct PreparedBinding<'a> {
    pub(crate) invocation: Invocation<'a>,
    pub(crate) script: Option<&'a ScriptSource>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
}

pub(crate) enum BindingCall {
    Remote(BindingRequest),
    Controller(ControllerRequest),
    Automation(AutomationRequest),
}

pub(crate) struct AutomationRequest {
    pub(crate) host: String,
    timeout_secs: Option<u64>,
    inputs: Value,
}

pub(crate) struct AutomationTransport<'a> {
    pub authority: crate::config::ResolvedAutomation<'a>,
    pub scratch_bytes: u64,
    pub scratch_files: usize,
    pub started: std::time::Instant,
}

pub(crate) struct AutomationPlan {
    reviewed: ReviewedContent,
    binding: crate::module_schema::CompiledModuleBinding,
    runtime: Value,
    controller: Arc<ControllerPlan>,
}

impl std::fmt::Debug for AutomationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AutomationPlan { reviewed: <private> }")
    }
}

enum ReviewedContent {
    Module {
        reviewed: crate::schema_import::ReviewedModule,
        source: String,
    },
    Role {
        reviewed: crate::role_import::ReviewedRole,
        role_path: Option<PathBuf>,
    },
    Playbook {
        reviewed: crate::playbook_import::ReviewedPlaybook,
        project_root: PathBuf,
    },
}

impl ReviewedContent {
    fn contract(&self) -> &Value {
        match self {
            Self::Module { reviewed, .. } => &reviewed.contract,
            Self::Role { reviewed, .. } => &reviewed.contract,
            Self::Playbook { reviewed, .. } => &reviewed.contract,
        }
    }

    fn binding(&self) -> Option<&Value> {
        match self {
            Self::Module { reviewed, .. } => reviewed.binding.as_ref(),
            Self::Role { reviewed, .. } => reviewed.binding.as_ref(),
            Self::Playbook { reviewed, .. } => reviewed.binding.as_ref(),
        }
    }

    fn expected(&self) -> ExpectedContent<'_> {
        match self {
            Self::Module { reviewed, source } => ExpectedContent::Module(ModuleContent {
                identity: &reviewed.runtime,
                collection: &reviewed.collection,
                content_sha256: &reviewed.content_sha256,
                source,
                module: &reviewed.module,
            }),
            Self::Role {
                reviewed,
                role_path,
            } => ExpectedContent::Role(RoleContent {
                identity: &reviewed.runtime,
                collection: &reviewed.collection,
                content_sha256: &reviewed.content_sha256,
                role: &reviewed.role,
                entry_point: &reviewed.entry_point,
                role_path: role_path.as_deref(),
            }),
            Self::Playbook {
                reviewed,
                project_root,
            } => ExpectedContent::Playbook(PlaybookContent {
                identity: &reviewed.runtime,
                content_sha256: &reviewed.content_sha256,
                playbook: &reviewed.playbook,
                project_root,
            }),
        }
    }

    fn mode(&self) -> crate::automation_exec::ExecutionMode {
        match self {
            Self::Module { .. } => crate::automation_exec::ExecutionMode::Module,
            Self::Role { .. } => crate::automation_exec::ExecutionMode::Role,
            Self::Playbook { .. } => crate::automation_exec::ExecutionMode::Playbook,
        }
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "payload limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct ModuleContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    collection: &'a Option<crate::automation::RuntimeCollection>,
    content_sha256: &'a str,
    source: &'a str,
    module: &'a str,
}

#[derive(Serialize)]
struct RoleContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    collection: &'a Option<crate::automation::RuntimeCollection>,
    content_sha256: &'a str,
    role: &'a str,
    entry_point: &'a str,
    role_path: Option<&'a Path>,
}

#[derive(Serialize)]
struct PlaybookContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    content_sha256: &'a str,
    playbook: &'a str,
    project_root: &'a Path,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ExpectedContent<'a> {
    Module(ModuleContent<'a>),
    Role(RoleContent<'a>),
    Playbook(PlaybookContent<'a>),
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum AgentReference<'a> {
    Inherit,
    Disabled,
    Fixed { socket: &'a Path },
}

#[derive(Serialize)]
struct AutomationSpec<'a> {
    schema: u32,
    invocation_id: &'a str,
    runtime: &'a Value,
    expected: ExpectedContent<'a>,
    destination: &'a str,
    target_python: &'a str,
    ssh_config: Option<&'a Path>,
    ssh_executable: &'a Path,
    r#become: Option<&'a crate::config::AutomationBecome>,
    agent: AgentReference<'a>,
    arguments: &'a Value,
    no_log: bool,
    projection: Option<&'a crate::projection::Plan>,
    timeout_secs: f64,
    scratch_bytes: u64,
    scratch_files: usize,
}

pub(crate) struct ControllerRequest {
    timeout_secs: Option<u64>,
    values: Vec<Value>,
}

#[derive(Debug)]
pub(crate) struct ControllerPlan {
    pub(crate) source: Cow<'static, str>,
    pub(crate) interpreter: String,
    pub(crate) interpreter_argv: Vec<String>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) workspace_root: Arc<Path>,
}

pub(crate) struct PreparedController {
    pub(crate) plan: Arc<ControllerPlan>,
    pub(crate) input_json: Vec<u8>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
    pub(crate) supervision: crate::controller::ControllerSupervision,
}

struct ControllerActivation<'a> {
    workspace_root: Option<&'a str>,
    permitted: bool,
    canonical_root: Option<Arc<Path>>,
}

impl ControllerActivation<'_> {
    fn root(&mut self) -> Result<Arc<Path>, ConfigError> {
        match &self.canonical_root {
            Some(root) => Ok(Arc::clone(root)),
            None => {
                let root = controller_root(self.workspace_root)?;
                self.canonical_root = Some(Arc::clone(&root));
                Ok(root)
            }
        }
    }
}

impl Bindings {
    pub(crate) fn compile(
        raw: BTreeMap<String, toml::Value>,
        enabled: &[String],
        limits: &Limits,
        target_exists: impl Fn(&str) -> bool,
        workspace_root: Option<&str>,
        active_profile: bool,
    ) -> Result<Self, ConfigError> {
        if raw.len() > 32 {
            return Err(invalid("At most 32 named tools are allowed"));
        }
        let selected: BTreeSet<_> = enabled.iter().map(String::as_str).collect();
        if selected.len() != enabled.len() || enabled.iter().any(|name| !raw.contains_key(name)) {
            return Err(ConfigError::new(
                "enabled_tools",
                "Enabled tool names must exist and be unique",
            ));
        }
        let mut activation = ControllerActivation {
            workspace_root,
            permitted: active_profile,
            canonical_root: None,
        };
        let entries = raw
            .into_iter()
            .map(|(name, value)| {
                if !identifier(&name) {
                    return Err(invalid("Invalid named tool identifier"));
                }
                let raw: RawBinding = value
                    .try_into()
                    .map_err(|_| invalid("Invalid named tool definition"))?;
                let enabled = selected.contains(name.as_str());
                CompiledBinding::compile(
                    name,
                    raw,
                    enabled,
                    limits,
                    &target_exists,
                    &mut activation,
                )
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = (BindingId, &CompiledBinding)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, entry)| (BindingId(i), entry))
    }
    pub(crate) fn get(&self, id: BindingId) -> Option<&CompiledBinding> {
        self.entries.get(id.0)
    }

    pub(crate) async fn activate_automation(
        &mut self,
        id: BindingId,
        runtime: Option<PathBuf>,
        root: Arc<Path>,
        agent_socket: Option<std::ffi::OsString>,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<(), ConfigError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let check_interrupted = || {
            if ct.is_cancelled() {
                Err(invalid("cancelled"))
            } else if tokio::time::Instant::now() >= deadline {
                Err(invalid("timeout"))
            } else {
                Ok(())
            }
        };
        check_interrupted()?;
        let binding = self
            .entries
            .get_mut(id.0)
            .ok_or_else(|| invalid("Unknown automation binding"))?;
        let Execution::Ansible {
            snapshot,
            overlay,
            source,
            plan,
            ..
        } = &mut binding.execution
        else {
            return Err(invalid("Not an automation binding"));
        };
        let snapshot = snapshot.clone();
        let overlay = overlay.clone();
        let source = source.clone();
        // Await started blocking work even when cancellation arrives, retaining its ownership.
        let prepared = tokio::task::spawn_blocking(move || {
            let reviewed = match source {
                AnsibleSource::Role { path } => ReviewedContent::Role {
                    reviewed: crate::role_import::load_reviewed(&snapshot).map_err(invalid)?,
                    role_path: path,
                },
                AnsibleSource::Module => ReviewedContent::Module {
                    reviewed: crate::schema_import::load_reviewed(&snapshot).map_err(invalid)?,
                    source: String::new(),
                },
                AnsibleSource::Playbook { project_root } => ReviewedContent::Playbook {
                    reviewed: crate::playbook_import::load_reviewed(&snapshot).map_err(invalid)?,
                    project_root,
                },
            };
            if reviewed
                .binding()
                .is_some_and(|expected| expected != &overlay)
            {
                return Err(invalid(
                    "Reviewed binding overlay does not match configuration",
                ));
            }
            let compiled = match &reviewed {
                ReviewedContent::Module { .. } => {
                    crate::module_schema::compile_binding(reviewed.contract(), &overlay)
                }
                ReviewedContent::Role { .. } => {
                    crate::role_import::compile_binding(reviewed.contract(), &overlay)
                }
                ReviewedContent::Playbook { .. } => {
                    crate::playbook_import::compile_binding(reviewed.contract(), &overlay)
                }
            }
            .map_err(invalid)?;
            Ok((reviewed, compiled))
        })
        .await;
        check_interrupted()?;
        let (mut reviewed, compiled) =
            prepared.map_err(|_| invalid("Automation activation preparation failed"))??;
        let context = crate::automation::RuntimeContext {
            deadline,
            ct,
            shutdown: ct,
        };
        match &mut reviewed {
            ReviewedContent::Module { reviewed, source } => {
                *source = crate::schema_import::verify_reviewed(reviewed, runtime.clone(), context)
                    .await
                    .map_err(invalid)?;
            }
            ReviewedContent::Role {
                reviewed,
                role_path,
            } => {
                crate::role_import::verify_reviewed(
                    reviewed,
                    role_path.as_deref(),
                    runtime.clone(),
                    context,
                )
                .await
                .map_err(invalid)?;
            }
            ReviewedContent::Playbook {
                reviewed,
                project_root,
            } => {
                crate::playbook_import::verify_reviewed(
                    reviewed,
                    project_root,
                    runtime.clone(),
                    context,
                )
                .await
                .map_err(invalid)?;
            }
        }
        check_interrupted()?;
        let selected = tokio::task::spawn_blocking(move || {
            crate::automation::runner_runtime(runtime, root, agent_socket).map_err(invalid)
        })
        .await;
        check_interrupted()?;
        let selected = selected.map_err(|_| invalid("Automation runtime preparation failed"))??;
        *plan = Some(Box::new(AutomationPlan {
            reviewed,
            binding: compiled,
            runtime: selected.payload,
            controller: selected.plan,
        }));
        Ok(())
    }
}
impl CompiledBinding {
    fn compile_automation(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
    ) -> Result<Self, ConfigError> {
        let (snapshot, no_log, source) = match raw.execution {
            RawExecution::AnsibleModule { snapshot, no_log } => {
                (snapshot, no_log, AnsibleSource::Module)
            }
            RawExecution::AnsibleRole {
                snapshot,
                role_path,
                no_log,
            } => {
                if role_path.as_deref().is_some_and(|path| !absolute(path)) {
                    return Err(invalid("Invalid fixed role source"));
                }
                (
                    snapshot,
                    no_log,
                    AnsibleSource::Role {
                        path: role_path.map(PathBuf::from),
                    },
                )
            }
            RawExecution::AnsiblePlaybook {
                snapshot,
                project_root,
                no_log,
            } => {
                if !absolute(&project_root) {
                    return Err(invalid("Invalid fixed playbook project"));
                }
                (
                    snapshot,
                    no_log,
                    AnsibleSource::Playbook {
                        project_root: PathBuf::from(project_root),
                    },
                )
            }
            _ => unreachable!("automation execution selected"),
        };
        let targets = raw.targets.unwrap_or_default();
        let authority = AutomationAuthority::parse(&raw.authority)?;
        if !matches!(
            &raw.result,
            RawResult::AnsibleSummary {} | RawResult::AnsibleProjection { .. }
        ) || raw.description.is_empty()
            || raw.description.len() > 1024
            || !identifier(&raw.revision)
            || !absolute(&snapshot)
            || targets.is_empty()
            || targets.len() > 32
            || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
            || targets.iter().any(|target| !target_exists(target))
            || raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid(
                "Invalid automation binding authority or definition",
            ));
        }
        let projection = match raw.result {
            RawResult::AnsibleSummary {} => None,
            RawResult::AnsibleProjection {
                fields,
                schema,
                max_bytes,
                max_items,
                max_depth,
            } => {
                if !matches!(source, AnsibleSource::Module)
                    && fields.values().any(|path| {
                        path.len() < 2 || path.first().map(String::as_str) != Some("mcp_result")
                    })
                {
                    return Err(invalid(
                        "Workflow projections require mcp_result member paths",
                    ));
                }
                let schema = serde_json::to_value(schema)
                    .map_err(|_| invalid("Invalid projection schema"))?;
                Some(Arc::new(
                    crate::projection::compile(json!({
                        "fields": fields, "schema": schema, "max_bytes": max_bytes,
                        "max_items": max_items, "max_depth": max_depth
                    }))
                    .map_err(invalid)?,
                ))
            }
            _ => unreachable!("module result checked"),
        };
        let schema =
            serde_json::to_value(raw.input_schema).map_err(|_| invalid("Invalid module schema"))?;
        let fixed = raw
            .fixed_args
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| invalid("Invalid fixed module arguments"))?
            .unwrap_or_else(|| json!({}));
        if !fixed.is_object() {
            return Err(invalid("Fixed module arguments must be an object"));
        }
        let overlay = json!({"input_schema":schema,"fixed_args":fixed,"input_map":raw.input_map.unwrap_or_default()});
        crate::module_schema::validate_overlay(&overlay).map_err(invalid)?;
        match &source {
            AnsibleSource::Module => {}
            AnsibleSource::Role { .. } => {
                crate::role_import::validate_overlay(&overlay).map_err(invalid)?;
            }
            AnsibleSource::Playbook { .. } => {
                crate::playbook_import::validate_overlay(&overlay).map_err(invalid)?;
            }
        }
        let timeout_secs = raw.limits.as_ref().and_then(|limits| limits.timeout_secs);
        if timeout_secs.is_some_and(|value| value == 0 || value > limits.max_timeout_secs)
            || raw
                .limits
                .as_ref()
                .and_then(|limits| limits.max_output_bytes)
                .is_some()
        {
            return Err(invalid("Module limits only support a bounded timeout"));
        }
        let published = json!({
            "type":"object","additionalProperties":false,
            "required":["host","inputs"],
            "properties":{
                "host":{"type":"string","enum":targets},
                "inputs":overlay["input_schema"],
                "timeout_secs":{"type":"integer","minimum":1,"maximum":timeout_secs.unwrap_or(limits.max_timeout_secs)}
            }
        }).as_object().cloned().ok_or_else(||invalid("Invalid module metadata"))?;
        if !schema_fits(&published) || !schema_fits(&overlay) {
            return Err(invalid("Module metadata exceeds bound"));
        }
        Ok(Self {
            name,
            description: raw.description,
            revision: raw.revision,
            targets,
            input_schema: Arc::new(published),
            enabled,
            effects: raw.effects,
            inputs: Vec::new(),
            execution: Execution::Ansible {
                snapshot: PathBuf::from(snapshot),
                source,
                authority,
                overlay,
                no_log,
                projection,
                plan: None,
            },
            argv: Vec::new(),
            timeout_secs,
            max_output_bytes: None,
        })
    }

    pub(crate) fn prepare_automation(
        &self,
        request: &AutomationRequest,
        limits: &Limits,
        transport: AutomationTransport<'_>,
    ) -> Result<crate::automation_exec::PreparedAutomation, ToolError> {
        let AutomationTransport {
            authority,
            scratch_bytes,
            scratch_files,
            started,
        } = transport;
        let Execution::Ansible {
            plan: Some(plan),
            no_log,
            projection,
            ..
        } = &self.execution
        else {
            return Err(ToolError::new(
                "policy_denied",
                "Operation is not authorized",
                false,
            ));
        };
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if !self.targets.contains(&request.host)
            || timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
        {
            return Err(bound("Invalid automation host or timeout"));
        }
        let arguments = plan
            .binding
            .prepare(&request.inputs)
            .map_err(|_| bound("Automation inputs violate the reviewed binding"))?;
        let invocation_id = crate::automation_exec::invocation_id();
        let spec = AutomationSpec {
            schema: 2,
            invocation_id: &invocation_id,
            runtime: &plan.runtime,
            expected: plan.reviewed.expected(),
            destination: &authority.target.destination,
            target_python: &authority.target.python,
            ssh_config: authority.ssh_config,
            ssh_executable: authority.ssh_executable,
            r#become: authority.r#become,
            agent: match authority.agent {
                crate::config::AutomationAgent::Inherit => AgentReference::Inherit,
                crate::config::AutomationAgent::Disabled => AgentReference::Disabled,
                crate::config::AutomationAgent::Fixed(socket) => AgentReference::Fixed { socket },
            },
            arguments: &arguments,
            no_log: *no_log,
            projection: projection.as_deref(),
            timeout_secs: Duration::from_secs(timeout)
                .saturating_sub(started.elapsed())
                .as_secs_f64(),
            scratch_bytes,
            scratch_files,
        };
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: 256 * 1024,
        };
        serde_json::to_writer(&mut writer, &spec)
            .map_err(|_| bound("Automation invocation exceeds byte bound"))?;
        let input_json = writer.bytes;
        Ok(crate::automation_exec::PreparedAutomation {
            controller: PreparedController {
                plan: Arc::clone(&plan.controller),
                input_json,
                duration: Duration::from_secs(timeout),
                max_output_bytes: 65_536,
                supervision: crate::controller::ControllerSupervision::Automation {
                    invocation_id,
                    mode: plan.reviewed.mode(),
                    scratch_bytes,
                    scratch_files,
                },
            },
            host: request.host.clone(),
            projection: projection.clone(),
        })
    }

    fn compile(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
        activation: &mut ControllerActivation<'_>,
    ) -> Result<Self, ConfigError> {
        if matches!(
            &raw.execution,
            RawExecution::AnsibleModule { .. }
                | RawExecution::AnsibleRole { .. }
                | RawExecution::AnsiblePlaybook { .. }
        ) {
            return Self::compile_automation(name, raw, enabled, limits, target_exists);
        }
        if raw.fixed_args.is_some() || raw.input_map.is_some() {
            return Err(invalid(
                "Module overlay fields require ansible_module execution",
            ));
        }
        if raw.description.is_empty() || raw.description.len() > 1024 || !identifier(&raw.revision)
        {
            return Err(invalid("Invalid description or revision"));
        }
        let authority = match raw.authority {
            toml::Value::String(value) if value == "ordinary" => Authority::Ordinary,
            toml::Value::String(value) if value == "controller" => Authority::Controller,
            toml::Value::Table(mut value) if value.len() == 1 => match value.remove("sudo") {
                Some(toml::Value::String(user)) if user.len() <= 64 && account_name(&user) => {
                    Authority::Sudo(user)
                }
                _ => return Err(invalid("Invalid fixed sudo account")),
            },
            _ => return Err(invalid("Invalid fixed tool authority")),
        };
        let controller = matches!(&raw.execution, RawExecution::ControllerScript { .. });
        if controller != matches!(authority, Authority::Controller)
            || !matches!(
                (&raw.result, controller),
                (RawResult::ControllerCommand {}, true) | (RawResult::Command {}, false)
            )
        {
            return Err(invalid("Execution, authority and result kinds must agree"));
        }
        if controller && raw.targets.is_some() {
            return Err(invalid("Controller tools must omit targets"));
        }
        let targets = raw.targets.unwrap_or_default();
        if !controller
            && (targets.is_empty()
                || targets.len() > 32
                || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
                || targets.iter().any(|v| !target_exists(v)))
        {
            return Err(invalid("Targets must be unique configured logical targets"));
        }
        if raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid("Effects must be nonempty and unique"));
        }
        let (execution, raw_argv, mut separator) = match raw.execution {
            RawExecution::NativeArgv { program, argv, cwd } => {
                if !absolute(&program)
                    || program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || argv.len() > 64
                {
                    return Err(invalid("Invalid fixed executable layout"));
                }
                if matches!(authority, Authority::Sudo(_)) && cwd.is_some() {
                    return Err(invalid("Elevated bindings do not support cwd"));
                }
                (
                    Execution::NativeArgv {
                        program,
                        cwd,
                        authority,
                    },
                    argv,
                    false,
                )
            }
            RawExecution::RemoteScript {
                source,
                interpreter,
                argv,
                cwd,
            } => {
                if !matches!(authority, Authority::Ordinary) {
                    return Err(invalid("Remote scripts require ordinary authority"));
                }
                if !absolute(&source.path)
                    || source.path.ends_with('/')
                    || !absolute(&interpreter.program)
                    || interpreter.program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || interpreter.argv.len() > 64
                    || argv.len() > 64 - interpreter.argv.len()
                    || interpreter
                        .argv
                        .iter()
                        .any(|v| v.len() > 4096 || v.contains('\0'))
                {
                    return Err(invalid("Invalid fixed remote script layout"));
                }
                let mut content_sha256 = [0; 32];
                if source.content_sha256.len() != 64
                    || hex::decode_to_slice(&source.content_sha256, &mut content_sha256).is_err()
                {
                    return Err(invalid(
                        "Script content_sha256 requires exactly 64 hexadecimal ASCII characters",
                    ));
                }
                let ceiling = limits.max_file_bytes.min(1_048_576);
                let max_bytes = source.max_bytes.unwrap_or(ceiling);
                if max_bytes == 0 || max_bytes > ceiling {
                    return Err(invalid(
                        "Script byte bound must be positive and within the server and 1 MiB ceilings",
                    ));
                }
                let separator = interpreter.argv.iter().any(|v| v == "--");
                (
                    Execution::RemoteScript {
                        source: ScriptSource {
                            path: source.path,
                            content_sha256,
                            max_bytes: max_bytes as usize,
                        },
                        program: interpreter.program,
                        prefix: interpreter.argv,
                        cwd,
                    },
                    argv,
                    separator,
                )
            }
            RawExecution::ControllerScript {
                source,
                interpreter,
                environment,
                cwd,
            } => {
                if !absolute(&source.path)
                    || source.path.ends_with('/')
                    || !absolute(&interpreter.program)
                    || interpreter.program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || interpreter.argv.len() > 64
                    || interpreter
                        .argv
                        .iter()
                        .any(|v| v.len() > 4096 || v.contains('\0'))
                {
                    return Err(invalid("Invalid fixed controller script layout"));
                }
                let mut digest = [0; 32];
                if source.content_sha256.len() != 64
                    || hex::decode_to_slice(&source.content_sha256, &mut digest).is_err()
                {
                    return Err(invalid("Invalid script content_sha256"));
                }
                let ceiling = limits.max_file_bytes.min(1_048_576);
                let max_bytes = source.max_bytes.unwrap_or(ceiling);
                if max_bytes == 0 || max_bytes > ceiling {
                    return Err(invalid("Invalid script byte bound"));
                }
                let environment = controller_environment(environment.unwrap_or_default())?;
                let plan = if enabled && activation.permitted {
                    let root = activation.root()?;
                    let metadata = fs::metadata(&interpreter.program)
                        .map_err(|_| invalid("Controller runtime is unavailable"))?;
                    if !metadata.is_file()
                        || metadata.permissions().mode() & 0o111 == 0
                        || cwd.as_ref().is_some_and(|path| !Path::new(path).is_dir())
                    {
                        return Err(invalid("Controller runtime or cwd is unavailable"));
                    }
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                        .open(&source.path)
                        .map_err(|_| invalid("Controller source is unavailable"))?;
                    if !file
                        .metadata()
                        .map_err(|_| invalid("Controller source is unavailable"))?
                        .is_file()
                    {
                        return Err(invalid("Controller source must be a regular file"));
                    }
                    let mut bytes = Vec::new();
                    file.take(max_bytes + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| invalid("Controller source is unavailable"))?;
                    let source =
                        crate::filedata::verify_script(bytes, true, &digest, max_bytes as usize)
                            .map_err(|_| invalid("Controller source verification failed"))?;
                    Some(Arc::new(ControllerPlan {
                        source: Cow::Owned(source),
                        interpreter: interpreter.program,
                        interpreter_argv: interpreter.argv,
                        cwd: cwd.map(PathBuf::from),
                        environment,
                        workspace_root: root,
                    }))
                } else {
                    None
                };
                (Execution::ControllerScript { plan }, Vec::new(), false)
            }
            RawExecution::AnsibleModule { .. }
            | RawExecution::AnsibleRole { .. }
            | RawExecution::AnsiblePlaybook { .. } => {
                unreachable!("compiled separately")
            }
        };
        let timeout_secs = raw.limits.as_ref().and_then(|v| v.timeout_secs);
        let max_output_bytes = raw.limits.as_ref().and_then(|v| v.max_output_bytes);
        if timeout_secs.is_some_and(|v| v == 0 || v > limits.max_timeout_secs)
            || max_output_bytes.is_some_and(|v| v == 0 || v > limits.max_output_bytes)
        {
            return Err(invalid(
                "Tool limits must be positive and no greater than server ceilings",
            ));
        }
        if !schema_fits(&(&raw.input_schema, &targets)) {
            return Err(invalid("Input schema exceeds metadata bound"));
        }
        let schema: RawSchema = raw
            .input_schema
            .try_into()
            .map_err(|_| invalid("Unsupported input schema"))?;
        if schema.kind != "object"
            || schema.additional_properties
            || schema.properties.len() > 16
            || schema.required.len() != schema.properties.len()
            || schema.required.iter().collect::<BTreeSet<_>>().len() != schema.required.len()
            || schema
                .required
                .iter()
                .any(|v| !schema.properties.contains_key(v))
        {
            return Err(invalid(
                "Input schema must be a closed flat required object",
            ));
        }
        let mut inputs = Vec::with_capacity(schema.properties.len());
        let mut properties = JsonObject::new();
        for (name, mut property) in schema.properties {
            if !parameter(&name) || property.description.as_ref().is_some_and(|v| v.len() > 512) {
                return Err(invalid("Invalid input identifier or description"));
            }
            let domain = match property.kind.as_str() {
                "string" if property.minimum.is_none() && property.maximum.is_none() => {
                    let minimum = property.min_length.unwrap_or(0);
                    let maximum = property
                        .max_length
                        .ok_or_else(|| invalid("Strings require maxLength"))?;
                    if minimum > maximum || maximum > 4096 {
                        return Err(invalid("Invalid string length bounds"));
                    }
                    Domain::String { minimum, maximum }
                }
                "integer" if property.min_length.is_none() && property.max_length.is_none() => {
                    let minimum = property
                        .minimum
                        .ok_or_else(|| invalid("Integers require minimum"))?;
                    let maximum = property
                        .maximum
                        .ok_or_else(|| invalid("Integers require maximum"))?;
                    if minimum > maximum {
                        return Err(invalid("Invalid integer bounds"));
                    }
                    Domain::Integer { minimum, maximum }
                }
                "boolean"
                    if property.min_length.is_none()
                        && property.max_length.is_none()
                        && property.minimum.is_none()
                        && property.maximum.is_none() =>
                {
                    Domain::Boolean
                }
                _ => return Err(invalid("Unsupported property schema")),
            };
            if matches!(domain, Domain::Integer { .. })
                && let Some(choices) = &mut property.choices
            {
                for value in choices {
                    *value = canonical_integer(std::mem::take(value));
                }
            }
            let input = Input {
                name: name.clone(),
                domain,
                choices: property.choices.clone(),
            };
            if let Some(choices) = &input.choices
                && (choices.is_empty()
                    || choices.len() > 32
                    || choices.iter().enumerate().any(|(i, v)| {
                        choices[..i].contains(v)
                            || !input.matches_type(v)
                            || input.validate(v).is_err()
                    }))
            {
                return Err(invalid("Invalid input enumeration"));
            }
            properties.insert(
                name,
                serde_json::to_value(property).map_err(|_| invalid("Invalid property metadata"))?,
            );
            inputs.push(input);
        }
        let mut used = vec![false; inputs.len()];
        let mut argv = Vec::with_capacity(raw_argv.len());
        for slot in raw_argv {
            argv.push(match slot {
                RawSlot::Fixed(value) => {
                    if value.len() > 4096 || value.contains('\0') {
                        return Err(invalid("Invalid fixed argv literal"));
                    }
                    if value == "--" {
                        separator = true;
                    }
                    Slot::Fixed(value)
                }
                RawSlot::Input(slot) => {
                    let index = inputs
                        .iter()
                        .position(|v| v.name == slot.input)
                        .ok_or_else(|| invalid("Unknown input mapping"))?;
                    if !separator && !inputs[index].option_safe() {
                        return Err(invalid(
                            "Unrestricted inputs require a preceding fixed option separator",
                        ));
                    }
                    used[index] = true;
                    Slot::Input(index)
                }
            });
        }
        if !controller && used.contains(&false) {
            return Err(invalid("Every input must occupy an argv slot"));
        }
        let ceiling = timeout_secs.unwrap_or(limits.max_timeout_secs);
        if !controller {
            properties.insert("host".into(), json!({"type":"string", "enum":targets}));
        }
        properties.insert(
            "timeout_secs".into(),
            json!({"type":"integer", "minimum":1, "maximum":ceiling}),
        );
        let mut required = schema.required;
        if !controller {
            required.push("host".into());
        }
        let metadata = json!({"type":"object", "additionalProperties":false, "properties":properties, "required":required});
        let Value::Object(metadata) = metadata else {
            return Err(invalid("Invalid schema metadata"));
        };
        if !schema_fits(&metadata) {
            return Err(invalid("Generated input schema exceeds metadata bound"));
        }
        let input_schema = Arc::new(metadata);
        let binding = Self {
            name,
            description: raw.description,
            revision: raw.revision,
            targets,
            input_schema,
            enabled,
            effects: raw.effects,
            inputs,
            execution,
            argv,
            timeout_secs,
            max_output_bytes,
        };
        if !controller {
            let mut arguments = binding.arguments();
            arguments.extend(binding.argv.iter().filter_map(|v| match v {
                Slot::Fixed(value) => Some(Cow::Borrowed(value.as_str())),
                Slot::Input(_) => None,
            }));
            binding
                .invocation(arguments)
                .encoded_len()
                .map_err(|_| invalid("Fixed command exceeds encoded command bound"))?;
        }
        Ok(binding)
    }
    pub(crate) fn executor_kind(&self) -> &'static str {
        match self.execution {
            Execution::NativeArgv { .. } => EXECUTOR_KIND,
            Execution::RemoteScript { .. } => "remote_script",
            Execution::ControllerScript { .. } => "controller_script",
            Execution::Ansible {
                source: AnsibleSource::Role { .. },
                ..
            } => "ansible_role",
            Execution::Ansible {
                source: AnsibleSource::Playbook { .. },
                ..
            } => "ansible_playbook",
            Execution::Ansible {
                source: AnsibleSource::Module,
                ..
            } => "ansible_module",
        }
    }

    pub(crate) fn is_controller(&self) -> bool {
        matches!(self.execution, Execution::ControllerScript { .. })
    }

    pub(crate) fn is_automation(&self) -> bool {
        matches!(self.execution, Execution::Ansible { .. })
    }

    pub(crate) fn automation_authority(&self) -> Option<&AutomationAuthority> {
        match &self.execution {
            Execution::Ansible { authority, .. } => Some(authority),
            _ => None,
        }
    }

    pub(crate) fn automation_activated(&self) -> bool {
        matches!(self.execution, Execution::Ansible { plan: Some(_), .. })
    }

    pub(crate) fn projection(&self) -> Option<&Arc<crate::projection::Plan>> {
        match &self.execution {
            Execution::Ansible { projection, .. } => projection.as_ref(),
            _ => None,
        }
    }

    pub(crate) fn result_kind(&self) -> &'static str {
        if self.projection().is_some() {
            "ansible_projection"
        } else if self.is_automation() {
            "ansible_summary"
        } else if self.is_controller() {
            "controller_command"
        } else {
            RESULT_KIND
        }
    }

    pub(crate) fn sudo(&self) -> Option<(&str, &str)> {
        match &self.execution {
            Execution::NativeArgv {
                program,
                authority: Authority::Sudo(user),
                ..
            } => Some((user, program)),
            _ => None,
        }
    }

    fn arguments(&self) -> Vec<Cow<'_, str>> {
        let prefix = match &self.execution {
            Execution::NativeArgv { .. }
            | Execution::ControllerScript { .. }
            | Execution::Ansible { .. } => &[][..],
            Execution::RemoteScript { prefix, .. } => prefix.as_slice(),
        };
        let mut arguments = Vec::with_capacity(prefix.len() + self.argv.len());
        arguments.extend(prefix.iter().map(|v| Cow::Borrowed(v.as_str())));
        arguments
    }

    fn invocation<'a>(&'a self, arguments: Vec<Cow<'a, str>>) -> Invocation<'a> {
        match &self.execution {
            Execution::NativeArgv {
                program,
                authority: Authority::Sudo(user),
                ..
            } => Invocation::BoundSudo {
                program,
                arguments,
                user,
            },
            Execution::NativeArgv {
                program,
                cwd,
                authority: Authority::Ordinary,
            }
            | Execution::RemoteScript { program, cwd, .. } => Invocation::BoundArgv {
                program,
                arguments,
                cwd: cwd.as_deref(),
            },
            Execution::ControllerScript { .. }
            | Execution::Ansible { .. }
            | Execution::NativeArgv {
                authority: Authority::Controller,
                ..
            } => unreachable!("controller bindings never produce remote invocations"),
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
    pub(crate) fn read_only(&self) -> bool {
        self.effects
            .iter()
            .all(|v| matches!(v, Effect::Read | Effect::SensitiveRead))
    }
    pub(crate) fn effects(&self) -> &[Effect] {
        &self.effects
    }
    pub(crate) fn parse_request(
        &self,
        mut arguments: JsonObject,
    ) -> Result<BindingCall, ErrorData> {
        let host = if self.is_controller() {
            None
        } else {
            match arguments.remove("host") {
                Some(Value::String(host)) => Some(host),
                _ => return Err(shape()),
            }
        };
        let timeout_secs = arguments
            .remove("timeout_secs")
            .map(|v| unsigned_integer(&v).ok_or_else(shape))
            .transpose()?;
        if self.is_automation() {
            let inputs = arguments.remove("inputs").ok_or_else(shape)?;
            if !arguments.is_empty() {
                return Err(shape());
            }
            let Execution::Ansible { overlay, .. } = &self.execution else {
                unreachable!("module request selected");
            };
            crate::module_schema::validate_input_shape(&overlay["input_schema"], &inputs)
                .map_err(|_| shape())?;
            return Ok(BindingCall::Automation(AutomationRequest {
                host: host.ok_or_else(shape)?,
                timeout_secs,
                inputs,
            }));
        }
        let values = self
            .inputs
            .iter()
            .map(|input| {
                let value = arguments.remove(&input.name).ok_or_else(shape)?;
                if !input.matches_type(&value) {
                    return Err(shape());
                }
                Ok(if matches!(input.domain, Domain::Integer { .. }) {
                    canonical_integer(value)
                } else {
                    value
                })
            })
            .collect::<Result<_, _>>()?;
        if !arguments.is_empty() {
            return Err(shape());
        }
        Ok(match host {
            Some(host) => BindingCall::Remote(BindingRequest {
                host,
                timeout_secs,
                values,
            }),
            None => BindingCall::Controller(ControllerRequest {
                timeout_secs,
                values,
            }),
        })
    }
    pub(crate) fn prepare<'a>(
        &'a self,
        request: &'a BindingRequest,
        limits: &Limits,
    ) -> Result<PreparedBinding<'a>, ToolError> {
        if !self.targets.contains(&request.host) {
            return Err(bound("Host is not a declared tool target"));
        }
        let ceiling = self.timeout_secs.unwrap_or(limits.max_timeout_secs);
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if timeout == 0 || timeout > ceiling || timeout > limits.max_timeout_secs {
            return Err(bound("Timeout exceeds named tool ceiling"));
        }
        if request.values.len() != self.inputs.len() {
            return Err(bound("Invalid named tool inputs"));
        }
        for (input, value) in self.inputs.iter().zip(&request.values) {
            input.validate(value)?;
        }
        let mut arguments = self.arguments();
        // Reused integer slots copy their already formatted bounded representation, never reformat.
        let mut numeric_slots: [Option<usize>; 16] = [None; 16];
        for slot in &self.argv {
            let value = match slot {
                Slot::Fixed(value) => Cow::Borrowed(value.as_str()),
                Slot::Input(index) => match &request.values[*index] {
                    Value::String(value) => Cow::Borrowed(value.as_str()),
                    Value::Bool(value) => Cow::Borrowed(if *value { "true" } else { "false" }),
                    Value::Number(value) => {
                        if let Some(previous) = numeric_slots[*index] {
                            arguments[previous].clone()
                        } else {
                            numeric_slots[*index] = Some(arguments.len());
                            Cow::Owned(value.to_string())
                        }
                    }
                    _ => return Err(bound("Invalid named tool inputs")),
                },
            };
            arguments.push(value);
        }
        let invocation = self.invocation(arguments);
        invocation.encoded_len()?;
        Ok(PreparedBinding {
            invocation,
            script: match &self.execution {
                Execution::RemoteScript { source, .. } => Some(source),
                Execution::NativeArgv { .. } => None,
                Execution::ControllerScript { .. } | Execution::Ansible { .. } => {
                    return Err(bound("Controller requires local preparation"));
                }
            },
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }

    pub(crate) fn prepare_controller(
        &self,
        request: &ControllerRequest,
        limits: &Limits,
    ) -> Result<PreparedController, ControllerError> {
        let invalid = || ControllerError::new("invalid_argument", "Invalid controller tool inputs");
        let Execution::ControllerScript { plan: Some(plan) } = &self.execution else {
            return Err(ControllerError::new(
                "policy_denied",
                "Operation is not authorized",
            ));
        };
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
            || timeout > limits.max_timeout_secs
            || request.values.len() != self.inputs.len()
        {
            return Err(invalid());
        }
        for (input, value) in self.inputs.iter().zip(&request.values) {
            input.validate(value).map_err(|_| invalid())?;
        }
        use serde::ser::SerializeMap;
        struct Payload<'a> {
            inputs: &'a [Input],
            values: &'a [Value],
        }
        impl Serialize for Payload<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(Some(self.inputs.len()))?;
                for (input, value) in self.inputs.iter().zip(self.values) {
                    map.serialize_entry(&input.name, value)?;
                }
                map.end()
            }
        }
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: 65_536,
        };
        serde_json::to_writer(
            &mut writer,
            &Payload {
                inputs: &self.inputs,
                values: &request.values,
            },
        )
        .map_err(|_| {
            ControllerError::new("resource_limit", "Controller input exceeds byte bound")
        })?;
        Ok(PreparedController {
            plan: Arc::clone(plan),
            input_json: writer.bytes,
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
            supervision: crate::controller::ControllerSupervision::Script,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection_result() -> toml::Value {
        toml::Value::try_from(json!({
            "kind":"ansible_projection","fields":{"platform":["ansible_facts","ansible_system"]},
            "schema":{"type":"object","additionalProperties":false,"required":["platform"],
                "properties":{"platform":{"type":"string","maxLength":64}}},
            "max_bytes":1024,"max_items":32,"max_depth":4
        }))
        .unwrap()
    }

    #[test]
    fn projected_binding_has_fixed_policy_and_rejects_request_selectors() {
        let mut raw = module_definition();
        raw["result"] = projection_result();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert_eq!(binding.result_kind(), "ansible_projection");
        assert_eq!(
            binding.projection().unwrap().fields["platform"],
            ["ansible_facts", "ansible_system"]
        );
        assert!(
            binding
                .parse_request(
                    json!({"host":"server","inputs":{"nested":{"items":[]}},
            "fields":{"platform":["env"]}})
                    .as_object()
                    .unwrap()
                    .clone()
                )
                .is_err()
        );
        let mut native = definition();
        native["result"] = projection_result();
        assert!(compile(native).is_err());
    }

    #[test]
    fn native_and_summary_result_kinds_reject_unknown_options() {
        for kind in ["command", "controller_command", "ansible_summary"] {
            let value = toml::Value::try_from(json!({"kind":kind,"unexpected":true})).unwrap();
            let result: Result<RawResult, _> = value.try_into();
            assert!(
                result.is_err(),
                "result kind {kind} accepted an unknown option"
            );
        }
    }

    #[test]
    fn disabled_projection_rejects_unknown_fields_and_unbounded_schema() {
        for invalid_result in [
            {
                let mut v = projection_result();
                v.as_table_mut()
                    .unwrap()
                    .insert("unexpected".into(), true.into());
                v
            },
            {
                let mut v = projection_result();
                v["schema"]["properties"]["platform"]
                    .as_table_mut()
                    .unwrap()
                    .remove("maxLength");
                v
            },
            {
                let mut v = projection_result();
                v["fields"]["platform"] = toml::Value::try_from(json!(["env"])).unwrap();
                v
            },
        ] {
            let mut raw = module_definition();
            raw["result"] = invalid_result;
            assert!(
                Bindings::compile(
                    BTreeMap::from([("observe".into(), raw)]),
                    &[],
                    &Limits::default(),
                    |_| true,
                    None,
                    true
                )
                .is_err()
            );
        }
    }

    #[test]
    fn module_domain_assertions_remain_nested_and_unmodified() {
        let mut raw = module_definition();
        let schema = json!({
            "type":"object","additionalProperties":false,"maxProperties":1,
            "required":["nested"],
            "properties":{"nested":{"type":"object","additionalProperties":false,
                "required":["items"],"properties":{"items":{"type":"array",
                    "items":{"type":"string"}}}}},
            "const":{"nested":{"items":["approved"]}},
            "enum":[{"nested":{"items":["approved"]}}],
            "if":{"properties":{"nested":{"type":"object","additionalProperties":false,
                "properties":{"items":{"type":"array","items":{"type":"string"}}}}}},
            "then":{"type":"object","additionalProperties":false,
                "properties":{"nested":{"type":"object","additionalProperties":false,
                    "properties":{"items":{"type":"array","items":{"type":"string"}}}}}}
        });
        raw["input_schema"] = toml::Value::try_from(schema.clone()).unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert_eq!(binding.input_schema["properties"]["inputs"], schema);
        assert_eq!(binding.input_schema["required"], json!(["host", "inputs"]));
        assert_eq!(
            binding.input_schema["properties"]
                .as_object()
                .unwrap()
                .len(),
            3
        );
        assert!(
            binding
                .parse_request(
                    json!({
                        "host":"server","inputs":{"nested":{"items":["not approved"]}}
                    })
                    .as_object()
                    .unwrap()
                    .clone()
                )
                .is_ok()
        );
    }

    #[test]
    fn module_request_shape_is_recursive_but_bounds_remain_policy() {
        let bindings = compile(module_definition()).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for input in [
            json!({"host":"server"}),
            json!({"host":"server","inputs":[]}),
            json!({"host":"server","inputs":{}}),
            json!({"host":"server","inputs":{"nested":{}}}),
            json!({"host":"server","inputs":{"nested":{"items":[false]}}}),
            json!({"host":"server","inputs":{"nested":{"items":[],"extra":true}}}),
            json!({"host":"server","inputs":{"nested":{"items":[]}},"extra":true}),
            json!({"host":"server","nested":{"items":[]}}),
        ] {
            assert!(
                binding
                    .parse_request(input.as_object().unwrap().clone())
                    .is_err()
            );
        }
        for items in [json!(["a", "b", "c"]), json!(["x".repeat(33)])] {
            assert!(
                binding
                    .parse_request(
                        json!({
                            "host":"server","inputs":{"nested":{"items":items}}
                        })
                        .as_object()
                        .unwrap()
                        .clone()
                    )
                    .is_ok()
            );
        }
    }

    fn module_definition() -> toml::Value {
        let mut raw = definition();
        raw["authority"] = "automation".into();
        raw["result"]["kind"] = "ansible_summary".into();
        raw["execution"] =
            toml::from_str("kind='ansible_module'\nsnapshot='/unavailable/reviewed.json'").unwrap();
        raw["input_schema"] = toml::Value::try_from(json!({
            "type":"object","additionalProperties":false,"required":["nested"],
            "properties":{"nested":{"type":"object","additionalProperties":false,
                "required":["items"],"properties":{"items":{"type":"array","maxItems":2,
                    "items":{"type":"string","maxLength":32}}}}}
        }))
        .unwrap();
        raw.as_table_mut().unwrap().insert(
            "input_map".into(),
            toml::from_str("nested='nested'").unwrap(),
        );
        raw
    }

    fn role_definition() -> toml::Value {
        let mut raw = module_definition();
        raw["execution"] = toml::from_str(
            "kind='ansible_role'\nsnapshot='/unavailable/role.json'\nrole_path='/unavailable/role'",
        )
        .unwrap();
        raw
    }

    fn playbook_definition() -> toml::Value {
        let mut raw = module_definition();
        raw["execution"] = toml::from_str(
            "kind='ansible_playbook'\nsnapshot='/unavailable/playbook.json'\nproject_root='/unavailable/project'",
        )
        .unwrap();
        raw
    }

    #[test]
    fn playbook_compilation_is_source_free_and_keeps_controls_private() {
        for enabled in [Vec::new(), vec!["observe".into()]] {
            let bindings = Bindings::compile(
                BTreeMap::from([("observe".into(), playbook_definition())]),
                &enabled,
                &Limits::default(),
                |_| true,
                None,
                false,
            )
            .unwrap();
            let binding = bindings.get(BindingId(0)).unwrap();
            assert_eq!(binding.executor_kind(), "ansible_playbook");
            assert!(!binding.automation_activated());
            let published = serde_json::to_string(&binding.input_schema).unwrap();
            assert!(!published.contains("/unavailable"));
            for control in [
                "playbook",
                "project_root",
                "inventory",
                "tags",
                "extra_vars",
            ] {
                let mut arguments = json!({"host":"server","inputs":{"nested":{"items":[]}}});
                arguments[control] = json!("caller");
                assert!(
                    binding
                        .parse_request(arguments.as_object().unwrap().clone())
                        .is_err()
                );
            }
        }
        for control in ["role_path", "playbook", "inventory", "tags", "extra_vars"] {
            let mut raw = playbook_definition();
            raw["execution"]
                .as_table_mut()
                .unwrap()
                .insert(control.into(), "caller".into());
            assert!(
                compile(raw).is_err(),
                "accepted execution control {control}"
            );
        }
        let mut raw = playbook_definition();
        raw["execution"]["project_root"] = "relative".into();
        assert!(compile(raw).is_err());
    }

    #[test]
    fn playbook_backend_controls_are_rejected_without_activation() {
        for name in [
            "playbook",
            "project_root",
            "ansible_connection",
            "ansible_python_interpreter",
            "inventory",
            "tags",
            "become",
            "connection",
            "interpreter",
            "estus_arguments",
        ] {
            for field in ["fixed_args", "input_map"] {
                let mut raw = playbook_definition();
                raw.as_table_mut().unwrap().insert(
                    field.into(),
                    toml::Value::try_from(json!({name:"nested"})).unwrap(),
                );
                assert!(
                    compile(raw).is_err(),
                    "accepted {field} playbook control {name}"
                );
            }
        }
    }

    #[test]
    fn playbook_projection_requires_concrete_domain_members() {
        for path in [
            vec!["ansible_facts", "platform"],
            vec!["mcp_result"],
            vec!["mcp_result", "platform"],
        ] {
            let mut raw = playbook_definition();
            let mut result = projection_result();
            result["fields"]["platform"] = toml::Value::Array(
                path.iter()
                    .map(|part| toml::Value::String((*part).into()))
                    .collect(),
            );
            raw["result"] = result;
            assert_eq!(
                compile(raw).is_ok(),
                path.len() == 2 && path[0] == "mcp_result"
            );
        }
    }

    #[test]
    fn role_compilation_keeps_source_private_and_caller_controls_closed() {
        let bindings = compile(role_definition()).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert_eq!(binding.executor_kind(), "ansible_role");
        assert_eq!(binding.result_kind(), "ansible_summary");
        assert!(binding.is_automation());
        assert!(!binding.automation_activated());
        let published = serde_json::to_string(&binding.input_schema).unwrap();
        assert!(!published.contains("/unavailable"));
        for control in ["role", "entry_point", "role_path", "extra_vars"] {
            let mut arguments = json!({"host":"server","inputs":{"nested":{"items":[]}}});
            arguments[control] = json!("caller");
            assert!(
                binding
                    .parse_request(arguments.as_object().unwrap().clone())
                    .is_err()
            );
            let mut raw = role_definition();
            raw["execution"]
                .as_table_mut()
                .unwrap()
                .insert(control.into(), "caller".into());
            assert!(compile(raw).is_err());
        }
    }

    #[test]
    fn role_projection_requires_a_concrete_mcp_result_member() {
        for path in [
            vec!["ansible_facts", "platform"],
            vec!["mcp_result"],
            vec!["mcp_result", "platform"],
        ] {
            let mut raw = role_definition();
            let mut result = projection_result();
            result["fields"]["platform"] = toml::Value::Array(
                path.iter()
                    .map(|part| toml::Value::String((*part).into()))
                    .collect(),
            );
            raw["result"] = result;
            assert_eq!(
                compile(raw).is_ok(),
                path.len() == 2 && path[0] == "mcp_result"
            );
        }
    }

    #[test]
    fn role_backend_controls_are_rejected_even_without_activation() {
        for name in [
            "mcp_result",
            "estus_arguments",
            "ansible_connection",
            "connection",
            "become_user",
            "hostvars",
            "inventory_file",
            "callback_plugins",
            "role_path",
            "tasks_from",
            "tags",
            "no_log",
        ] {
            let mut raw = role_definition();
            raw.as_table_mut().unwrap().insert(
                "fixed_args".into(),
                toml::Value::try_from(json!({name:"value"})).unwrap(),
            );
            assert!(compile(raw).is_err(), "accepted fixed role control {name}");
            let mut raw = role_definition();
            raw["input_map"] = toml::Value::try_from(json!({name:"nested"})).unwrap();
            assert!(compile(raw).is_err(), "accepted mapped role control {name}");
        }
        let mut raw = role_definition();
        raw["execution"]["role_path"] = "relative/role".into();
        assert!(compile(raw).is_err());
    }

    #[test]
    fn module_compilation_is_lazy_and_preserves_recursive_public_domain() {
        let bindings = compile(module_definition()).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(binding.is_automation());
        assert_eq!(binding.executor_kind(), "ansible_module");
        assert_eq!(binding.result_kind(), "ansible_summary");
        assert!(binding.input_schema["properties"]["inputs"]["properties"]["nested"]["properties"]["items"].is_object());
        let input = json!({"host":"server","inputs":{"nested":{"items":["{{ literal }}"]}}});
        let BindingCall::Automation(request) = binding
            .parse_request(input.as_object().unwrap().clone())
            .unwrap()
        else {
            panic!("module request expected");
        };
        assert_eq!(
            request.inputs,
            json!({"nested":{"items":["{{ literal }}"]}})
        );
        let target = crate::config::AutomationTarget {
            destination: "fixed".into(),
            python: "/python".into(),
        };
        assert!(
            binding
                .prepare_automation(
                    &request,
                    &Limits::default(),
                    AutomationTransport {
                        authority: crate::config::ResolvedAutomation {
                            target: &target,
                            ssh_config: None,
                            ssh_executable: Path::new("/usr/bin/ssh"),
                            r#become: None,
                            agent: crate::config::AutomationAgent::Inherit,
                        },
                        scratch_bytes: 1024,
                        scratch_files: 10,
                        started: std::time::Instant::now(),
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn module_authority_result_and_native_overlay_boundaries_are_strict() {
        for authority in ["ordinary", "controller"] {
            let mut raw = module_definition();
            raw["authority"] = authority.into();
            assert!(compile(raw).is_err());
        }
        let mut raw = module_definition();
        raw["result"]["kind"] = "command".into();
        assert!(compile(raw).is_err());
        let mut raw = definition();
        raw.as_table_mut()
            .unwrap()
            .insert("fixed_args".into(), toml::Value::Table(Default::default()));
        assert!(compile(raw).is_err());
        let mut raw = module_definition();
        raw["input_schema"]["properties"]
            .as_table_mut()
            .unwrap()
            .insert("host".into(), toml::from_str("type='string'").unwrap());
        assert!(compile(raw).is_err());
    }

    #[test]
    fn active_controller_rejects_unavailable_and_unverified_prerequisites() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source");
        fs::write(&source, b"abc").unwrap();
        let good = controller_definition(&source);
        for (field, value) in [
            ("program", "/unavailable/private-runtime"),
            ("program", "/"),
            ("program", "/dev/null"),
        ] {
            let mut raw = good.clone();
            raw["execution"]["interpreter"][field] = value.into();
            assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
        }
        let mut raw = good.clone();
        raw["execution"]
            .as_table_mut()
            .unwrap()
            .insert("cwd".into(), "/unavailable/private-cwd".into());
        assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
        let mut raw = good.clone();
        raw["execution"]["source"]["path"] = dir.path().to_str().unwrap().into();
        assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
        for bytes in [b"abd".as_slice(), b"abcd", b"\xff", b"a\0c"] {
            fs::write(&source, bytes).unwrap();
            let error = controller_compile(good.clone(), true, true, Some(dir.path()))
                .err()
                .unwrap();
            assert!(!error.to_string().contains(dir.path().to_str().unwrap()));
        }
        fs::remove_file(&source).unwrap();
        assert!(controller_compile(good.clone(), true, true, Some(dir.path())).is_err());
        assert!(controller_compile(good, false, true, Some(dir.path())).is_ok());
    }

    #[test]
    fn configured_controller_environment_obeys_entry_value_and_aggregate_bounds() {
        assert!(
            controller_environment(BTreeMap::from([("MCP_VALUE".into(), "x".repeat(4096))]))
                .is_ok()
        );
        assert!(
            controller_environment(BTreeMap::from([("MCP_VALUE".into(), "x".repeat(4097))]))
                .is_err()
        );
        assert!(
            controller_environment(
                (0..32)
                    .map(|i| (format!("MCP_{i}"), String::new()))
                    .collect()
            )
            .is_ok()
        );
        assert!(
            controller_environment(
                (0..33)
                    .map(|i| (format!("MCP_{i}"), String::new()))
                    .collect()
            )
            .is_err()
        );
        assert!(
            controller_environment(BTreeMap::from([
                ("MCP_A".into(), "x".repeat(4096)),
                ("MCP_B".into(), "x".repeat(4086)),
            ]))
            .is_ok()
        );
        assert!(
            controller_environment(BTreeMap::from([
                ("MCP_A".into(), "x".repeat(4096)),
                ("MCP_B".into(), "x".repeat(4087)),
            ]))
            .is_err()
        );
    }

    fn controller_definition(source: &Path) -> toml::Value {
        let shell = std::env::split_paths(&std::env::var_os("PATH").expect("test utility PATH"))
            .map(|directory| directory.join("sh"))
            .find(|path| path.is_file())
            .expect("declared POSIX interpreter is available");
        let mut raw = definition();
        raw.as_table_mut().unwrap().remove("targets");
        raw["authority"] = "controller".into();
        raw["result"]["kind"] = "controller_command".into();
        raw["execution"] = toml::from_str(&format!(
            "kind='controller_script'\nsource={{path={:?},content_sha256='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',max_bytes=3}}\ninterpreter={{program={:?},argv=[]}}",
            source.to_str().unwrap(), shell.to_str().unwrap())).unwrap();
        raw
    }

    fn controller_compile(
        raw: toml::Value,
        enabled: bool,
        permitted: bool,
        root: Option<&Path>,
    ) -> Result<Bindings, ConfigError> {
        let selected = enabled.then(|| "observe".to_owned());
        Bindings::compile(
            BTreeMap::from([("observe".into(), raw)]),
            selected.as_slice(),
            &Limits::default(),
            |_| false,
            root.map(|p| p.to_str().unwrap()),
            permitted,
        )
    }

    #[test]
    fn inactive_controller_declarations_do_not_open_runtime_source_or_root() {
        let raw = controller_definition(Path::new("/unavailable/source"));
        for (enabled, permitted) in [(false, true), (true, false), (false, false)] {
            let mut raw = raw.clone();
            raw["execution"]["interpreter"]["program"] = "/unavailable/runtime".into();
            assert!(
                controller_compile(
                    raw,
                    enabled,
                    permitted,
                    Some(Path::new("/unavailable/root"))
                )
                .is_ok()
            );
        }
        assert!(controller_compile(raw.clone(), true, true, None).is_err());
        for targets in [vec![], vec!["server".into()]] {
            let mut raw = raw.clone();
            put(&mut raw, "targets", toml::Value::Array(targets));
            assert!(controller_compile(raw, false, true, None).is_err());
        }
        for (name, value) in [
            ("HOME", "private"),
            ("MCP_", "x"),
            ("MCP_lower", "x"),
            ("PATH", "bad\0value"),
        ] {
            let mut raw = raw.clone();
            raw["execution"].as_table_mut().unwrap().insert(
                "environment".into(),
                toml::Value::Table(toml::Table::from_iter([(name.into(), value.into())])),
            );
            assert!(
                controller_compile(raw, false, true, None).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn controller_pins_source_and_rejects_host_controls() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source");
        fs::write(&source, b"abc").unwrap();
        let bindings =
            controller_compile(controller_definition(&source), true, true, Some(dir.path()))
                .unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        fs::write(&source, b"changed").unwrap();
        for arguments in [
            json!({"value":"ok","host":"server"}),
            json!({"value":"ok","cwd":"/"}),
        ] {
            assert!(
                binding
                    .parse_request(arguments.as_object().unwrap().clone())
                    .is_err()
            );
        }
        let BindingCall::Controller(request) = binding
            .parse_request(
                json!({"value":"$(not shell) ☃\n","timeout_secs":1})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap()
        else {
            panic!("expected controller request")
        };
        let prepared = binding
            .prepare_controller(&request, &Limits::default())
            .unwrap();
        assert_eq!(prepared.plan.source, "abc");
        assert_eq!(
            serde_json::from_slice::<Value>(&prepared.input_json).unwrap(),
            json!({"value":"$(not shell) ☃\n"})
        );
        for mode in [0o755, 0o770, 0o1700] {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                controller_compile(controller_definition(&source), true, true, Some(dir.path()))
                    .is_err()
            );
        }
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn controller_json_limit_counts_actual_escaped_payload() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source");
        fs::write(&source, b"abc").unwrap();
        let mut raw = controller_definition(&source);
        let names: Vec<_> = ('a'..='p').map(|c| c.to_string()).collect();
        raw["input_schema"]["required"] =
            toml::Value::Array(names.iter().cloned().map(Into::into).collect());
        raw["input_schema"]["properties"] = toml::Value::Table(
            names
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        toml::from_str("type='string'\nmaxLength=4096").unwrap(),
                    )
                })
                .collect(),
        );
        let bindings = controller_compile(raw, true, true, Some(dir.path())).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let mut arguments: JsonObject = names
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    Value::String("x".repeat(if name == "p" { 3983 } else { 4096 })),
                )
            })
            .collect();
        let BindingCall::Controller(request) = binding.parse_request(arguments.clone()).unwrap()
        else {
            panic!("expected controller request")
        };
        assert_eq!(
            binding
                .prepare_controller(&request, &Limits::default())
                .unwrap()
                .input_json
                .len(),
            65_536
        );
        arguments.insert(
            "p".into(),
            Value::String("\n".to_owned() + &"x".repeat(3982)),
        );
        let BindingCall::Controller(request) = binding.parse_request(arguments).unwrap() else {
            panic!("expected controller request")
        };
        assert_eq!(
            binding
                .prepare_controller(&request, &Limits::default())
                .err()
                .unwrap()
                .code,
            "resource_limit"
        );
    }

    fn definition() -> toml::Value {
        toml::from_str(r#"
description = "Literal observation"
revision = "review-1"
targets = ["server"]
authority = "ordinary"
effects = ["read"]
execution = { kind = "native_argv", program = "/usr/bin/printf", argv = ["--", { input = "value" }] }
input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 4096 } } }
result = { kind = "command" }
"#).unwrap()
    }
    fn compile(value: toml::Value) -> Result<Bindings, ConfigError> {
        Bindings::compile(
            BTreeMap::from([("observe".into(), value)]),
            &["observe".into()],
            &Limits::default(),
            |v| v == "server",
            None,
            true,
        )
    }
    fn request(binding: &CompiledBinding, value: Value) -> BindingRequest {
        let BindingCall::Remote(request) = binding
            .parse_request(
                json!({"host":"server", "value":value})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap()
        else {
            panic!("expected remote request")
        };
        request
    }
    fn property(raw: &mut toml::Value) -> &mut toml::Value {
        &mut raw["input_schema"]["properties"]["value"]
    }
    fn put(table: &mut toml::Value, key: &str, value: toml::Value) {
        table.as_table_mut().unwrap().insert(key.into(), value);
    }

    #[test]
    fn fixed_sudo_borrows_literal_inputs_without_exposing_authority_controls() {
        let mut raw = definition();
        raw["authority"] = toml::from_str("sudo = 'root'").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(binding.read_only());
        let text = "-n ' \"$();\\\n雪";
        let request = request(binding, json!(text));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        match prepared.invocation {
            Invocation::BoundSudo {
                program,
                arguments,
                user,
            } => {
                assert_eq!(program, "/usr/bin/printf");
                assert_eq!(user, "root");
                assert_eq!(arguments, [Cow::Borrowed("--"), Cow::Borrowed(text)]);
                assert!(arguments.iter().all(|v| matches!(v, Cow::Borrowed(_))));
            }
            _ => panic!("Expected fixed sudo invocation"),
        }
        for key in ["user", "authority", "program"] {
            let mut arguments = json!({"host":"server", "value":"ok"})
                .as_object()
                .unwrap()
                .clone();
            arguments.insert(key.into(), json!("root"));
            assert_eq!(
                binding.parse_request(arguments).err().unwrap().code,
                rmcp::model::ErrorCode::INVALID_PARAMS
            );
        }
    }

    #[test]
    fn literal_slots_borrow_and_preserve_adversarial_text() {
        let mut raw = definition();
        put(
            &mut raw["execution"],
            "cwd",
            "/tmp/quotes ' and spaces".into(),
        );
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .insert(1, "fixed '$()`;\n".into());
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let text = "-a ' \"$()`;\\\n雪";
        let request = request(binding, json!(text));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        match prepared.invocation {
            Invocation::BoundArgv {
                program,
                arguments,
                cwd,
            } => {
                assert_eq!(program, "/usr/bin/printf");
                assert_eq!(cwd, Some("/tmp/quotes ' and spaces"));
                assert_eq!(
                    arguments.iter().map(Cow::as_ref).collect::<Vec<_>>(),
                    ["--", "fixed '$()`;\n", text]
                );
            }
            _ => panic!("Expected bound argv"),
        }
    }

    #[test]
    fn closed_shape_and_types_reject_before_preparation() {
        let bindings = compile(definition()).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for arguments in [
            json!({"host":"server"}),
            json!({"host":42, "value":"ok"}),
            json!({"host":"server", "value":1}),
            json!({"host":"server", "value":"ok", "program":"/bin/sh"}),
            json!({"host":"server", "value":"ok", "timeout_secs":-1}),
            json!({"host":"server", "value":"ok", "timeout_secs":null}),
            json!({"host":"server", "value":"ok", "env":{}}),
        ] {
            let error = binding
                .parse_request(arguments.as_object().unwrap().clone())
                .err()
                .unwrap();
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        }
    }

    #[test]
    fn string_bounds_count_characters_and_enum_is_enforced() {
        let mut raw = definition();
        *property(&mut raw) = toml::from_str("type='string'\nminLength=1\nmaxLength=2").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for (text, accepted) in [
            ("", false),
            ("雪", true),
            ("雪雪", true),
            ("雪雪雪", false),
            ("\0", false),
        ] {
            let request = request(binding, json!(text));
            let result = binding.prepare(&request, &Limits::default());
            assert_eq!(result.is_ok(), accepted, "{text:?}");
            if let Err(error) = result {
                assert_eq!(error.code, "invalid_argument");
                assert!(!error.remote_state_unknown);
            }
        }
        let mut raw = definition();
        put(
            property(&mut raw),
            "enum",
            toml::Value::Array(vec!["approved".into()]),
        );
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(
            binding
                .prepare(&request(binding, json!("approved")), &Limits::default())
                .is_ok()
        );
        assert!(
            binding
                .prepare(&request(binding, json!("other")), &Limits::default())
                .is_err()
        );
    }

    #[test]
    fn integer_and_boolean_domains_render_exactly() {
        for (schema, values) in [
            (
                "type='integer'\nminimum=-2\nmaximum=2",
                vec![
                    (json!(-2), Some("-2")),
                    (json!(2), Some("2")),
                    (json!(3), None),
                ],
            ),
            (
                "type='boolean'\nenum=[true]",
                vec![(json!(true), Some("true")), (json!(false), None)],
            ),
            (
                "type='integer'\nminimum=-9223372036854775808\nmaximum=9223372036854775807",
                vec![
                    (json!(i64::MIN), Some("-9223372036854775808")),
                    (json!(i64::MAX), Some("9223372036854775807")),
                ],
            ),
        ] {
            let mut raw = definition();
            *property(&mut raw) = toml::from_str(schema).unwrap();
            let bindings = compile(raw).unwrap();
            let binding = bindings.get(BindingId(0)).unwrap();
            for (value, expected) in values {
                let request = request(binding, value);
                let result = binding.prepare(&request, &Limits::default());
                if let Some(expected) = expected {
                    match result.unwrap().invocation {
                        Invocation::BoundArgv { arguments, .. } => {
                            assert_eq!(arguments[1], expected)
                        }
                        _ => panic!("Expected bound argv"),
                    }
                } else {
                    assert!(result.is_err());
                }
            }
            for wrong in [json!("1"), json!(1.5), json!([])] {
                assert!(
                    binding
                        .parse_request(
                            json!({"host":"server","value":wrong})
                                .as_object()
                                .unwrap()
                                .clone()
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn option_safety_depends_on_fixed_separator_or_closed_domain() {
        for (schema, accepted) in [
            ("type='string'\nmaxLength=32", false),
            ("type='string'\nmaxLength=32\nenum=['--version']", true),
            ("type='integer'\nminimum=-1\nmaximum=5", false),
            ("type='integer'\nminimum=-1\nmaximum=5\nenum=[-1,2]", true),
            ("type='integer'\nminimum=0\nmaximum=5", true),
            ("type='boolean'", true),
        ] {
            let mut raw = definition();
            raw["execution"]["argv"].as_array_mut().unwrap().remove(0);
            *property(&mut raw) = toml::from_str(schema).unwrap();
            assert_eq!(compile(raw).is_ok(), accepted, "{schema}");
        }
        let mut raw = definition();
        raw["execution"]["argv"].as_array_mut().unwrap().swap(0, 1);
        assert!(
            compile(raw).is_err(),
            "A later separator must not authorize an earlier free slot"
        );
    }

    #[test]
    fn unsupported_schemas_and_bad_mappings_fail_even_when_disabled() {
        for schema in [
            "type='string'",
            "type='string'\nmaxLength=4097",
            "type='string'\nmaxLength=2\nminLength=3",
            "type='string'\nmaxLength=2\npattern='.*'",
            "type='string'\nmaxLength=2\ndefault='x'",
            "type='object'\nproperties={}",
            "type='integer'\nminimum=0",
            "type='integer'\nminimum=2\nmaximum=1",
            "type='integer'\nminimum=0\nmaximum=2\nenum=['1']",
            "type='boolean'\nenum=[]",
            "type='boolean'\nenum=[true,true]",
            "type='boolean'\nmaximum=2",
        ] {
            let mut raw = definition();
            *property(&mut raw) = toml::from_str(schema).unwrap();
            assert!(
                Bindings::compile(
                    BTreeMap::from([("observe".into(), raw)]),
                    &[],
                    &Limits::default(),
                    |_| true,
                    None,
                    true
                )
                .is_err(),
                "{schema}"
            );
        }
        for name in RESERVED
            .iter()
            .copied()
            .chain(["_hidden", "bad-name", "1value"])
        {
            let mut raw = definition();
            let properties = raw["input_schema"]["properties"].as_table_mut().unwrap();
            let value = properties.remove("value").unwrap();
            properties.insert(name.into(), value);
            raw["input_schema"]["required"] = toml::Value::Array(vec![name.into()]);
            raw["execution"]["argv"][1]["input"] = name.into();
            assert!(compile(raw).is_err(), "{name}");
        }
        for argv in [
            vec![],
            vec![toml::Value::String("--".into())],
            vec![toml::from_str("input='unknown'").unwrap()],
            vec![toml::from_str("input='value'\nfixed='override'").unwrap()],
        ] {
            let mut raw = definition();
            raw["execution"]["argv"] = toml::Value::Array(argv);
            assert!(compile(raw).is_err());
        }
        for required in [vec![], vec!["value", "value"], vec!["missing"]] {
            let mut raw = definition();
            raw["input_schema"]["required"] =
                toml::Value::Array(required.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
    }

    #[test]
    fn limits_targets_revision_and_enablement_are_enforced() {
        let mut raw = definition();
        put(
            &mut raw,
            "limits",
            toml::from_str("timeout_secs=3\nmax_output_bytes=7").unwrap(),
        );
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let mut request = request(binding, json!("ok"));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        assert_eq!(prepared.duration, Duration::from_secs(3));
        assert_eq!(prepared.max_output_bytes, 7);
        for timeout in [0, 4] {
            request.timeout_secs = Some(timeout);
            assert!(binding.prepare(&request, &Limits::default()).is_err());
        }
        request.timeout_secs = Some(2);
        assert_eq!(
            binding
                .prepare(&request, &Limits::default())
                .unwrap()
                .duration,
            Duration::from_secs(2)
        );
        request.host = "arbitrary.example".into();
        assert!(binding.prepare(&request, &Limits::default()).is_err());
        for revision in ["", "not secret!", "☃"] {
            let mut raw = definition();
            raw["revision"] = revision.into();
            assert!(compile(raw).is_err());
        }
        for targets in [vec![], vec!["server", "server"], vec!["unknown"]] {
            let mut raw = definition();
            raw["targets"] = toml::Value::Array(targets.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
        for limits in [
            "timeout_secs=0",
            "timeout_secs=601",
            "max_output_bytes=0",
            "max_output_bytes=1048577",
        ] {
            let mut raw = definition();
            put(&mut raw, "limits", toml::from_str(limits).unwrap());
            assert!(compile(raw).is_err());
        }
        for enabled in [
            vec!["missing".into()],
            vec!["observe".into(), "observe".into()],
        ] {
            assert!(
                Bindings::compile(
                    BTreeMap::from([("observe".into(), definition())]),
                    &enabled,
                    &Limits::default(),
                    |_| true,
                    None,
                    true
                )
                .is_err()
            );
        }
        let disabled = Bindings::compile(
            BTreeMap::from([("observe".into(), definition())]),
            &[],
            &Limits::default(),
            |_| true,
            None,
            true,
        )
        .unwrap();
        assert!(!disabled.get(BindingId(0)).unwrap().enabled());
    }

    #[test]
    fn actual_expansion_obeys_exact_encoded_command_boundary() {
        // The fixed prefix "command -- /x --" is 16 bytes; sixteen references
        // contribute 65504 bytes at 4093 bytes each plus their leading spaces.
        // A 15-byte literal plus its leading space reaches exactly 65536.
        let mut raw = definition();
        raw["execution"]["program"] = "/x".into();
        let mut argv = vec![
            toml::Value::String("--".into()),
            toml::Value::String("x".repeat(15)),
        ];
        argv.extend((0..16).map(|_| toml::from_str("input='value'").unwrap()));
        raw["execution"]["argv"] = toml::Value::Array(argv);
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let exact = request(binding, json!("x".repeat(4093)));
        let prepared = binding.prepare(&exact, &Limits::default()).unwrap();
        assert_eq!(prepared.invocation.encoded_len().unwrap(), 65536);
        let over = request(binding, json!("x".repeat(4094)));
        let error = binding.prepare(&over, &Limits::default()).err().unwrap();
        assert_eq!(error.code, "invalid_argument");
        assert!(!error.remote_state_unknown);
    }

    #[test]
    fn static_layout_and_metadata_bounds_reject_overflow() {
        for (field, value) in [
            ("program", Value::String("relative".into())),
            ("program", Value::String("/bin/".into())),
            ("program", Value::String("/".to_owned() + &"x".repeat(4096))),
            ("cwd", Value::String("relative".into())),
        ] {
            let mut raw = definition();
            put(&mut raw["execution"], field, value.as_str().unwrap().into());
            assert!(compile(raw).is_err());
        }
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .push("x".repeat(4097).into());
        assert!(compile(raw).is_err());
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .extend((0..63).map(|_| "x".into()));
        assert!(compile(raw).is_err(), "More than 64 slots");
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .extend((0..32).map(|_| "x".repeat(4096).into()));
        assert!(
            compile(raw).is_err(),
            "Fixed-only command must fit before any request"
        );
        let mut raw = definition();
        put(
            property(&mut raw),
            "enum",
            toml::Value::Array(
                (0..5)
                    .map(|i| format!("{i}{}", "x".repeat(4000)).into())
                    .collect(),
            ),
        );
        assert!(compile(raw).is_err(), "Aggregate enum text is bounded");
        let raw = (0..33)
            .map(|i| (format!("tool_{i}"), definition()))
            .collect();
        assert!(Bindings::compile(raw, &[], &Limits::default(), |_| true, None, true).is_err());
    }

    #[test]
    fn effect_annotations_are_conservative_and_unique() {
        for (effects, read_only) in [
            (vec!["read", "sensitive_read"], true),
            (vec!["read", "probe"], false),
            (vec!["runtime_write"], false),
            (vec!["persistent_write"], false),
            (vec!["availability"], false),
            (vec!["unknown"], false),
        ] {
            let mut raw = definition();
            raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
            let bindings = compile(raw).unwrap();
            assert_eq!(bindings.get(BindingId(0)).unwrap().read_only(), read_only);
        }
        for effects in [vec![], vec!["read", "read"], vec!["invented"]] {
            let mut raw = definition();
            raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
    }

    #[test]
    fn integer_schema_normalizes_integral_numbers_without_truncating() {
        let mut raw = definition();
        *property(&mut raw) =
            toml::from_str("type='integer'\nminimum=-2\nmaximum=2\nenum=[1,2]").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for (token, expected) in [("1", "1"), ("1.0", "1"), ("1e0", "1"), ("2.0", "2")] {
            let value: Value = serde_json::from_str(token).unwrap();
            let BindingCall::Remote(request) = binding
                .parse_request(
                    json!({
                        "host":"server", "value":value, "timeout_secs":1.0
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                )
                .unwrap()
            else {
                panic!("expected remote request")
            };
            let prepared = binding.prepare(&request, &Limits::default()).unwrap();
            assert_eq!(prepared.duration, Duration::from_secs(1));
            match prepared.invocation {
                Invocation::BoundArgv { arguments, .. } => assert_eq!(arguments[1], expected),
                _ => panic!("wrong native invocation"),
            }
        }
        for token in ["1.5", "1e100", "3.0"] {
            let value: Value = serde_json::from_str(token).unwrap();
            if let Ok(BindingCall::Remote(request)) = binding.parse_request(
                json!({
                    "host":"server", "value":value
                })
                .as_object()
                .unwrap()
                .clone(),
            ) {
                assert!(binding.prepare(&request, &Limits::default()).is_err());
            }
        }
        let mut raw = definition();
        *property(&mut raw) =
            toml::from_str("type='integer'\nminimum=0\nmaximum=2\nenum=[1,1.0]").unwrap();
        assert!(
            compile(raw).is_err(),
            "numeric enum aliases must not become distinct choices"
        );
    }

    #[test]
    fn generated_host_enums_share_the_complete_input_schema_budget() {
        for (target, choices) in [
            ("x".repeat(MAX_SCHEMA_BYTES + 1), None),
            (
                "x".repeat(MAX_SCHEMA_BYTES - 1024),
                Some(vec!["a".repeat(1000), "b".repeat(1000)]),
            ),
        ] {
            let mut raw = definition();
            raw["targets"] = toml::Value::Array(vec![target.into()]);
            if let Some(choices) = choices {
                put(
                    property(&mut raw),
                    "enum",
                    toml::Value::Array(choices.into_iter().map(toml::Value::String).collect()),
                );
            }
            let result = Bindings::compile(
                BTreeMap::from([("observe".into(), raw)]),
                &["observe".into()],
                &Limits::default(),
                |_| true,
                None,
                true,
            );
            assert!(
                result.is_err(),
                "generated host choices escaped the schema cap"
            );
        }
    }
}
