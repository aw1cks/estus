use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize, Serializer};

use crate::{
    bindings::{AutomationAuthority, BindingId, Bindings},
    command::MAX_COMMAND_BYTES,
    reply::ToolError,
    wire::MAX_RESPONSE_BYTES,
};

const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_LABELS: usize = 16;
const MAX_LABEL_KEY_BYTES: usize = 64;
const MAX_LABEL_VALUE_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolId {
    Targets,
    Exec,
    Run,
    ReadFile,
    WriteFile,
    Mkdir,
    Stat,
    ListDirectory,
    Sudo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolKey {
    Builtin(ToolId),
    Binding(BindingId),
}

#[derive(Clone, Copy, Default, Deserialize)]
enum Profile {
    #[default]
    #[serde(rename = "baseline")]
    Baseline,
    #[serde(rename = "read-only-files")]
    ReadOnlyFiles,
    #[serde(rename = "files-only")]
    FilesOnly,
    #[serde(rename = "actions-only")]
    ActionsOnly,
}

impl Profile {
    fn permits(self, tool: ToolId) -> bool {
        // Keep every ID classified explicitly so a new binding requires a policy decision.
        match tool {
            ToolId::Targets => true,
            ToolId::ReadFile | ToolId::Stat | ToolId::ListDirectory => {
                matches!(self, Self::Baseline | Self::ReadOnlyFiles | Self::FilesOnly)
            }
            ToolId::WriteFile | ToolId::Mkdir => matches!(self, Self::Baseline | Self::FilesOnly),
            ToolId::Exec | ToolId::Run | ToolId::Sudo => matches!(self, Self::Baseline),
        }
    }

    fn permits_bindings(self) -> bool {
        matches!(self, Self::Baseline | Self::ActionsOnly)
    }
}

#[derive(Debug)]
pub(crate) struct ToolEntry {
    pub(crate) id: ToolKey,
    pub(crate) name: Cow<'static, str>,
}

#[derive(Debug)]
pub(crate) struct ToolCatalog {
    entries: Vec<ToolEntry>,
}

impl ToolCatalog {
    pub(crate) fn new(mut entries: Vec<ToolEntry>) -> Result<Self, ConfigError> {
        for (index, entry) in entries.iter().enumerate() {
            if entries[..index].iter().any(|other| other.id == entry.id) {
                return Err(invalid("tools", "tool catalogue contains duplicate IDs"));
            }
            if entries[..index]
                .iter()
                .any(|other| other.name == entry.name)
            {
                return Err(invalid("tools", "tool catalogue contains duplicate names"));
            }
        }
        entries.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(Self { entries })
    }

    pub(crate) fn retain(&mut self, mut predicate: impl FnMut(ToolKey) -> bool) {
        self.entries.retain(|entry| predicate(entry.id));
    }

    pub(crate) fn contains(&self, id: ToolKey) -> bool {
        self.name(id).is_some()
    }

    pub(crate) fn name(&self, id: ToolKey) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.as_ref())
    }
}

#[derive(Parser)]
#[command(version, about = "Estus: operator-controlled SSH over MCP")]
pub(crate) struct Cli {
    /// Operator TOML configuration; no file is discovered automatically.
    #[arg(long, global = true, env = "ESTUS_CONFIG", hide_env_values = true)]
    config: Option<PathBuf>,
    /// Replacement OpenSSH configuration (not an overlay).
    #[arg(long, global = true, env = "ESTUS_SSH_CONFIG", hide_env_values = true)]
    ssh_config: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Subcommand)]
pub(crate) enum CliCommand {
    /// Check runtime health or configured targets without executing automation or commands.
    Doctor(DoctorArgs),
    /// Import and verify reviewed offline Ansible module contracts; never execute them.
    Schema(crate::schema_import::SchemaArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeKind {
    Ansible,
}

#[derive(Args)]
pub(crate) struct DoctorArgs {
    /// Configured logical target; repeat to select additional targets.
    #[arg(
        long = "target",
        value_name = "LOGICAL_TARGET",
        required_unless_present = "runtime"
    )]
    pub targets: Vec<String>,
    /// Check the explicitly selected optional runtime's import and identity health.
    #[arg(long, value_enum)]
    pub runtime: Option<RuntimeKind>,
    /// Deadline in seconds for the entire diagnostic run.
    #[arg(long)]
    pub timeout_secs: Option<u64>,
}

// Only fixed schema paths and fixed reasons enter diagnostics. In particular, neither
// TOML's error Display/source nor unknown field/target names are safe to render.
#[derive(Debug, thiserror::Error)]
#[error("{field}: {reason}")]
pub(crate) struct ConfigError {
    field: &'static str,
    reason: &'static str,
}

impl ConfigError {
    pub(crate) fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::new(field, reason)
}

pub(crate) struct Config {
    profile: Profile,
    ssh_config: Option<PathBuf>,
    limits: Limits,
    targets: Option<BTreeMap<String, Target>>,
    bindings: Bindings,
    automation: Automation,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Document {
    profile: Profile,
    ssh: Ssh,
    limits: Limits,
    targets: Option<BTreeMap<String, Target>>,
    tools: BTreeMap<String, toml::Value>,
    enabled_tools: Vec<String>,
    controller: Controller,
    automation: Automation,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Automation {
    required: bool,
    runtime: Option<PathBuf>,
    workspace_root: Option<String>,
    max_concurrent: usize,
    max_scratch_bytes: u64,
    max_scratch_files: usize,
    targets: BTreeMap<String, AutomationTarget>,
    authorities: BTreeMap<String, NamedAutomationAuthority>,
    ssh_executable: Option<PathBuf>,
}

impl Default for Automation {
    fn default() -> Self {
        Self {
            required: false,
            runtime: None,
            ssh_executable: None,
            workspace_root: None,
            max_concurrent: 2,
            max_scratch_bytes: 16 * 1024 * 1024,
            max_scratch_files: 512,
            targets: BTreeMap::new(),
            authorities: BTreeMap::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomationTarget {
    pub(crate) destination: String,
    pub(crate) python: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedAutomationAuthority {
    ssh_config_file: PathBuf,
    runtime: Option<PathBuf>,
    ssh_auth_sock: Option<PathBuf>,
    r#become: AutomationBecome,
    targets: BTreeMap<String, AutomationTarget>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum AutomationBecome {
    Sudo { user: String },
}

pub(crate) enum AutomationAgent<'a> {
    Inherit,
    Disabled,
    Fixed(&'a Path),
}

pub(crate) struct ResolvedAutomation<'a> {
    pub(crate) target: &'a AutomationTarget,
    pub(crate) ssh_config: Option<&'a Path>,
    pub(crate) ssh_executable: &'a Path,
    pub(crate) r#become: Option<&'a AutomationBecome>,
    pub(crate) agent: AutomationAgent<'a>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Controller {
    workspace_root: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Ssh {
    config_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub(crate) connect_timeout_secs: u64,
    pub(crate) operation_timeout_secs: u64,
    pub(crate) max_timeout_secs: u64,
    pub(crate) max_output_bytes: u64,
    pub(crate) max_file_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 10,
            operation_timeout_secs: 60,
            max_timeout_secs: 600,
            max_output_bytes: 1_048_576,
            max_file_bytes: 1_048_576,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    ssh_host: String,
    #[serde(default)]
    profile: Profile,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    sudo: Sudo,
}

#[derive(Default, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum Sudo {
    #[default]
    Disabled,
    SameAccount {
        #[serde(default = "root_users")]
        users: Vec<String>,
        programs: Option<Vec<String>>,
    },
    SeparateIdentity {
        ssh_host: String,
        #[serde(default = "root_users")]
        users: Vec<String>,
        programs: Option<Vec<String>>,
    },
}

fn root_users() -> Vec<String> {
    vec!["root".to_owned()]
}

#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct TargetDiscovery<'a> {
    mode: TargetMode,
    #[schemars(with = "Vec<TargetSummary<'a>>")]
    targets: TargetSummaries<'a>,
    limits: DiscoveryLimits,
}

#[derive(Serialize, schemars::JsonSchema)]
struct TargetSummary<'a> {
    name: &'a str,
    sudo_mode: SudoMode,
    description: Option<&'a str>,
    labels: &'a BTreeMap<String, String>,
    #[schemars(with = "Vec<&'a str>")]
    permitted_operations: PermittedOperations<'a>,
    observed_capabilities: ObservedCapabilities,
}

// Select only public fields as each row is serialized. In particular, do not
// allocate a summary Vec before the shared response-budget guard is applied.
struct TargetSummaries<'a> {
    targets: Option<&'a BTreeMap<String, Target>>,
    tools: &'a ToolCatalog,
    profile: Profile,
    bindings: &'a Bindings,
}

impl Serialize for TargetSummaries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.targets.iter().flat_map(|targets| targets.iter()).map(
            |(name, target)| TargetSummary {
                name,
                sudo_mode: target.sudo.mode(),
                description: target.description.as_deref(),
                labels: &target.labels,
                permitted_operations: PermittedOperations {
                    tools: self.tools,
                    bindings: self.bindings,
                    target_name: name,
                    sudo: &target.sudo,
                    global_profile: self.profile,
                    target_profile: target.profile,
                },
                observed_capabilities: ObservedCapabilities::Unknown,
            },
        ))
    }
}

struct PermittedOperations<'a> {
    tools: &'a ToolCatalog,
    bindings: &'a Bindings,
    target_name: &'a str,
    sudo: &'a Sudo,
    global_profile: Profile,
    target_profile: Profile,
}

impl Serialize for PermittedOperations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.tools
                .entries
                .iter()
                .filter(|entry| match entry.id {
                    ToolKey::Builtin(id) => {
                        self.global_profile.permits(id)
                            && self.target_profile.permits(id)
                            && match id {
                                ToolId::Targets => false,
                                ToolId::Sudo => self.sudo.permits_programs(),
                                ToolId::Exec
                                | ToolId::Run
                                | ToolId::ReadFile
                                | ToolId::WriteFile
                                | ToolId::Mkdir
                                | ToolId::Stat
                                | ToolId::ListDirectory => true,
                            }
                    }
                    ToolKey::Binding(id) => {
                        self.global_profile.permits_bindings()
                            && self.target_profile.permits_bindings()
                            && self.bindings.get(id).is_some_and(|binding| {
                                binding.enabled()
                                    && !binding.is_controller()
                                    && binding.targets.iter().any(|name| name == self.target_name)
                                    && binding.sudo().is_none_or(|(user, program)| {
                                        self.sudo.permits(user, program)
                                    })
                            })
                    }
                })
                .map(|entry| entry.name.as_ref()),
        )
    }
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ObservedCapabilities {
    Unknown,
}

/// Resolved policy ceilings; escaping and JSON framing may reduce usable bytes.
#[derive(Serialize, schemars::JsonSchema)]
struct DiscoveryLimits {
    connect_timeout_secs: u64,
    operation_timeout_secs: u64,
    max_timeout_secs: u64,
    max_output_bytes: u64,
    max_file_bytes: u64,
    max_stdin_bytes: u64,
    max_command_bytes: usize,
    max_encoded_command_bytes: usize,
    max_response_bytes: usize,
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum TargetMode {
    Open,
    Configured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SudoMode {
    Disabled,
    SameAccount,
    SeparateIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IdentityRole {
    Ordinary,
    Elevated,
    Controller,
    Automation,
}

pub(crate) struct ResolvedTarget<'a> {
    pub(crate) name: &'a str,
    pub(crate) destination: &'a str,
    pub(crate) role: IdentityRole,
}

impl Sudo {
    fn mode(&self) -> SudoMode {
        match self {
            Self::Disabled => SudoMode::Disabled,
            Self::SameAccount { .. } => SudoMode::SameAccount,
            Self::SeparateIdentity { .. } => SudoMode::SeparateIdentity,
        }
    }

    fn permits(&self, user: &str, program: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::SameAccount { users, programs }
            | Self::SeparateIdentity {
                users, programs, ..
            } => {
                users.iter().any(|allowed| allowed == user)
                    && programs
                        .as_ref()
                        .is_none_or(|allowed| allowed.iter().any(|allowed| allowed == program))
            }
        }
    }

    fn resolve<'a>(
        &'a self,
        host: &'a str,
        ordinary: &'a str,
        user: &str,
        program: &str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        if !self.permits(user, program) {
            return Err(ToolError::new(
                "policy_denied",
                "Elevated target, user, or program is not authorized",
                false,
            ));
        }
        let (destination, role) = match self {
            Self::Disabled => unreachable!("disabled sudo policy cannot permit execution"),
            Self::SameAccount { .. } => (ordinary, IdentityRole::Ordinary),
            Self::SeparateIdentity { ssh_host, .. } => (ssh_host.as_str(), IdentityRole::Elevated),
        };
        Ok(ResolvedTarget {
            name: host,
            destination,
            role,
        })
    }

    fn permits_programs(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::SameAccount { programs, .. } | Self::SeparateIdentity { programs, .. } => {
                programs
                    .as_ref()
                    .is_none_or(|programs| !programs.is_empty())
            }
        }
    }
}

impl Config {
    pub(crate) fn load(cli: Cli) -> Result<Self, ConfigError> {
        let cwd = std::env::current_dir()
            .map_err(|_| invalid("config", "cannot determine launch directory"))?;
        Self::load_with(cli, &cwd, |key| std::env::var_os(key))
    }

    // Inject environment and launch directory so tests never mutate process state.
    fn load_with(
        cli: Cli,
        cwd: &Path,
        env: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, ConfigError> {
        let config_path = cli
            .config
            .or_else(|| env("ESTUS_CONFIG").map(PathBuf::from));
        let (mut document, base) = if let Some(path) = config_path {
            let path = resolve_path(path, cwd, "config")?;
            let text = std::fs::read_to_string(&path)
                .map_err(|_| invalid("config", "cannot read explicitly selected TOML file"))?;
            let value: toml::Value = toml::from_str(&text)
                .map_err(|_| invalid("config", "invalid TOML syntax or duplicate key"))?;
            validate_schema(&value)?;
            let document = value
                .try_into::<Document>()
                .map_err(|_| invalid("config", "invalid configuration structure"))?;
            let base = path.parent().unwrap_or(cwd).to_path_buf();
            (document, base)
        } else {
            (Document::default(), cwd.to_path_buf())
        };

        let ssh_override = cli
            .ssh_config
            .or_else(|| env("ESTUS_SSH_CONFIG").map(PathBuf::from));
        let ssh_config = match ssh_override {
            Some(path) => Some(resolve_path(path, cwd, "ssh.config_file")?),
            None => document
                .ssh
                .config_file
                .map(|path| resolve_path(path, &base, "ssh.config_file"))
                .transpose()?,
        };
        if let Some(path) = &ssh_config {
            // An explicit replacement must be readable now; never silently fall back
            // to the invoking user's normal SSH configuration.
            let file = std::fs::File::open(path).map_err(|_| {
                invalid(
                    "ssh.config_file",
                    "cannot read replacement SSH configuration",
                )
            })?;
            if !file
                .metadata()
                .map_err(|_| {
                    invalid(
                        "ssh.config_file",
                        "cannot inspect replacement SSH configuration",
                    )
                })?
                .is_file()
            {
                return Err(invalid("ssh.config_file", "must be a readable file"));
            }
        }
        let limits = &mut document.limits;
        for (field, variable, limit) in [
            (
                "limits.connect_timeout_secs",
                "ESTUS_CONNECT_TIMEOUT_SECS",
                &mut limits.connect_timeout_secs,
            ),
            (
                "limits.operation_timeout_secs",
                "ESTUS_OPERATION_TIMEOUT_SECS",
                &mut limits.operation_timeout_secs,
            ),
            (
                "limits.max_timeout_secs",
                "ESTUS_MAX_TIMEOUT_SECS",
                &mut limits.max_timeout_secs,
            ),
            (
                "limits.max_output_bytes",
                "ESTUS_MAX_OUTPUT_BYTES",
                &mut limits.max_output_bytes,
            ),
            (
                "limits.max_file_bytes",
                "ESTUS_MAX_FILE_BYTES",
                &mut limits.max_file_bytes,
            ),
        ] {
            if let Some(value) = env(variable) {
                let value = value
                    .to_str()
                    .ok_or_else(|| invalid(field, "must be a positive decimal integer"))?;
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid(field, "must be a positive decimal integer"));
                }
                *limit = value
                    .parse()
                    .map_err(|_| invalid(field, "positive integer exceeds supported range"))?;
            }
            if *limit == 0 {
                return Err(invalid(field, "must be strictly positive"));
            }
        }
        for (field, timeout) in [
            ("limits.connect_timeout_secs", limits.connect_timeout_secs),
            (
                "limits.operation_timeout_secs",
                limits.operation_timeout_secs,
            ),
        ] {
            if timeout > limits.max_timeout_secs {
                return Err(invalid(field, "must not exceed limits.max_timeout_secs"));
            }
        }
        if let Some(targets) = &document.targets {
            validate_targets(targets)?;
        }
        if let Some(root) = &document.controller.workspace_root
            && (!root.starts_with('/') || root.len() > 1024 || root.contains('\0'))
        {
            return Err(invalid(
                "controller.workspace_root",
                "must be a bounded absolute path",
            ));
        }
        let automation = &document.automation;
        if !(1..=16).contains(&automation.max_concurrent)
            || automation.max_scratch_bytes == 0
            || automation.max_scratch_bytes > 64 * 1024 * 1024
            || !(1..=4096).contains(&automation.max_scratch_files)
        {
            return Err(invalid(
                "automation",
                "invalid concurrency or scratch bounds",
            ));
        }
        if let Some(root) = &automation.workspace_root {
            validate_runtime_path(root)?;
        }
        for (name, target) in &automation.targets {
            if !document
                .targets
                .as_ref()
                .is_some_and(|targets| targets.contains_key(name))
            {
                return Err(invalid(
                    "automation.targets",
                    "must name configured logical targets",
                ));
            }
            destination(&target.destination, "automation.targets.destination")?;
            validate_runtime_path(&target.python)?;
        }
        for authority in automation.authorities.values() {
            validate_automation_targets(
                &authority.targets,
                document.targets.as_ref(),
                "automation.authorities.*.targets",
            )?;
        }
        let bindings = Bindings::compile(
            document.tools,
            &document.enabled_tools,
            &document.limits,
            |name| {
                document
                    .targets
                    .as_ref()
                    .is_some_and(|targets| targets.contains_key(name))
            },
            document.controller.workspace_root.as_deref(),
            document.profile.permits_bindings(),
        )?;
        // Definitions are operator capabilities even when hidden or disabled.
        // Validate their authority before exposure profiles select callable tools.
        for (_, binding) in bindings.entries() {
            if let Some((user, program)) = binding.sudo() {
                for name in &binding.targets {
                    if !document
                        .targets
                        .as_ref()
                        .and_then(|targets| targets.get(name))
                        .is_some_and(|target| target.sudo.permits(user, program))
                    {
                        return Err(invalid(
                            "tools",
                            "binding authority exceeds target sudo policy",
                        ));
                    }
                }
            }
        }
        for (_, binding) in bindings
            .entries()
            .filter(|(_, binding)| binding.is_automation())
        {
            let targets = match binding.automation_authority() {
                Some(AutomationAuthority::Ordinary) => &document.automation.targets,
                Some(AutomationAuthority::Named(name)) => {
                    &document
                        .automation
                        .authorities
                        .get(name)
                        .ok_or_else(|| invalid("tools", "automation authority is not configured"))?
                        .targets
                }
                None => unreachable!("automation binding has a typed authority"),
            };
            if binding
                .targets
                .iter()
                .any(|name| !targets.contains_key(name))
            {
                return Err(invalid(
                    "tools",
                    "automation targets require explicit automation authority",
                ));
            }
        }
        Ok(Self {
            profile: document.profile,
            ssh_config,
            limits: document.limits,
            targets: document.targets,
            bindings,
            automation: document.automation,
        })
    }

    /// A startup prerequisite only; this does not enable automation tools.
    pub(crate) fn automation_required(&self) -> bool {
        self.automation.required
    }

    /// Resolve the optional reference only when runtime health is requested.
    /// This validates its shape without inspecting any runtime files.
    pub(crate) fn automation_runtime(&self) -> Result<Option<PathBuf>, ConfigError> {
        self.automation_runtime_with(|key| std::env::var_os(key))
    }

    fn automation_runtime_with(
        &self,
        env: impl FnOnce(&str) -> Option<OsString>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        if let Some(path) = &self.automation.runtime {
            return Ok(Some(path.clone()));
        }
        env("ESTUS_ANSIBLE_RUNTIME")
            .map(|value| {
                let value = value.to_str().ok_or_else(|| {
                    invalid("automation.runtime", "must be a bounded absolute path")
                })?;
                validate_runtime_path(value)?;
                Ok(PathBuf::from(value))
            })
            .transpose()
    }

    pub(crate) async fn activate_automation(
        &mut self,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<bool, ConfigError> {
        let active: Vec<_> = self
            .bindings
            .entries()
            .filter(|(id, binding)| binding.is_automation() && self.binding_enabled(*id))
            .map(|(id, _)| id)
            .collect();
        if active.is_empty() {
            return Ok(false);
        }
        let ssh = self
            .automation
            .ssh_executable
            .clone()
            .or_else(|| std::env::var_os("ESTUS_AUTOMATION_SSH").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/usr/bin/ssh"));
        let text = ssh.to_str().ok_or_else(|| {
            invalid(
                "automation.ssh_executable",
                "must be a bounded absolute path",
            )
        })?;
        validate_runtime_path(text)?;
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&ssh).map_err(|_| {
            invalid(
                "automation.ssh_executable",
                "selected executable is unavailable",
            )
        })?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid(
                "automation.ssh_executable",
                "selected executable is unavailable",
            ));
        }
        self.automation.ssh_executable = Some(ssh);
        let needs_inherited_runtime = active.iter().any(|id| {
            match self
                .bindings
                .get(*id)
                .and_then(|binding| binding.automation_authority())
            {
                Some(AutomationAuthority::Ordinary) => true,
                Some(AutomationAuthority::Named(name)) => self
                    .automation
                    .authorities
                    .get(name)
                    .is_some_and(|authority| authority.runtime.is_none()),
                None => false,
            }
        });
        let inherited_runtime = if needs_inherited_runtime {
            self.automation_runtime()?
        } else {
            None
        };
        let root = crate::bindings::controller_root(self.automation.workspace_root.as_deref())?;
        let mut inspected = BTreeSet::new();
        for id in active {
            let (runtime, agent_socket) = match self
                .bindings
                .get(id)
                .and_then(|binding| binding.automation_authority())
            {
                Some(AutomationAuthority::Named(name)) => {
                    let (name, authority) = self
                        .automation
                        .authorities
                        .get_key_value(name)
                        .ok_or_else(|| {
                            invalid("tools", "automation authority is not configured")
                        })?;
                    if inspected.insert(name.as_str()) {
                        let config = authority.ssh_config_file.clone();
                        let socket = authority.ssh_auth_sock.clone();
                        tokio::task::spawn_blocking(move || {
                            inspect_automation_authority(&config, socket.as_deref())
                        })
                        .await
                        .map_err(|_| {
                            invalid(
                                "automation.authorities.*",
                                "cannot inspect selected authority",
                            )
                        })??;
                    }
                    (
                        authority
                            .runtime
                            .as_ref()
                            .or(inherited_runtime.as_ref())
                            .cloned(),
                        authority
                            .ssh_auth_sock
                            .as_ref()
                            .map(|path| path.as_os_str().to_owned()),
                    )
                }
                Some(AutomationAuthority::Ordinary) => {
                    (inherited_runtime.clone(), std::env::var_os("SSH_AUTH_SOCK"))
                }
                None => return Err(invalid("tools", "automation authority is not configured")),
            };
            self.bindings
                .activate_automation(id, runtime, root.clone(), agent_socket, ct)
                .await?;
        }
        Ok(true)
    }

    pub(crate) fn automation_concurrency(&self) -> usize {
        self.automation.max_concurrent
    }

    pub(crate) fn automation_scratch(&self) -> (u64, usize) {
        (
            self.automation.max_scratch_bytes,
            self.automation.max_scratch_files,
        )
    }

    pub(crate) fn automation_target(
        &self,
        id: BindingId,
        host: &str,
    ) -> Result<ResolvedAutomation<'_>, ToolError> {
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
        if !self.binding_enabled(id)
            || !self.bindings.get(id).is_some_and(|binding| {
                binding.is_automation() && binding.targets.iter().any(|target| target == host)
            })
            || !self
                .targets
                .as_ref()
                .and_then(|targets| targets.get(host))
                .is_some_and(|target| target.profile.permits_bindings())
        {
            return Err(denied());
        }
        let ssh_executable = self
            .automation
            .ssh_executable
            .as_deref()
            .ok_or_else(denied)?;
        match self
            .bindings
            .get(id)
            .and_then(|binding| binding.automation_authority())
        {
            Some(AutomationAuthority::Ordinary) => Ok(ResolvedAutomation {
                target: self.automation.targets.get(host).ok_or_else(denied)?,
                ssh_config: self.ssh_config.as_deref(),
                ssh_executable,
                r#become: None,
                agent: AutomationAgent::Inherit,
            }),
            Some(AutomationAuthority::Named(name)) => {
                let authority = self.automation.authorities.get(name).ok_or_else(denied)?;
                Ok(ResolvedAutomation {
                    target: authority.targets.get(host).ok_or_else(denied)?,
                    ssh_config: Some(&authority.ssh_config_file),
                    ssh_executable,
                    r#become: Some(&authority.r#become),
                    agent: authority
                        .ssh_auth_sock
                        .as_deref()
                        .map_or(AutomationAgent::Disabled, AutomationAgent::Fixed),
                })
            }
            None => Err(denied()),
        }
    }

    pub(crate) fn automation_hosts(&self) -> impl Iterator<Item = &String> {
        self.targets.iter().flat_map(|targets| targets.keys())
    }

    pub(crate) fn targets<'a>(&'a self, tools: &'a ToolCatalog) -> TargetDiscovery<'a> {
        TargetDiscovery {
            mode: if self.targets.is_some() {
                TargetMode::Configured
            } else {
                TargetMode::Open
            },
            targets: TargetSummaries {
                targets: self.targets.as_ref(),
                tools,
                profile: self.profile,
                bindings: &self.bindings,
            },
            limits: DiscoveryLimits {
                connect_timeout_secs: self.limits.connect_timeout_secs,
                operation_timeout_secs: self.limits.operation_timeout_secs,
                max_timeout_secs: self.limits.max_timeout_secs,
                max_output_bytes: self.limits.max_output_bytes,
                max_file_bytes: self.limits.max_file_bytes,
                max_stdin_bytes: self.limits.max_file_bytes,
                max_command_bytes: MAX_COMMAND_BYTES,
                max_encoded_command_bytes: MAX_COMMAND_BYTES,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
        }
    }

    pub(crate) fn ssh_config(&self) -> Option<&Path> {
        self.ssh_config.as_deref()
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) fn bindings(&self) -> &Bindings {
        &self.bindings
    }

    pub(crate) fn binding_enabled(&self, id: BindingId) -> bool {
        self.profile.permits_bindings()
            && self.bindings.get(id).is_some_and(|binding| {
                binding.enabled()
                    && (!binding.is_automation()
                        || binding.targets.iter().any(|name| {
                            self.targets
                                .as_ref()
                                .and_then(|targets| targets.get(name))
                                .is_some_and(|target| target.profile.permits_bindings())
                        }))
            })
    }

    pub(crate) fn controller_enabled(&self, id: BindingId) -> bool {
        self.binding_enabled(id)
            && self
                .bindings
                .get(id)
                .is_some_and(|binding| binding.is_controller())
    }

    pub(crate) fn resolve_binding<'a>(
        &'a self,
        host: &'a str,
        id: BindingId,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
        let binding = self.bindings.get(id).ok_or_else(denied)?;
        if binding.is_controller()
            || !self.binding_enabled(id)
            || !binding.targets.iter().any(|name| name == host)
        {
            return Err(denied());
        }
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        if !target.profile.permits_bindings() {
            return Err(denied());
        }
        match binding.sudo() {
            Some((user, program)) => target.sudo.resolve(host, &target.ssh_host, user, program),
            None => self.resolve_ordinary(host),
        }
    }

    pub(crate) fn tool_enabled(&self, tool: ToolId) -> bool {
        self.profile.permits(tool) && (tool != ToolId::Sudo || self.has_sudo())
    }

    pub(crate) fn has_sudo(&self) -> bool {
        self.targets.as_ref().is_some_and(|targets| {
            targets
                .values()
                .any(|target| !matches!(target.sudo, Sudo::Disabled))
        })
    }

    pub(crate) fn sudo_mode(&self, host: &str) -> SudoMode {
        self.targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .map_or(SudoMode::Disabled, |target| target.sudo.mode())
    }

    pub(crate) fn resolve<'a>(
        &'a self,
        host: &'a str,
        tool: ToolId,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
        match tool {
            ToolId::Targets | ToolId::Sudo => return Err(denied()),
            ToolId::Exec
            | ToolId::Run
            | ToolId::ReadFile
            | ToolId::WriteFile
            | ToolId::Mkdir
            | ToolId::Stat
            | ToolId::ListDirectory => {}
        }
        if !self.profile.permits(tool) {
            return Err(denied());
        }
        if self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .is_some_and(|target| !target.profile.permits(tool))
        {
            return Err(denied());
        }
        self.resolve_ordinary(host)
    }

    /// Resolve an operator diagnostic independently of MCP publication profiles.
    /// Only configured logical names qualify, and sudo identities are never selected.
    pub(crate) fn doctor_target<'a>(
        &'a self,
        host: &'a str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(|| {
                ToolError::new(
                    "policy_denied",
                    "Host is not a configured logical target",
                    false,
                )
            })?;
        Ok(ResolvedTarget {
            name: host,
            destination: &target.ssh_host,
            role: IdentityRole::Ordinary,
        })
    }

    fn resolve_ordinary<'a>(&'a self, host: &'a str) -> Result<ResolvedTarget<'a>, ToolError> {
        let destination = match &self.targets {
            Some(targets) => targets
                .get(host)
                .map(|target| target.ssh_host.as_str())
                .ok_or_else(|| {
                    ToolError::new(
                        "policy_denied",
                        "Host is not a configured logical target",
                        false,
                    )
                })?,
            None => {
                destination(host, "host").map_err(|_| {
                    ToolError::new(
                        "invalid_argument",
                        "Host must be a safe nonempty SSH destination",
                        false,
                    )
                })?;
                host
            }
        };
        Ok(ResolvedTarget {
            name: host,
            destination,
            role: IdentityRole::Ordinary,
        })
    }

    pub(crate) fn resolve_sudo<'a>(
        &'a self,
        host: &'a str,
        user: &str,
        program: &str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || {
            ToolError::new(
                "policy_denied",
                "Elevated target, user, or program is not authorized",
                false,
            )
        };
        if !self.profile.permits(ToolId::Sudo) {
            return Err(denied());
        }
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        if !target.profile.permits(ToolId::Sudo) {
            return Err(denied());
        }
        target.sudo.resolve(host, &target.ssh_host, user, program)
    }

    pub(crate) fn timeout(&self, seconds: Option<u64>) -> Result<std::time::Duration, ToolError> {
        let seconds = seconds.unwrap_or(self.limits.operation_timeout_secs);
        if seconds == 0 || seconds > self.limits.max_timeout_secs {
            return Err(ToolError::new(
                "invalid_argument",
                "timeout_secs must be positive and not exceed the configured maximum",
                false,
            ));
        }
        Ok(std::time::Duration::from_secs(seconds))
    }
}

fn validate_authorities_schema(value: &toml::Value) -> Result<(), ConfigError> {
    let authorities = value
        .as_table()
        .ok_or_else(|| invalid("automation.authorities", "must be a table"))?;
    if authorities.len() > 16 {
        return Err(invalid(
            "automation.authorities",
            "must contain at most 16 authorities",
        ));
    }
    for (name, value) in authorities {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic()
                    || byte == b'_'
                    || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
            })
        {
            return Err(invalid(
                "automation.authorities",
                "invalid authority identifier",
            ));
        }
        let authority = table(
            value,
            "automation.authorities.*",
            &[
                "ssh_config_file",
                "runtime",
                "ssh_auth_sock",
                "become",
                "targets",
            ],
        )?;
        for (key, field, required) in [
            (
                "ssh_config_file",
                "automation.authorities.*.ssh_config_file",
                true,
            ),
            ("runtime", "automation.authorities.*.runtime", false),
            (
                "ssh_auth_sock",
                "automation.authorities.*.ssh_auth_sock",
                false,
            ),
        ] {
            match authority.get(key) {
                Some(value) => {
                    let path = value
                        .as_str()
                        .ok_or_else(|| invalid(field, "must be a string"))?;
                    authority_path(path, field)?;
                }
                None if required => return Err(invalid(field, "required field is missing")),
                None => {}
            }
        }
        let r#become = authority.get("become").ok_or_else(|| {
            invalid(
                "automation.authorities.*.become",
                "required field is missing",
            )
        })?;
        let r#become = table(
            r#become,
            "automation.authorities.*.become",
            &["method", "user"],
        )?;
        if r#become.get("method").and_then(toml::Value::as_str) != Some("sudo") {
            return Err(invalid(
                "automation.authorities.*.become.method",
                "must be sudo",
            ));
        }
        if !r#become
            .get("user")
            .and_then(toml::Value::as_str)
            .is_some_and(account_name)
        {
            return Err(invalid(
                "automation.authorities.*.become.user",
                "must be a named POSIX account",
            ));
        }
        let mappings = authority
            .get("targets")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                invalid(
                    "automation.authorities.*.targets",
                    "required target table is missing or invalid",
                )
            })?;
        for value in mappings.values() {
            let mapping = table(
                value,
                "automation.authorities.*.targets.*",
                &["destination", "python"],
            )?;
            let destination_value = mapping
                .get("destination")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    invalid(
                        "automation.authorities.*.targets.*.destination",
                        "required string field is missing or invalid",
                    )
                })?;
            destination(
                destination_value,
                "automation.authorities.*.targets.*.destination",
            )?;
            let python = mapping
                .get("python")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    invalid(
                        "automation.authorities.*.targets.*.python",
                        "required string field is missing or invalid",
                    )
                })?;
            authority_path(python, "automation.authorities.*.targets.*.python")?;
        }
    }
    Ok(())
}

fn authority_path(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid(field, "must be a bounded absolute path"));
    }
    Ok(())
}

fn validate_automation_targets(
    mappings: &BTreeMap<String, AutomationTarget>,
    targets: Option<&BTreeMap<String, Target>>,
    field: &'static str,
) -> Result<(), ConfigError> {
    for (name, target) in mappings {
        if !targets.is_some_and(|targets| targets.contains_key(name)) {
            return Err(invalid(field, "must name configured logical targets"));
        }
        destination(&target.destination, field)?;
        authority_path(&target.python, field)?;
    }
    Ok(())
}

fn inspect_automation_authority(config: &Path, socket: Option<&Path>) -> Result<(), ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(config)
        .map_err(|_| {
            invalid(
                "automation.authorities.*.ssh_config_file",
                "cannot read replacement SSH configuration",
            )
        })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(invalid(
            "automation.authorities.*.ssh_config_file",
            "must be a readable file",
        ));
    }
    if let Some(socket) = socket {
        use std::os::unix::fs::FileTypeExt;
        if !std::fs::metadata(socket).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            return Err(invalid(
                "automation.authorities.*.ssh_auth_sock",
                "selected agent socket is unavailable",
            ));
        }
    }
    Ok(())
}

fn resolve_path(path: PathBuf, base: &Path, field: &'static str) -> Result<PathBuf, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(invalid(field, "path must not be empty"));
    }
    Ok(if path.is_absolute() {
        path
    } else {
        base.join(path)
    })
}

fn validate_runtime_path(value: &str) -> Result<(), ConfigError> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid(
            "automation.runtime",
            "must be a bounded absolute path",
        ));
    }
    Ok(())
}

// Named POSIX-style accounts only, not sudo's numeric-ID syntax or options.
pub(crate) fn account_name(user: &str) -> bool {
    !user.is_empty()
        && user.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || byte == b'_'
                || (index > 0 && (byte.is_ascii_digit() || byte == b'-' || byte == b'.'))
        })
}

fn validate_targets(targets: &BTreeMap<String, Target>) -> Result<(), ConfigError> {
    let ordinary: BTreeSet<&str> = targets
        .values()
        .map(|target| target.ssh_host.as_str())
        .collect();
    let mut metadata_remaining = MAX_METADATA_BYTES;
    for target in targets.values() {
        destination(&target.ssh_host, "targets.*.ssh_host")?;
        if target
            .description
            .as_ref()
            .is_some_and(|description| description.len() > MAX_DESCRIPTION_BYTES)
        {
            return Err(invalid("targets.*.description", "exceeds UTF-8 byte limit"));
        }
        if target.labels.len() > MAX_LABELS {
            return Err(invalid("targets.*.labels", "exceeds label count limit"));
        }
        for (key, value) in &target.labels {
            if key.is_empty() || key.len() > MAX_LABEL_KEY_BYTES {
                return Err(invalid(
                    "targets.*.labels",
                    "keys must be nonempty and within UTF-8 byte limit",
                ));
            }
            if value.len() > MAX_LABEL_VALUE_BYTES {
                return Err(invalid("targets.*.labels.*", "exceeds UTF-8 byte limit"));
            }
        }
        for bytes in target.description.iter().map(String::len).chain(
            target
                .labels
                .iter()
                .map(|(key, value)| key.len() + value.len()),
        ) {
            metadata_remaining = metadata_remaining
                .checked_sub(bytes)
                .ok_or_else(|| invalid("targets", "exceeds aggregate metadata UTF-8 byte limit"))?;
        }
        let (users, programs) = match &target.sudo {
            Sudo::Disabled => continue,
            Sudo::SameAccount { users, programs } => (users, programs),
            Sudo::SeparateIdentity {
                ssh_host,
                users,
                programs,
            } => {
                destination(ssh_host, "targets.*.sudo.ssh_host")?;
                if ordinary.contains(ssh_host.as_str()) {
                    return Err(invalid(
                        "targets.*.sudo.ssh_host",
                        "privileged alias must not be any configured ordinary alias",
                    ));
                }
                (users, programs)
            }
        };
        if users.is_empty() {
            return Err(invalid(
                "targets.*.sudo.users",
                "must contain at least one user",
            ));
        }
        let mut seen = BTreeSet::new();
        for user in users {
            if !account_name(user) {
                return Err(invalid(
                    "targets.*.sudo.users",
                    "must contain valid account names",
                ));
            }
            if !seen.insert(user) {
                return Err(invalid("targets.*.sudo.users", "duplicate policy entry"));
            }
        }
        if let Some(programs) = programs {
            let mut seen = BTreeSet::new();
            for program in programs {
                if !program.starts_with('/') || program.ends_with('/') || program.contains('\0') {
                    return Err(invalid(
                        "targets.*.sudo.programs",
                        "must contain absolute executable paths without NUL or a trailing slash",
                    ));
                }
                if !seen.insert(program) {
                    return Err(invalid("targets.*.sudo.programs", "duplicate policy entry"));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn destination(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .chars()
            .any(|character| character == '\0' || character.is_whitespace())
    {
        return Err(invalid(
            field,
            "destination must be nonempty, contain no NUL or whitespace, and not start with '-'",
        ));
    }
    Ok(())
}

// Check shapes before serde conversion to report fixed, precise schema paths without
// ever formatting parser errors (which include source, values, and unknown keys).
fn table<'a>(
    value: &'a toml::Value,
    field: &'static str,
    allowed: &[&str],
) -> Result<&'a toml::Table, ConfigError> {
    let table = value
        .as_table()
        .ok_or_else(|| invalid(field, "must be a table"))?;
    if table.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(field, "unknown field in table"));
    }
    Ok(table)
}

fn string(value: &toml::Value, field: &'static str) -> Result<(), ConfigError> {
    if value.as_str().is_none() {
        return Err(invalid(field, "must be a string"));
    }
    Ok(())
}

fn validate_profile(value: &toml::Value, field: &'static str) -> Result<(), ConfigError> {
    let value = value
        .as_str()
        .ok_or_else(|| invalid(field, "must be a string"))?;
    let value = serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(value);
    Profile::deserialize(value)
        .map(|_| ())
        .map_err(|_| invalid(field, "unknown startup profile"))
}

fn validate_schema(value: &toml::Value) -> Result<(), ConfigError> {
    let root = table(
        value,
        "config",
        &[
            "profile",
            "ssh",
            "limits",
            "targets",
            "tools",
            "enabled_tools",
            "controller",
            "automation",
        ],
    )?;
    if let Some(value) = root.get("tools")
        && !value.is_table()
    {
        return Err(invalid("tools", "must be a table"));
    }
    if let Some(value) = root.get("enabled_tools") {
        let entries = value
            .as_array()
            .ok_or_else(|| invalid("enabled_tools", "must be an array of strings"))?;
        for entry in entries {
            string(entry, "enabled_tools")?;
        }
    }
    if let Some(value) = root.get("profile") {
        validate_profile(value, "profile")?;
    }
    if let Some(value) = root.get("automation") {
        let automation = table(
            value,
            "automation",
            &[
                "required",
                "runtime",
                "workspace_root",
                "max_concurrent",
                "max_scratch_bytes",
                "max_scratch_files",
                "targets",
                "authorities",
                "ssh_executable",
            ],
        )?;
        if let Some(value) = automation.get("required")
            && !value.is_bool()
        {
            return Err(invalid("automation.required", "must be a boolean"));
        }
        if let Some(value) = automation.get("runtime") {
            let value = value
                .as_str()
                .ok_or_else(|| invalid("automation.runtime", "must be a string"))?;
            validate_runtime_path(value)?;
        }
        if let Some(value) = automation.get("authorities") {
            validate_authorities_schema(value)?;
        }
    }
    if let Some(value) = root.get("controller") {
        let controller = table(value, "controller", &["workspace_root"])?;
        if let Some(value) = controller.get("workspace_root") {
            string(value, "controller.workspace_root")?;
        }
    }
    if let Some(value) = root.get("ssh") {
        let ssh = table(value, "ssh", &["config_file"])?;
        if let Some(value) = ssh.get("config_file") {
            string(value, "ssh.config_file")?;
        }
    }
    if let Some(value) = root.get("limits") {
        let fields = [
            ("connect_timeout_secs", "limits.connect_timeout_secs"),
            ("operation_timeout_secs", "limits.operation_timeout_secs"),
            ("max_timeout_secs", "limits.max_timeout_secs"),
            ("max_output_bytes", "limits.max_output_bytes"),
            ("max_file_bytes", "limits.max_file_bytes"),
        ];
        let limits = table(value, "limits", &fields.map(|(key, _)| key))?;
        for (key, field) in fields {
            if let Some(value) = limits.get(key)
                && value.as_integer().is_none_or(|number| number <= 0)
            {
                return Err(invalid(field, "must be a strictly positive integer"));
            }
        }
    }
    if let Some(value) = root.get("targets") {
        let targets = value
            .as_table()
            .ok_or_else(|| invalid("targets", "must be a table"))?;
        for (name, value) in targets {
            if name.is_empty() || name.chars().any(char::is_control) {
                return Err(invalid(
                    "targets",
                    "logical names must be nonempty and contain no control characters",
                ));
            }
            let target = table(
                value,
                "targets.*",
                &["ssh_host", "profile", "sudo", "description", "labels"],
            )?;
            string(
                target
                    .get("ssh_host")
                    .ok_or_else(|| invalid("targets.*.ssh_host", "required field is missing"))?,
                "targets.*.ssh_host",
            )?;
            if let Some(value) = target.get("profile") {
                validate_profile(value, "targets.*.profile")?;
            }
            if let Some(value) = target.get("description") {
                string(value, "targets.*.description")?;
            }
            if let Some(value) = target.get("labels") {
                let labels = value
                    .as_table()
                    .ok_or_else(|| invalid("targets.*.labels", "must be a table"))?;
                for value in labels.values() {
                    string(value, "targets.*.labels.*")?;
                }
            }
            if let Some(value) = target.get("sudo") {
                let sudo = value
                    .as_table()
                    .ok_or_else(|| invalid("targets.*.sudo", "must be a table"))?;
                let mode = sudo
                    .get("mode")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        invalid(
                            "targets.*.sudo.mode",
                            "required string field is missing or invalid",
                        )
                    })?;
                let allowed: &[&str] = match mode {
                    "disabled" => &["mode"],
                    "same-account" => &["mode", "users", "programs"],
                    "separate-identity" => &["mode", "ssh_host", "users", "programs"],
                    _ => {
                        return Err(invalid(
                            "targets.*.sudo.mode",
                            "must be disabled, same-account, or separate-identity",
                        ));
                    }
                };
                table(value, "targets.*.sudo", allowed)?;
                if mode == "separate-identity" {
                    string(
                        sudo.get("ssh_host").ok_or_else(|| {
                            invalid("targets.*.sudo.ssh_host", "required field is missing")
                        })?,
                        "targets.*.sudo.ssh_host",
                    )?;
                }
                for (key, field) in [
                    ("users", "targets.*.sudo.users"),
                    ("programs", "targets.*.sudo.programs"),
                ] {
                    if let Some(value) = sudo.get(key) {
                        let entries = value
                            .as_array()
                            .ok_or_else(|| invalid(field, "must be an array of strings"))?;
                        for entry in entries {
                            string(entry, field)?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_authorities_require_complete_private_capabilities_and_bounded_count() {
        let text = named_authority_text("baseline", "baseline", false);
        for invalid_text in [
            text.replace("ssh_config_file='/private-authority/config'\n", ""),
            text.replace("become={method='sudo',user='root'}\n", ""),
            text.replace(
                "[automation.authorities.ops.targets.server]\ndestination='private-authority-alias'\npython='/private-authority/python'\n",
                "",
            ),
            (0..17).fold(text.clone(), |text, index| text + &format!(
                "\n[automation.authorities.extra{index}]\nssh_config_file='/private-authority/config'\nbecome={{method='sudo',user='root'}}\ntargets={{}}\n"
            )),
        ] {
            let error = load_text(&invalid_text, &[]).err().unwrap();
            assert!(error.field.starts_with("automation.authorities"));
            assert!(!error.to_string().contains("private-authority"));
        }
    }

    #[test]
    fn active_authority_inspection_rejects_missing_config_and_non_socket_agent_privately() {
        let text = named_authority_text("baseline", "baseline", true);
        let config = load_text(&text, &[]).unwrap();
        let authority = &config.automation.authorities["ops"];
        let error = inspect_automation_authority(
            &authority.ssh_config_file,
            authority.ssh_auth_sock.as_deref(),
        )
        .err()
        .unwrap();
        assert_eq!(error.field, "automation.authorities.*.ssh_config_file");
        assert!(!error.to_string().contains("private-authority"));

        let dir = tempfile::tempdir().unwrap();
        let ssh_config = dir.path().join("config");
        std::fs::write(&ssh_config, "").unwrap();
        let text = text.replace(
            "ssh_config_file='/private-authority/config'",
            &format!(
                "ssh_config_file={:?}\nssh_auth_sock={:?}",
                ssh_config.to_str().unwrap(),
                ssh_config.to_str().unwrap()
            ),
        );
        let config = load_text(&text, &[]).unwrap();
        let authority = &config.automation.authorities["ops"];
        let error = inspect_automation_authority(
            &authority.ssh_config_file,
            authority.ssh_auth_sock.as_deref(),
        )
        .err()
        .unwrap();
        assert_eq!(error.field, "automation.authorities.*.ssh_auth_sock");
        assert!(!error.to_string().contains(dir.path().to_str().unwrap()));
        let fifo = dir.path().join("config-fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(inspect_automation_authority(&fifo, None).map_err(|error| error.field))
                .unwrap();
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("named SSH configuration inspection blocked on a FIFO");
        assert_eq!(
            result.err(),
            Some("automation.authorities.*.ssh_config_file")
        );
        worker.join().unwrap();
    }

    fn named_authority_text(global: &str, target: &str, enabled: bool) -> String {
        automation_text(global, target, enabled)
            .replace("authority='automation'", "authority='automation:ops'")
            + r#"
[automation.authorities.ops]
ssh_config_file='/private-authority/config'
runtime='/private-authority/runtime'
become={method='sudo',user='root'}
[automation.authorities.ops.targets.server]
destination='private-authority-alias'
python='/private-authority/python'
"#
    }

    #[tokio::test]
    async fn inactive_named_authorities_do_not_inspect_private_files() {
        for (global, target, enabled) in [
            ("baseline", "baseline", false),
            ("files-only", "baseline", true),
            ("baseline", "files-only", true),
        ] {
            let text = named_authority_text(global, target, enabled).replace(
                "become={",
                "ssh_auth_sock='/private-authority/socket'\nbecome={",
            );
            let mut config = load_text(&text, &[]).unwrap();
            assert!(
                !config
                    .activate_automation(&tokio_util::sync::CancellationToken::new())
                    .await
                    .unwrap()
            );
            assert!(config.automation_target(BindingId(0), "server").is_err());
        }
    }

    #[test]
    fn missing_named_authority_or_mapping_rejects_even_disabled_bindings() {
        let text = named_authority_text("baseline", "baseline", false);
        for invalid_text in [
            automation_text("baseline", "baseline", false)
                .replace("authority='automation'", "authority='automation:ops'"),
            text.replace(
                "automation.authorities.ops.targets.server",
                "automation.authorities.ops.targets.other",
            ),
            text.replace("targets=['server']", "targets=['server','second']")
                + "\n[targets.second]\nssh_host='second-native'\n",
        ] {
            let error = load_text(&invalid_text, &[]).err().unwrap();
            assert!(!error.to_string().contains("private-authority"));
        }
    }

    #[test]
    fn named_authority_resolution_never_falls_back_to_native_or_ordinary_credentials() {
        let text = named_authority_text("baseline", "baseline", true).replace(
            "[automation]\n",
            "[automation]\nssh_executable='/selected/ssh'\n",
        );
        for (socket_config, fixed) in [("", false), ("ssh_auth_sock='/selected/agent'\n", true)] {
            let config = load_text(
                &text.replace("become={", &format!("{socket_config}become={{")),
                &[],
            )
            .unwrap();
            let authority = config.automation_target(BindingId(0), "server").unwrap();
            assert_eq!(authority.target.destination, "private-authority-alias");
            assert_eq!(authority.target.python, "/private-authority/python");
            assert_eq!(
                authority.ssh_config,
                Some(Path::new("/private-authority/config"))
            );
            assert_eq!(authority.ssh_executable, Path::new("/selected/ssh"));
            assert_eq!(
                serde_json::to_value(authority.r#become).unwrap(),
                serde_json::json!({"method":"sudo","user":"root"})
            );
            match authority.agent {
                AutomationAgent::Fixed(socket) if fixed => {
                    assert_eq!(socket, Path::new("/selected/agent"))
                }
                AutomationAgent::Disabled if !fixed => {}
                _ => panic!("named authority must not inherit the ambient agent"),
            }
            for host in [
                "native-alias",
                "automation-alias",
                "private-authority-alias",
                "untrusted-secret-host",
            ] {
                let error = config.automation_target(BindingId(0), host).err().unwrap();
                assert_eq!(error.code, "policy_denied");
            }
            let tools = ToolCatalog::new(Vec::new()).unwrap();
            let discovery = serde_json::to_string(&config.targets(&tools)).unwrap();
            assert!(!discovery.contains("private-authority"));
            assert!(!discovery.contains("/selected/"));
        }
    }

    #[test]
    fn named_authority_invalid_private_values_have_fixed_diagnostics() {
        let text = named_authority_text("baseline", "baseline", false);
        for replacement in [
            (
                "ssh_config_file='/private-authority/config'",
                "ssh_config_file='private-secret'",
            ),
            (
                "runtime='/private-authority/runtime'",
                "runtime=['private-secret']",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='private-secret',user='root'}",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='sudo',user='#private-secret'}",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='sudo',user='root',password='private-secret'}",
            ),
            (
                "destination='private-authority-alias'",
                "destination='private-secret invalid'",
            ),
            (
                "python='/private-authority/python'",
                "python='private-secret'",
            ),
            (
                "[automation.authorities.ops]",
                "[automation.authorities.'private-secret!']",
            ),
        ] {
            let error = load_text(&text.replace(replacement.0, replacement.1), &[])
                .err()
                .unwrap();
            let diagnostic = error.to_string();
            assert!(diagnostic.starts_with("automation.authorities"));
            assert!(!diagnostic.contains("private-secret"));
            assert!(!diagnostic.contains("private-authority"));
        }
    }

    #[test]
    fn automation_destinations_share_explicit_ssh_destination_grammar() {
        for alias in [
            "_alias",
            "2001:db8::1",
            "[2001:db8::1]",
            "user@_alias",
            "é-alias",
        ] {
            assert!(destination(alias, "automation.targets.destination").is_ok());
        }
        for alias in ["", "-option", "a b", "a\0b", "a\u{2003}b"] {
            assert!(destination(alias, "automation.targets.destination").is_err());
        }
    }

    fn automation_text(global: &str, target: &str, enabled: bool) -> String {
        format!(
            r#"
profile={global:?}
enabled_tools={}
[targets.server]
ssh_host='native-alias'
profile={target:?}
[automation]
runtime='/unavailable/runtime.json'
workspace_root='/unavailable/workspace'
[automation.targets.server]
destination='automation-alias'
python='/unavailable/python'
[tools.probe]
description='Reviewed probe'
revision='review-1'
targets=['server']
authority='automation'
effects=['probe']
execution={{kind='ansible_module',snapshot='/unavailable/snapshot.json'}}
result={{kind='ansible_summary'}}
input_schema={{type='object',additionalProperties=false,required=[],properties={{}}}}
"#,
            if enabled { "['probe']" } else { "[]" }
        )
    }

    #[tokio::test]
    async fn automation_activation_is_lazy_for_disabled_and_effectively_hidden_bindings() {
        for (global, target, enabled) in [
            ("baseline", "baseline", false),
            ("files-only", "baseline", true),
            ("baseline", "files-only", true),
        ] {
            for kind in ["ansible_module", "ansible_role"] {
                let text = automation_text(global, target, enabled).replace("ansible_module", kind);
                let mut config = load_text(&text, &[]).unwrap();
                config
                    .activate_automation(&tokio_util::sync::CancellationToken::new())
                    .await
                    .unwrap();
                assert!(!config.binding_enabled(BindingId(0)));
            }
        }
    }

    #[tokio::test]
    async fn active_automation_requires_real_startup_prerequisites() {
        let mut config = load_text(&automation_text("baseline", "baseline", true), &[]).unwrap();
        assert!(
            config
                .activate_automation(&tokio_util::sync::CancellationToken::new())
                .await
                .is_err()
        );
        let target = config.automation_target(BindingId(0), "server").unwrap();
        assert_eq!(target.target.destination, "automation-alias");
        assert!(
            config
                .automation_target(BindingId(0), "native-alias")
                .is_err()
        );
    }

    #[test]
    fn automation_defaults_and_bounds_are_explicit() {
        let config = load_text("", &[]).unwrap();
        assert_eq!(config.automation_concurrency(), 2);
        assert_eq!(config.automation_scratch(), (16 * 1024 * 1024, 512));
        for field in [
            "max_concurrent=0",
            "max_concurrent=17",
            "max_scratch_bytes=0",
            "max_scratch_bytes=67108865",
            "max_scratch_files=4097",
        ] {
            assert!(load_text(&format!("[automation]\n{field}"), &[]).is_err());
        }
    }

    fn cli() -> Cli {
        Cli {
            config: None,
            ssh_config: None,
            command: None,
        }
    }

    #[test]
    fn doctor_is_optional_and_accepts_repeated_explicit_targets() {
        assert!(Cli::try_parse_from(["estus"]).unwrap().command.is_none());
        let parsed = Cli::try_parse_from([
            "estus",
            "doctor",
            "--target",
            "two",
            "--target",
            "one",
            "--timeout-secs",
            "7",
        ])
        .unwrap();
        let Some(CliCommand::Doctor(args)) = parsed.command else {
            panic!("doctor subcommand expected");
        };
        assert_eq!(args.targets, ["two", "one"]);
        assert_eq!(args.timeout_secs, Some(7));
        assert_eq!(args.runtime, None);

        let parsed = Cli::try_parse_from(["estus", "doctor", "--target", "one"]).unwrap();
        let Some(CliCommand::Doctor(args)) = parsed.command else {
            panic!("doctor subcommand expected");
        };
        assert_eq!(args.timeout_secs, None);
    }

    #[test]
    fn doctor_runtime_selection_allows_no_targets_or_combined_targets() {
        for argv in [
            vec!["estus", "doctor", "--runtime", "ansible"],
            vec!["estus", "doctor", "--runtime", "ansible", "--target", "one"],
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            let Some(CliCommand::Doctor(args)) = parsed.command else {
                panic!("doctor subcommand expected");
            };
            assert_eq!(args.runtime, Some(RuntimeKind::Ansible));
        }
        for argv in [
            vec!["estus", "doctor", "--runtime"],
            vec!["estus", "doctor", "--runtime", "unknown"],
            vec!["estus", "--runtime", "ansible"],
            vec![
                "estus",
                "doctor",
                "--runtime",
                "ansible",
                "--runtime-path",
                "/private",
            ],
        ] {
            assert!(Cli::try_parse_from(argv).is_err());
        }
        assert_eq!(
            serde_json::to_string(&RuntimeKind::Ansible).unwrap(),
            "\"ansible\""
        );
    }

    #[test]
    fn doctor_requires_named_selection_and_exposes_no_execution_controls() {
        for args in [
            vec!["estus", "doctor"],
            vec!["estus", "doctor", "one"],
            vec!["estus", "doctor", "--target"],
            vec!["estus", "doctor", "--target", "one", "two"],
            vec!["estus", "doctor", "--all"],
            vec!["estus", "doctor", "--target", "one", "--sudo"],
            vec!["estus", "doctor", "--target", "one", "--host", "private"],
            vec!["estus", "doctor", "--target", "one", "--command", "id"],
            vec!["estus", "doctor", "--target", "one", "--identity", "key"],
            vec![
                "estus",
                "doctor",
                "--target",
                "one",
                "--timeout-secs",
                "bad",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn doctor_global_paths_work_before_and_after_subcommand_with_cli_precedence() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(
            dir.path().join("nested/operator.toml"),
            "[ssh]\nconfig_file='missing-private-file'\n[targets.one]\nssh_host='private-alias'\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("selected-ssh"), "").unwrap();
        for argv in [
            vec![
                "estus",
                "--config",
                "nested/operator.toml",
                "--ssh-config",
                "selected-ssh",
                "doctor",
                "--target",
                "one",
            ],
            vec![
                "estus",
                "doctor",
                "--target",
                "one",
                "--config",
                "nested/operator.toml",
                "--ssh-config",
                "selected-ssh",
            ],
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            assert!(matches!(parsed.command, Some(CliCommand::Doctor(_))));
            let config = Config::load_with(parsed, dir.path(), |key| match key {
                "ESTUS_CONFIG" | "ESTUS_SSH_CONFIG" => Some("missing-env-private".into()),
                _ => None,
            })
            .unwrap();
            assert_eq!(
                config.ssh_config(),
                Some(dir.path().join("selected-ssh").as_path())
            );
            assert_eq!(
                config.doctor_target("one").unwrap().destination,
                "private-alias"
            );
        }
    }

    #[test]
    fn doctor_resolves_only_configured_names_with_private_denials() {
        for text in [
            "",
            "[targets]",
            "[targets.one]\nssh_host='private-alias'\n\
             [targets.one.sudo]\nmode='separate-identity'\nssh_host='private-elevated'",
        ] {
            let config = load_text(text, &[]).unwrap();
            for host in [
                "private-alias",
                "private-elevated",
                "private-unknown",
                "user@host",
            ] {
                let error = config.doctor_target(host).err().unwrap();
                assert_eq!(error.code, "policy_denied");
                assert!(!error.remote_state_unknown);
                let encoded = serde_json::to_string(&error).unwrap();
                for secret in [
                    "private-alias",
                    "private-elevated",
                    "private-unknown",
                    "user@host",
                ] {
                    assert!(!encoded.contains(secret));
                    assert!(!format!("{error:?}").contains(secret));
                }
            }
            if config.targets.as_ref().is_none_or(BTreeMap::is_empty) {
                assert!(config.doctor_target("one").is_err());
            }
        }
        // The operator-only restriction must not close native open-host mode.
        let open = load_text("", &[]).unwrap();
        assert_eq!(
            open.resolve("user@host", ToolId::Exec).unwrap().destination,
            "user@host",
        );
    }

    #[test]
    fn doctor_ignores_publication_profiles_but_never_selects_sudo_identity() {
        for global in ["baseline", "actions-only", "files-only", "read-only-files"] {
            for target in ["baseline", "actions-only", "files-only", "read-only-files"] {
                for sudo in [
                    "",
                    "[targets.one.sudo]\nmode='same-account'\n",
                    "[targets.one.sudo]\nmode='separate-identity'\nssh_host='private-elevated'\n",
                ] {
                    let config = load_text(
                        &format!(
                            "profile='{global}'\n[targets.one]\n\
                             ssh_host='private-ordinary'\nprofile='{target}'\n{sudo}"
                        ),
                        &[],
                    )
                    .unwrap();
                    let resolved = config.doctor_target("one").unwrap();
                    assert_eq!(resolved.name, "one");
                    assert_eq!(resolved.destination, "private-ordinary");
                    assert_eq!(resolved.role, IdentityRole::Ordinary);
                    assert_eq!(
                        config.resolve("one", ToolId::Exec).is_ok(),
                        global == "baseline" && target == "baseline",
                    );
                    assert_eq!(
                        config.resolve("one", ToolId::ReadFile).is_ok(),
                        global != "actions-only" && target != "actions-only",
                    );
                }
            }
        }
    }

    // Deliberately unrelated to production wire names and declaration order.
    fn catalog() -> ToolCatalog {
        ToolCatalog::new(
            [
                (ToolId::Exec, "z-exec"),
                (ToolId::Targets, "0-global-discovery"),
                (ToolId::Sudo, "m-elevate"),
                (ToolId::ReadFile, "n-read"),
                (ToolId::WriteFile, "c-write"),
                (ToolId::Stat, "q-stat"),
                (ToolId::ListDirectory, "b-list"),
                (ToolId::Run, "a-run"),
            ]
            .into_iter()
            .map(|(id, name)| ToolEntry {
                id: ToolKey::Builtin(id),
                name: name.into(),
            })
            .collect(),
        )
        .unwrap()
    }

    fn builtin(key: ToolKey) -> ToolId {
        match key {
            ToolKey::Builtin(id) => id,
            ToolKey::Binding(_) => panic!("builtin-only test catalogue"),
        }
    }

    #[test]
    fn catalog_rejects_duplicate_ids_even_with_distinct_names() {
        let error = ToolCatalog::new(vec![
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "first".into(),
            },
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "second".into(),
            },
        ])
        .unwrap_err();
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn catalog_rejects_duplicate_names_before_disabled_routes_can_be_removed() {
        let error = ToolCatalog::new(vec![
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "secret_collision".into(),
            },
            ToolEntry {
                id: ToolKey::Binding(BindingId(0)),
                name: "secret_collision".into(),
            },
        ])
        .unwrap_err();
        assert!(!format!("{error:?}").contains("secret_collision"));
    }

    fn binding_definition() -> &'static str {
        r#"
[tools.observe]
description = "Observe a fixed account"
revision = "1"
targets = ["one"]
authority = "ordinary"
effects = ["read"]
execution = { kind = "native_argv", program = "/usr/bin/id", argv = ["--", { input = "account" }] }
input_schema = { type = "object", additionalProperties = false, required = ["account"], properties = { account = { type = "string", minLength = 1, maxLength = 32 } } }
result = { kind = "command" }
"#
    }

    #[test]
    fn binding_policy_intersects_selection_profiles_and_declared_targets() {
        for (global, globally_allowed) in [
            ("baseline", true),
            ("actions-only", true),
            ("read-only-files", false),
            ("files-only", false),
        ] {
            for (target, target_allowed) in [
                ("baseline", true),
                ("actions-only", true),
                ("read-only-files", false),
                ("files-only", false),
            ] {
                for selected in [false, true] {
                    let text = format!(
                        "profile='{global}'\nenabled_tools={enabled}\n\
                         [targets.one]\nssh_host='ordinary-private'\nprofile='{target}'\n\
                         [targets.one.sudo]\nmode='separate-identity'\nssh_host='elevated-private'\n\
                         [targets.two]\nssh_host='other-private'\n{definition}",
                        enabled = if selected { "['observe']" } else { "[]" },
                        definition = binding_definition(),
                    );
                    let config = load_text(&text, &[]).unwrap();
                    let (id, binding) = config.bindings().entries().next().unwrap();
                    assert_eq!(config.binding_enabled(id), selected && globally_allowed);
                    let allowed = selected && globally_allowed && target_allowed;
                    let result = config.resolve_binding("one", id);
                    assert_eq!(result.is_ok(), allowed, "{global}/{target}/{selected}");
                    if let Ok(resolved) = result {
                        assert_eq!(resolved.destination, "ordinary-private");
                        assert_eq!(resolved.role, IdentityRole::Ordinary);
                    } else {
                        let error = result.err().unwrap();
                        assert_eq!(error.code, "policy_denied");
                        assert!(!error.remote_state_unknown);
                    }
                    for host in ["two", "ordinary-private", "elevated-private", "unknown"] {
                        assert!(config.resolve_binding(host, id).is_err());
                    }
                    let tools = ToolCatalog::new(vec![ToolEntry {
                        id: ToolKey::Binding(id),
                        name: binding.name.clone().into(),
                    }])
                    .unwrap();
                    let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
                    let rows = discovery["targets"].as_array().unwrap();
                    let one = rows.iter().find(|row| row["name"] == "one").unwrap();
                    assert_eq!(
                        one["permitted_operations"],
                        if allowed {
                            serde_json::json!(["observe"])
                        } else {
                            serde_json::json!([])
                        }
                    );
                    let two = rows.iter().find(|row| row["name"] == "two").unwrap();
                    assert_eq!(two["permitted_operations"], serde_json::json!([]));
                }
            }
        }
    }

    #[test]
    fn fixed_sudo_bindings_intersect_profiles_without_exposing_generic_sudo() {
        let elevated = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        let ordinary = binding_definition().replace("[tools.observe]", "[tools.ordinary]");
        for (mode, alias, destination, role) in [
            (
                "same-account",
                "",
                "ordinary-private",
                IdentityRole::Ordinary,
            ),
            (
                "separate-identity",
                "ssh_host='elevated-private'\n",
                "elevated-private",
                IdentityRole::Elevated,
            ),
        ] {
            for (global, global_allowed) in [
                ("baseline", true),
                ("actions-only", true),
                ("files-only", false),
                ("read-only-files", false),
            ] {
                for (profile, target_allowed) in [
                    ("baseline", true),
                    ("actions-only", true),
                    ("files-only", false),
                    ("read-only-files", false),
                ] {
                    for selected in [false, true] {
                        let config = load_text(
                            &format!(
                                "profile='{global}'\nenabled_tools={enabled}\n\
                                 [targets.one]\nssh_host='ordinary-private'\nprofile='{profile}'\n\
                                 [targets.one.sudo]\nmode='{mode}'\n{alias}\
                                 users=['root']\nprograms=['/usr/bin/id']\n\
                                 [targets.two]\nssh_host='other-private'\n{elevated}{ordinary}",
                                enabled = if selected {
                                    "['observe','ordinary']"
                                } else {
                                    "[]"
                                },
                            ),
                            &[],
                        )
                        .unwrap();
                        let mut entries = vec![ToolEntry {
                            id: ToolKey::Builtin(ToolId::Sudo),
                            name: "generic-sudo".into(),
                        }];
                        for (id, binding) in config.bindings().entries() {
                            let allowed = selected && global_allowed && target_allowed;
                            assert_eq!(config.binding_enabled(id), selected && global_allowed);
                            let result = config.resolve_binding("one", id);
                            assert_eq!(
                                result.is_ok(),
                                allowed,
                                "{mode}/{global}/{profile}/{selected}/{}",
                                binding.name,
                            );
                            if let Ok(resolved) = result {
                                assert_eq!(resolved.name, "one");
                                let expected = if binding.name == "observe" {
                                    (destination, role)
                                } else {
                                    ("ordinary-private", IdentityRole::Ordinary)
                                };
                                assert_eq!((resolved.destination, resolved.role), expected);
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.code, "policy_denied");
                                assert!(!error.remote_state_unknown);
                            }
                            for host in ["two", "ordinary-private", "elevated-private", "unknown"] {
                                assert!(config.resolve_binding(host, id).is_err(), "{host}");
                            }
                            entries.push(ToolEntry {
                                id: ToolKey::Binding(id),
                                name: binding.name.clone().into(),
                            });
                        }
                        let tools = ToolCatalog::new(entries).unwrap();
                        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
                        let rows = discovery["targets"].as_array().unwrap();
                        let one = rows.iter().find(|row| row["name"] == "one").unwrap();
                        let generic_allowed = global == "baseline" && profile == "baseline";
                        let mut expected = Vec::new();
                        if generic_allowed {
                            expected.push("generic-sudo");
                        }
                        if selected && global_allowed && target_allowed {
                            expected.extend(["observe", "ordinary"]);
                        }
                        assert_eq!(one["permitted_operations"], serde_json::json!(expected));
                        assert_eq!(
                            config.resolve_sudo("one", "root", "/usr/bin/id").is_ok(),
                            generic_allowed,
                        );
                        assert_eq!(config.tool_enabled(ToolId::Sudo), global == "baseline");
                        for tool in [ToolId::Exec, ToolId::Run] {
                            assert_eq!(config.resolve("one", tool).is_ok(), generic_allowed,);
                        }
                        let two = rows.iter().find(|row| row["name"] == "two").unwrap();
                        assert_eq!(two["permitted_operations"], serde_json::json!([]));
                    }
                }
            }
        }
    }

    #[test]
    fn every_fixed_sudo_definition_must_narrow_every_declared_target_policy() {
        let definition = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        for (mode, alias) in [
            ("same-account", ""),
            ("separate-identity", "ssh_host='secret_elevated'\n"),
        ] {
            for (policy, permitted) in [
                ("", true),
                ("users=['root']\nprograms=['/usr/bin/id']", true),
                ("users=['service']\nprograms=['/usr/bin/id']", false),
                ("programs=[]", false),
                ("programs=['/bin/id']", false),
                ("programs=['/usr/bin/id-other']", false),
            ] {
                for profile in ["baseline", "actions-only", "files-only", "read-only-files"] {
                    for enabled in ["[]", "['observe']"] {
                        for bad_second in [false, true] {
                            let definition = if bad_second {
                                definition
                                    .replace("targets = [\"one\"]", "targets = [\"one\", \"two\"]")
                            } else {
                                definition.clone()
                            };
                            let result = load_text(
                                &format!(
                                    "profile='{profile}'\nenabled_tools={enabled}\n\
                                     [targets.one]\nssh_host='secret_ordinary'\nprofile='{profile}'\n\
                                     [targets.one.sudo]\nmode='{mode}'\n{alias}{policy}\n\
                                     [targets.two]\nssh_host='secret_second'\n{definition}",
                                ),
                                &[],
                            );
                            assert_eq!(
                                result.is_ok(),
                                permitted && !bad_second,
                                "{mode}/{policy}/{profile}/{enabled}/{bad_second}",
                            );
                            if let Err(error) = result {
                                assert_eq!(error.field, "tools");
                                assert!(std::error::Error::source(&error).is_none());
                                let diagnostic = format!("{error:?} {error}");
                                for secret in ["secret_", "/usr/bin/id", "/bin/id", "service"] {
                                    assert!(!diagnostic.contains(secret), "{diagnostic}");
                                }
                            }
                        }
                    }
                }
            }
        }
        for enabled in ["[]", "['observe']"] {
            let error = load_text(
                &format!(
                    "enabled_tools={enabled}\n\
                     [targets.one]\nssh_host='secret_ordinary'\n{definition}",
                ),
                &[],
            )
            .err()
            .expect("disabled sudo cannot authorize a definition");
            assert_eq!(error.field, "tools");
        }
    }

    #[test]
    fn binding_dispatch_and_discovery_recheck_sudo_policy_without_affecting_ordinary() {
        let definition = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        let ordinary = binding_definition().replace("[tools.observe]", "[tools.ordinary]");
        for (users, programs, disabled, allowed) in [
            (vec!["root".to_owned()], None, false, true),
            (
                vec!["root".to_owned()],
                Some(vec!["/usr/bin/id".to_owned()]),
                false,
                true,
            ),
            (vec!["service".to_owned()], None, false, false),
            (vec!["root".to_owned()], Some(vec![]), false, false),
            (
                vec!["root".to_owned()],
                Some(vec!["/bin/id".to_owned()]),
                false,
                false,
            ),
            (vec!["root".to_owned()], None, true, false),
        ] {
            let mut config = load_text(
                &format!(
                    "profile='actions-only'\nenabled_tools=['observe','ordinary']\n\
                     [targets.one]\nssh_host='ordinary-private'\nprofile='actions-only'\n\
                     [targets.one.sudo]\nmode='same-account'\n{definition}{ordinary}",
                ),
                &[],
            )
            .unwrap();
            // Exercise runtime/discovery independently of startup rejection.
            config
                .targets
                .as_mut()
                .unwrap()
                .get_mut("one")
                .unwrap()
                .sudo = if disabled {
                Sudo::Disabled
            } else {
                Sudo::SameAccount { users, programs }
            };
            let mut entries = Vec::new();
            for (id, binding) in config.bindings().entries() {
                let permitted = binding.name == "ordinary" || allowed;
                assert_eq!(config.resolve_binding("one", id).is_ok(), permitted);
                entries.push(ToolEntry {
                    id: ToolKey::Binding(id),
                    name: binding.name.clone().into(),
                });
            }
            let tools = ToolCatalog::new(entries).unwrap();
            let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                if allowed {
                    serde_json::json!(["observe", "ordinary"])
                } else {
                    serde_json::json!(["ordinary"])
                },
            );
            assert!(!config.tool_enabled(ToolId::Sudo));
        }
    }

    #[test]
    fn binding_startup_rejects_missing_targets_selection_and_invalid_disabled_definitions() {
        let definition = binding_definition();
        for text in [
            format!("enabled_tools=['observe']\n{definition}"),
            format!("enabled_tools=['observe']\n[targets.two]\nssh_host='private'\n{definition}"),
            format!("enabled_tools=['missing']\n[targets.one]\nssh_host='private'\n{definition}"),
            format!(
                "enabled_tools=['observe','observe']\n[targets.one]\nssh_host='private'\n{definition}"
            ),
            format!(
                "[targets.one]\nssh_host='private'\n{}",
                definition.replace("authority = \"ordinary\"", "authority = \"secret_payload\"")
            ),
        ] {
            let error = load_text(&text, &[])
                .err()
                .expect("invalid binding must fail startup");
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn binding_limits_use_resolved_environment_ceiling() {
        let text = format!(
            "[targets.one]\nssh_host='ordinary'\n{}\n[tools.observe.limits]\nmax_output_bytes=100",
            binding_definition(),
        );
        assert!(load_text(&text, &[("ESTUS_MAX_OUTPUT_BYTES", "99")]).is_err());
        assert!(load_text(&text, &[("ESTUS_MAX_OUTPUT_BYTES", "100")]).is_ok());
    }

    #[test]
    fn discovery_intersects_target_policy_with_enabled_catalog() {
        let config = load_text(
            "[targets.one]\nssh_host='private'\n[targets.one.sudo]\nmode='same-account'",
            &[],
        )
        .unwrap();
        let mut tools = catalog();
        tools.retain(|id| matches!(builtin(id), ToolId::Targets | ToolId::Exec | ToolId::Run));
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!(["a-run", "z-exec"])
        );
        tools.retain(|_| false);
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!([])
        );
    }

    #[test]
    fn empty_program_policy_keeps_global_sudo_but_excludes_target_permission() {
        let config = load_text(
            "[targets.one]\nssh_host='private'\n[targets.one.sudo]\n\
             mode='same-account'\nprograms=[]",
            &[],
        )
        .unwrap();
        let tools = catalog();
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(discovery["targets"][0]["sudo_mode"], "same-account");
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!(["a-run", "b-list", "c-write", "n-read", "q-stat", "z-exec"])
        );
    }

    #[test]
    fn omitted_and_explicit_baseline_preserve_publication_and_identity_policy() {
        for root in ["", "profile='baseline'\n"] {
            let config = load_text(
                &format!(
                    "{root}[targets.one]\nssh_host='ordinary'\n\
                     [targets.one.sudo]\nmode='separate-identity'\nssh_host='elevated'\n\
                     users=['service']\nprograms=['/usr/bin/id']"
                ),
                &[],
            )
            .unwrap();
            let mut tools = catalog();
            tools.retain(|id| config.tool_enabled(builtin(id)));
            assert_eq!(tools.entries.len(), 8);
            for entry in &tools.entries {
                if !matches!(builtin(entry.id), ToolId::Targets | ToolId::Sudo) {
                    let resolved = config.resolve("one", builtin(entry.id)).unwrap();
                    assert_eq!(resolved.destination, "ordinary");
                    assert_eq!(resolved.role, IdentityRole::Ordinary);
                }
            }
            let elevated = config
                .resolve_sudo("one", "service", "/usr/bin/id")
                .unwrap();
            assert_eq!(elevated.destination, "elevated");
            assert_eq!(elevated.role, IdentityRole::Elevated);
            assert!(config.resolve_sudo("one", "root", "/usr/bin/id").is_err());
            assert!(config.resolve_sudo("one", "service", "/bin/sh").is_err());
            assert_eq!(
                serde_json::to_value(config.targets(&tools)).unwrap()["targets"][0]["permitted_operations"],
                serde_json::json!([
                    "a-run",
                    "b-list",
                    "c-write",
                    "m-elevate",
                    "n-read",
                    "q-stat",
                    "z-exec"
                ])
            );
        }
    }

    #[test]
    fn restrictive_profiles_publish_authorize_and_discover_only_their_file_sets() {
        for (profile, published, permitted) in [
            (
                "read-only-files",
                vec!["0-global-discovery", "b-list", "n-read", "q-stat"],
                vec!["b-list", "n-read", "q-stat"],
            ),
            (
                "files-only",
                vec![
                    "0-global-discovery",
                    "b-list",
                    "c-write",
                    "n-read",
                    "q-stat",
                ],
                vec!["b-list", "c-write", "n-read", "q-stat"],
            ),
            ("actions-only", vec!["0-global-discovery"], vec![]),
        ] {
            let config = load_text(
                &format!(
                    "profile='{profile}'\n[targets.one]\nssh_host='private-alias'\n\
                     description='execution allowed'\nlabels={{exec='enabled'}}\n\
                     [targets.one.sudo]\nmode='same-account'"
                ),
                &[],
            )
            .unwrap();
            let all = catalog();
            let mut active = catalog();
            active.retain(|id| config.tool_enabled(builtin(id)));
            assert_eq!(
                active
                    .entries
                    .iter()
                    .map(|entry| entry.name.as_ref())
                    .collect::<Vec<_>>(),
                published,
                "{profile}"
            );
            for entry in &all.entries {
                if matches!(builtin(entry.id), ToolId::Targets | ToolId::Sudo) {
                    continue;
                }
                let result = config.resolve("one", builtin(entry.id));
                if permitted.contains(&entry.name.as_ref()) {
                    assert_eq!(result.unwrap().destination, "private-alias", "{profile}");
                } else {
                    let error = result.err().unwrap();
                    assert_eq!(error.code, "policy_denied", "{profile}/{:?}", entry.id);
                    assert!(!error.remote_state_unknown);
                    assert!(!format!("{error:?}").contains("private"));
                    assert!(!format!("{error:?}").contains(profile));
                }
            }
            assert_eq!(
                config
                    .resolve_sudo("one", "root", "/bin/sh")
                    .err()
                    .unwrap()
                    .code,
                "policy_denied"
            );
            // Even an unfiltered catalogue cannot advertise a profile-disabled operation.
            let discovery = serde_json::to_value(config.targets(&all)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                serde_json::json!(permitted),
                "{profile}"
            );
            assert_eq!(discovery["targets"][0]["sudo_mode"], "same-account");
            assert_eq!(discovery["targets"][0]["observed_capabilities"], "unknown");
        }
    }

    #[test]
    fn target_profiles_intersect_global_policy_without_changing_publication() {
        let config = load_text(
            "profile='files-only'\n\
             [targets.base]\nssh_host='base-alias'\nprofile='baseline'\n\
             [targets.reader]\nssh_host='reader-alias'\nprofile='read-only-files'\n\
             [targets.actions]\nssh_host='actions-alias'\nprofile='actions-only'\n\
             [targets.implicit]\nssh_host='implicit-alias'",
            &[],
        )
        .unwrap();
        let mut tools = catalog();
        tools.retain(|id| config.tool_enabled(builtin(id)));
        assert!(tools.contains(ToolKey::Builtin(ToolId::WriteFile)));
        assert!(!tools.contains(ToolKey::Builtin(ToolId::Exec)));
        assert!(!tools.contains(ToolKey::Builtin(ToolId::Run)));
        for name in ["base", "implicit"] {
            assert!(config.resolve(name, ToolId::WriteFile).is_ok());
            assert!(config.resolve(name, ToolId::Exec).is_err());
        }
        assert!(config.resolve("reader", ToolId::ReadFile).is_ok());
        assert!(config.resolve("reader", ToolId::WriteFile).is_err());
        assert!(config.resolve("actions", ToolId::ReadFile).is_err());
        tools.retain(|id| id != ToolKey::Builtin(ToolId::Stat));
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        let rows = discovery["targets"].as_array().unwrap();
        let operations = |name: &str| &rows.iter().find(|row| row["name"] == name).unwrap()["permitted_operations"];
        assert_eq!(
            operations("base"),
            &serde_json::json!(["b-list", "c-write", "n-read"])
        );
        assert_eq!(operations("implicit"), operations("base"));
        assert_eq!(
            operations("reader"),
            &serde_json::json!(["b-list", "n-read"])
        );
        assert_eq!(operations("actions"), &serde_json::json!([]));
    }

    #[test]
    fn restrictive_targets_do_not_hide_baseline_routes_or_authorize_sudo() {
        let config = load_text(
            "[targets.reader]\nssh_host='private-reader'\nprofile='read-only-files'\n\
             [targets.reader.sudo]\nmode='separate-identity'\nssh_host='private-elevated'\n\
             [targets.files]\nssh_host='private-files'\nprofile='files-only'\n\
             [targets.files.sudo]\nmode='same-account'\n\
             [targets.actions]\nssh_host='private-actions'\nprofile='actions-only'\n\
             [targets.actions.sudo]\nmode='same-account'\n\
             [targets.disabled]\nssh_host='private-disabled'\nprofile='baseline'\n\
             [targets.empty]\nssh_host='private-empty'\nprofile='baseline'\n\
             [targets.empty.sudo]\nmode='same-account'\nprograms=[]",
            &[],
        )
        .unwrap();
        assert!(config.tool_enabled(ToolId::Exec));
        assert!(config.tool_enabled(ToolId::Run));
        assert!(config.tool_enabled(ToolId::Sudo));
        for name in ["reader", "files", "actions", "disabled", "empty"] {
            let error = config.resolve_sudo(name, "root", "/bin/sh").err().unwrap();
            assert_eq!(error.code, "policy_denied");
            assert!(!error.remote_state_unknown);
        }
        for name in ["reader", "files", "actions"] {
            assert!(config.resolve(name, ToolId::Exec).is_err());
            assert!(config.resolve(name, ToolId::Run).is_err());
        }
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        for row in discovery["targets"].as_array().unwrap() {
            assert!(
                !row["permitted_operations"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("m-elevate"))
            );
        }
    }

    #[test]
    fn profile_policy_preserves_open_validation_closed_targets_and_resolver_boundaries() {
        let open = load_text("profile='read-only-files'", &[]).unwrap();
        let resolved = open.resolve("user@example", ToolId::ReadFile).unwrap();
        assert_eq!(resolved.destination, "user@example");
        assert_eq!(resolved.role, IdentityRole::Ordinary);
        assert_eq!(
            open.resolve("-option", ToolId::ReadFile)
                .err()
                .unwrap()
                .code,
            "invalid_argument"
        );
        assert_eq!(
            open.resolve("user@example", ToolId::WriteFile)
                .err()
                .unwrap()
                .code,
            "policy_denied"
        );
        let closed = load_text(
            "profile='read-only-files'\n[targets.logical]\nssh_host='private-alias'",
            &[],
        )
        .unwrap();
        assert!(closed.resolve("logical", ToolId::ReadFile).is_ok());
        assert!(closed.resolve("private-alias", ToolId::ReadFile).is_err());
        let empty = load_text("profile='files-only'\n[targets]", &[]).unwrap();
        assert!(empty.tool_enabled(ToolId::WriteFile));
        assert!(empty.tool_enabled(ToolId::Targets));
        assert!(empty.resolve("anything", ToolId::ReadFile).is_err());
        let baseline_empty = load_text("[targets]", &[]).unwrap();
        assert!(baseline_empty.tool_enabled(ToolId::Exec));
        assert!(baseline_empty.tool_enabled(ToolId::WriteFile));
        assert!(!baseline_empty.tool_enabled(ToolId::Sudo));
        for tool in [ToolId::Targets, ToolId::Sudo] {
            assert_eq!(
                closed.resolve("logical", tool).err().unwrap().code,
                "policy_denied"
            );
            assert_eq!(
                load_text("", &[])
                    .unwrap()
                    .resolve("host", tool)
                    .err()
                    .unwrap()
                    .code,
                "policy_denied"
            );
        }
        let discovery = serde_json::to_value(open.targets(&catalog())).unwrap();
        assert_eq!(discovery["mode"], "open");
        assert_eq!(discovery["targets"], serde_json::json!([]));
    }

    #[test]
    fn unknown_and_wrong_type_profiles_use_only_fixed_secret_free_schema_paths() {
        for value in [
            "'secret_payload'",
            "'Baseline'",
            "'read_only_files'",
            "''",
            "42",
            "true",
            "1.5",
            "['secret_payload']",
            "{secret_payload='secret_payload'}",
        ] {
            for (text, field) in [
                (format!("profile={value}"), "profile"),
                (
                    format!("[targets.secret_target]\nssh_host='secret_alias'\nprofile={value}"),
                    "targets.*.profile",
                ),
            ] {
                let error = load_text(&text, &[]).err().unwrap();
                assert_eq!(error.field, field);
                for secret in ["secret_payload", "secret_target", "secret_alias"] {
                    assert!(!error.to_string().contains(secret));
                    assert!(!format!("{error:?}").contains(secret));
                }
                assert!(std::error::Error::source(&error).is_none());
            }
        }
    }

    fn load_text(text: &str, vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, text).unwrap();
        Config::load_with(
            Cli {
                config: Some(path),
                ssh_config: None,
                command: None,
            },
            dir.path(),
            |key| {
                vars.iter()
                    .find(|(name, _)| *name == key)
                    .map(|(_, value)| OsString::from(*value))
            },
        )
    }

    #[test]
    fn controller_activation_uses_global_profile_without_target_capabilities() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"abc").unwrap();
        let definition = format!(
            r#"
[controller]
workspace_root={root:?}
[targets.server]
ssh_host="never-used"
profile="read-only-files"
[tools.local]
description="Controller observation"
revision="1"
authority="controller"
effects=["read"]
execution={{kind="controller_script",source={{path={source:?},content_sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},interpreter={{program="/bin/sh",argv=[]}}}}
input_schema={{type="object",additionalProperties=false,required=[],properties={{}}}}
result={{kind="controller_command"}}
"#,
            root = dir.path().to_str().unwrap(),
            source = source.to_str().unwrap()
        );
        for profile in ["baseline", "actions-only"] {
            let config = load_text(
                &format!("profile={profile:?}\nenabled_tools=['local']\n{definition}"),
                &[],
            )
            .unwrap();
            assert!(config.controller_enabled(BindingId(0)));
            assert!(config.resolve_binding("server", BindingId(0)).is_err());
            let catalog = ToolCatalog::new(vec![ToolEntry {
                id: ToolKey::Binding(BindingId(0)),
                name: "local".into(),
            }])
            .unwrap();
            let discovery = serde_json::to_value(config.targets(&catalog)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                serde_json::json!([])
            );
        }
        std::fs::remove_file(source).unwrap();
        for profile in ["files-only", "read-only-files"] {
            let config = load_text(
                &format!("profile={profile:?}\nenabled_tools=['local']\n{definition}"),
                &[],
            )
            .unwrap();
            assert!(!config.binding_enabled(BindingId(0)));
            assert!(!config.controller_enabled(BindingId(0)));
        }
        assert!(load_text(&definition, &[]).is_ok());
        assert!(load_text(&format!("enabled_tools=['local']\n{definition}"), &[]).is_err());
    }

    #[test]
    fn missing_and_present_empty_targets_are_distinct() {
        let open = load_text("", &[]).unwrap();
        let open = serde_json::to_value(open.targets(&catalog())).unwrap();
        assert_eq!(open["mode"], "open");
        assert_eq!(open["targets"], serde_json::json!([]));
        let empty = load_text("[targets]", &[]).unwrap();
        let empty = serde_json::to_value(empty.targets(&catalog())).unwrap();
        assert_eq!(empty["mode"], "configured");
        assert_eq!(empty["targets"], serde_json::json!([]));
    }

    #[test]
    fn discovery_sorts_supplied_names_and_targets_without_exposing_aliases() {
        let config = load_text(
            r#"
[targets.zebra]
ssh_host = "ordinary-secret"
[targets.zebra.sudo]
mode = "separate-identity"
ssh_host = "privileged-secret"
[targets.alpha]
ssh_host = "other-secret"
[targets.alpha.sudo]
mode = "same-account"
"#,
            &[],
        )
        .unwrap();
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        assert_eq!(discovery["mode"], "configured");
        assert_eq!(
            discovery["targets"],
            serde_json::json!([
                {
                    "name":"alpha", "sudo_mode":"same-account",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "a-run", "b-list", "c-write", "m-elevate",
                        "n-read", "q-stat", "z-exec"
                    ],
                    "observed_capabilities":"unknown"
                },
                {
                    "name":"zebra", "sudo_mode":"separate-identity",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "a-run", "b-list", "c-write", "m-elevate",
                        "n-read", "q-stat", "z-exec"
                    ],
                    "observed_capabilities":"unknown"
                }
            ])
        );
        assert!(!discovery.to_string().contains("secret"));
        match &config.targets.as_ref().unwrap()["alpha"].sudo {
            Sudo::SameAccount { users, programs } => {
                assert_eq!(users, &["root"]);
                assert!(programs.is_none());
            }
            _ => panic!("incorrect sudo mode"),
        }
    }

    #[test]
    fn metadata_bounds_count_utf8_bytes_and_accept_exact_limits() {
        let text = |description: &str, key: &str, value: &str| {
            format!(
                "[targets.one]\nssh_host='ordinary'\ndescription='{description}'\n\
                 [targets.one.labels]\n'{key}'='{value}'"
            )
        };
        let description = "é".repeat(512);
        let key = "é".repeat(32);
        let value = "é".repeat(128);
        assert!(load_text(&text(&description, &key, &value), &[]).is_ok());
        for (text, field) in [
            (
                text(&format!("{description}a"), &key, &value),
                "targets.*.description",
            ),
            (
                text(&description, &format!("{key}a"), &value),
                "targets.*.labels",
            ),
            (
                text(&description, &key, &format!("{value}a")),
                "targets.*.labels.*",
            ),
            (text("", "", ""), "targets.*.labels"),
        ] {
            assert_eq!(load_text(&text, &[]).err().unwrap().field, field);
        }
        let mut labels = String::from(
            "[targets.one]\nssh_host='ordinary'\ndescription=''\n[targets.one.labels]\n",
        );
        for index in 0..16 {
            labels.push_str(&format!("label{index}=''\n"));
        }
        assert!(load_text(&labels, &[]).is_ok());
        labels.push_str("extra=''\n");
        assert_eq!(
            load_text(&labels, &[]).err().unwrap().field,
            "targets.*.labels"
        );
    }

    #[test]
    fn aggregate_metadata_bounds_include_all_targets_keys_and_values() {
        let mut text = String::new();
        for index in 0..48 {
            text.push_str(&format!(
                "[targets.target{index}]\nssh_host='ordinary'\ndescription='{}'\n\
                 [targets.target{index}.labels]\n'{}'='{}'\n",
                "é".repeat(512),
                "é".repeat(32),
                "é".repeat(128),
            ));
        }
        text.push_str(&format!(
            "[targets.last]\nssh_host='ordinary'\ndescription='{}'\n",
            "é".repeat(512),
        ));
        // 48 * (1024 + 64 + 256) + 1024 = 65536 bytes, all sudo disabled.
        assert!(load_text(&text, &[]).is_ok());
        text.push_str("[targets.last.labels]\na=''\n");
        assert_eq!(load_text(&text, &[]).err().unwrap().field, "targets");
    }

    #[test]
    fn metadata_schema_and_bound_failures_never_echo_operator_content() {
        for (metadata, field) in [
            ("description=42".to_owned(), "targets.*.description"),
            ("labels='secret_payload'".to_owned(), "targets.*.labels"),
            (
                "labels={secret_payload=['secret_payload']}".to_owned(),
                "targets.*.labels.*",
            ),
            (
                format!("description='secret_payload{}'", "é".repeat(512)),
                "targets.*.description",
            ),
            (
                format!(
                    "labels={{'secret_payload{}'='secret_payload'}}",
                    "é".repeat(32)
                ),
                "targets.*.labels",
            ),
            (
                format!(
                    "labels={{secret_payload='secret_payload{}'}}",
                    "é".repeat(128)
                ),
                "targets.*.labels.*",
            ),
        ] {
            let text = format!(
                "[targets.secret_payload]\nssh_host='private_alias'\n{metadata}\n\
                 [targets.secret_payload.sudo]\nmode='disabled'"
            );
            let error = load_text(&text, &[]).err().unwrap();
            assert_eq!(error.field, field);
            for secret in ["secret_payload", "private_alias"] {
                assert!(!error.to_string().contains(secret));
                assert!(!format!("{error:?}").contains(secret));
            }
        }
    }

    #[test]
    fn metadata_is_advisory_and_empty_program_allowlists_do_not_advertise_sudo() {
        let config = load_text(
            r#"
[targets.disabled]
ssh_host='private-ordinary'
description='sudo is available'
labels={sudo='enabled'}
[targets.empty_same]
ssh_host='private-same'
[targets.empty_same.sudo]
mode='same-account'
programs=[]
[targets.empty_split]
ssh_host='private-reader'
[targets.empty_split.sudo]
mode='separate-identity'
ssh_host='private-elevated'
users=['private_user']
programs=[]
[targets.allowed]
ssh_host='private-allowed'
[targets.allowed.sudo]
mode='same-account'
users=['private_user']
programs=['/private/program']
"#,
            &[],
        )
        .unwrap();
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        let rows = discovery["targets"].as_array().unwrap();
        for (name, mode) in [
            ("disabled", "disabled"),
            ("empty_same", "same-account"),
            ("empty_split", "separate-identity"),
        ] {
            let row = rows.iter().find(|row| row["name"] == name).unwrap();
            assert_eq!(row["sudo_mode"], mode);
            assert_eq!(
                row["permitted_operations"],
                serde_json::json!(["a-run", "b-list", "c-write", "n-read", "q-stat", "z-exec"])
            );
            assert_eq!(row["observed_capabilities"], "unknown");
            assert_eq!(
                config
                    .resolve_sudo(name, "private_user", "/private/program")
                    .err()
                    .unwrap()
                    .code,
                "policy_denied"
            );
        }
        let disabled = rows.iter().find(|row| row["name"] == "disabled").unwrap();
        assert_eq!(disabled["description"], "sudo is available");
        assert_eq!(disabled["labels"], serde_json::json!({"sudo":"enabled"}));
        let allowed = rows.iter().find(|row| row["name"] == "allowed").unwrap();
        assert!(
            allowed["permitted_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| operation == "m-elevate")
        );
        assert!(!discovery.to_string().contains("private"));
    }

    #[test]
    fn discovery_limits_report_resolved_toml_and_environment_policy_without_clamping() {
        let text = "[limits]\nconnect_timeout_secs=2\noperation_timeout_secs=3\n\
                    max_timeout_secs=4\nmax_output_bytes=5\nmax_file_bytes=6";
        let config = load_text(text, &[]).unwrap();
        let limits = serde_json::to_value(config.targets(&catalog())).unwrap()["limits"].clone();
        assert_eq!(
            limits,
            serde_json::json!({
                "connect_timeout_secs":2, "operation_timeout_secs":3, "max_timeout_secs":4,
                "max_output_bytes":5, "max_file_bytes":6, "max_stdin_bytes":6,
                "max_command_bytes":MAX_COMMAND_BYTES,
                "max_encoded_command_bytes":MAX_COMMAND_BYTES,
                "max_response_bytes":MAX_RESPONSE_BYTES
            })
        );
        let config = load_text(
            text,
            &[
                ("ESTUS_CONNECT_TIMEOUT_SECS", "7"),
                ("ESTUS_OPERATION_TIMEOUT_SECS", "8"),
                ("ESTUS_MAX_TIMEOUT_SECS", "9"),
                ("ESTUS_MAX_OUTPUT_BYTES", "20000000"),
                ("ESTUS_MAX_FILE_BYTES", "30000000"),
            ],
        )
        .unwrap();
        let limits = serde_json::to_value(config.targets(&catalog())).unwrap()["limits"].clone();
        assert_eq!(
            limits,
            serde_json::json!({
                "connect_timeout_secs":7, "operation_timeout_secs":8, "max_timeout_secs":9,
                "max_output_bytes":20000000, "max_file_bytes":30000000,
                "max_stdin_bytes":30000000, "max_command_bytes":MAX_COMMAND_BYTES,
                "max_encoded_command_bytes":MAX_COMMAND_BYTES,
                "max_response_bytes":MAX_RESPONSE_BYTES
            })
        );
    }

    #[test]
    fn discovery_schema_describes_public_summary_array_not_private_target_map() {
        fn resolve<'a>(
            document: &'a serde_json::Value,
            node: &'a serde_json::Value,
        ) -> &'a serde_json::Value {
            match node["$ref"].as_str() {
                Some(reference) => document
                    .pointer(reference.strip_prefix('#').unwrap())
                    .unwrap(),
                None => node,
            }
        }
        let schema = serde_json::to_value(schemars::schema_for!(TargetDiscovery<'_>)).unwrap();
        let targets = &schema["properties"]["targets"];
        assert_eq!(targets["type"], "array");
        let summary = &resolve(&schema, &targets["items"])["properties"];
        for field in [
            "description",
            "labels",
            "name",
            "observed_capabilities",
            "permitted_operations",
            "sudo_mode",
        ] {
            assert!(summary.get(field).is_some(), "missing public field {field}");
        }
        let limits = resolve(&schema, &schema["properties"]["limits"]);
        assert_eq!(limits["type"], "object");
        assert!(limits["properties"].get("max_response_bytes").is_some());
        let encoded = schema.to_string();
        for private_field in ["ssh_host", "config_file", "\"users\"", "\"programs\""] {
            assert!(!encoded.contains(private_field), "{private_field}");
        }
    }

    #[test]
    fn paths_have_correct_bases_and_precedence_without_interpolation() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir(cwd.join("nested")).unwrap();
        std::fs::write(
            cwd.join("nested/operator.toml"),
            "[ssh]\nconfig_file = './$HOME'\n",
        )
        .unwrap();
        std::fs::write(cwd.join("nested/$HOME"), "").unwrap();
        std::fs::write(cwd.join("env-ssh"), "").unwrap();
        std::fs::write(cwd.join("cli-ssh"), "").unwrap();
        let env = |key: &str| match key {
            "ESTUS_CONFIG" => Some(OsString::from("nested/operator.toml")),
            _ => None,
        };
        let from_toml = Config::load_with(cli(), cwd, env).unwrap();
        assert_eq!(from_toml.ssh_config.unwrap(), cwd.join("nested/./$HOME"));
        let env = |key: &str| match key {
            "ESTUS_CONFIG" => Some(OsString::from("nested/operator.toml")),
            "ESTUS_SSH_CONFIG" => Some(OsString::from("env-ssh")),
            _ => None,
        };
        let from_env = Config::load_with(cli(), cwd, env).unwrap();
        assert_eq!(from_env.ssh_config.unwrap(), cwd.join("env-ssh"));
        let from_cli = Config::load_with(
            Cli {
                config: Some("nested/operator.toml".into()),
                ssh_config: Some("cli-ssh".into()),
                command: None,
            },
            cwd,
            |key| match key {
                "ESTUS_CONFIG" => Some("missing-secret".into()),
                "ESTUS_SSH_CONFIG" => Some("missing-secret".into()),
                _ => None,
            },
        )
        .unwrap();
        assert_eq!(from_cli.ssh_config.unwrap(), cwd.join("cli-ssh"));
    }

    #[test]
    fn explicit_files_never_fall_back() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            Config::load_with(
                Cli {
                    config: Some("missing".into()),
                    ssh_config: None,
                    command: None,
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );
        assert!(
            Config::load_with(
                Cli {
                    config: None,
                    ssh_config: Some("missing".into()),
                    command: None,
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );
        assert!(
            Config::load_with(
                Cli {
                    config: None,
                    ssh_config: Some(dir.path().into()),
                    command: None,
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );
        assert!(
            Config::load_with(cli(), dir.path(), |key| (key == "ESTUS_CONFIG")
                .then(|| OsString::from("")))
            .is_err()
        );
    }

    #[test]
    fn environment_wins_and_limits_are_positive_and_bounded() {
        let config = load_text("[limits]\nconnect_timeout_secs=2\noperation_timeout_secs=3\nmax_timeout_secs=4\nmax_output_bytes=5\nmax_file_bytes=6", &[
            ("ESTUS_CONNECT_TIMEOUT_SECS", "7"), ("ESTUS_OPERATION_TIMEOUT_SECS", "8"),
            ("ESTUS_MAX_TIMEOUT_SECS", "9"), ("ESTUS_MAX_OUTPUT_BYTES", "10"), ("ESTUS_MAX_FILE_BYTES", "11"),
        ]).unwrap();
        assert_eq!(
            (
                config.limits.connect_timeout_secs,
                config.limits.operation_timeout_secs,
                config.limits.max_timeout_secs,
                config.limits.max_output_bytes,
                config.limits.max_file_bytes
            ),
            (7, 8, 9, 10, 11)
        );
        for value in [
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "1.0",
            "1_000",
            "",
            "18446744073709551616",
        ] {
            assert!(
                load_text("", &[("ESTUS_MAX_FILE_BYTES", value)]).is_err(),
                "{value:?}"
            );
        }
        for key in [
            "connect_timeout_secs",
            "operation_timeout_secs",
            "max_timeout_secs",
            "max_output_bytes",
            "max_file_bytes",
        ] {
            for value in ["0", "-1", "1.0", "'1'"] {
                assert!(
                    load_text(&format!("[limits]\n{key}={value}"), &[]).is_err(),
                    "{key}={value}"
                );
            }
        }
        assert!(load_text("", &[("ESTUS_MAX_TIMEOUT_SECS", "59")]).is_err());
        assert!(load_text("[limits]\nconnect_timeout_secs=601", &[]).is_err());
        assert!(
            load_text(
                "[limits]\noperation_timeout_secs=600\nconnect_timeout_secs=600",
                &[]
            )
            .is_ok()
        );
    }

    #[test]
    fn automation_loading_never_reads_the_runtime_environment() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load_with(cli(), dir.path(), |key| {
            assert_ne!(key, "ESTUS_ANSIBLE_RUNTIME");
            None
        })
        .unwrap();
        assert!(!config.automation_required());
        assert_eq!(config.automation_runtime_with(|_| None).unwrap(), None);

        // Neither required nor a configured reference inspects runtime files.
        for required in [false, true] {
            let config = load_text(
                &format!(
                    "[automation]\nrequired={required}\nruntime='/nonexistent-private-runtime'"
                ),
                &[],
            )
            .unwrap();
            assert_eq!(config.automation_required(), required);
            assert_eq!(
                config
                    .automation_runtime_with(|_| panic!("file reference must win"))
                    .unwrap(),
                Some(PathBuf::from("/nonexistent-private-runtime"))
            );
        }
    }

    #[test]
    fn automation_environment_reference_is_validated_only_when_requested() {
        let config = load_text("", &[]).unwrap();
        assert_eq!(
            config
                .automation_runtime_with(|key| {
                    assert_eq!(key, "ESTUS_ANSIBLE_RUNTIME");
                    Some("/nonexistent-private-runtime".into())
                })
                .unwrap(),
            Some(PathBuf::from("/nonexistent-private-runtime"))
        );
        for value in [
            String::new(),
            "private-relative-runtime".to_owned(),
            "/private\0runtime".to_owned(),
            format!("/{}", "x".repeat(4096)),
        ] {
            let error = config
                .automation_runtime_with(|_| Some(value.into()))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "automation.runtime: must be a bounded absolute path"
            );
        }
        let boundary = format!("/{}", "x".repeat(4095));
        assert_eq!(
            config
                .automation_runtime_with(|_| Some(boundary.clone().into()))
                .unwrap(),
            Some(PathBuf::from(boundary))
        );
    }

    #[cfg(unix)]
    #[test]
    fn automation_non_unicode_environment_reference_is_sanitized_on_use() {
        use std::os::unix::ffi::OsStringExt;
        let config = load_text("", &[]).unwrap();
        let error = config
            .automation_runtime_with(|_| Some(OsString::from_vec(vec![b'/', 0xff])))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "automation.runtime: must be a bounded absolute path"
        );
    }

    #[test]
    fn automation_schema_rejects_private_invalid_shapes_without_disclosure() {
        for (text, field) in [
            ("automation='secret_payload'", "automation"),
            ("[automation]\nsecret_payload=true", "automation"),
            (
                "[automation]\nrequired='secret_payload'",
                "automation.required",
            ),
            (
                "[automation]\nruntime=['secret_payload']",
                "automation.runtime",
            ),
            (
                "[automation]\nruntime='secret_payload'",
                "automation.runtime",
            ),
            ("[automation]\nruntime=''", "automation.runtime"),
            (
                "[automation]\nruntime=\"/secret_payload\\u0000\"",
                "automation.runtime",
            ),
        ] {
            let error = load_text(text, &[]).err().unwrap();
            assert_eq!(error.field, field);
            assert!(!error.to_string().contains("secret_payload"));
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
        let oversized = format!("[automation]\nruntime='/{}'", "x".repeat(4096));
        assert_eq!(
            load_text(&oversized, &[]).err().unwrap().field,
            "automation.runtime"
        );
    }

    #[test]
    fn unknown_fields_and_parser_errors_are_sanitized_at_every_level() {
        for text in [
            "secret_payload='secret_payload'",
            "[ssh]\nsecret_payload='secret_payload'",
            "[limits]\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='disabled'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='same-account'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='separate-identity'\nssh_host='privileged'\nsecret_payload=1",
            "secret_payload = [broken",
            "[targets.secret_payload]\nssh_host='a'\nssh_host='secret_payload'",
            "[targets.secret_payload]\nssh_host='a'\n[targets.secret_payload.sudo]\nmode='secret_payload'",
        ] {
            let error = load_text(text, &[])
                .err()
                .expect("must reject malformed configuration");
            assert!(!error.to_string().contains("secret_payload"));
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn destination_safety_and_authority_separation_are_enforced() {
        for host in [
            "",
            "-option",
            "two words",
            "tab\there",
            "line\nhere",
            "nul\0here",
            "unicode\u{a0}space",
        ] {
            let text = format!(
                "[targets.one]\nssh_host={}",
                serde_json::to_string(host).unwrap()
            );
            assert!(load_text(&text, &[]).is_err(), "{host:?}");
        }
        for text in [
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nssh_host='privileged'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'\nssh_host='ordinary'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'\nssh_host='privileged'\n[targets.two]\nssh_host='privileged'",
        ] {
            assert!(load_text(text, &[]).is_err());
        }
        assert!(load_text("[targets.one]\nssh_host='user@host:22'", &[]).is_ok());
    }

    #[test]
    fn sudo_policy_rejects_invalid_and_duplicate_entries() {
        for policy in [
            "users=[]",
            "users=['root','root']",
            "users=['']",
            "users=['-root']",
            "users=['#0']",
            "users=['two words']",
            "users=['root\\n']",
            "programs=['relative']",
            "programs=['/']",
            "programs=['/bin/sh','/bin/sh']",
            "programs=['/bin/']",
        ] {
            let text = format!(
                "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\n{policy}"
            );
            assert!(load_text(&text, &[]).is_err(), "{policy}");
        }
        let config = load_text("[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nusers=['root','service-user','_service']\nprograms=[]", &[]).unwrap();
        match &config.targets.as_ref().unwrap()["one"].sudo {
            Sudo::SameAccount { programs, .. } => {
                assert!(programs.as_ref().is_some_and(Vec::is_empty))
            }
            _ => panic!("incorrect sudo mode"),
        }
        assert!(load_text("[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nprograms=['/opt/My Program/run']", &[]).is_ok());
    }

    #[test]
    fn absence_of_config_does_not_discover_local_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("estus.toml"),
            "invalid syntax secret_payload",
        )
        .unwrap();
        let config = Config::load_with(cli(), dir.path(), |_| None).unwrap();
        assert!(config.targets.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_environment_limit_is_safely_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let dir = tempfile::tempdir().unwrap();
        let error = Config::load_with(cli(), dir.path(), |key| {
            (key == "ESTUS_MAX_FILE_BYTES").then(|| OsString::from_vec(vec![0xff]))
        })
        .err()
        .expect("non-Unicode limit must fail");
        assert_eq!(
            error.to_string(),
            "limits.max_file_bytes: must be a positive decimal integer"
        );
    }

    #[test]
    fn configured_dispatch_never_accepts_aliases_and_open_dispatch_is_validated() {
        let config = load_text("[targets.logical]\nssh_host='ordinary-alias'", &[]).unwrap();
        let resolved = config.resolve("logical", ToolId::Exec).unwrap();
        assert_eq!(
            (resolved.name, resolved.destination, resolved.role),
            ("logical", "ordinary-alias", IdentityRole::Ordinary)
        );
        for host in ["ordinary-alias", "unknown", ""] {
            assert_eq!(
                config.resolve(host, ToolId::Exec).err().unwrap().code,
                "policy_denied"
            );
        }
        let empty = load_text("[targets]", &[]).unwrap();
        assert_eq!(
            empty.resolve("anything", ToolId::Exec).err().unwrap().code,
            "policy_denied"
        );
        let open = load_text("", &[]).unwrap();
        let resolved = open.resolve("user@example", ToolId::Exec).unwrap();
        assert_eq!(
            (resolved.name, resolved.destination),
            ("user@example", "user@example")
        );
        for host in ["", "-option", "host name", "host\0name"] {
            assert_eq!(
                open.resolve(host, ToolId::Exec).err().unwrap().code,
                "invalid_argument"
            );
        }
        assert!(!open.has_sudo());
        assert_eq!(
            open.resolve_sudo("user@example", "root", "/bin/id")
                .err()
                .unwrap()
                .code,
            "policy_denied"
        );
    }

    #[test]
    fn sudo_dispatch_uses_exact_policy_and_the_configured_role() {
        let config = load_text(
            r#"
[targets.same]
ssh_host = "ordinary"
[targets.same.sudo]
mode = "same-account"
programs = ["/usr/bin/id"]
[targets.split]
ssh_host = "reader"
[targets.split.sudo]
mode = "separate-identity"
ssh_host = "operator"
users = ["service"]
programs = ["/usr/bin/printf"]
[targets.empty]
ssh_host = "empty"
[targets.empty.sudo]
mode = "same-account"
programs = []
[targets.unrestricted]
ssh_host = "unrestricted"
[targets.unrestricted.sudo]
mode = "same-account"
"#,
            &[],
        )
        .unwrap();
        assert!(config.has_sudo());
        let same = config.resolve_sudo("same", "root", "/usr/bin/id").unwrap();
        assert_eq!(
            (same.name, same.destination, same.role),
            ("same", "ordinary", IdentityRole::Ordinary)
        );
        let split = config
            .resolve_sudo("split", "service", "/usr/bin/printf")
            .unwrap();
        assert_eq!(
            (split.name, split.destination, split.role),
            ("split", "operator", IdentityRole::Elevated)
        );
        assert_eq!(
            config
                .resolve("split", ToolId::ReadFile)
                .unwrap()
                .destination,
            "reader"
        );
        for (host, user, program) in [
            ("same", "service", "/usr/bin/id"),
            ("same", "root", "/bin/id"),
            ("same", "root", "/usr/bin/id-extra"),
            ("same", "root", "id"),
            ("split", "root", "/usr/bin/printf"),
            ("operator", "service", "/usr/bin/printf"),
            ("empty", "root", "/usr/bin/id"),
        ] {
            assert_eq!(
                config.resolve_sudo(host, user, program).err().unwrap().code,
                "policy_denied",
                "{host}/{user}/{program}"
            );
        }
        assert_eq!(
            config
                .resolve_sudo("unrestricted", "root", "/opt/arbitrary")
                .unwrap()
                .role,
            IdentityRole::Ordinary
        );
        assert_eq!(
            config.timeout(Some(600)).unwrap(),
            std::time::Duration::from_secs(600)
        );
        for seconds in [0, 601] {
            assert_eq!(
                config.timeout(Some(seconds)).err().unwrap().code,
                "invalid_argument"
            );
        }
    }
}
