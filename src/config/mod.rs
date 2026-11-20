//! Configuration boundary: shared state is private; loading produces resolved `Config`
//! values consumed by authority policy and allocation-free discovery serialization.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    bindings::{BindingId, Bindings},
    reply::ToolError,
};

mod discovery;
mod loading;
mod policy;
mod rules;
mod validation;

pub(crate) use discovery::{CleanupDiagnostics, TargetDiscovery};
pub(crate) use loading::{Cli, CliCommand, DoctorArgs, RuntimeKind};
pub(crate) use policy::{risk_tier_for_binding, risk_tier_for_builtin};
pub(crate) use rules::HostRule;
pub(crate) use validation::{account_name, destination};
#[cfg(test)]
mod test_support;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolId {
    Targets,
    ReadOutput,
    Exec,
    Run,
    ReadFile,
    WriteFile,
    Mkdir,
    Rename,
    RemoveFile,
    RemoveDirectory,
    ReplaceFile,
    Stat,
    ListDirectory,
    Sudo,
    ClearTargetQuarantine,
}

impl ToolId {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Targets => "observe_targets",
            Self::ReadOutput => "inspect_output",
            Self::Exec => "exec_command",
            Self::Run => "exec_argv",
            Self::ReadFile => "inspect_file",
            Self::WriteFile => "change_file_write",
            Self::Mkdir => "change_mkdir",
            Self::Rename => "change_rename",
            Self::RemoveFile => "change_file_remove",
            Self::RemoveDirectory => "change_directory_remove",
            Self::ReplaceFile => "change_file_replace",
            Self::Stat => "observe_stat",
            Self::ListDirectory => "inspect_directory",
            Self::Sudo => "exec_sudo",
            Self::ClearTargetQuarantine => "change_target_quarantine_clear",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ToolKey {
    Builtin(ToolId),
    Binding(BindingId),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    Workstation,
    #[default]
    Headless,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RiskTier {
    Observe,
    Inspect,
    Preview,
    Change,
    Exec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Capabilities {
    pub(crate) named: bool,
    pub(crate) file_read: bool,
    pub(crate) file_write: bool,
    pub(crate) exec: bool,
    pub(crate) sudo: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::actions_only()
    }
}

impl Capabilities {
    pub(crate) const fn all() -> Self {
        Self {
            named: true,
            file_read: true,
            file_write: true,
            exec: true,
            sudo: true,
        }
    }

    pub(crate) const fn actions_only() -> Self {
        Self {
            named: true,
            file_read: false,
            file_write: false,
            exec: false,
            sudo: false,
        }
    }

    pub(crate) const fn intersect(self, other: Self) -> Self {
        Self {
            named: self.named && other.named,
            file_read: self.file_read && other.file_read,
            file_write: self.file_write && other.file_write,
            exec: self.exec && other.exec,
            sudo: self.sudo && other.sudo,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TargetCapabilities(Capabilities);

impl Default for TargetCapabilities {
    fn default() -> Self {
        Self(Capabilities::all())
    }
}

impl<'de> Deserialize<'de> for TargetCapabilities {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Explicit {
            named: bool,
            file_read: bool,
            file_write: bool,
            exec: bool,
            sudo: bool,
        }
        let explicit = Explicit::deserialize(deserializer)?;
        Ok(Self(Capabilities {
            named: explicit.named,
            file_read: explicit.file_read,
            file_write: explicit.file_write,
            exec: explicit.exec,
            sudo: explicit.sudo,
        }))
    }
}

impl From<TargetCapabilities> for Capabilities {
    fn from(value: TargetCapabilities) -> Self {
        value.0
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

    pub(crate) fn get_by_name(&self, name: &str) -> Option<ToolKey> {
        self.entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.id)
    }
}

// Only fixed schema paths and fixed reasons enter diagnostics. In particular, neither
// TOML's error Display/source nor unknown field/target names are safe to render.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[error("{field}: {reason}")]
pub(crate) struct ConfigError {
    #[serde(rename = "schema_path")]
    field: &'static str,
    #[serde(rename = "message")]
    reason: &'static str,
    code: &'static str,
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<SourceLocation>,
}

#[derive(Debug, serde::Serialize)]
struct SourceLocation {
    line: usize,
    column: usize,
}

impl ConfigError {
    pub(crate) fn new(field: &'static str, reason: &'static str) -> Self {
        Self {
            field,
            reason,
            code: "invalid_config",
            phase: "config_validation",
            location: None,
        }
    }

    pub(crate) fn with_cause(mut self, code: &'static str, phase: &'static str) -> Self {
        self.code = code;
        self.phase = phase;
        self
    }

    pub(crate) fn toml_syntax(text: &str, error: &toml::de::Error) -> Self {
        let location = error
            .span()
            .and_then(|span| text.get(..span.start))
            .map(|prefix| SourceLocation {
                line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
                column: prefix
                    .rsplit('\n')
                    .next()
                    .map_or(1, |line| line.chars().count() + 1),
            });
        Self {
            location,
            ..Self::new("config", "invalid TOML syntax or duplicate key")
                .with_cause("invalid_toml", "config_parse")
        }
    }

    pub(crate) fn toml_structure(text: &str, error: &toml::de::Error) -> Self {
        let location = error
            .span()
            .and_then(|span| text.get(..span.start))
            .map(|prefix| SourceLocation {
                line: prefix.bytes().filter(|byte| *byte == b'\n').count() + 1,
                column: prefix
                    .rsplit('\n')
                    .next()
                    .map_or(1, |line| line.chars().count() + 1),
            });
        Self {
            location,
            ..Self::new("config", "invalid configuration structure")
        }
    }

    pub(crate) fn record(&self) -> impl serde::Serialize + '_ {
        #[derive(serde::Serialize)]
        struct Record<'a> {
            event: &'static str,
            #[serde(flatten)]
            diagnostic: &'a ConfigError,
        }
        Record {
            event: "error",
            diagnostic: self,
        }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::new(field, reason)
}

pub(crate) struct Config {
    mode: Mode,
    capabilities: Capabilities,
    disclose_sudo_policy: bool,
    ssh_config: Option<PathBuf>,
    ssh_executable: PathBuf,
    quarantine_state_dir: Option<PathBuf>,
    limits: Limits,
    output: crate::output::Limits,
    targets: Option<BTreeMap<String, Target>>,
    rules: Vec<HostRule>,
    bindings: Bindings,
    automation: Automation,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Automation {
    required: bool,
    bundle: Option<PathBuf>,
    max_concurrent: usize,
    targets: BTreeMap<String, AutomationTarget>,
    authorities: BTreeMap<String, NamedAutomationAuthority>,
}

impl Default for Automation {
    fn default() -> Self {
        Self {
            required: false,
            bundle: None,
            max_concurrent: 8,
            targets: BTreeMap::new(),
            authorities: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomationTarget {
    pub(crate) destination: String,
    #[serde(default)]
    pub(crate) python: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedAutomationAuthority {
    ssh_config_file: PathBuf,
    bundle: Option<PathBuf>,
    ssh_auth_sock: Option<PathBuf>,
    r#become: AutomationBecome,
    targets: BTreeMap<String, AutomationTarget>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum AutomationBecome {
    Sudo {
        user: String,
        #[serde(default = "default_sudo_executable")]
        executable: String,
    },
}

fn default_sudo_executable() -> String {
    "/usr/bin/sudo".to_owned()
}

pub(crate) enum AutomationAgent<'a> {
    Inherit,
    Disabled,
    Fixed(&'a Path),
}

pub(crate) struct ResolvedAutomation<'a> {
    pub(crate) target: Cow<'a, AutomationTarget>,
    pub(crate) ssh_config: Option<&'a Path>,
    pub(crate) ssh_executable: &'a Path,
    pub(crate) r#become: Option<&'a AutomationBecome>,
    pub(crate) agent: AutomationAgent<'a>,
    pub(crate) dynamic_python: bool,
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
    capabilities: TargetCapabilities,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    sudo: Sudo,
    #[serde(default)]
    tool_presets: Option<Vec<String>>,
    #[serde(default)]
    enabled_tools: Option<Vec<String>>,
    #[serde(default)]
    disabled_tools: Vec<String>,
    #[serde(skip)]
    selected_bindings: Option<BTreeSet<String>>,
}

#[derive(Default)]
enum Sudo {
    #[default]
    Disabled,
    SameAccount {
        users: Vec<String>,
        programs: Option<Vec<String>>,
    },
    SeparateIdentity {
        ssh_host: String,
        users: Vec<String>,
        programs: Option<Vec<String>>,
    },
}

fn root_users() -> Vec<String> {
    vec!["root".to_owned()]
}

/// Serde cannot combine `deny_unknown_fields` with an internally tagged enum,
/// so the tag is resolved here and every variant's own members are enforced.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RawSudoMode {
    Disabled,
    SameAccount,
    SeparateIdentity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSudo {
    mode: RawSudoMode,
    #[serde(default)]
    ssh_host: Option<String>,
    #[serde(default)]
    users: Option<Vec<String>>,
    #[serde(default)]
    programs: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for Sudo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let raw = RawSudo::deserialize(deserializer)?;
        let sudo = match raw.mode {
            RawSudoMode::Disabled => {
                if raw.ssh_host.is_some() {
                    return Err(D::Error::unknown_field(
                        "ssh_host",
                        &["mode", "users", "programs"],
                    ));
                }
                Self::Disabled
            }
            RawSudoMode::SameAccount => {
                if raw.ssh_host.is_some() {
                    return Err(D::Error::unknown_field(
                        "ssh_host",
                        &["mode", "users", "programs"],
                    ));
                }
                Self::SameAccount {
                    users: raw.users.unwrap_or_else(root_users),
                    programs: raw.programs,
                }
            }
            RawSudoMode::SeparateIdentity => Self::SeparateIdentity {
                ssh_host: raw
                    .ssh_host
                    .ok_or_else(|| D::Error::missing_field("ssh_host"))?,
                users: raw.users.unwrap_or_else(root_users),
                programs: raw.programs,
            },
        };
        Ok(sudo)
    }
}

#[derive(Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum TargetMode {
    Open,
    #[default]
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
