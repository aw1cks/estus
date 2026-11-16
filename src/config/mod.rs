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
mod validation;

pub(crate) use discovery::TargetDiscovery;
pub(crate) use loading::{Cli, CliCommand, DoctorArgs, RuntimeKind};
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
    profile: Profile,
    ssh_config: Option<PathBuf>,
    ssh_executable: PathBuf,
    limits: Limits,
    output: crate::output::Limits,
    directory: crate::filesystem::data::DirectoryLimits,
    targets: Option<BTreeMap<String, Target>>,
    bindings: Bindings,
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
}

impl Default for Automation {
    fn default() -> Self {
        Self {
            required: false,
            runtime: None,
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
    #[serde(default)]
    tool_presets: Option<Vec<String>>,
    #[serde(default)]
    enabled_tools: Option<Vec<String>>,
    #[serde(default)]
    disabled_tools: Vec<String>,
    #[serde(skip)]
    selected_bindings: Option<BTreeSet<String>>,
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

