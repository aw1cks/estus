use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::{Deserialize, Serialize, Serializer};

use crate::{command::MAX_COMMAND_BYTES, reply::ToolError, wire::MAX_RESPONSE_BYTES};

const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_LABELS: usize = 16;
const MAX_LABEL_KEY_BYTES: usize = 64;
const MAX_LABEL_VALUE_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 65_536;

const ORDINARY_OPERATIONS: &[&str] = &[
    "ssh_exec",
    "ssh_list_directory",
    "ssh_read_file",
    "ssh_run",
    "ssh_stat",
    "ssh_write_file",
];
const SUDO_OPERATIONS: &[&str] = &[
    "ssh_exec",
    "ssh_list_directory",
    "ssh_read_file",
    "ssh_run",
    "ssh_stat",
    "ssh_sudo",
    "ssh_write_file",
];

#[derive(Parser)]
#[command(version, about = "Stdio SSH MCP server")]
pub(crate) struct Cli {
    /// Operator TOML configuration; no file is discovered automatically.
    #[arg(long, env = "SSH_MCP_CONFIG", hide_env_values = true)]
    config: Option<PathBuf>,
    /// Replacement OpenSSH configuration (not an overlay).
    #[arg(long, env = "SSH_MCP_SSH_CONFIG", hide_env_values = true)]
    ssh_config: Option<PathBuf>,
}

// Only fixed schema paths and fixed reasons enter diagnostics. In particular, neither
// TOML's error Display/source nor unknown field/target names are safe to render.
#[derive(Debug, thiserror::Error)]
#[error("{field}: {reason}")]
pub(crate) struct ConfigError {
    field: &'static str,
    reason: &'static str,
}

fn invalid(field: &'static str, reason: &'static str) -> ConfigError {
    ConfigError { field, reason }
}

pub(crate) struct Config {
    ssh_config: Option<PathBuf>,
    limits: Limits,
    targets: Option<BTreeMap<String, Target>>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Document {
    ssh: Ssh,
    limits: Limits,
    targets: Option<BTreeMap<String, Target>>,
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
    #[serde(serialize_with = "serialize_target_summaries")]
    #[schemars(with = "Vec<TargetSummary<'a>>")]
    targets: Option<&'a BTreeMap<String, Target>>,
    limits: DiscoveryLimits,
}

#[derive(Serialize, schemars::JsonSchema)]
struct TargetSummary<'a> {
    name: &'a str,
    sudo_mode: SudoMode,
    description: Option<&'a str>,
    labels: &'a BTreeMap<String, String>,
    permitted_operations: &'static [&'static str],
    observed_capabilities: ObservedCapabilities,
}

// Select only public fields as each row is serialized. In particular, do not
// allocate a summary Vec before the shared response-budget guard is applied.
fn serialize_target_summaries<S: Serializer>(
    targets: &Option<&BTreeMap<String, Target>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(targets.iter().flat_map(|targets| targets.iter()).map(
        |(name, target)| TargetSummary {
            name,
            sudo_mode: target.sudo.mode(),
            description: target.description.as_deref(),
            labels: &target.labels,
            permitted_operations: if target.sudo.permits_programs() {
                SUDO_OPERATIONS
            } else {
                ORDINARY_OPERATIONS
            },
            observed_capabilities: ObservedCapabilities::Unknown,
        },
    ))
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
            .or_else(|| env("SSH_MCP_CONFIG").map(PathBuf::from));
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
            .or_else(|| env("SSH_MCP_SSH_CONFIG").map(PathBuf::from));
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
                "SSH_MCP_CONNECT_TIMEOUT_SECS",
                &mut limits.connect_timeout_secs,
            ),
            (
                "limits.operation_timeout_secs",
                "SSH_MCP_OPERATION_TIMEOUT_SECS",
                &mut limits.operation_timeout_secs,
            ),
            (
                "limits.max_timeout_secs",
                "SSH_MCP_MAX_TIMEOUT_SECS",
                &mut limits.max_timeout_secs,
            ),
            (
                "limits.max_output_bytes",
                "SSH_MCP_MAX_OUTPUT_BYTES",
                &mut limits.max_output_bytes,
            ),
            (
                "limits.max_file_bytes",
                "SSH_MCP_MAX_FILE_BYTES",
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
        Ok(Self {
            ssh_config,
            limits: document.limits,
            targets: document.targets,
        })
    }

    pub(crate) fn targets(&self) -> TargetDiscovery<'_> {
        TargetDiscovery {
            mode: if self.targets.is_some() {
                TargetMode::Configured
            } else {
                TargetMode::Open
            },
            targets: self.targets.as_ref(),
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

    pub(crate) fn resolve<'a>(&'a self, host: &'a str) -> Result<ResolvedTarget<'a>, ToolError> {
        let destination = match &self.targets {
            Some(targets) => {
                &targets
                    .get(host)
                    .ok_or_else(|| {
                        ToolError::new(
                            "policy_denied",
                            "Host is not a configured logical target",
                            false,
                        )
                    })?
                    .ssh_host
            }
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
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        let (destination, role, users, programs) = match &target.sudo {
            Sudo::Disabled => return Err(denied()),
            Sudo::SameAccount { users, programs } => (
                target.ssh_host.as_str(),
                IdentityRole::Ordinary,
                users,
                programs,
            ),
            Sudo::SeparateIdentity {
                ssh_host,
                users,
                programs,
            } => (ssh_host.as_str(), IdentityRole::Elevated, users, programs),
        };
        if !users.iter().any(|allowed| allowed == user)
            || programs
                .as_ref()
                .is_some_and(|allowed| !allowed.iter().any(|allowed| allowed == program))
        {
            return Err(denied());
        }
        Ok(ResolvedTarget {
            name: host,
            destination,
            role,
        })
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
            // Named POSIX-style accounts only, not sudo's numeric-ID syntax or options.
            if user.is_empty()
                || !user.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphabetic()
                        || byte == b'_'
                        || (index > 0 && (byte.is_ascii_digit() || byte == b'-' || byte == b'.'))
                })
            {
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

fn destination(value: &str, field: &'static str) -> Result<(), ConfigError> {
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

fn validate_schema(value: &toml::Value) -> Result<(), ConfigError> {
    let root = table(value, "config", &["ssh", "limits", "targets"])?;
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
                &["ssh_host", "sudo", "description", "labels"],
            )?;
            string(
                target
                    .get("ssh_host")
                    .ok_or_else(|| invalid("targets.*.ssh_host", "required field is missing"))?,
                "targets.*.ssh_host",
            )?;
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

    fn cli() -> Cli {
        Cli {
            config: None,
            ssh_config: None,
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
    fn missing_and_present_empty_targets_are_distinct() {
        let open = load_text("", &[]).unwrap();
        let open = serde_json::to_value(open.targets()).unwrap();
        assert_eq!(open["mode"], "open");
        assert_eq!(open["targets"], serde_json::json!([]));
        let empty = load_text("[targets]", &[]).unwrap();
        let empty = serde_json::to_value(empty.targets()).unwrap();
        assert_eq!(empty["mode"], "configured");
        assert_eq!(empty["targets"], serde_json::json!([]));
    }

    #[test]
    fn discovery_is_sorted_and_never_contains_aliases() {
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
        let discovery = serde_json::to_value(config.targets()).unwrap();
        assert_eq!(discovery["mode"], "configured");
        assert_eq!(
            discovery["targets"],
            serde_json::json!([
                {
                    "name":"alpha", "sudo_mode":"same-account",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "ssh_exec", "ssh_list_directory", "ssh_read_file", "ssh_run",
                        "ssh_stat", "ssh_sudo", "ssh_write_file"
                    ],
                    "observed_capabilities":"unknown"
                },
                {
                    "name":"zebra", "sudo_mode":"separate-identity",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "ssh_exec", "ssh_list_directory", "ssh_read_file", "ssh_run",
                        "ssh_stat", "ssh_sudo", "ssh_write_file"
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
        let discovery = serde_json::to_value(config.targets()).unwrap();
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
                serde_json::json!([
                    "ssh_exec",
                    "ssh_list_directory",
                    "ssh_read_file",
                    "ssh_run",
                    "ssh_stat",
                    "ssh_write_file"
                ])
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
                .any(|operation| operation == "ssh_sudo")
        );
        assert!(!discovery.to_string().contains("private"));
    }

    #[test]
    fn discovery_limits_report_resolved_toml_and_environment_policy_without_clamping() {
        let text = "[limits]\nconnect_timeout_secs=2\noperation_timeout_secs=3\n\
                    max_timeout_secs=4\nmax_output_bytes=5\nmax_file_bytes=6";
        let config = load_text(text, &[]).unwrap();
        let limits = serde_json::to_value(config.targets()).unwrap()["limits"].clone();
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
                ("SSH_MCP_CONNECT_TIMEOUT_SECS", "7"),
                ("SSH_MCP_OPERATION_TIMEOUT_SECS", "8"),
                ("SSH_MCP_MAX_TIMEOUT_SECS", "9"),
                ("SSH_MCP_MAX_OUTPUT_BYTES", "20000000"),
                ("SSH_MCP_MAX_FILE_BYTES", "30000000"),
            ],
        )
        .unwrap();
        let limits = serde_json::to_value(config.targets()).unwrap()["limits"].clone();
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
            "SSH_MCP_CONFIG" => Some(OsString::from("nested/operator.toml")),
            _ => None,
        };
        let from_toml = Config::load_with(cli(), cwd, env).unwrap();
        assert_eq!(from_toml.ssh_config.unwrap(), cwd.join("nested/./$HOME"));
        let env = |key: &str| match key {
            "SSH_MCP_CONFIG" => Some(OsString::from("nested/operator.toml")),
            "SSH_MCP_SSH_CONFIG" => Some(OsString::from("env-ssh")),
            _ => None,
        };
        let from_env = Config::load_with(cli(), cwd, env).unwrap();
        assert_eq!(from_env.ssh_config.unwrap(), cwd.join("env-ssh"));
        let from_cli = Config::load_with(
            Cli {
                config: Some("nested/operator.toml".into()),
                ssh_config: Some("cli-ssh".into()),
            },
            cwd,
            |key| match key {
                "SSH_MCP_CONFIG" => Some("missing-secret".into()),
                "SSH_MCP_SSH_CONFIG" => Some("missing-secret".into()),
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
                    ssh_config: None
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
                    ssh_config: Some("missing".into())
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
                    ssh_config: Some(dir.path().into())
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );
        assert!(
            Config::load_with(cli(), dir.path(), |key| (key == "SSH_MCP_CONFIG")
                .then(|| OsString::from("")))
            .is_err()
        );
    }

    #[test]
    fn environment_wins_and_limits_are_positive_and_bounded() {
        let config = load_text("[limits]\nconnect_timeout_secs=2\noperation_timeout_secs=3\nmax_timeout_secs=4\nmax_output_bytes=5\nmax_file_bytes=6", &[
            ("SSH_MCP_CONNECT_TIMEOUT_SECS", "7"), ("SSH_MCP_OPERATION_TIMEOUT_SECS", "8"),
            ("SSH_MCP_MAX_TIMEOUT_SECS", "9"), ("SSH_MCP_MAX_OUTPUT_BYTES", "10"), ("SSH_MCP_MAX_FILE_BYTES", "11"),
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
                load_text("", &[("SSH_MCP_MAX_FILE_BYTES", value)]).is_err(),
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
        assert!(load_text("", &[("SSH_MCP_MAX_TIMEOUT_SECS", "59")]).is_err());
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
            dir.path().join("ssh-mcp.toml"),
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
            (key == "SSH_MCP_MAX_FILE_BYTES").then(|| OsString::from_vec(vec![0xff]))
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
        let resolved = config.resolve("logical").unwrap();
        assert_eq!(
            (resolved.name, resolved.destination, resolved.role),
            ("logical", "ordinary-alias", IdentityRole::Ordinary)
        );
        for host in ["ordinary-alias", "unknown", ""] {
            assert_eq!(config.resolve(host).err().unwrap().code, "policy_denied");
        }
        let empty = load_text("[targets]", &[]).unwrap();
        assert_eq!(
            empty.resolve("anything").err().unwrap().code,
            "policy_denied"
        );
        let open = load_text("", &[]).unwrap();
        let resolved = open.resolve("user@example").unwrap();
        assert_eq!(
            (resolved.name, resolved.destination),
            ("user@example", "user@example")
        );
        for host in ["", "-option", "host name", "host\0name"] {
            assert_eq!(open.resolve(host).err().unwrap().code, "invalid_argument");
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
        assert_eq!(config.resolve("split").unwrap().destination, "reader");
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
