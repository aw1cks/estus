use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::{Deserialize, Serialize};

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
    _ssh_config: Option<PathBuf>,
    _limits: Limits,
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
struct Limits {
    connect_timeout_secs: u64,
    operation_timeout_secs: u64,
    max_timeout_secs: u64,
    max_output_bytes: u64,
    max_file_bytes: u64,
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
    targets: Vec<TargetSummary<'a>>,
}

#[derive(Serialize, schemars::JsonSchema)]
struct TargetSummary<'a> {
    name: &'a str,
    sudo_mode: SudoMode,
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum TargetMode {
    Open,
    Configured,
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
enum SudoMode {
    Disabled,
    SameAccount,
    SeparateIdentity,
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
            _ssh_config: ssh_config,
            _limits: document.limits,
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
            targets: self
                .targets
                .iter()
                .flat_map(|targets| targets.iter())
                .map(|(name, target)| TargetSummary {
                    name,
                    sudo_mode: match target.sudo {
                        Sudo::Disabled => SudoMode::Disabled,
                        Sudo::SameAccount { .. } => SudoMode::SameAccount,
                        Sudo::SeparateIdentity { .. } => SudoMode::SeparateIdentity,
                    },
                })
                .collect(),
        }
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
    for target in targets.values() {
        destination(&target.ssh_host, "targets.*.ssh_host")?;
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
            let target = table(value, "targets.*", &["ssh_host", "sudo"])?;
            string(
                target
                    .get("ssh_host")
                    .ok_or_else(|| invalid("targets.*.ssh_host", "required field is missing"))?,
                "targets.*.ssh_host",
            )?;
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
        assert_eq!(
            serde_json::to_value(open.targets()).unwrap(),
            serde_json::json!({"mode":"open", "targets":[]})
        );
        let empty = load_text("[targets]", &[]).unwrap();
        assert_eq!(
            serde_json::to_value(empty.targets()).unwrap(),
            serde_json::json!({"mode":"configured", "targets":[]})
        );
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
        assert_eq!(
            serde_json::to_value(config.targets()).unwrap(),
            serde_json::json!({
                "mode":"configured", "targets":[
                    {"name":"alpha", "sudo_mode":"same-account"},
                    {"name":"zebra", "sudo_mode":"separate-identity"}
                ]
            })
        );
        match &config.targets.as_ref().unwrap()["alpha"].sudo {
            Sudo::SameAccount { users, programs } => {
                assert_eq!(users, &["root"]);
                assert!(programs.is_none());
            }
            _ => panic!("incorrect sudo mode"),
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
        assert_eq!(from_toml._ssh_config.unwrap(), cwd.join("nested/./$HOME"));
        let env = |key: &str| match key {
            "SSH_MCP_CONFIG" => Some(OsString::from("nested/operator.toml")),
            "SSH_MCP_SSH_CONFIG" => Some(OsString::from("env-ssh")),
            _ => None,
        };
        let from_env = Config::load_with(cli(), cwd, env).unwrap();
        assert_eq!(from_env._ssh_config.unwrap(), cwd.join("env-ssh"));
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
        assert_eq!(from_cli._ssh_config.unwrap(), cwd.join("cli-ssh"));
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
                config._limits.connect_timeout_secs,
                config._limits.operation_timeout_secs,
                config._limits.max_timeout_secs,
                config._limits.max_output_bytes,
                config._limits.max_file_bytes
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
}
