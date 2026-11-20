use std::{ffi::OsString, io::Read, os::unix::fs::OpenOptionsExt};

use clap::{Args, Parser, Subcommand, ValueEnum};

use super::{
    validation::{
        validate_automation, validate_bindings, validate_limits, validate_schema, validate_targets,
    },
    *,
};

#[derive(Parser)]
#[command(version, about = "Estus: operator-controlled SSH over MCP")]
pub(crate) struct Cli {
    /// Operator TOML configuration; no file is discovered automatically.
    #[arg(long, global = true, env = "ESTUS_CONFIG", hide_env_values = true)]
    pub(super) config: Option<PathBuf>,
    /// Replacement OpenSSH configuration (not an overlay).
    #[arg(long, global = true, env = "ESTUS_SSH_CONFIG", hide_env_values = true)]
    pub(super) ssh_config: Option<PathBuf>,
    /// Local OpenSSH executable; defaults to ssh resolved from PATH.
    #[arg(long, global = true, env = "ESTUS_SSH", hide_env_values = true)]
    pub(super) ssh: Option<PathBuf>,
    /// Opt in to workstation mode: open destinations and caller-chosen hosts.
    /// Without a configuration file this is required to expose anything beyond
    /// the read-only inspection builtins.
    #[arg(long, global = true, env = "ESTUS_WORKSTATION")]
    pub(super) workstation: bool,
    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Subcommand)]
pub(crate) enum CliCommand {
    /// Check runtime health or configured targets without executing automation or commands.
    Doctor(DoctorArgs),
    /// Build or inspect offline Ansible module bundle packs.
    Bundle(crate::bundle::BundleArgs),
    /// Discover, export and prepare bundled catalog definitions offline.
    Catalog(crate::catalog::cli::CatalogArgs),
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

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawCapabilities {
    named: Option<bool>,
    file_read: Option<bool>,
    file_write: Option<bool>,
    exec: Option<bool>,
    sudo: Option<bool>,
}

impl RawCapabilities {
    fn resolve(self, defaults: Capabilities) -> Capabilities {
        Capabilities {
            named: self.named.unwrap_or(defaults.named),
            file_read: self.file_read.unwrap_or(defaults.file_read),
            file_write: self.file_write.unwrap_or(defaults.file_write),
            exec: self.exec.unwrap_or(defaults.exec),
            sudo: self.sudo.unwrap_or(defaults.sudo),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Document {
    mode: Mode,
    capabilities: Option<RawCapabilities>,
    disclose_sudo_policy: bool,
    destination_policy: Option<TargetMode>,
    ssh: Ssh,
    limits: Limits,
    output: crate::output::Limits,
    directory: crate::filesystem::data::DirectoryLimits,
    quarantine: QuarantineSettings,
    targets: Option<BTreeMap<String, Target>>,
    rules: BTreeMap<String, rules::RawHostRule>,
    tools: BTreeMap<String, toml::Value>,
    enabled_tools: Vec<String>,
    tool_presets: Vec<String>,
    disabled_tools: Vec<String>,
    catalog: CatalogSettings,
    controller: Controller,
    automation: Automation,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            mode: Mode::Headless,
            capabilities: None,
            disclose_sudo_policy: false,
            destination_policy: None,
            ssh: Ssh::default(),
            limits: Limits::default(),
            output: crate::output::Limits::default(),
            directory: crate::filesystem::data::DirectoryLimits::default(),
            quarantine: QuarantineSettings::default(),
            targets: None,
            rules: BTreeMap::new(),
            tools: BTreeMap::new(),
            enabled_tools: Vec::new(),
            tool_presets: Vec::new(),
            disabled_tools: Vec::new(),
            catalog: CatalogSettings::default(),
            controller: Controller::default(),
            automation: Automation::default(),
        }
    }
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CatalogSettings {
    root: Option<PathBuf>,
    version: Option<String>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct QuarantineSettings {
    state_dir: Option<PathBuf>,
}

fn resolve_catalog_selection(
    document: &mut Document,
    base: &Path,
    env: &impl Fn(&str) -> Option<OsString>,
) -> Result<(), ConfigError> {
    let definitions: BTreeSet<&str> = document.tools.keys().map(String::as_str).collect();
    let unknown = |names: &[String]| names.iter().any(|n| !definitions.contains(n.as_str()));
    let target_needs_catalog = document.targets.iter().flat_map(|t| t.values()).any(|t| {
        t.tool_presets.as_ref().is_some_and(|v| !v.is_empty())
            || t.enabled_tools.as_deref().is_some_and(unknown)
            || unknown(&t.disabled_tools)
    });
    let needs_catalog = !document.tool_presets.is_empty()
        || target_needs_catalog
        || unknown(&document.enabled_tools)
        || unknown(&document.disabled_tools)
        || document.catalog.version.is_some()
        || document.catalog.root.is_some();
    let catalog = if needs_catalog {
        let path = document
            .catalog
            .root
            .as_ref()
            .cloned()
            .or_else(|| env("ESTUS_CATALOG_ROOT").map(PathBuf::from))
            .map(|p| resolve_path(p, base, "catalog.root"))
            .transpose()?;
        Some(
            crate::catalog::assets::Catalog::load(path.as_deref())
                .map_err(|reason| invalid("catalog", reason))?,
        )
    } else {
        None
    };
    let uses_presets = !document.tool_presets.is_empty()
        || document
            .targets
            .iter()
            .flat_map(|t| t.values())
            .any(|t| t.tool_presets.as_ref().is_some_and(|v| !v.is_empty()));
    if uses_presets && document.catalog.version.is_none() {
        return Err(invalid(
            "catalog.version",
            "preset selection requires an explicit catalog version",
        ));
    }
    if let Some(version) = &document.catalog.version
        && catalog
            .as_ref()
            .is_none_or(|c| c.manifest().version != *version)
    {
        return Err(invalid(
            "catalog.version",
            "review the changed catalog version before selecting presets",
        ));
    }
    let manifest = catalog.as_ref().map(|c| c.manifest());
    let selected = crate::catalog::selection::expand(
        &definitions,
        manifest,
        &document.enabled_tools,
        &document.tool_presets,
        &document.disabled_tools,
    )
    .map_err(|reason| invalid("enabled_tools", reason))?;
    if selected
        .iter()
        .any(|name| !definitions.contains(name.as_str()))
    {
        return Err(invalid(
            "tools",
            "selected catalog tools require prepared reviewed definitions",
        ));
    }
    if let Some(targets) = &mut document.targets {
        for target in targets.values_mut() {
            if target.enabled_tools.is_some()
                || target.tool_presets.is_some()
                || !target.disabled_tools.is_empty()
            {
                let mut allowed = if target.enabled_tools.is_some() || target.tool_presets.is_some()
                {
                    crate::catalog::selection::expand(
                        &definitions,
                        manifest,
                        target.enabled_tools.as_deref().unwrap_or(&[]),
                        target.tool_presets.as_deref().unwrap_or(&[]),
                        &target.disabled_tools,
                    )
                    .map_err(|reason| invalid("targets.*.enabled_tools", reason))?
                } else {
                    // Validate disable names even when none is globally selected.
                    crate::catalog::selection::expand(
                        &definitions,
                        manifest,
                        &[],
                        &[],
                        &target.disabled_tools,
                    )
                    .map_err(|reason| invalid("targets.*.disabled_tools", reason))?;
                    let mut inherited = selected.clone();
                    for name in &target.disabled_tools {
                        inherited.remove(name);
                    }
                    inherited
                };
                allowed.retain(|name| selected.contains(name));
                target.selected_bindings = Some(allowed);
            }
        }
    }
    document.enabled_tools = selected
        .into_iter()
        .filter(|name| {
            let Some(hosts) = document
                .tools
                .get(name)
                .and_then(|v| v.get("targets"))
                .and_then(toml::Value::as_array)
            else {
                return true;
            };
            hosts.iter().any(|host| {
                host.as_str()
                    .and_then(|host| document.targets.as_ref().and_then(|t| t.get(host)))
                    .is_none_or(|target| {
                        target
                            .selected_bindings
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(name))
                    })
            })
        })
        .collect();
    Ok(())
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
    executable: Option<PathBuf>,
}

impl Config {
    pub(crate) fn load(cli: Cli) -> Result<Self, ConfigError> {
        let cwd = std::env::current_dir()
            .map_err(|_| invalid("config", "cannot determine launch directory"))?;
        Self::load_with(cli, &cwd, |key| std::env::var_os(key))
    }

    // Inject environment and launch directory so tests never mutate process state.
    pub(super) fn load_with(
        cli: Cli,
        cwd: &Path,
        env: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, ConfigError> {
        Self::load_with_catalog_root(cli, cwd, env, None)
    }

    fn load_with_catalog_root(
        cli: Cli,
        cwd: &Path,
        env: impl Fn(&str) -> Option<OsString>,
        catalog_root: Option<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let config_path = cli
            .config
            .or_else(|| env("ESTUS_CONFIG").map(PathBuf::from));
        let workstation_opt_in = cli.workstation;
        let (mut document, base) = if let Some(path) = config_path {
            let path = resolve_path(path, cwd, "config")?;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(&path)
                .map_err(|_| invalid("config", "cannot read explicitly selected TOML file"))?;
            if !file
                .metadata()
                .map_err(|_| invalid("config", "cannot inspect TOML file"))?
                .is_file()
            {
                return Err(invalid("config", "must be a regular TOML file"));
            }
            let mut text = String::new();
            file.read_to_string(&mut text)
                .map_err(|_| invalid("config", "cannot read explicitly selected TOML file"))?;
            let value: toml::Value =
                toml::from_str(&text).map_err(|error| ConfigError::toml_syntax(&text, &error))?;
            validate_schema(&value)?;
            let document = toml::from_str::<Document>(&text)
                .map_err(|error| ConfigError::toml_structure(&text, &error))?;
            // The flag never escalates a configuration file: it may only restate
            // the mode the operator already declared there.
            if workstation_opt_in && document.mode != Mode::Workstation {
                return Err(invalid(
                    "mode",
                    "workstation opt-in conflicts with the selected configuration",
                ));
            }
            let base = path.parent().unwrap_or(cwd).to_path_buf();
            (document, base)
        } else if workstation_opt_in {
            // Workstation mode is an explicit opt-in, never a silent default:
            // no configuration file has to state that it trusts the caller.
            let document = Document {
                mode: Mode::Workstation,
                destination_policy: Some(TargetMode::Open),
                ..Default::default()
            };
            (document, cwd.to_path_buf())
        } else {
            // Restrictive default: configured destinations (none), action-only
            // capabilities. A client that omits --workstation gets no exec,
            // sudo, file-write or catalog exposure.
            (Document::default(), cwd.to_path_buf())
        };

        let capabilities = match (document.mode, document.capabilities.take()) {
            (Mode::Workstation, None) => Capabilities::all(),
            (Mode::Workstation, Some(raw)) => raw.resolve(Capabilities::all()),
            (Mode::Headless, None) => Capabilities::actions_only(),
            (Mode::Headless, Some(raw)) => raw.resolve(Capabilities {
                named: false,
                file_read: false,
                file_write: false,
                exec: false,
                sudo: false,
            }),
        };

        let destination_policy = match (document.mode, document.destination_policy.take()) {
            (_, Some(policy)) => policy,
            (Mode::Workstation, None) if document.targets.is_none() => TargetMode::Open,
            (_, None) => TargetMode::Configured,
        };
        match destination_policy {
            TargetMode::Configured => {
                document.targets.get_or_insert_with(BTreeMap::new);
            }
            TargetMode::Open if document.targets.is_some() => {
                return Err(invalid(
                    "destination_policy",
                    "open mode must not include a targets table",
                ));
            }
            TargetMode::Open => {}
        }

        if let Some(root) = catalog_root {
            document.catalog.root = Some(root);
        }
        resolve_catalog_selection(&mut document, &base, &env)?;
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
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| {
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
        validate_limits(limits)?;
        document
            .output
            .validate()
            .map_err(|reason| invalid("output", reason))?;
        document
            .directory
            .validate()
            .map_err(|reason| invalid("directory", reason))?;
        if let Some(targets) = &document.targets {
            validate_targets(targets)?;
        }
        validate_automation(
            document.controller.workspace_root.as_deref(),
            &document.automation,
            document.targets.as_ref(),
        )?;
        let rules = rules::compile_rules(document.rules)?;
        let mut bindings = Bindings::compile_with_mode(
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
            capabilities.permits_bindings(),
            document.mode == Mode::Workstation,
        )?;
        validate_bindings(&bindings, document.targets.as_ref(), &document.automation)?;
        if document.mode == Mode::Workstation && capabilities.named {
            let catalog_source = match document
                .catalog
                .root
                .clone()
                .or_else(|| env("ESTUS_CATALOG_ROOT").map(PathBuf::from))
            {
                Some(p) => Some(resolve_path(p, &base, "catalog.root")?),
                None => crate::catalog::assets::discover_default_root(),
            };
            if let Some(path) = catalog_source {
                let catalog = crate::catalog::assets::Catalog::load(Some(&path))
                    .map_err(|reason| invalid("catalog", reason))?;
                for name in catalog.workstation_tool_names() {
                    if document.disabled_tools.iter().any(|d| d == name)
                        || bindings.entries().any(|(_, b)| b.name == name)
                    {
                        continue;
                    }
                    match catalog
                        .load_workstation_entry(name)
                        .map_err(|reason| invalid("catalog", reason))?
                    {
                        crate::catalog::assets::WorkstationEntry::Payload {
                            definition,
                            source,
                            manifest,
                        } => {
                            let needs_sudo = definition
                                .get("authority")
                                .and_then(toml::Value::as_str)
                                .is_some_and(|a| a.starts_with("automation:"));
                            if needs_sudo && !capabilities.sudo {
                                continue;
                            }
                            bindings.push_dynamic_payload(
                                name.to_owned(),
                                definition,
                                source,
                                &manifest,
                                &document.limits,
                            )?;
                        }
                        crate::catalog::assets::WorkstationEntry::Module { definition } => {
                            let needs_sudo = definition
                                .get("authority")
                                .and_then(toml::Value::as_str)
                                .is_some_and(|a| a.starts_with("automation:"));
                            if needs_sudo && !capabilities.sudo {
                                continue;
                            }
                            bindings.push_dynamic_ansible_module(
                                name.to_owned(),
                                definition,
                                &document.limits,
                            )?;
                        }
                    }
                }
            }
        }
        let ssh_override = cli.ssh.or_else(|| env("ESTUS_SSH").map(PathBuf::from));
        let selected = match ssh_override {
            Some(path) => Some(resolve_path(path, cwd, "ssh.executable")?),
            None => document
                .ssh
                .executable
                .map(|path| resolve_path(path, &base, "ssh.executable"))
                .transpose()?,
        };
        let ssh_executable = resolve_ssh_executable(selected, || env("PATH"))?;
        let quarantine_state_dir = document
            .quarantine
            .state_dir
            .map(|path| resolve_path(path, &base, "quarantine.state_dir"))
            .transpose()?;
        Ok(Self {
            mode: document.mode,
            capabilities,
            disclose_sudo_policy: document.disclose_sudo_policy,
            ssh_config,
            ssh_executable,
            quarantine_state_dir,
            limits: document.limits,
            output: document.output,
            directory: document.directory,
            targets: document.targets,
            rules,
            bindings,
            automation: document.automation,
        })
    }

    pub(crate) fn from_file_with_catalog_root(
        mut cli: Cli,
        path: PathBuf,
        root: Option<PathBuf>,
    ) -> Result<Self, ConfigError> {
        let cwd = std::env::current_dir()
            .map_err(|_| invalid("config", "cannot determine launch directory"))?;
        // --site is the explicit catalog document. The caller rejects an
        // explicit --config conflict; ambient ESTUS_CONFIG does not replace it.
        cli.config = Some(path);
        Self::load_with_catalog_root(cli, &cwd, |key| std::env::var_os(key), root)
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

fn resolve_ssh_executable(
    selected: Option<PathBuf>,
    path: impl FnOnce() -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let available = |path: &Path| {
        path.is_absolute()
            && path
                .to_str()
                .is_some_and(|text| text.len() <= 4096 && !text.contains('\0'))
            && std::fs::metadata(path).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
    };
    if let Some(selected) = selected {
        return if available(&selected) {
            Ok(selected)
        } else {
            Err(invalid(
                "ssh.executable",
                "selected executable is unavailable",
            ))
        };
    }
    if let Some(path) = path() {
        for directory in std::env::split_paths(&path) {
            if !directory.is_absolute() {
                continue;
            }
            let candidate = directory.join("ssh");
            if available(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err(invalid(
        "ssh.executable",
        "cannot find an executable ssh on PATH",
    ))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{binding_definition, cli, load_text};
    use super::*;

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
        let executable = std::env::current_exe().unwrap();
        let executable = executable.to_str().unwrap();
        for argv in [
            vec![
                "estus",
                "--config",
                "nested/operator.toml",
                "--ssh-config",
                "selected-ssh",
                "--ssh",
                executable,
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
                "--ssh",
                executable,
            ],
        ] {
            let parsed = Cli::try_parse_from(argv).unwrap();
            assert!(matches!(parsed.command, Some(CliCommand::Doctor(_))));
            let config = Config::load_with(parsed, dir.path(), |key| match key {
                "ESTUS_CONFIG" | "ESTUS_SSH_CONFIG" | "ESTUS_SSH" => {
                    Some("missing-env-private".into())
                }
                _ => None,
            })
            .unwrap();
            assert_eq!(
                config.ssh_config(),
                Some(dir.path().join("selected-ssh").as_path())
            );
            assert_eq!(config.ssh_executable(), Path::new(executable));
            assert_eq!(
                config.doctor_target("one").unwrap().destination,
                "private-alias"
            );
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
    fn ssh_executable_obeys_cli_environment_file_and_path_precedence() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir(cwd.join("nested")).unwrap();
        std::fs::create_dir(cwd.join("bin")).unwrap();
        let executable = std::env::current_exe().unwrap();
        for name in ["cli-ssh", "env-ssh", "nested/$HOME", "bin/ssh"] {
            symlink(&executable, cwd.join(name)).unwrap();
        }
        let file = cwd.join("nested/operator.toml");
        for (cli_value, env_value, file_value, expected) in [
            (
                Some("cli-ssh"),
                Some("missing-env"),
                Some("missing-file"),
                "cli-ssh",
            ),
            (None, Some("env-ssh"), Some("missing-file"), "env-ssh"),
            (None, None, Some("./$HOME"), "nested/./$HOME"),
            (None, None, None, "bin/ssh"),
        ] {
            let text = file_value
                .map(|value| format!("[ssh]\nexecutable={value:?}\n"))
                .unwrap_or_default();
            std::fs::write(&file, text).unwrap();
            let mut args = cli();
            args.config = Some(file.clone());
            args.ssh = cli_value.map(PathBuf::from);
            let config = Config::load_with(args, cwd, |key| match key {
                "ESTUS_SSH" => env_value.map(OsString::from),
                "PATH" => Some(cwd.join("bin").into_os_string()),
                _ => None,
            })
            .unwrap();
            assert_eq!(config.ssh_executable(), cwd.join(expected));
        }
    }

    #[test]
    fn invalid_ssh_overrides_never_fall_back_or_disclose_their_values() {
        use std::os::unix::{
            ffi::OsStringExt,
            fs::{PermissionsExt, symlink},
        };

        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        std::fs::create_dir(cwd.join("bin")).unwrap();
        symlink(std::env::current_exe().unwrap(), cwd.join("bin/ssh")).unwrap();
        let nonexecutable = cwd.join("private-nonexecutable");
        std::fs::write(&nonexecutable, "").unwrap();
        std::fs::set_permissions(&nonexecutable, std::fs::Permissions::from_mode(0o600)).unwrap();
        for value in [
            OsString::from(""),
            OsString::from("private-missing"),
            OsString::from("private-nonexecutable"),
            cwd.as_os_str().to_owned(),
            OsString::from("/private\0ssh"),
            OsString::from(format!("/private{}", "x".repeat(4096))),
            OsString::from_vec(b"/private-\xff".to_vec()),
        ] {
            for source in ["cli", "env", "file"] {
                let mut args = cli();
                args.ssh = (source == "cli").then(|| PathBuf::from(&value));
                if source == "file" {
                    let Some(value) = value.to_str() else {
                        continue;
                    };
                    let file = cwd.join("operator.toml");
                    let text =
                        toml::to_string(&serde_json::json!({"ssh":{"executable":value}})).unwrap();
                    std::fs::write(&file, text).unwrap();
                    args.config = Some(file);
                }
                let error = Config::load_with(args, cwd, |key| match key {
                    "ESTUS_SSH" if source == "env" => Some(value.clone()),
                    "PATH" => Some(cwd.join("bin").into_os_string()),
                    _ => None,
                })
                .err()
                .expect("invalid selected executable must fail despite valid PATH");
                assert_eq!(error.field, "ssh.executable", "{source}: {value:?}");
                assert!(!error.to_string().contains("private"));
            }
        }
        let error = load_text("[automation]\nssh_executable='/private-old-setting'", &[])
            .err()
            .unwrap();
        assert_eq!(error.field, "automation");
    }

    #[test]
    fn ssh_path_search_skips_unusable_entries_and_requires_a_match() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path();
        for name in ["nonexecutable", "directory", "selected"] {
            std::fs::create_dir(cwd.join(name)).unwrap();
        }
        std::fs::write(cwd.join("nonexecutable/ssh"), "").unwrap();
        std::fs::set_permissions(
            cwd.join("nonexecutable/ssh"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::create_dir(cwd.join("directory/ssh")).unwrap();
        let executable = std::env::current_exe().unwrap();
        symlink(&executable, cwd.join("selected/ssh")).unwrap();
        symlink(&executable, cwd.join("ssh")).unwrap();
        let path = std::env::join_paths([
            cwd.join("missing"),
            cwd.join("nonexecutable"),
            cwd.join("directory"),
            PathBuf::from("relative-selected"),
            cwd.join("selected"),
        ])
        .unwrap();
        let mut args = cli();
        args.ssh = None;
        let config =
            Config::load_with(args, cwd, |key| (key == "PATH").then(|| path.clone())).unwrap();
        assert_eq!(config.ssh_executable(), cwd.join("selected/ssh"));
        let relative_only = std::env::join_paths([
            PathBuf::from("selected"),
            PathBuf::from("."),
            PathBuf::from(""),
        ])
        .unwrap();
        for path in [
            None,
            Some(OsString::from("missing:nonexecutable:directory")),
            Some(relative_only),
        ] {
            let mut args = cli();
            args.ssh = None;
            let error = Config::load_with(args, cwd, |key| {
                (key == "PATH").then(|| path.clone()).flatten()
            })
            .err()
            .unwrap();
            assert_eq!(error.field, "ssh.executable");
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
                ssh: Some(std::env::current_exe().unwrap()),
                command: None,
                workstation: false,
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
                    ssh: Some(std::env::current_exe().unwrap()),
                    command: None,
                    workstation: false,
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
                    ssh: Some(std::env::current_exe().unwrap()),
                    command: None,
                    workstation: false,
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
                    ssh: Some(std::env::current_exe().unwrap()),
                    command: None,
                    workstation: false,
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
            assert_ne!(key, "ESTUS_ANSIBLE_BUNDLE");
            None
        })
        .unwrap();
        assert!(!config.automation_required());
        assert_eq!(config.automation_bundle_with(|_| None).unwrap(), None);

        // Neither required nor a configured reference inspects bundle files.
        for required in [false, true] {
            let config = load_text(
                &format!("[automation]\nrequired={required}\nbundle='/nonexistent-private-bundle'"),
                &[],
            )
            .unwrap();
            assert_eq!(config.automation_required(), required);
            assert_eq!(
                config
                    .automation_bundle_with(|_| panic!("file reference must win"))
                    .unwrap(),
                Some(PathBuf::from("/nonexistent-private-bundle"))
            );
        }
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
        assert_eq!(config.mode, Mode::Headless);
        assert_eq!(config.capabilities, Capabilities::actions_only());
        assert!(
            config
                .targets
                .as_ref()
                .is_some_and(|targets| targets.is_empty())
        );
        for tool in [
            ToolId::Exec,
            ToolId::Run,
            ToolId::Sudo,
            ToolId::WriteFile,
            ToolId::ReadFile,
            ToolId::Stat,
            ToolId::ListDirectory,
        ] {
            assert!(!config.tool_enabled(tool), "{tool:?} must stay unpublished");
        }
        assert!(config.tool_enabled(ToolId::Targets));
    }

    #[test]
    fn workstation_opt_in_is_required_and_never_escalates_a_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let workstation = Cli {
            workstation: true,
            ..cli()
        };
        let config = Config::load_with(workstation, dir.path(), |_| None).unwrap();
        assert_eq!(config.mode, Mode::Workstation);
        assert_eq!(config.capabilities, Capabilities::all());
        assert!(config.targets.is_none());

        // No flag: restrictive headless default.
        let config = Config::load_with(cli(), dir.path(), |_| None).unwrap();
        assert_eq!(config.mode, Mode::Headless);

        // The explicit opt-in must never turn a headless file into workstation mode.
        let path = dir.path().join("operator.toml");
        std::fs::write(&path, "[targets.one]\nssh_host='host-alias'\n").unwrap();
        let error = Config::load_with(
            Cli {
                config: Some(path.clone()),
                workstation: true,
                ..cli()
            },
            dir.path(),
            |_| None,
        )
        .err()
        .expect("opt-in must not escalate a configuration file");
        assert_eq!(
            error.to_string(),
            "mode: workstation opt-in conflicts with the selected configuration"
        );
    }

    #[tokio::test]
    async fn workstation_loads_pinned_bundled_dynamic_payloads() {
        let dir = tempfile::tempdir().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let mut config = Config::load_with(
            Cli {
                workstation: true,
                ..cli()
            },
            dir.path(),
            |key| (key == "ESTUS_CATALOG_ROOT").then(|| root.as_os_str().to_owned()),
        )
        .unwrap();
        assert_eq!(config.mode, Mode::Workstation);
        config
            .activate_automation(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap();
        for name in ["observe_cpu", "observe_memory", "observe_pressure"] {
            assert!(
                config.bindings.entries().any(|(id, b)| b.name == name
                    && config.binding_enabled(id)
                    && b.has_dynamic_targets()),
                "missing dynamic workstation tool {name}"
            );
        }
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
}

#[cfg(test)]
mod catalog_selection_tests {
    use super::*;

    fn definition(name: &str) -> String {
        format!(
            r#"
[tools.{name}]
description = "Bounded account observation"
revision = "1"
targets = ["one", "two"]
authority = "ordinary"
effects = ["read"]
execution = {{ kind = "native_argv", program = "/usr/bin/id", argv = ["--", {{ input = "account" }}] }}
input_schema = {{ type = "object", additionalProperties = false, required = ["account"], properties = {{ account = {{ type = "string", minLength = 1, maxLength = 32 }} }} }}
result = {{ kind = "command" }}
"#
        )
    }

    fn load(text: &str) -> Result<Config, ConfigError> {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("site.toml");
        std::fs::write(&path, text).unwrap();
        Config::load_with(
            Cli {
                config: Some(path),
                ssh_config: None,
                ssh: Some(std::env::current_exe().unwrap()),
                command: None,
                workstation: false,
            },
            directory.path(),
            |_| None,
        )
    }

    #[test]
    fn target_selection_matches_discovery_and_cannot_resurrect_global_disables() {
        let config = load(&format!(
            r#"
capabilities = {{ named = true }}
enabled_tools = ["observe", "other"]
disabled_tools = ["other"]
[targets.one]
ssh_host = "ordinary-one"
enabled_tools = ["observe"]
[targets.two]
ssh_host = "ordinary-two"
enabled_tools = ["other"]
{}{}
"#,
            definition("observe"),
            definition("other")
        ))
        .unwrap();
        let (id, _) = config
            .bindings
            .entries()
            .find(|(_, b)| b.name == "observe")
            .unwrap();
        let (disabled, _) = config
            .bindings
            .entries()
            .find(|(_, b)| b.name == "other")
            .unwrap();
        assert!(config.binding_enabled(id));
        assert!(!config.binding_enabled(disabled));
        assert!(config.resolve_binding("one", id).is_ok());
        assert_eq!(
            config.resolve_binding("two", id).err().unwrap().code(),
            "policy_denied"
        );
        assert_eq!(
            config
                .resolve_binding("two", disabled)
                .err()
                .unwrap()
                .code(),
            "policy_denied"
        );
        let tools = ToolCatalog::new(
            config
                .bindings
                .entries()
                .map(|(id, b)| ToolEntry {
                    id: ToolKey::Binding(id),
                    name: Cow::Owned(b.name.clone()),
                })
                .collect(),
        )
        .unwrap();
        let discovered = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(
            discovered["targets"][0]["permitted_operations"],
            serde_json::json!(["observe"])
        );
        assert_eq!(
            discovered["targets"][1]["permitted_operations"],
            serde_json::json!([])
        );
    }

    #[test]
    fn explicit_empty_target_selection_denies_every_named_tool() {
        let config = load(&format!(
            r#"
capabilities = {{ named = true }}
enabled_tools = ["observe"]
[targets.one]
ssh_host = "ordinary-one"
enabled_tools = []
[targets.two]
ssh_host = "ordinary-two"
tool_presets = []
{}
"#,
            definition("observe")
        ))
        .unwrap();
        assert!(
            config
                .bindings
                .entries()
                .all(|(id, _)| !config.binding_enabled(id))
        );
    }

    #[test]
    fn presets_are_pinned_inert_templates_not_authority_or_definition_grants() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = crate::catalog::assets::Catalog::load(Some(&root)).unwrap();
        let pin = format!("version={:?}", catalog.manifest().version);
        let inert = load(&format!("[catalog]\nroot={root:?}\n{pin}\n")).unwrap();
        assert_eq!(inert.bindings.entries().count(), 0);
        assert!(!inert.automation.required);
        let prefix = format!(
            "capabilities = {{ named = true }}\ntool_presets=['linux-health']\n[catalog]\nroot={root:?}\n{pin}\n[targets.one]\nssh_host='one'\n[targets.two]\nssh_host='two'\n"
        );
        assert!(
            load(&prefix).is_err(),
            "preset fabricated unreviewed definitions"
        );
        let text = format!(
            "{prefix}{}{}{}",
            definition("observe_cpu"),
            definition("observe_memory"),
            definition("observe_pressure")
        );
        let config = load(&text).unwrap();
        assert!(
            config
                .bindings
                .entries()
                .all(|(id, _)| config.binding_enabled(id))
        );
        assert!(load(&text.replace(&pin, "version='unreviewed-upgrade'")).is_err());
        assert!(load(&text.replace(&pin, "")).is_err());
        assert!(load(&text.replace("linux-health", "unknown-preset")).is_err());
    }
}
