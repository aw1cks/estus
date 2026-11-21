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
    /// the read-only inspection builtins. Deliberately flag-only: an inherited
    /// environment variable must never widen authority.
    #[arg(long, global = true)]
    pub(super) workstation: bool,
    /// Unrestricted workstation escape hatch: open destinations, full capabilities,
    /// same-account root sudo, and all non-lab catalog tools. Deliberately flag-only
    /// and cannot be combined with a configuration file.
    #[arg(long, global = true)]
    pub(super) yolo: bool,
    /// With --yolo, also publish laboratory_only hardware/kernel templates.
    #[arg(long, global = true)]
    pub(super) include_lab: bool,
    #[command(subcommand)]
    pub(crate) command: Option<CliCommand>,
}

#[derive(Subcommand)]
pub(crate) enum CliCommand {
    /// Check runtime health or configured targets without executing automation or commands.
    Doctor(DoctorArgs),
    /// Explain effective policy and check per-host tool authorization offline.
    Auth(AuthArgs),
    /// Build or inspect offline Ansible module bundle packs.
    Bundle(crate::bundle::BundleArgs),
    /// Discover the bundled catalog and export selected definitions offline.
    Catalog(crate::catalog::cli::CatalogArgs),
}

#[derive(Args)]
pub(crate) struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommand,
}

#[derive(Subcommand)]
pub(crate) enum AuthCommand {
    /// Explain which groups/profiles match a host and the resulting effective policy.
    Explain {
        /// Target name (configured mode) or SSH destination (open mode).
        host: String,
        /// Emit structured JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Check whether a specific tool is authorized on a host (exit 0 = yes, 1 = no).
    CanI {
        /// Published tool name (e.g. change_systemd_unit, exec_command, inspect_file).
        tool: String,
        /// Target name (configured mode) or SSH destination (open mode).
        host: String,
        /// Emit structured JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
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
pub(super) struct RawCapabilities {
    named: Option<bool>,
    file_read: Option<bool>,
    file_write: Option<bool>,
    exec: Option<bool>,
    sudo: Option<bool>,
}

impl RawCapabilities {
    fn resolve(self, defaults: Capabilities) -> Capabilities {
        self.resolve_ref(defaults)
    }

    pub(super) fn resolve_ref(&self, defaults: Capabilities) -> Capabilities {
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
    require_preview: bool,
    default_profile: Option<String>,
    profiles: BTreeMap<String, profiles::RawProfile>,
    groups: Vec<profiles::RawGroup>,
    ssh: Ssh,
    limits: Limits,
    output: crate::output::Limits,
    quarantine: QuarantineSettings,
    targets: Option<BTreeMap<String, Target>>,
    tools: BTreeMap<String, toml::Value>,
    selection: Selection,
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
            require_preview: false,
            default_profile: None,
            profiles: BTreeMap::new(),
            groups: Vec::new(),
            ssh: Ssh::default(),
            limits: Limits::default(),
            output: crate::output::Limits::default(),
            quarantine: QuarantineSettings::default(),
            targets: None,
            tools: BTreeMap::new(),
            selection: Selection::default(),
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

/// Resolve the two selection layers: the global `[selection]` publishes names,
/// and each `[targets.<name>.selection]` narrows that set for its own target.
/// Everything else about a tool lives in its `[tools]` definition.
fn resolve_selection(
    document: &mut Document,
    capabilities: Capabilities,
    yolo: bool,
    base: &Path,
    env: &impl Fn(&str) -> Option<OsString>,
) -> Result<profiles::PolicyEngine, ConfigError> {
    // no local definition is a catalog template, which is what pulls the
    // installed inventory in at all. Presets are always catalog data.
    // Builtin wire names are always definable, so naming one never means "load
    // the catalog"; only a site tool with no `[tools]` entry does.
    let builtin_names: BTreeSet<&str> = ToolId::ALL
        .into_iter()
        .map(|tool| tool.wire_name())
        .collect();
    // Only a complete definition (one with `execution`) is local; a table
    // without it is site policy for a catalog template and must load the catalog.
    let defined: BTreeSet<String> = document
        .tools
        .iter()
        .filter(|(_, value)| value.get("execution").is_some())
        .map(|(name, _)| name.clone())
        .collect();
    let unknown = |names: &[String]| {
        names
            .iter()
            .any(|name| !defined.contains(name) && !builtin_names.contains(name.as_str()))
    };
    let selection_needs_catalog = |selection: &Selection| {
        !selection.presets.is_empty() || unknown(&selection.allow) || unknown(&selection.deny)
    };
    let target_needs_catalog = document
        .targets
        .iter()
        .flat_map(|t| t.values())
        .filter_map(|t| t.selection.as_ref())
        .any(&selection_needs_catalog);
    let profile_needs_catalog = document
        .profiles
        .values()
        .filter_map(|p| p.selection.as_ref())
        .any(&selection_needs_catalog);
    // A name that has no local definition is enabled from the installed catalog.
    let needs_catalog = selection_needs_catalog(&document.selection)
        || target_needs_catalog
        || profile_needs_catalog
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
                .map_err(|e| invalid("catalog", e.reason()))?,
        )
    } else {
        None
    };
    // `catalog.version` is an optional assertion: when present the installed
    // inventory must still be the one the operator reviewed.
    if let Some(version) = &document.catalog.version
        && catalog
            .as_ref()
            .is_none_or(|c| c.manifest().version != *version)
    {
        return Err(invalid(
            "catalog.version",
            "installed catalog version differs from the configured assertion",
        ));
    }
    let manifest = catalog.as_ref().map(|c| c.manifest());
    // Every known name is selectable: local `[tools]` definitions and the
    // installed catalog's templates alike.
    let mut definitions: BTreeSet<String> = defined;
    if let Some(manifest) = manifest {
        definitions.extend(manifest.tools.keys().cloned());
    }
    // A selection names any callable tool. The global default is every builtin
    // the capability ceiling permits, plus whatever the operator lists; `deny`
    // always subtracts. Only named tools reach the binding compiler.
    let permitted_builtins: BTreeSet<String> = ToolId::ALL
        .into_iter()
        .filter(|tool| capabilities.permits(*tool))
        .map(|tool| tool.wire_name().to_owned())
        .collect();
    // Name validation accepts every builtin, even one the ceiling removed: a
    // target may still name it, and the intersection below denies it.
    let mut definable = definitions.clone();
    definable.extend(ToolId::ALL.map(|tool| tool.wire_name().to_owned()));
    let mut global = permitted_builtins.clone();
    global.extend(
        crate::catalog::selection::expand(
            &definable,
            manifest,
            &document.selection.allow,
            &document.selection.presets,
            &document.selection.deny,
        )
        .map_err(|reason| invalid("selection", reason))?,
    );
    global.retain(|name| !document.selection.deny.contains(name));
    // Workstation exposure is its own reviewed path; site definitions here
    // describe a configured destination policy and do not apply.
    if let Some(catalog) = &catalog
        && document.mode == Mode::Headless
    {
        // Builtins have no catalog template and need no materialization.
        let named: BTreeSet<String> = global.difference(&permitted_builtins).cloned().collect();
        materialize_catalog_tools(document, catalog, &named)?;
    }
    if let Some(targets) = &mut document.targets {
        for target in targets.values_mut() {
            // An absent table inherits the global set. A present table either
            // lists this host's names (`allow`/`presets`) or subtracts from the
            // inherited set (`deny` only); a table with every list empty denies
            // every named tool. Nothing can exceed the global set.
            let Some(selection) = &target.selection else {
                continue;
            };
            let mut names = if selection.presets.is_empty() && selection.allow.is_empty() {
                global.clone()
            } else {
                crate::catalog::selection::expand(
                    &definable,
                    manifest,
                    &selection.allow,
                    &selection.presets,
                    &[],
                )
                .map_err(|reason| invalid("targets.*.selection", reason))?
            };
            if selection.presets.is_empty()
                && selection.allow.is_empty()
                && selection.deny.is_empty()
            {
                names.clear();
            }
            names.retain(|name| !selection.deny.contains(name) && global.contains(name));
            target.selected_bindings = Some(names);
        }
    }
    let policy_engine = profiles::PolicyEngine::compile(
        yolo,
        document.default_profile.take(),
        std::mem::take(&mut document.profiles),
        std::mem::take(&mut document.groups),
        document.targets.as_ref(),
        &definable,
        manifest,
        &global,
        &permitted_builtins,
    )?;
    // Builtins are published by the capability ceiling; only named tools are
    // compiled, so the compiler sees the difference.
    document.selection.builtins = global.intersection(&permitted_builtins).cloned().collect();
    // A name every declared target now denies is not published at all, so the
    // tool list and the per-host answer agree.
    document.selection.allow = global
        .into_iter()
        .filter(|name| !permitted_builtins.contains(name))
        .filter(|name| {
            let Some(hosts) = document
                .tools
                .get(name)
                .and_then(|value| value.get("targets"))
                .and_then(toml::Value::as_array)
            else {
                return true;
            };
            hosts.iter().any(|host| {
                host.as_str().is_none_or(|host| {
                    document
                        .targets
                        .as_ref()
                        .and_then(|targets| targets.get(host))
                        .is_none_or(|target| {
                            target
                                .selected_bindings
                                .as_ref()
                                .is_none_or(|allowed| allowed.contains(name))
                        })
                })
            })
        })
        .collect();
    document.selection.presets.clear();
    document.selection.deny.clear();
    Ok(policy_engine)
}

/// Replace selected catalog names with the installed definition, applying site
/// policy from the config's `[tools.<name>]` table. A table without `execution`
/// is site policy only (targets, authority, fixed args, constraints, limits);
/// a table with `execution` is a complete operator-authored definition and is
/// left alone.
fn materialize_catalog_tools(
    document: &mut Document,
    catalog: &crate::catalog::assets::Catalog,
    selected: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    let destinations: Vec<String> = document
        .targets
        .iter()
        .flat_map(|targets| targets.keys().cloned())
        .collect();
    let mut resolved: BTreeMap<String, toml::Value> = BTreeMap::new();
    for name in selected {
        let local = document.tools.get(name);
        let overrides = match local {
            None => None,
            Some(value) if value.get("execution").is_some() => continue,
            Some(value) => Some(value),
        };
        let definition = catalog
            .site_definition(
                name,
                overrides.and_then(toml::Value::as_table),
                &destinations,
            )
            .map_err(|e| invalid("tools", e.reason()))?;
        resolved.insert(name.clone(), definition);
    }
    for (name, definition) in resolved {
        document.tools.insert(name, definition);
    }
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
        let config_path = cli
            .config
            .or_else(|| env("ESTUS_CONFIG").map(PathBuf::from));
        let workstation_opt_in = cli.workstation;
        let yolo = cli.yolo;
        let include_lab = cli.include_lab;
        if include_lab && !yolo {
            return Err(invalid("mode", "include-lab requires --yolo"));
        }
        if yolo && config_path.is_some() {
            return Err(invalid(
                "mode",
                "yolo opt-in cannot be combined with a configuration file",
            ));
        }
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
        } else if yolo || workstation_opt_in {
            // Workstation / --yolo mode is an explicit opt-in, never a silent default:
            // no configuration file has to state that it trusts the caller.
            let document = Document {
                mode: Mode::Workstation,
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

        // Destination policy is structural, not a second switch: a `[targets]`
        // table (even an empty one) closes the server to the names it lists,
        // and its absence leaves the caller naming a raw SSH destination.
        if document.targets.is_none() && document.mode != Mode::Workstation {
            document.targets = Some(BTreeMap::new());
        }

        let policy = resolve_selection(&mut document, capabilities, yolo, &base, &env)?;
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
        if let Some(targets) = &document.targets {
            validate_targets(targets)?;
        }
        validate_automation(
            document.controller.workspace_root.as_deref(),
            &document.automation,
            document.targets.as_ref(),
        )?;
        let mut bindings = Bindings::compile_with_mode(
            document.tools,
            &document.selection.allow,
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
                    .map_err(|e| invalid("catalog", e.reason()))?;
                let names: Vec<String> = if yolo {
                    catalog
                        .yolo_tool_names(include_lab)
                        .map(str::to_owned)
                        .collect()
                } else {
                    catalog
                        .workstation_tool_names()
                        .map(str::to_owned)
                        .collect()
                };
                for name in names {
                    if bindings.entries().any(|(_, b)| b.name == name) {
                        continue;
                    }
                    let entry = if yolo {
                        catalog
                            .load_yolo_entry(&name, include_lab)
                            .map_err(|e| invalid("catalog", e.reason()))?
                    } else {
                        catalog
                            .load_workstation_entry(&name)
                            .map_err(|e| invalid("catalog", e.reason()))?
                    };
                    match entry {
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
                                name,
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
                                name,
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
            targets: document.targets,
            builtins: document.selection.builtins,
            require_preview: document.require_preview,
            bindings,
            automation: document.automation,
            policy,
            yolo,
        })
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
        assert_eq!(error.field, "config");
        assert!(!error.to_string().contains("private-old-setting"));
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
                yolo: false,
                include_lab: false,
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
                    yolo: false,
                    include_lab: false,
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
                    yolo: false,
                    include_lab: false,
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
                    yolo: false,
                    include_lab: false,
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
    use crate::reply::ErrorCode;

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
                yolo: false,
                include_lab: false,
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
[selection]
allow = ["observe", "other"]
deny = ["other"]
[targets.one]
ssh_host = "ordinary-one"
selection = {{ allow = ["observe"] }}
[targets.two]
ssh_host = "ordinary-two"
selection = {{ allow = ["other"] }}
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
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            config
                .resolve_binding("two", disabled)
                .err()
                .unwrap()
                .code(),
            ErrorCode::PolicyDenied
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
[selection]
allow = ["observe"]
[targets.one]
ssh_host = "ordinary-one"
selection = {{}}
[targets.two]
ssh_host = "ordinary-two"
selection = {{ deny = ["observe"] }}
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
    fn presets_enable_installed_templates_and_a_version_pin_still_asserts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = crate::catalog::assets::Catalog::load(Some(&root)).unwrap();
        let pin = format!("version={:?}", catalog.manifest().version);
        let inert = load(&format!("[catalog]\nroot={root:?}\n{pin}\n")).unwrap();
        assert_eq!(inert.bindings.entries().count(), 0);
        assert!(!inert.automation.required);
        // A preset names installed templates; the definitions come from the
        // catalog with an absolute payload source, never from the config. These
        // three templates carry no site policy, so they need no overrides.
        // The health templates run through the automation authority, which the
        // site must configure (and provision separately) exactly as before.
        let text = format!(
            "capabilities = {{ named = true }}\n[selection]\npresets=['linux-health']\n[catalog]\nroot={root:?}\n{pin}\n[targets.one]\nssh_host='one'\n[automation.targets.one]\ndestination='one'\npython='/usr/bin/python3'\n"
        );
        let config = load(&text).unwrap();
        let enabled: Vec<_> = config
            .bindings
            .entries()
            .filter(|(id, _)| config.binding_enabled(*id))
            .map(|(_, binding)| binding.name.as_str())
            .collect();
        assert_eq!(
            enabled,
            ["observe_cpu", "observe_memory", "observe_pressure"]
        );
        assert!(
            config
                .bindings
                .entries()
                .all(|(_, binding)| !binding.payload_activated()),
            "installed definitions must not be pre-activated"
        );
        assert!(load(&text.replace(&pin, "version='unreviewed-upgrade'")).is_err());
        // Without a pin the installed inventory is used as-is.
        assert!(load(&text.replace(&pin, "")).is_ok());
        assert!(load(&text.replace("linux-health", "unknown-preset")).is_err());
    }

    #[test]
    fn a_site_overlay_alone_selects_the_catalog_template() {
        // A `[tools.<name>]` table without `execution` is site policy, not a
        // local definition: naming the tool must still load the catalog and
        // materialise the installed definition with the overlay merged in.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let config = load(&format!(
            "capabilities = {{ named = true }}\n[selection]\nallow=['observe_cpu']\n[catalog]\nroot={root:?}\n[targets.one]\nssh_host='one'\n[automation.targets.one]\ndestination='one'\npython='/usr/bin/python3'\n[tools.observe_cpu]\nlimits = {{ timeout_secs = 30 }}\n"
        ))
        .unwrap();
        let (id, binding) = config.bindings.entries().next().unwrap();
        assert_eq!(binding.name, "observe_cpu");
        assert!(config.binding_enabled(id));
        // Without a pinned root the environment's catalog root is used.
        let text = "capabilities = { named = true }\n[selection]\nallow=['observe_cpu']\n[targets.one]\nssh_host='one'\n[automation.targets.one]\ndestination='one'\npython='/usr/bin/python3'\n[tools.observe_cpu]\nlimits = { timeout_secs = 30 }\n";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("site.toml");
        std::fs::write(&path, text).unwrap();
        let config = Config::load_with(
            Cli {
                config: Some(path),
                ssh_config: None,
                ssh: Some(std::env::current_exe().unwrap()),
                command: None,
                workstation: false,
                yolo: false,
                include_lab: false,
            },
            directory.path(),
            |key| (key == "ESTUS_CATALOG_ROOT").then(|| root.as_os_str().to_owned()),
        )
        .unwrap();
        assert!(
            config
                .bindings
                .entries()
                .any(|(id, b)| b.name == "observe_cpu" && config.binding_enabled(id))
        );
    }
}
