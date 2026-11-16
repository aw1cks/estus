//! Installed catalog discovery and explicit offline authoring; never target execution.
use std::collections::BTreeSet;
use std::fs::{DirBuilder, File, Metadata, OpenOptions};
use std::io::{Read, Seek, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::{catalog_assets::Catalog, config::Config};

#[derive(Debug)]
enum Failure {
    Code {
        code: &'static str,
        phase: Option<&'static str>,
    },
    Config(crate::config::ConfigError),
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self::Code { code, phase: None }
    }
}

impl From<crate::config::ConfigError> for Failure {
    fn from(error: crate::config::ConfigError) -> Self {
        Self::Config(error)
    }
}

impl Failure {
    fn publish(self, operation: &'static str) -> u8 {
        match self {
            Self::Config(error) => crate::audit::emit(&error.record()),
            Self::Code { code, phase } => crate::audit::emit(
                &json!({"event":"error","code":code,"phase":phase.unwrap_or(operation)}),
            ),
        }
        2
    }
}

#[derive(Args)]
pub(crate) struct CatalogArgs {
    /// Explicit installed asset directory; no fallback if it is invalid.
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    command: CatalogCommand,
}

impl CatalogArgs {
    pub(crate) fn validate_global_options(
        &self,
        explicit_config: bool,
        explicit_ssh: bool,
    ) -> Result<(), &'static str> {
        let offline = matches!(
            &self.command,
            CatalogCommand::List { .. } | CatalogCommand::Export { .. }
        );
        if offline && (explicit_config || explicit_ssh) {
            return Err("catalog_option_not_applicable");
        }
        if !offline && explicit_config {
            return Err("catalog_config_site_conflict");
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// List bundled templates and presets without SSH or Ansible.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Explain resolved named-tool exposure without connecting or verifying runtimes.
    Inspect {
        #[arg(long)]
        site: PathBuf,
    },
    /// Export inert templates, role sources and exact overlays for operator review.
    Export {
        #[arg(long = "tool", required_unless_present = "presets")]
        tools: Vec<String>,
        #[arg(long = "preset", required_unless_present = "tools")]
        presets: Vec<String>,
        /// New private directory; existing paths are never replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Import reviewed exported definitions using the site's selected runtimes.
    Prepare {
        /// Site configuration supplying targets, identities and optional runtimes.
        #[arg(long)]
        site: PathBuf,
        /// Operator-reviewed tools.toml from export, including reviewed role paths.
        #[arg(long)]
        definitions: PathBuf,
        /// Optional logical target allowlist applied to the prepared definitions.
        #[arg(long = "target")]
        targets: Vec<String>,
        /// New private directory containing estus.toml, overlays and snapshots.
        #[arg(long)]
        output: PathBuf,
        /// Overall offline preparation deadline, including all selected imports.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout_secs: u64,
    },
}

struct PrivateOutput {
    parent: File,
    directory: File,
    path: PathBuf,
    keep: bool,
}

impl PrivateOutput {
    fn create(path: &Path) -> Result<Self, &'static str> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = parent
            .canonicalize()
            .map_err(|_| "catalog_output_unavailable")?;
        let path = parent.join(path.file_name().ok_or("catalog_output_unavailable")?);
        let parent = trusted_output_parent(&parent)?;
        let name = path.file_name().ok_or("catalog_output_unavailable")?;
        nix::sys::stat::mkdirat(&parent, name, nix::sys::stat::Mode::S_IRWXU)
            .map_err(|_| "catalog_output_exists_or_unavailable")?;
        let directory = File::from(
            nix::fcntl::openat(
                &parent,
                name,
                nix::fcntl::OFlag::O_RDONLY
                    | nix::fcntl::OFlag::O_DIRECTORY
                    | nix::fcntl::OFlag::O_NOFOLLOW
                    | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|_| "catalog_output_unavailable")?,
        );
        Ok(Self {
            path,
            parent,
            directory,
            keep: false,
        })
    }

    fn finish(mut self) {
        self.keep = true;
    }
}

impl Drop for PrivateOutput {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        // A pathname is not ownership. Do not recursively remove a replacement
        // directory after an ancestor rename, even in our same-UID trust model.
        let same = |left: &Metadata, right: &Metadata| {
            left.dev() == right.dev() && left.ino() == right.ino()
        };
        let intact = (|| {
            let current_parent = trusted_output_parent(self.path.parent()?).ok()?;
            if !same(
                &current_parent.metadata().ok()?,
                &self.parent.metadata().ok()?,
            ) {
                return None;
            }
            let current = std::fs::symlink_metadata(&self.path).ok()?;
            (current.is_dir() && same(&current, &self.directory.metadata().ok()?)).then_some(())
        })()
        .is_some();
        if intact {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn trusted_output_metadata(metadata: &Metadata) -> bool {
    let owner = metadata.uid();
    let mode = metadata.mode();
    (owner == 0 || owner == nix::unistd::geteuid().as_raw())
        && (mode & 0o022 == 0 || owner == 0 && mode & 0o1000 != 0)
}

fn trusted_output_parent(path: &Path) -> Result<File, &'static str> {
    let mut directory = File::open("/").map_err(|_| "catalog_output_unavailable")?;
    for component in path.components() {
        let std::path::Component::Normal(name) = component else {
            if component == std::path::Component::RootDir {
                continue;
            }
            return Err("catalog_output_untrusted_parent");
        };
        directory = File::from(
            nix::fcntl::openat(
                &directory,
                name,
                nix::fcntl::OFlag::O_RDONLY
                    | nix::fcntl::OFlag::O_DIRECTORY
                    | nix::fcntl::OFlag::O_NOFOLLOW
                    | nix::fcntl::OFlag::O_CLOEXEC,
                nix::sys::stat::Mode::empty(),
            )
            .map_err(|_| "catalog_output_untrusted_parent")?,
        );
        if !trusted_output_metadata(
            &directory
                .metadata()
                .map_err(|_| "catalog_output_unavailable")?,
        ) {
            return Err("catalog_output_untrusted_parent");
        }
    }
    Ok(directory)
}

fn read_toml(path: &Path) -> Result<toml::Table, Failure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "catalog_definition_unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "catalog_definition_unavailable")?
        .is_file()
    {
        return Err("catalog_definition_unavailable".into());
    }
    let mut text = String::new();
    file.take(1_048_577)
        .read_to_string(&mut text)
        .map_err(|_| "catalog_definition_invalid")?;
    if text.len() > 1_048_576 {
        return Err("catalog_definition_limit".into());
    }
    toml::from_str(&text)
        .map_err(|error| crate::config::ConfigError::toml_syntax(&text, &error).into())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<File, &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "catalog_output_unavailable")?;
    file.write_all(bytes)
        .map_err(|_| "catalog_output_unavailable")?;
    Ok(file)
}

fn overlay(definition: &toml::Value) -> Result<Value, &'static str> {
    let table = definition.as_table().ok_or("catalog_definition_invalid")?;
    let mut value = serde_json::Map::new();
    for key in ["input_schema", "fixed_args", "input_map"] {
        let field = table.get(key).ok_or("catalog_definition_invalid")?;
        value.insert(
            key.to_owned(),
            serde_json::to_value(field).map_err(|_| "catalog_definition_invalid")?,
        );
    }
    let value = Value::Object(value);
    crate::role_import::validate_overlay(&value)?;
    Ok(value)
}

fn selected(
    catalog: &Catalog,
    tools: Vec<String>,
    presets: Vec<String>,
) -> Result<BTreeSet<String>, &'static str> {
    let mut names = BTreeSet::new();
    let mut explicit = BTreeSet::new();
    for name in tools {
        if !catalog.manifest().tools.contains_key(&name) || !explicit.insert(name.clone()) {
            return Err("catalog_tool_unknown_or_duplicate");
        }
        names.insert(name);
    }
    let mut seen = BTreeSet::new();
    for preset in presets {
        if !seen.insert(preset.clone()) {
            return Err("catalog_preset_duplicate");
        }
        let members = catalog
            .manifest()
            .presets
            .get(&preset)
            .ok_or("catalog_preset_unknown")?;
        names.extend(members.iter().cloned());
    }
    if names.is_empty() || names.len() > 32 {
        return Err("catalog_selection_limit");
    }
    Ok(names)
}

fn template_metadata(template: &crate::catalog_assets::Template) -> Value {
    json!({
        "qualification":template.qualification,
        "policy_required":template.policy_required,
        "requires":template.requires,
    })
}

fn describe(catalog: &Catalog, as_json: bool) -> Result<Vec<u8>, &'static str> {
    let mut tools = Vec::with_capacity(catalog.manifest().tools.len());
    for (name, template) in &catalog.manifest().tools {
        let definition = catalog.definition(name)?;
        let description = definition
            .get("tools")
            .and_then(|v| v.get(name))
            .and_then(|v| v.get("description"))
            .and_then(toml::Value::as_str)
            .ok_or("catalog_definition_invalid")?;
        tools.push(json!({"name":name,"description":description,"qualification":template.qualification,"policy_required":template.policy_required,"requires":template.requires}));
    }
    if as_json {
        let mut bytes = serde_json::to_vec(&json!({"schema":catalog.manifest().schema,"version":catalog.manifest().version,"presets":catalog.manifest().presets,"tools":tools}))
            .map_err(|_| "catalog_output_invalid")?;
        bytes.push(b'\n');
        return Ok(bytes);
    }
    let mut text = format!(
        "Catalog {} — bundled templates, not automatically enabled\n",
        catalog.manifest().version
    );
    for (name, members) in &catalog.manifest().presets {
        text.push_str(&format!("preset {name}: {}\n", members.join(", ")));
    }
    for tool in tools {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t",
            tool["name"].as_str().ok_or("catalog_output_invalid")?,
            tool["qualification"]
                .as_str()
                .ok_or("catalog_output_invalid")?,
            if tool["policy_required"] == true {
                "site policy required"
            } else {
                "review before enabling"
            },
            tool["description"]
                .as_str()
                .ok_or("catalog_output_invalid")?
        ));
        for (index, requirement) in tool["requires"]
            .as_array()
            .ok_or("catalog_output_invalid")?
            .iter()
            .enumerate()
        {
            if index != 0 {
                text.push(',');
            }
            text.push_str(requirement.as_str().ok_or("catalog_output_invalid")?);
        }
        text.push('\n');
    }
    Ok(text.into_bytes())
}

fn export(
    catalog: &Catalog,
    tools: Vec<String>,
    presets: Vec<String>,
    path: &Path,
) -> Result<Value, &'static str> {
    let names = selected(catalog, tools, presets)?;
    let output = PrivateOutput::create(path)?;
    for directory in ["roles", "overlays", "snapshots"] {
        DirBuilder::new()
            .mode(0o700)
            .create(output.path.join(directory))
            .map_err(|_| "catalog_output_unavailable")?;
    }
    let mut definitions = toml::Table::new();
    let mut metadata = serde_json::Map::new();
    for name in &names {
        let template = catalog
            .manifest()
            .tools
            .get(name)
            .ok_or("catalog_tool_unknown")?;
        metadata.insert(name.clone(), template_metadata(template));
        let mut document = catalog.definition(name)?;
        let mut definition = document
            .get_mut("tools")
            .and_then(toml::Value::as_table_mut)
            .and_then(|tools| tools.remove(name))
            .ok_or("catalog_definition_invalid")?;
        let role = output.path.join("roles").join(name);
        catalog.copy_role(name, &role)?;
        let execution = definition
            .get_mut("execution")
            .and_then(toml::Value::as_table_mut)
            .ok_or("catalog_definition_invalid")?;
        execution.insert(
            "role_path".into(),
            role.to_str().ok_or("catalog_output_unavailable")?.into(),
        );
        execution.insert(
            "snapshot".into(),
            output
                .path
                .join("snapshots")
                .join(format!("{name}.json"))
                .to_str()
                .ok_or("catalog_output_unavailable")?
                .into(),
        );
        write_private(
            &output.path.join("overlays").join(format!("{name}.json")),
            &serde_json::to_vec_pretty(&overlay(&definition)?)
                .map_err(|_| "catalog_output_invalid")?,
        )?;
        definitions.insert(name.clone(), definition);
    }
    let mut document = toml::Table::new();
    document.insert("tools".into(), toml::Value::Table(definitions));
    let text = format!(
        "# INERT export. Review targets, fixed policies and role contents before prepare.\n{}",
        toml::to_string_pretty(&document).map_err(|_| "catalog_output_invalid")?
    );
    write_private(&output.path.join("tools.toml"), text.as_bytes())?;
    write_private(
        &output.path.join("catalog-selection.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":catalog.manifest().schema,"version":catalog.manifest().version,
            "scope":"catalog_templates","tools":metadata,
        }))
        .map_err(|_| "catalog_output_invalid")?,
    )?;
    let report = json!({"ok":true,"version":catalog.manifest().version,"tools":names,"enabled":false,"qualification_file":"catalog-selection.json"});
    output.finish();
    Ok(report)
}

fn absolute_path(value: &mut toml::Value, base: &Path) -> Result<(), &'static str> {
    let text = value.as_str().ok_or("catalog_definition_invalid")?;
    let path = Path::new(text);
    if !path.is_absolute() {
        *value = base
            .join(path)
            .to_str()
            .ok_or("catalog_definition_invalid")?
            .into();
    }
    Ok(())
}

fn preserve_site_paths(document: &mut toml::Table, base: &Path) -> Result<(), &'static str> {
    if let Some(ssh) = document.get_mut("ssh").and_then(toml::Value::as_table_mut) {
        for key in ["config_file", "executable"] {
            if let Some(value) = ssh.get_mut(key) {
                absolute_path(value, base)?;
            }
        }
    }
    if let Some(value) = document.get_mut("catalog").and_then(|v| v.get_mut("root")) {
        absolute_path(value, base)?;
    }
    if let Some(automation) = document
        .get_mut("automation")
        .and_then(toml::Value::as_table_mut)
    {
        if let Some(value) = automation.get_mut("runtime") {
            absolute_path(value, base)?;
        }
        if let Some(authorities) = automation
            .get_mut("authorities")
            .and_then(toml::Value::as_table_mut)
        {
            for (_, authority) in authorities.iter_mut() {
                for key in ["runtime", "ssh_config_file"] {
                    if let Some(value) = authority.get_mut(key) {
                        absolute_path(value, base)?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn prepare(
    catalog: Catalog,
    pin_root: bool,
    site: PathBuf,
    definitions: PathBuf,
    targets: Vec<String>,
    path: PathBuf,
    cli: crate::config::Cli,
    shutdown: CancellationToken,
) -> Result<Value, Failure> {
    let version = catalog.manifest().version.clone();
    let work = tokio::task::spawn_blocking(move || {
        let site = if site.is_absolute() {
            site
        } else {
            std::env::current_dir()
                .map_err(|_| "catalog_definition_unavailable")?
                .join(site)
        };
        let mut document = read_toml(&site)?;
        preserve_site_paths(
            &mut document,
            site.parent().ok_or("catalog_definition_invalid")?,
        )?;
        let mut exported = read_toml(&definitions)?;
        if exported.len() != 1 {
            return Err("catalog_definition_invalid".into());
        }
        let tools = exported
            .remove("tools")
            .and_then(|v| v.as_table().cloned())
            .ok_or("catalog_definition_invalid")?;
        if tools.is_empty() || tools.len() > 32 {
            return Err("catalog_selection_limit".into());
        }
        let output = PrivateOutput::create(&path)?;
        for directory in ["overlays", "snapshots"] {
            DirBuilder::new()
                .mode(0o700)
                .create(output.path.join(directory))
                .map_err(|_| "catalog_output_unavailable")?;
        }
        let configured = document
            .entry("tools")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or("catalog_definition_invalid")?;
        let mut imports = Vec::with_capacity(tools.len());
        let mut reviewed_bundle: Option<PathBuf> = None;
        let mut authoring_parent: Option<PathBuf> = None;
        for (name, mut definition) in tools {
            if !catalog.manifest().tools.contains_key(&name) || configured.contains_key(&name) {
                return Err("catalog_tool_unknown_or_collision".into());
            }
            if !targets.is_empty() {
                definition
                    .as_table_mut()
                    .ok_or("catalog_definition_invalid")?
                    .insert(
                        "targets".into(),
                        toml::Value::Array(targets.iter().map(|s| s.as_str().into()).collect()),
                    );
            }
            let execution = definition
                .get_mut("execution")
                .and_then(toml::Value::as_table_mut)
                .ok_or("catalog_definition_invalid")?;
            if execution.get("kind").and_then(toml::Value::as_str) != Some("ansible_role") {
                return Err("catalog_definition_invalid".into());
            }
            let role_path = PathBuf::from(
                execution
                    .get("role_path")
                    .and_then(toml::Value::as_str)
                    .ok_or("catalog_definition_invalid")?,
            );
            if !role_path.is_absolute() {
                return Err("catalog_definition_invalid".into());
            }
            let snapshot = output.path.join("snapshots").join(format!("{name}.json"));
            let parent =
                std::fs::canonicalize(role_path.parent().ok_or("catalog_definition_invalid")?)
                    .map_err(|_| "catalog_definition_invalid")?;
            if authoring_parent
                .as_ref()
                .is_some_and(|selected| selected != &parent)
            {
                return Err("catalog_role_search_root_mismatch".into());
            }
            let root = match &reviewed_bundle {
                Some(root) => root,
                None => {
                    let root = crate::role_import::author_bundle(&name, &role_path, &snapshot)?;
                    authoring_parent = Some(parent);
                    reviewed_bundle.insert(root)
                }
            };
            let role_path = root.join(&name);
            execution.insert(
                "role_path".into(),
                role_path
                    .to_str()
                    .ok_or("catalog_output_unavailable")?
                    .into(),
            );
            execution.insert(
                "snapshot".into(),
                snapshot
                    .to_str()
                    .ok_or("catalog_output_unavailable")?
                    .into(),
            );
            let overlay_path = output.path.join("overlays").join(format!("{name}.json"));
            write_private(
                &overlay_path,
                &serde_json::to_vec(&overlay(&definition)?)
                    .map_err(|_| "catalog_output_invalid")?,
            )?;
            let authority = definition
                .get("authority")
                .and_then(toml::Value::as_str)
                .ok_or("catalog_definition_invalid")?
                .to_owned();
            configured.insert(name.clone(), definition);
            imports.push((name, role_path, overlay_path, snapshot, authority));
        }
        document
            .entry("profile")
            .or_insert_with(|| "actions-only".into());
        if !document.contains_key("enabled_tools") && !document.contains_key("tool_presets") {
            document.insert(
                "enabled_tools".into(),
                toml::Value::Array(
                    imports
                        .iter()
                        .map(|(name, ..)| name.as_str().into())
                        .collect(),
                ),
            );
        }
        let catalog_config = document
            .entry("catalog")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or("catalog_definition_invalid")?;
        if let Some(value) = catalog_config.get("version")
            && value.as_str() != Some(version.as_str())
        {
            return Err("catalog_version_mismatch".into());
        }
        catalog_config.insert("version".into(), version.into());
        if pin_root {
            catalog_config.insert(
                "root".into(),
                catalog
                    .root()
                    .to_str()
                    .ok_or("catalog_definition_invalid")?
                    .into(),
            );
        }
        let config_path = output.path.join("estus.toml");
        let mut config_file = write_private(
            &config_path,
            toml::to_string_pretty(&document)
                .map_err(|_| "catalog_output_invalid")?
                .as_bytes(),
        )?;
        let config = Config::from_file_with_catalog_root(cli, config_path, None)?;
        // Publish the effective absolute SSH selection, not the lower-priority
        // site values. Keep the exclusively created file handle while updating
        // this still-private output; failure drops the complete owned directory.
        let ssh = document
            .entry("ssh")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or("catalog_definition_invalid")?;
        ssh.insert(
            "executable".into(),
            config
                .ssh_executable()
                .to_str()
                .ok_or("catalog_ssh_path_not_utf8")?
                .into(),
        );
        if let Some(path) = config.ssh_config() {
            ssh.insert(
                "config_file".into(),
                path.to_str().ok_or("catalog_ssh_path_not_utf8")?.into(),
            );
        }
        let text = toml::to_string_pretty(&document).map_err(|_| "catalog_output_invalid")?;
        config_file
            .rewind()
            .map_err(|_| "catalog_output_unavailable")?;
        config_file
            .set_len(0)
            .map_err(|_| "catalog_output_unavailable")?;
        config_file
            .write_all(text.as_bytes())
            .map_err(|_| "catalog_output_unavailable")?;
        Ok::<_, Failure>((output, config, imports))
    })
    .await
    .map_err(|_| "catalog_output_unavailable")??;
    let (output, config, imports) = work;
    for (name, role_path, overlay, snapshot, authority) in &imports {
        if shutdown.is_cancelled() {
            return Err("cancelled".into());
        }
        let reference = config.catalog_runtime(authority)?;
        let report = crate::role_import::perform_with_reference(
            &config,
            crate::role_import::Command::Import(crate::role_import::ImportArgs::reviewed(
                name.clone(),
                role_path.clone(),
                snapshot.clone(),
                overlay.clone(),
            )),
            None,
            shutdown.clone(),
            reference,
        )
        .await;
        if let Some((code, phase)) = report.failure() {
            return Err(Failure::Code {
                code,
                phase: Some(phase),
            });
        }
    }
    if shutdown.is_cancelled() {
        return Err("cancelled".into());
    }
    let report = json!({"ok":true,"prepared":imports.len(),"activated":false});
    output.finish();
    Ok(report)
}

pub(crate) async fn run(
    args: CatalogArgs,
    cli: crate::config::Cli,
    shutdown: CancellationToken,
) -> u8 {
    let phase = match &args.command {
        CatalogCommand::List { .. } => "catalog_list",
        CatalogCommand::Inspect { .. } => "catalog_inspection",
        CatalogCommand::Export { .. } => "catalog_export",
        CatalogCommand::Prepare { .. } => "catalog_preparation",
    };
    let explicit_root = args.root.is_some();
    let root = args.root;
    let command = args.command;
    let loaded = tokio::task::spawn_blocking(move || {
        let root = if root.is_some() {
            root
        } else {
            match &command {
                CatalogCommand::Inspect { site } | CatalogCommand::Prepare { site, .. } => {
                    let absolute = if site.is_absolute() {
                        site.to_path_buf()
                    } else {
                        std::env::current_dir()
                            .map_err(|_| "catalog_definition_unavailable")?
                            .join(site)
                    };
                    let document = read_toml(&absolute)?;
                    document
                        .get("catalog")
                        .and_then(|v| v.get("root"))
                        .map(|v| {
                            let path =
                                PathBuf::from(v.as_str().ok_or("catalog_definition_invalid")?);
                            Ok::<_, &'static str>(if path.is_absolute() {
                                path
                            } else {
                                absolute
                                    .parent()
                                    .ok_or("catalog_definition_invalid")?
                                    .join(path)
                            })
                        })
                        .transpose()?
                }
                _ => None,
            }
        };
        Catalog::load(root.as_deref())
            .map(|catalog| (catalog, command))
            .map_err(Failure::from)
    })
    .await;
    let result = match loaded {
        Ok(Ok((catalog, command))) if !shutdown.is_cancelled() => match command {
            CatalogCommand::List { json } => {
                match tokio::task::spawn_blocking(move || describe(&catalog, json)).await {
                    Ok(value) => value.map_err(Failure::from),
                    Err(_) => Err("catalog_unavailable".into()),
                }
            }
            CatalogCommand::Inspect { site } => {
                let root = explicit_root.then(|| catalog.root().to_path_buf());
                match tokio::task::spawn_blocking(move || inspect(site, root, cli, &catalog)).await
                {
                    Ok(value) => value.and_then(|v| {
                        serde_json::to_vec(&v).map_err(|_| Failure::from("catalog_output_invalid"))
                    }),
                    Err(_) => Err("catalog_definition_invalid".into()),
                }
            }
            CatalogCommand::Export {
                tools,
                presets,
                output,
            } => {
                match tokio::task::spawn_blocking(move || export(&catalog, tools, presets, &output))
                    .await
                {
                    Ok(Ok(value)) => serde_json::to_vec(&value)
                        .map_err(|_| Failure::from("catalog_output_invalid")),
                    Ok(Err(error)) => Err(error.into()),
                    Err(_) => Err("catalog_output_unavailable".into()),
                }
            }
            CatalogCommand::Prepare {
                site,
                definitions,
                targets,
                output,
                timeout_secs,
            } => {
                let operation = prepare(
                    catalog,
                    explicit_root,
                    site,
                    definitions,
                    targets,
                    output,
                    cli,
                    shutdown.clone(),
                );
                tokio::pin!(operation);
                tokio::select! {
                    result = &mut operation => result,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)) => {
                        shutdown.cancel();
                        let _ = operation.as_mut().await;
                        Err("catalog_prepare_timeout".into())
                    }
                }
                .and_then(|v| {
                    serde_json::to_vec(&v).map_err(|_| Failure::from("catalog_output_invalid"))
                })
            }
        },
        Ok(Err(error)) => Err(error),
        Ok(Ok(_)) => Err("cancelled".into()),
        Err(_) => Err("catalog_unavailable".into()),
    };
    match result {
        Ok(mut bytes) if !shutdown.is_cancelled() => {
            if bytes.last() != Some(&b'\n') {
                bytes.push(b'\n');
            }
            if tokio::io::stdout().write_all(&bytes).await.is_ok() {
                0
            } else {
                2
            }
        }
        Ok(_) => Failure::from("cancelled").publish(phase),
        Err(error) => error.publish(phase),
    }
}

fn inspect(
    site: PathBuf,
    root: Option<PathBuf>,
    cli: crate::config::Cli,
    catalog: &Catalog,
) -> Result<Value, Failure> {
    let config = Config::from_file_with_catalog_root(cli, site, root)?;
    let tools: Vec<_> = config
        .bindings()
        .entries()
        .map(|(id, binding)| {
            let targets: Vec<_> = binding
                .targets
                .iter()
                .map(|host| {
                    let permitted = if binding.is_automation() {
                        config.automation_target(id, host).is_ok()
                    } else {
                        config.resolve_binding(host, id).is_ok()
                    };
                    json!({"name":host,"permitted":permitted})
                })
                .collect();
            let template = catalog
                .manifest()
                .tools
                .get(&binding.name)
                .map(template_metadata)
                .unwrap_or_else(|| json!({"qualification":"unqualified"}));
            json!({
                "name":binding.name,"enabled":config.binding_enabled(id),
                "targets":targets,"catalog_template":template,
                "executor":binding.executor_kind(),"authority":binding.public_authority(),
                "execution_location":binding.execution_location(),
                "trusted_controller_code":binding.trusted_controller_code(),
                "restriction_boundary":binding.restriction_boundary(),
            })
        })
        .collect();
    Ok(
        json!({"scope":"named_tools","global_native_execution":config.tool_enabled(crate::config::ToolId::Exec),
        "global_native_file_read":config.tool_enabled(crate::config::ToolId::ReadFile),
        "global_native_file_write":config.tool_enabled(crate::config::ToolId::WriteFile),
        "runtime_verification":"not_performed","qualification_scope":"catalog_template","tools":tools,
        "deployment_boundary":{
            "mcp":"request_policy",
            "same_identity_arbitrary_execution":"outside_restriction",
            "service_account_separation":"operator_managed_not_observed",
            "sandbox":"not_provided_by_estus",
        }}),
    )
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[test]
    fn cleanup_does_not_follow_a_replaced_output_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let parent = root.join("parent");
        let victim = root.join("victim");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&victim).unwrap();
        std::fs::create_dir(victim.join("export")).unwrap();
        std::fs::write(victim.join("export/sentinel"), b"unrelated").unwrap();
        let output = PrivateOutput::create(&parent.join("export")).unwrap();
        std::fs::rename(&parent, root.join("moved-parent")).unwrap();
        std::os::unix::fs::symlink(&victim, &parent).unwrap();
        drop(output);
        assert_eq!(
            std::fs::read(victim.join("export/sentinel")).unwrap(),
            b"unrelated"
        );
    }

    #[test]
    fn output_rejects_a_shared_writable_nonsticky_parent() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(PrivateOutput::create(&root.path().join("export")).is_err());
        assert!(!root.path().join("export").exists());
    }
}
