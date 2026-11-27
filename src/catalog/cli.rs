//! Installed catalog discovery, inert export for operator review, and writing
//! the catalog bundled in this binary to disk. Site configuration enables
//! catalog tools directly; nothing here approves anything.
use std::collections::BTreeSet;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use crate::catalog::assets::Catalog;

#[derive(Debug)]
enum Failure {
    Code(&'static str),
    Config(crate::config::ConfigError),
    Catalog(crate::catalog::assets::CatalogError),
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self::Code(code)
    }
}

impl From<crate::catalog::assets::CatalogError> for Failure {
    fn from(error: crate::catalog::assets::CatalogError) -> Self {
        Self::Catalog(error)
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
            Self::Code(code) => {
                crate::audit::emit(&json!({"event":"error","code":code,"phase":operation}))
            }
            Self::Catalog(error) => {
                let mut record = error.payload();
                record["phase"] = json!(operation);
                crate::audit::emit(&record)
            }
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
        // Both subcommands are offline; a site or SSH selection cannot apply.
        if explicit_config || explicit_ssh {
            return Err("catalog_option_not_applicable");
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
    /// Copy inert templates and payload sources out for operator review.
    Export {
        #[arg(long = "tool", required_unless_present = "presets")]
        tools: Vec<String>,
        #[arg(long = "preset", required_unless_present = "tools")]
        presets: Vec<String>,
        /// New directory; existing paths are never replaced.
        #[arg(long)]
        output: PathBuf,
    },
    /// Write the catalog bundled in this binary to disk, so the server can find it.
    Install {
        /// Directory to create. Defaults to the place the server looks first,
        /// `<prefix>/share/estus/catalog` for a binary at `<prefix>/bin/estus`.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Replace an existing catalog that differs from this build's, for
        /// example after an upgrade.
        #[arg(long)]
        replace: bool,
    },
}

fn selected(
    catalog: &Catalog,
    tools: Vec<String>,
    presets: Vec<String>,
) -> Result<BTreeSet<String>, Failure> {
    let mut names = BTreeSet::new();
    let mut explicit = BTreeSet::new();
    for name in tools {
        if !catalog.manifest().tools.contains_key(&name) || !explicit.insert(name.clone()) {
            return Err(Failure::Code("catalog_tool_unknown_or_duplicate"));
        }
        names.insert(name);
    }
    let mut seen = BTreeSet::new();
    for preset in presets {
        if !seen.insert(preset.clone()) {
            return Err(Failure::Code("catalog_preset_duplicate"));
        }
        let members = catalog
            .manifest()
            .presets
            .get(&preset)
            .ok_or(Failure::Code("catalog_preset_unknown"))?;
        names.extend(members.iter().cloned());
    }
    if names.is_empty() || names.len() > 256 {
        return Err(Failure::Code("catalog_selection_limit"));
    }
    Ok(names)
}

fn template_metadata(template: &super::assets::Template) -> Value {
    json!({
        "qualification":template.qualification,
        "policy_required":template.policy_required,
        "requires":template.requires,
        "executor":template.executor,
    })
}

fn describe(catalog: &Catalog, as_json: bool) -> Result<Vec<u8>, Failure> {
    let mut tools = Vec::with_capacity(catalog.manifest().tools.len());
    for (name, template) in &catalog.manifest().tools {
        let definition = catalog.definition(name)?;
        let description = definition
            .get("tools")
            .and_then(|v| v.get(name))
            .and_then(|v| v.get("description"))
            .and_then(toml::Value::as_str)
            .ok_or(Failure::Code("catalog_definition_invalid"))?;
        tools.push(json!({"name":name,"description":description,"qualification":template.qualification,"policy_required":template.policy_required,"requires":template.requires}));
    }
    if as_json {
        let mut bytes = serde_json::to_vec(&json!({"schema":catalog.manifest().schema,"version":catalog.manifest().version,"presets":catalog.manifest().presets,"tools":tools}))
            .map_err(|_| Failure::Code("catalog_output_invalid"))?;
        bytes.push(b'\n');
        return Ok(bytes);
    }
    let mut text = format!(
        "Catalog {} — bundled templates; a site configuration enables them by name\n",
        catalog.manifest().version
    );
    for (name, members) in &catalog.manifest().presets {
        text.push_str(&format!("preset {name}: {}\n", members.join(", ")));
    }
    for tool in tools {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t",
            tool["name"]
                .as_str()
                .ok_or(Failure::Code("catalog_output_invalid"))?,
            tool["qualification"]
                .as_str()
                .ok_or(Failure::Code("catalog_output_invalid"))?,
            if tool["policy_required"] == true {
                "review fixed policy before enabling"
            } else {
                "ready to enable"
            },
            tool["description"]
                .as_str()
                .ok_or(Failure::Code("catalog_output_invalid"))?
        ));
        for (index, requirement) in tool["requires"]
            .as_array()
            .ok_or(Failure::Code("catalog_output_invalid"))?
            .iter()
            .enumerate()
        {
            if index != 0 {
                text.push(',');
            }
            text.push_str(
                requirement
                    .as_str()
                    .ok_or(Failure::Code("catalog_output_invalid"))?,
            );
        }
        text.push('\n');
    }
    Ok(text.into_bytes())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Failure> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    #[cfg(windows)]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|_| Failure::Code("catalog_output_unavailable"))?;
    file.write_all(bytes)
        .map_err(|_| Failure::Code("catalog_output_unavailable"))
}

fn export(
    catalog: &Catalog,
    tools: Vec<String>,
    presets: Vec<String>,
    path: &Path,
) -> Result<Value, Failure> {
    let names = selected(catalog, tools, presets)?;
    #[cfg_attr(windows, allow(unused_mut))]
    let mut dir_builder = DirBuilder::new();
    #[cfg(unix)]
    dir_builder.mode(0o700);
    dir_builder
        .create(path)
        .map_err(|_| Failure::Code("catalog_output_exists_or_unavailable"))?;
    let result = (|| {
        #[cfg_attr(windows, allow(unused_mut))]
        let mut payloads_builder = DirBuilder::new();
        #[cfg(unix)]
        payloads_builder.mode(0o700);
        payloads_builder
            .create(path.join("payloads"))
            .map_err(|_| Failure::Code("catalog_output_unavailable"))?;
        let mut definitions = toml::Table::new();
        let mut metadata = serde_json::Map::new();
        for name in &names {
            let template = catalog
                .manifest()
                .tools
                .get(name)
                .ok_or(Failure::Code("catalog_tool_unknown"))?;
            metadata.insert(name.clone(), template_metadata(template));
            let mut document = catalog.definition(name)?;
            let mut definition = document
                .get_mut("tools")
                .and_then(toml::Value::as_table_mut)
                .and_then(|tools| tools.remove(name))
                .ok_or(Failure::Code("catalog_definition_invalid"))?;
            if let super::assets::Executor::NativePayload { .. } = &template.executor {
                let bundle = path.join("payloads").join(name);
                catalog.copy_assets(name, &bundle)?;
                definition
                    .get_mut("execution")
                    .and_then(toml::Value::as_table_mut)
                    .ok_or(Failure::Code("catalog_definition_invalid"))?
                    .insert(
                        "source".into(),
                        bundle
                            .join("collector.py")
                            .to_str()
                            .ok_or(Failure::Code("catalog_output_unavailable"))?
                            .into(),
                    );
            }
            definitions.insert(name.clone(), definition);
        }
        let mut document = toml::Table::new();
        document.insert("tools".into(), toml::Value::Table(definitions));
        let text = format!(
            "# Inert definitions for review: tool tables only, with no site policy.\n\
             # Copy each [tools.<name>] table into your site configuration and add\n\
             # targets, authority and the fixed_args/constraints allowlists it needs\n\
             # (or write a [tools.<name>] overlay that restates them, without execution).\n{}",
            toml::to_string_pretty(&document)
                .map_err(|_| Failure::Code("catalog_output_invalid"))?
        );
        write_new(&path.join("tools.toml"), text.as_bytes(), 0o600)?;
        write_new(
            &path.join("catalog-selection.json"),
            &serde_json::to_vec_pretty(&json!({
                "schema":catalog.manifest().schema,"version":catalog.manifest().version,
                "scope":"catalog_templates","tools":metadata,
            }))
            .map_err(|_| Failure::Code("catalog_output_invalid"))?,
            0o600,
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(path);
        return Err(error);
    }
    Ok(
        json!({"ok":true,"version":catalog.manifest().version,"tools":names,"enabled":false,"qualification_file":"catalog-selection.json"}),
    )
}

/// True when `root` holds exactly the bundled files, byte for byte, and
/// nothing else. Symlinks and special files never match.
fn installed_matches(root: &Path, files: &[(&str, &[u8])]) -> bool {
    fn count(directory: &Path, total: &mut usize) -> bool {
        let Ok(entries) = fs::read_dir(directory) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => {
                    if !count(&entry.path(), total) {
                        return false;
                    }
                }
                Ok(kind) if kind.is_file() => *total += 1,
                _ => return false,
            }
        }
        true
    }
    let mut total = 0;
    if !count(root, &mut total) || total != files.len() {
        return false;
    }
    files.iter().all(|(relative, bytes)| {
        let path = root.join(relative);
        fs::symlink_metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() == bytes.len() as u64)
            && fs::read(&path).is_ok_and(|found| found == *bytes)
    })
}

/// Write the bundled catalog next to its destination and rename it into place,
/// so a failure never leaves a half-written catalog behind.
fn install(dir: Option<PathBuf>, replace: bool) -> Result<Value, Failure> {
    let unavailable = || Failure::Code("catalog_install_unavailable");
    let target = match dir {
        Some(dir) => dir,
        None => super::assets::default_install_dir()
            .ok_or(Failure::Code("catalog_install_dir_unknown"))?,
    };
    let files = super::embedded::files();
    let summary = |installed: bool| {
        json!({
            "ok": true,
            "installed": installed,
            "dir": target.display().to_string(),
            "version": super::embedded::version(),
            "files": files.len(),
        })
    };

    let existing = match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.is_dir() => true,
        Ok(_) => return Err(Failure::Code("catalog_path_unsafe")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => return Err(unavailable()),
    };
    if existing {
        if installed_matches(&target, files) {
            return Ok(summary(false));
        }
        if !replace {
            return Err(Failure::Code("catalog_install_exists"));
        }
    }

    let parent = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut parent_builder = DirBuilder::new();
    parent_builder.recursive(true);
    #[cfg(unix)]
    parent_builder.mode(0o755);
    parent_builder.create(parent).map_err(|_| unavailable())?;
    let stamp = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    );
    let staging = parent.join(format!(".estus-catalog-{stamp}"));
    #[cfg_attr(windows, allow(unused_mut))]
    let mut staging_builder = DirBuilder::new();
    #[cfg(unix)]
    staging_builder.mode(0o755);
    staging_builder
        .create(&staging)
        .map_err(|_| unavailable())?;
    let staged = (|| -> Result<(), Failure> {
        for (relative, bytes) in files {
            let path = staging.join(relative);
            if let Some(directory) = path.parent() {
                let mut sub_builder = DirBuilder::new();
                sub_builder.recursive(true);
                #[cfg(unix)]
                sub_builder.mode(0o755);
                sub_builder.create(directory).map_err(|_| unavailable())?;
            }
            write_new(&path, bytes, 0o644).map_err(|_| unavailable())?;
        }
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    let swapped = if existing {
        let previous = parent.join(format!(".estus-catalog-old-{stamp}"));
        fs::rename(&target, &previous)
            .and_then(|()| {
                fs::rename(&staging, &target).inspect_err(|_| {
                    let _ = fs::rename(&previous, &target);
                })
            })
            .map(|()| {
                let _ = fs::remove_dir_all(&previous);
            })
    } else {
        fs::rename(&staging, &target)
    };
    if swapped.is_err() {
        let _ = fs::remove_dir_all(&staging);
        return Err(unavailable());
    }
    Ok(summary(true))
}

pub(crate) async fn run(
    args: CatalogArgs,
    _cli: crate::config::Cli,
    shutdown: tokio_util::sync::CancellationToken,
) -> u8 {
    let phase = match &args.command {
        CatalogCommand::List { .. } => "catalog_list",
        CatalogCommand::Export { .. } => "catalog_export",
        CatalogCommand::Install { .. } => "catalog_install",
    };
    let root = args.root;
    let result = match args.command {
        CatalogCommand::Install { dir, replace } => {
            if root.is_some() {
                // `--root` selects a catalog that exists; install creates one.
                Err(Failure::Code("catalog_option_not_applicable"))
            } else {
                match tokio::task::spawn_blocking(move || install(dir, replace)).await {
                    Ok(Ok(value)) => serde_json::to_vec(&value)
                        .map_err(|_| Failure::Code("catalog_output_invalid")),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(Failure::Code("catalog_install_unavailable")),
                }
            }
        }
        command => {
            let loaded = tokio::task::spawn_blocking(move || {
                Catalog::load(root.as_deref())
                    .map(|catalog| (catalog, command))
                    .map_err(Failure::from)
            })
            .await;
            match loaded {
                Ok(Ok((catalog, command))) if !shutdown.is_cancelled() => match command {
                    CatalogCommand::List { json } => {
                        match tokio::task::spawn_blocking(move || describe(&catalog, json)).await {
                            Ok(value) => value,
                            Err(_) => Err(Failure::Code("catalog_unavailable")),
                        }
                    }
                    CatalogCommand::Export {
                        tools,
                        presets,
                        output,
                    } => {
                        match tokio::task::spawn_blocking(move || {
                            export(&catalog, tools, presets, &output)
                        })
                        .await
                        {
                            Ok(Ok(value)) => serde_json::to_vec(&value)
                                .map_err(|_| Failure::Code("catalog_output_invalid")),
                            Ok(Err(error)) => Err(error),
                            Err(_) => Err(Failure::Code("catalog_output_unavailable")),
                        }
                    }
                    CatalogCommand::Install { .. } => Err(Failure::Code("catalog_unavailable")),
                },
                Ok(Err(error)) => Err(error),
                Ok(Ok(_)) => Err(Failure::Code("cancelled")),
                Err(_) => Err(Failure::Code("catalog_unavailable")),
            }
        }
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
        Ok(_) => Failure::Code("cancelled").publish(phase),
        Err(error) => error.publish(phase),
    }
}
