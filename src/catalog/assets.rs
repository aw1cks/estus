use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};

const MANIFEST_LIMIT: u64 = 256 * 1024;
const DEFINITION_LIMIT: u64 = 256 * 1024;
const PAYLOAD_LIMIT: u64 = 8 * 1024 * 1024;
const PAYLOAD_FILES: usize = 256;
const ERROR: &str = "invalid or unavailable catalog assets";

pub(crate) enum WorkstationEntry {
    Payload {
        definition: toml::Value,
        source: Vec<u8>,
        manifest: Vec<u8>,
    },
    Module {
        definition: toml::Value,
    },
}

pub(crate) fn discover_default_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    for relative in [
        "../share/estus/catalog",
        "../../catalog",
        "../../../catalog",
    ] {
        let candidate = exe_dir.join(relative);
        if candidate.join("catalog.json").is_file() {
            return candidate.canonicalize().ok();
        }
    }
    None
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub version: String,
    #[serde(deserialize_with = "unique_map")]
    pub presets: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "unique_map")]
    pub tools: BTreeMap<String, Template>,
}

#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Qualification {
    Unqualified,
    SitePolicyTemplate,
    LaboratoryOnly,
    DeploymentQualified,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub definition: String,
    pub executor: Executor,
    pub policy_required: bool,
    pub requires: Vec<String>,
    pub qualification: Qualification,
    /// Explicit, reviewed workstation policy. A template without one is not
    /// loaded in workstation mode; nothing is widened or inferred at runtime.
    #[serde(default)]
    pub workstation: Option<WorkstationPolicy>,
}

/// Literal overlay a workstation-mode binding is compiled with. These values
/// are catalog data reviewed like any other definition; the controller never
/// rewrites them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationPolicy {
    #[serde(default)]
    pub fixed_args: toml::Table,
    #[serde(default)]
    pub input_schema: toml::Table,
    #[serde(default)]
    pub input_map: BTreeMap<String, String>,
    /// Published description, when the site-policy template description is not
    /// truthful for the workstation overlay.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Executor {
    NativePayload { path: String },
    AnsibleModule { module: String },
}

fn unique_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Unique<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Unique<T> {
        type Value = BTreeMap<String, T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map without duplicate names")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, value)) = map.next_entry::<String, T>()? {
                if result.insert(name, value).is_some() {
                    return Err(serde::de::Error::custom("duplicate catalog name"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

pub struct Catalog {
    root: PathBuf,
    directory: File,
    manifest: Manifest,
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn has_catalog_risk_prefix(name: &str) -> bool {
    name.starts_with("observe_")
        || name.starts_with("inspect_")
        || name.starts_with("preview_")
        || name.starts_with("change_")
}

fn risk_prefix_matches_effects(name: &str, effects: &[&str]) -> bool {
    if effects.is_empty() {
        return false;
    }
    let mut seen = BTreeSet::new();
    if effects.iter().any(|effect| !seen.insert(*effect)) {
        return false;
    }
    let is_read_like = |effect: &str| matches!(effect, "read" | "sensitive_read" | "probe");
    let is_mutating = |effect: &str| {
        matches!(
            effect,
            "runtime_write" | "persistent_write" | "availability" | "unknown"
        )
    };
    if !effects
        .iter()
        .all(|effect| is_read_like(effect) || is_mutating(effect))
    {
        return false;
    }
    if name.starts_with("observe_") {
        effects.iter().all(|effect| *effect == "read")
    } else if name.starts_with("inspect_") {
        effects.iter().all(|effect| is_read_like(effect))
            && effects
                .iter()
                .any(|effect| matches!(*effect, "sensitive_read" | "probe"))
    } else if name.starts_with("preview_") {
        effects.iter().all(|effect| is_read_like(effect))
    } else if name.starts_with("change_") {
        effects.iter().any(|effect| is_mutating(effect))
    } else {
        false
    }
}

fn open_child(directory: &File, name: &Path, is_directory: bool) -> Result<File, &'static str> {
    if name.components().count() != 1
        || !matches!(
            name.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(ERROR);
    }
    let flags = OFlag::O_RDONLY
        | OFlag::O_NOFOLLOW
        | OFlag::O_CLOEXEC
        | OFlag::O_NONBLOCK
        | if is_directory {
            OFlag::O_DIRECTORY
        } else {
            OFlag::empty()
        };
    let file = File::from(openat(directory, name, flags, Mode::empty()).map_err(|_| ERROR)?);
    let metadata = file.metadata().map_err(|_| ERROR)?;
    if (is_directory && !metadata.is_dir()) || (!is_directory && !metadata.is_file()) {
        return Err(ERROR);
    }
    Ok(file)
}

fn bounded_read(file: File, limit: u64) -> Result<Vec<u8>, &'static str> {
    if file.metadata().map_err(|_| ERROR)?.len() > limit {
        return Err(ERROR);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ERROR)?;
    if bytes.len() as u64 > limit {
        return Err(ERROR);
    }
    Ok(bytes)
}

impl Catalog {
    pub fn load(root: Option<&Path>) -> Result<Self, &'static str> {
        let root = match root {
            Some(root) => root.to_path_buf(),
            None => PathBuf::from(std::env::var_os("ESTUS_CATALOG_ROOT").ok_or(ERROR)?),
        };
        if fs::symlink_metadata(&root)
            .map_err(|_| ERROR)?
            .file_type()
            .is_symlink()
        {
            return Err(ERROR);
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&root)
            .map_err(|_| ERROR)?;
        let root = fs::canonicalize(root).map_err(|_| ERROR)?;
        let bytes = bounded_read(
            open_child(&directory, Path::new("catalog.json"), false)?,
            MANIFEST_LIMIT,
        )?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|_| ERROR)?;
        if manifest.schema != 3
            || !name_valid(&manifest.version)
            || manifest.tools.is_empty()
            || manifest.tools.len() > 1024
            || manifest.presets.len() > 64
        {
            return Err(ERROR);
        }
        for (name, template) in &manifest.tools {
            if !name_valid(name)
                || !has_catalog_risk_prefix(name)
                || template.definition != format!("{name}.toml")
                || match &template.executor {
                    Executor::NativePayload { path } => path != &format!("payloads/{name}"),
                    Executor::AnsibleModule { module } => {
                        !crate::contracts::module_schema::valid_fqcn(module)
                    }
                }
                || template.requires.len() > 32
                || template
                    .requires
                    .iter()
                    .any(|requirement| !name_valid(requirement))
                // A workstation policy is only meaningful where no site policy
                // is required; site-policy templates stay out of open mode.
                || template.workstation.is_some() && template.policy_required
            {
                return Err(ERROR);
            }
            Self::validate_definition(&directory, name, &template.definition)?;
        }
        for (name, tools) in &manifest.presets {
            let mut seen = BTreeSet::new();
            if !name_valid(name)
                || tools.is_empty()
                || tools.len() > manifest.tools.len()
                || tools
                    .iter()
                    .any(|tool| !manifest.tools.contains_key(tool) || !seen.insert(tool))
            {
                return Err(ERROR);
            }
        }
        Ok(Self {
            root,
            directory,
            manifest,
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Templates that explicitly declare a reviewed workstation policy. This is
    /// the only source of workstation-mode catalog exposure.
    pub(crate) fn workstation_tool_names(&self) -> impl Iterator<Item = &str> {
        self.manifest.tools.iter().filter_map(|(name, template)| {
            (template.workstation.is_some()
                && !matches!(template.qualification, Qualification::LaboratoryOnly))
            .then_some(name.as_str())
        })
    }

    fn validate_definition(
        directory: &File,
        name: &str,
        definition: &str,
    ) -> Result<toml::Table, &'static str> {
        let bytes = bounded_read(
            open_child(directory, Path::new(definition), false)?,
            DEFINITION_LIMIT,
        )?;
        let table: toml::Table = std::str::from_utf8(&bytes)
            .map_err(|_| ERROR)?
            .parse()
            .map_err(|_| ERROR)?;
        let tools = table
            .get("tools")
            .and_then(toml::Value::as_table)
            .ok_or(ERROR)?;
        let tool = tools
            .get(name)
            .and_then(toml::Value::as_table)
            .ok_or(ERROR)?;
        if tools.len() != 1 {
            return Err(ERROR);
        }
        let effects = tool
            .get("effects")
            .and_then(toml::Value::as_array)
            .ok_or(ERROR)?;
        let mut effect_names = Vec::with_capacity(effects.len());
        for effect in effects {
            effect_names.push(effect.as_str().ok_or(ERROR)?);
        }
        if !risk_prefix_matches_effects(name, &effect_names) {
            return Err(ERROR);
        }
        Ok(table)
    }

    pub fn definition(&self, name: &str) -> Result<toml::Table, &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        Self::validate_definition(&self.directory, name, &template.definition)
    }

    /// The installed definition for `name`, wired to the installed payload
    /// directory and to the site's own targets.
    ///
    /// `overrides` is the config's `[tools.<name>]` table when it carries no
    /// `execution`; each key it names replaces the installed one wholesale.
    /// `targets` and `constraints` never survive from the catalog: they name
    /// hosts and allowlists that only the site knows. Targets default to every
    /// configured destination (per-host permission is still checked
    /// separately). A `policy_required` template must restate its fixed
    /// arguments or supply constraints, so an example allowlist can never be
    /// inherited by an operator who did not review it.
    pub(crate) fn site_definition(
        &self,
        name: &str,
        overrides: Option<&toml::Table>,
        destinations: &[String],
    ) -> Result<toml::Value, &'static str> {
        const SITE_KEYS: [&str; 7] = [
            "targets",
            "authority",
            "fixed_args",
            "constraints",
            "input_schema",
            "input_map",
            "limits",
        ];
        let template = self.manifest.tools.get(name).ok_or(ERROR)?;
        if let Some(overrides) = overrides
            && overrides
                .keys()
                .any(|key| !SITE_KEYS.contains(&key.as_str()))
        {
            return Err("catalog_definition_override_not_site_policy");
        }
        if template.policy_required
            && overrides.is_none_or(|table| {
                !(table.contains_key("fixed_args")
                    || table.contains_key("constraints")
                    || table.contains_key("input_schema"))
            })
        {
            return Err("catalog_definition_requires_site_policy");
        }
        let mut document = Self::validate_definition(&self.directory, name, &template.definition)?;
        let tools = document
            .remove("tools")
            .and_then(|value| value.try_into::<toml::Table>().ok())
            .ok_or(ERROR)?;
        let mut definition = tools
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .ok_or(ERROR)?;
        let table = definition.as_table_mut().ok_or(ERROR)?;
        table.remove("targets");
        table.remove("constraints");
        if let Executor::NativePayload { path } = &template.executor {
            table.insert(
                "execution".into(),
                toml::Value::Table(toml::Table::from_iter([
                    ("kind".to_owned(), toml::Value::from("native_payload")),
                    (
                        "source".to_owned(),
                        toml::Value::from(
                            self.root
                                .join(path)
                                .join("collector.py")
                                .to_str()
                                .ok_or(ERROR)?,
                        ),
                    ),
                ])),
            );
        }
        if let Some(overrides) = overrides {
            for (key, value) in overrides {
                table.insert(key.clone(), value.clone());
            }
        }
        if !table.contains_key("targets") {
            if destinations.is_empty() {
                return Err("catalog_definition_requires_targets");
            }
            table.insert(
                "targets".into(),
                toml::Value::Array(
                    destinations
                        .iter()
                        .map(|name| name.as_str().into())
                        .collect(),
                ),
            );
        }
        Ok(definition)
    }

    /// Build a workstation-mode entry from its declared policy. The definition's
    /// own fixed arguments, schema and constraints are replaced by the reviewed
    /// `workstation` block; nothing is inferred from names or example values.
    pub(crate) fn load_workstation_entry(
        &self,
        name: &str,
    ) -> Result<WorkstationEntry, &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        let policy = template.workstation.as_ref().ok_or(ERROR)?;
        if matches!(template.qualification, Qualification::LaboratoryOnly) {
            return Err(ERROR);
        }
        let mut table = Self::validate_definition(&self.directory, name, &template.definition)?;
        let mut tools = table
            .remove("tools")
            .and_then(|v| v.try_into::<toml::Table>().ok())
            .ok_or(ERROR)?;
        let mut definition = tools.remove(name).ok_or(ERROR)?;
        if !tools.is_empty() {
            return Err(ERROR);
        }
        let table = definition.as_table_mut().ok_or(ERROR)?;
        table.remove("constraints");
        table.insert(
            "fixed_args".into(),
            toml::Value::Table(policy.fixed_args.clone()),
        );
        table.insert(
            "input_schema".into(),
            toml::Value::Table(policy.input_schema.clone()),
        );
        if policy.input_map.is_empty() {
            table.remove("input_map");
        } else {
            table.insert(
                "input_map".into(),
                toml::Value::Table(
                    policy
                        .input_map
                        .iter()
                        .map(|(key, value)| (key.clone(), toml::Value::String(value.clone())))
                        .collect(),
                ),
            );
        }
        if let Some(description) = &policy.description {
            table.insert(
                "description".into(),
                toml::Value::String(description.clone()),
            );
        }
        match &template.executor {
            Executor::AnsibleModule { .. } => Ok(WorkstationEntry::Module { definition }),
            Executor::NativePayload { .. } => {
                let payloads_dir = open_child(&self.directory, Path::new("payloads"), true)?;
                let tool_dir = open_child(&payloads_dir, Path::new(name), true)?;
                let source_bytes = bounded_read(
                    open_child(&tool_dir, Path::new("collector.py"), false)?,
                    1_048_576,
                )?;
                let manifest_raw = bounded_read(
                    open_child(&tool_dir, Path::new("manifest.json"), false)?,
                    262_144,
                )?;
                Ok(WorkstationEntry::Payload {
                    definition,
                    source: source_bytes,
                    manifest: manifest_raw,
                })
            }
        }
    }

    pub fn copy_assets(&self, name: &str, destination: &Path) -> Result<(), &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        let required: &[&str] = match &template.executor {
            Executor::NativePayload { .. } => &["collector.py", "manifest.json"],
            Executor::AnsibleModule { .. } => return Err(ERROR),
        };
        if destination.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(ERROR);
        }
        let payloads = open_child(&self.directory, Path::new("payloads"), true)?;
        let directory = open_child(&payloads, Path::new(name), true)?;
        let mut scan = PayloadScan {
            files: Vec::new(),
            remaining: PAYLOAD_LIMIT,
            entries: 0,
        };
        collect_payload(
            &directory,
            &self.root.join("payloads").join(name),
            Path::new(""),
            &mut scan,
            0,
        )?;
        let files = scan.files;
        if required
            .iter()
            .any(|req| !files.iter().any(|(path, _)| path == Path::new(req)))
        {
            return Err(ERROR);
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut ancestor = Some(parent);
        while let Some(path) = ancestor {
            if !path.as_os_str().is_empty()
                && fs::symlink_metadata(path)
                    .map_err(|_| ERROR)?
                    .file_type()
                    .is_symlink()
            {
                return Err(ERROR);
            }
            ancestor = path.parent();
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(destination)
            .map_err(|_| ERROR)?;
        let result = (|| {
            for (relative, bytes) in files {
                let output = destination.join(relative);
                if let Some(parent) = output.parent() {
                    fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)
                        .map_err(|_| ERROR)?;
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                    .open(output)
                    .map_err(|_| ERROR)?;
                file.write_all(&bytes).map_err(|_| ERROR)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        result
    }
}

struct PayloadScan {
    files: Vec<(PathBuf, Vec<u8>)>,
    remaining: u64,
    entries: usize,
}

fn collect_payload(
    directory: &File,
    source: &Path,
    relative: &Path,
    scan: &mut PayloadScan,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > 16 {
        return Err(ERROR);
    }
    for entry in fs::read_dir(source).map_err(|_| ERROR)? {
        let entry = entry.map_err(|_| ERROR)?;
        scan.entries += 1;
        if scan.entries > PAYLOAD_FILES {
            return Err(ERROR);
        }
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|_| ERROR)?;
        let path = relative.join(&name);
        if kind.is_dir() {
            if name == "__pycache__" {
                continue;
            }
            let child = open_child(directory, Path::new(&name), true)?;
            collect_payload(&child, &source.join(&name), &path, scan, depth + 1)?;
        } else if kind.is_file() {
            if matches!(
                Path::new(&name)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("pyc" | "pyo")
            ) {
                continue;
            }
            if !matches!(
                Path::new(&name)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("yml" | "yaml" | "py" | "json" | "toml")
            ) {
                return Err(ERROR);
            }
            let bytes = bounded_read(
                open_child(directory, Path::new(&name), false)?,
                scan.remaining,
            )?;
            scan.remaining -= bytes.len() as u64;
            scan.files.push((path, bytes));
        } else {
            return Err(ERROR);
        }
    }
    Ok(())
}

#[cfg(test)]
mod workstation_tests {
    use super::*;
    use crate::bindings::Bindings;
    use crate::config::Limits;

    #[test]
    fn eligible_workstation_payloads_activate() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = Catalog::load(Some(&root)).expect("load catalog");
        let limits = Limits::default();
        let mut bindings = Bindings::compile_with_mode(
            BTreeMap::new(),
            &[],
            &limits,
            |_| false,
            None,
            false,
            true,
        )
        .unwrap();
        let mut failures = Vec::new();
        for name in catalog.workstation_tool_names() {
            if let WorkstationEntry::Payload {
                definition,
                source,
                manifest,
            } = catalog
                .load_workstation_entry(name)
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                && let Err(error) = bindings.push_dynamic_payload(
                    name.to_owned(),
                    definition,
                    source,
                    &manifest,
                    &limits,
                )
            {
                failures.push(format!("{name}: {error:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
