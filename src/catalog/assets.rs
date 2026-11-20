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
use serde_json::{Value, json};

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

fn adapt_workstation_definition(
    name: &str,
    tool_def: &mut toml::Value,
) -> Result<(), &'static str> {
    let table = tool_def.as_table_mut().ok_or(ERROR)?;
    // Strip site-specific fixture constraints for workstation dynamic mode.
    let removed_constraints = table.remove("constraints");
    let had_allowed_units = removed_constraints
        .as_ref()
        .and_then(toml::Value::as_table)
        .is_some_and(|c| c.contains_key("allowed_units"));
    let had_allowed_keys = removed_constraints
        .as_ref()
        .and_then(toml::Value::as_table)
        .is_some_and(|c| c.contains_key("allowed_keys"));
    if had_allowed_units
        || had_allowed_keys
        || matches!(
            name,
            "change_sysctl_config"
                | "change_sysctl_runtime"
                | "change_boot_default"
                | "change_boot_oneshot"
        )
    {
        table
            .entry("fixed_args")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }
    if let Some(fixed) = table
        .get_mut("fixed_args")
        .and_then(toml::Value::as_table_mut)
    {
        if had_allowed_units || fixed.contains_key("allowed_units") {
            fixed.insert(
                "allowed_units".into(),
                toml::Value::Array(vec![toml::Value::String("*".into())]),
            );
        }
        if name == "change_sysctl_config" || name == "change_sysctl_runtime" {
            fixed.insert(
                "approved_keys".into(),
                toml::Value::Array(vec![toml::Value::String("*".into())]),
            );
        }
        if name == "change_boot_default" || name == "change_boot_oneshot" {
            fixed.insert(
                "allowed_entries".into(),
                toml::Value::Array(vec![toml::Value::String("*".into())]),
            );
        }
        if fixed.contains_key("approved_packages") {
            fixed.insert(
                "approved_packages".into(),
                toml::Value::Array(vec![toml::Value::String("*".into())]),
            );
        }
        if name == "observe_systemd_units" && fixed.contains_key("unit_pattern") {
            fixed.insert("unit_pattern".into(), toml::Value::String("*".into()));
        }
        if (name.starts_with("observe_cgroup_") || name == "inspect_cgroup_processes")
            && fixed.contains_key("approved_root")
        {
            fixed.insert("approved_root".into(), toml::Value::String("/".into()));
        }
        if let Some(policy) = fixed
            .get_mut("operator_policy")
            .and_then(toml::Value::as_table_mut)
        {
            if policy.contains_key("interfaces") {
                policy.insert(
                    "interfaces".into(),
                    toml::Value::Array(vec![toml::Value::String("*".into())]),
                );
            }
            for key in ["interface", "mac", "driver"] {
                if policy.contains_key(key) {
                    policy.insert(key.into(), toml::Value::String("*".into()));
                }
            }
        }
    }
    if name == "observe_filesystem_usage" {
        let mut paths = toml::Table::new();
        for (id, path) in [
            ("root", "/"),
            ("var", "/var"),
            ("tmp", "/tmp"),
            ("home", "/home"),
            ("run", "/run"),
        ] {
            paths.insert(id.into(), toml::Value::String(path.into()));
        }
        if let Some(fixed) = table
            .get_mut("fixed_args")
            .and_then(toml::Value::as_table_mut)
        {
            fixed.insert("configured_paths".into(), toml::Value::Table(paths));
        }
        if let Some(path_id) = table
            .get_mut("input_schema")
            .and_then(toml::Value::as_table_mut)
            .and_then(|s| s.get_mut("properties"))
            .and_then(toml::Value::as_table_mut)
            .and_then(|p| p.get_mut("path_id"))
            .and_then(toml::Value::as_table_mut)
        {
            path_id.insert(
                "enum".into(),
                toml::Value::Array(
                    ["root", "var", "tmp", "home", "run"]
                        .into_iter()
                        .map(|s| toml::Value::String(s.into()))
                        .collect(),
                ),
            );
        }
    }
    if let Some(props) = table
        .get_mut("input_schema")
        .and_then(toml::Value::as_table_mut)
        .and_then(|s| s.get_mut("properties"))
        .and_then(toml::Value::as_table_mut)
    {
        for (prop_name, max_len) in [
            ("unit", 128),
            ("interface", 15),
            ("destination", 64),
            ("address", 64),
            ("device", 64),
            ("package", 128),
            ("key", 128),
            ("entry_id", 255),
        ] {
            if let Some(prop) = props.get_mut(prop_name).and_then(toml::Value::as_table_mut)
                && prop.get("type").and_then(toml::Value::as_str) == Some("string")
                && prop.contains_key("enum")
            {
                prop.remove("enum");
                prop.entry("minLength")
                    .or_insert_with(|| toml::Value::Integer(1));
                prop.entry("maxLength")
                    .or_insert_with(|| toml::Value::Integer(max_len));
            }
        }
        if let Some(items) = props
            .get_mut("name")
            .and_then(toml::Value::as_table_mut)
            .and_then(|n| n.get_mut("items"))
            .and_then(toml::Value::as_table_mut)
            && items.get("type").and_then(toml::Value::as_str) == Some("string")
            && items.contains_key("enum")
        {
            items.remove("enum");
            items
                .entry("minLength")
                .or_insert_with(|| toml::Value::Integer(1));
            items
                .entry("maxLength")
                .or_insert_with(|| toml::Value::Integer(128));
        }
        if name == "observe_sysctl"
            && let Some(keys) = props.get_mut("keys").and_then(toml::Value::as_table_mut)
            && keys.get("type").and_then(toml::Value::as_str) == Some("array")
        {
            keys.insert("maxItems".into(), toml::Value::Integer(16));
            if let Some(items) = keys.get_mut("items").and_then(toml::Value::as_table_mut)
                && items.get("type").and_then(toml::Value::as_str) == Some("string")
                && items.contains_key("enum")
            {
                items.remove("enum");
                items
                    .entry("minLength")
                    .or_insert_with(|| toml::Value::Integer(1));
                items
                    .entry("maxLength")
                    .or_insert_with(|| toml::Value::Integer(64));
            }
            if let Some(fixed) = table
                .get_mut("fixed_args")
                .and_then(toml::Value::as_table_mut)
            {
                fixed.insert(
                    "approved_keys".into(),
                    toml::Value::Array(vec![toml::Value::String("*".into())]),
                );
            }
        }
    }
    Ok(())
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

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub(crate) fn workstation_tool_names(&self) -> impl Iterator<Item = &str> {
        self.manifest.tools.iter().filter_map(|(name, template)| {
            (!matches!(template.qualification, Qualification::LaboratoryOnly))
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

    pub(crate) fn load_workstation_entry(
        &self,
        name: &str,
    ) -> Result<WorkstationEntry, &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        if matches!(template.qualification, Qualification::LaboratoryOnly) {
            return Err(ERROR);
        }
        let mut table = Self::validate_definition(&self.directory, name, &template.definition)?;
        let mut tools = table
            .remove("tools")
            .and_then(|v| v.try_into::<toml::Table>().ok())
            .ok_or(ERROR)?;
        let mut tool_def = tools.remove(name).ok_or(ERROR)?;
        if !tools.is_empty() {
            return Err(ERROR);
        }
        adapt_workstation_definition(name, &mut tool_def)?;
        match &template.executor {
            Executor::AnsibleModule { .. } => Ok(WorkstationEntry::Module {
                definition: tool_def,
            }),
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
                let mut manifest_val: Value =
                    crate::strict_json::parse(&manifest_raw).map_err(|_| ERROR)?;
                let def_table = tool_def.as_table().ok_or(ERROR)?;
                let adapted_overlay = json!({
                    "input_schema": serde_json::to_value(def_table.get("input_schema").ok_or(ERROR)?).map_err(|_| ERROR)?,
                    "fixed_args": def_table.get("fixed_args").map(serde_json::to_value).transpose().map_err(|_| ERROR)?.unwrap_or_else(|| json!({})),
                    "input_map": def_table.get("input_map").map(serde_json::to_value).transpose().map_err(|_| ERROR)?.unwrap_or_else(|| json!({})),
                });
                if let Some(approval) = manifest_val
                    .get_mut("approval")
                    .and_then(Value::as_object_mut)
                {
                    approval.insert("overlay".into(), adapted_overlay);
                }
                // Widen contract enums removed by workstation adaptation so compile_binding accepts open inputs.
                if let Some(contract_props) = manifest_val
                    .get_mut("contract")
                    .and_then(|c| c.get_mut("schema"))
                    .and_then(|s| s.get_mut("properties"))
                    .and_then(Value::as_object_mut)
                {
                    for (_, prop) in contract_props.iter_mut() {
                        if let Some(obj) = prop.as_object_mut()
                            && obj.get("type").and_then(Value::as_str) == Some("string")
                            && obj.contains_key("enum")
                        {
                            // Keep closed operational enums (direction, scope, signal), drop fixture target enums.
                            let is_fixture_enum = obj
                                .get("enum")
                                .and_then(Value::as_array)
                                .is_some_and(|arr| {
                                    arr.iter().any(|v| {
                                        v.as_str().is_some_and(|s| {
                                            s.contains("estus-fixture")
                                                || s == "catalog0"
                                                || s == "eth0"
                                                || s == "vda"
                                                || s == "queue0"
                                                || s.starts_with("estus-")
                                                || s.starts_with("192.0.2.")
                                                || s.starts_with("198.51.100.")
                                        })
                                    })
                                });
                            if is_fixture_enum {
                                obj.remove("enum");
                            }
                        }
                    }
                }
                let manifest_bytes = serde_json::to_vec(&manifest_val).map_err(|_| ERROR)?;
                Ok(WorkstationEntry::Payload {
                    definition: tool_def,
                    source: source_bytes,
                    manifest: manifest_bytes,
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
