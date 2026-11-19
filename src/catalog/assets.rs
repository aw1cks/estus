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
use sha2::{Digest, Sha256};

const MANIFEST_LIMIT: u64 = 256 * 1024;
const DEFINITION_LIMIT: u64 = 256 * 1024;
const ROLE_LIMIT: u64 = 8 * 1024 * 1024;
const ROLE_FILES: usize = 256;
const ERROR: &str = "invalid or unavailable catalog assets";

struct PinnedDynamicPayload {
    name: &'static str,
    toml_sha256: &'static str,
    source_sha256: &'static str,
    manifest_sha256: &'static str,
}

const PINNED_DYNAMIC_PAYLOADS: &[PinnedDynamicPayload] = &[
    PinnedDynamicPayload {
        name: "observe_cpu",
        toml_sha256: "dfaa4def61f1f3d2ae6383eaa2f6f6f09475910a35f306ced1294f5eac117200",
        source_sha256: "f8767fb99e075259f3b104f23e5cbff8478cf502f2c91308a9fd27b9117cef64",
        manifest_sha256: "6035fca16346ca8913557980e4f6925ff42fb3b271fb65a84a34fa80f8a7cbce",
    },
    PinnedDynamicPayload {
        name: "observe_memory",
        toml_sha256: "75e97867765313558ad6257716c903fdb4f08944bef9557734b820b6c936ff0e",
        source_sha256: "eae9433cc26d1bb5ae810b9b680ef35acd120da960fadb9db205087d90814b27",
        manifest_sha256: "e88b7365b9c8afc9f8f2c4fba59b81fd4975a5e612e5291ab61623853d851811",
    },
    PinnedDynamicPayload {
        name: "observe_pressure",
        toml_sha256: "7751ea63a765e676e7cf9c250e8aeb4855773230016aa93174a40ff2aad81476",
        source_sha256: "bf1e7663c14cd92cdaa8cc5e603007adea8c668a359ce7e22f907c83f88bdf9e",
        manifest_sha256: "3c38e3ea311dc50792f6d10684c6b16df1d0200d28005fb202eb934b8b459868",
    },
];

pub(crate) fn pinned_dynamic_payload_names() -> impl Iterator<Item = &'static str> {
    PINNED_DYNAMIC_PAYLOADS.iter().map(|p| p.name)
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
    AnsibleRole { path: String },
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
                    Executor::AnsibleRole { path } => path != &format!("roles/{name}"),
                    Executor::NativePayload { path } => path != &format!("payloads/{name}"),
                    Executor::AnsibleModule { module } => {
                        module.len() > 256
                            || module.split('.').count() != 3
                            || module.split('.').any(|part| {
                                part.is_empty()
                                    || !part.bytes().enumerate().all(|(index, byte)| {
                                        byte.is_ascii_lowercase()
                                            || byte == b'_'
                                            || (index > 0 && byte.is_ascii_digit())
                                    })
                            })
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

    pub(crate) fn load_pinned_payload(
        &self,
        name: &str,
    ) -> Result<(toml::Value, Vec<u8>, Vec<u8>), &'static str> {
        let pinned = PINNED_DYNAMIC_PAYLOADS
            .iter()
            .find(|entry| entry.name == name)
            .ok_or("unknown pinned bundled payload")?;
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        if matches!(template.qualification, Qualification::LaboratoryOnly)
            || template.policy_required
            || !matches!(template.executor, Executor::NativePayload { .. })
        {
            return Err(ERROR);
        }
        let toml_bytes = bounded_read(
            open_child(&self.directory, Path::new(&template.definition), false)?,
            DEFINITION_LIMIT,
        )?;
        if hex::encode(Sha256::digest(&toml_bytes)) != pinned.toml_sha256 {
            return Err(ERROR);
        }
        let mut table: toml::Table = std::str::from_utf8(&toml_bytes)
            .map_err(|_| ERROR)?
            .parse()
            .map_err(|_| ERROR)?;
        let mut tools = table
            .remove("tools")
            .and_then(|v| v.try_into::<toml::Table>().ok())
            .ok_or(ERROR)?;
        let tool_def = tools.remove(name).ok_or(ERROR)?;
        if !tools.is_empty() {
            return Err(ERROR);
        }
        let payloads_dir = open_child(&self.directory, Path::new("payloads"), true)?;
        let tool_dir = open_child(&payloads_dir, Path::new(name), true)?;
        let source_bytes = bounded_read(
            open_child(&tool_dir, Path::new("collector.py"), false)?,
            1_048_576,
        )?;
        if hex::encode(Sha256::digest(&source_bytes)) != pinned.source_sha256 {
            return Err(ERROR);
        }
        let manifest_bytes = bounded_read(
            open_child(&tool_dir, Path::new("manifest.json"), false)?,
            262_144,
        )?;
        if hex::encode(Sha256::digest(&manifest_bytes)) != pinned.manifest_sha256 {
            return Err(ERROR);
        }
        Ok((tool_def, source_bytes, manifest_bytes))
    }
    pub fn copy_assets(&self, name: &str, destination: &Path) -> Result<(), &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        let (directory_name, required) = match &template.executor {
            Executor::AnsibleRole { .. } => ("roles", &["tasks/main.yml"][..]),
            Executor::NativePayload { .. } => ("payloads", &["collector.py", "manifest.json"][..]),
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
        let roles = open_child(&self.directory, Path::new(directory_name), true)?;
        let directory = open_child(&roles, Path::new(name), true)?;
        let mut files = Vec::new();
        let mut remaining = ROLE_LIMIT;
        let mut entries = 0;
        collect_role(
            &directory,
            &self.root.join(directory_name).join(name),
            Path::new(""),
            &mut files,
            &mut remaining,
            &mut entries,
            0,
        )?;
        if required
            .iter()
            .any(|required| !files.iter().any(|(path, _)| path == Path::new(required)))
        {
            return Err(ERROR);
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        // The caller owns destination selection; reject symlinked ancestors before
        // creating the private directory, and never merge into an existing tree.
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

fn collect_role(
    directory: &File,
    source: &Path,
    relative: &Path,
    files: &mut Vec<(PathBuf, Vec<u8>)>,
    remaining: &mut u64,
    entries: &mut usize,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > 16 {
        return Err(ERROR);
    }
    for entry in fs::read_dir(source).map_err(|_| ERROR)? {
        let entry = entry.map_err(|_| ERROR)?;
        *entries += 1;
        if *entries > ROLE_FILES {
            return Err(ERROR);
        }
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|_| ERROR)?;
        let path = relative.join(&name);
        if kind.is_dir() {
            // Installers may byte-compile packaged collectors. These caches are
            // generated installation state, not reviewed role source assets.
            if name == "__pycache__" {
                continue;
            }
            let child = open_child(directory, Path::new(&name), true)?;
            collect_role(
                &child,
                &source.join(&name),
                &path,
                files,
                remaining,
                entries,
                depth + 1,
            )?;
        } else if kind.is_file() {
            if matches!(
                Path::new(&name)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("pyc" | "pyo")
            ) {
                continue;
            }
            let bytes = bounded_read(open_child(directory, Path::new(&name), false)?, *remaining)?;
            *remaining -= bytes.len() as u64;
            files.push((path, bytes));
        } else {
            return Err(ERROR);
        }
    }
    Ok(())
}

#[cfg(test)]
mod pinned_tests {
    use super::*;

    #[test]
    fn pinned_bundled_dynamic_payloads_match_manifest_and_hashes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = Catalog::load(Some(&root)).unwrap();
        let mut names: Vec<&str> = pinned_dynamic_payload_names().collect();
        names.sort_unstable();
        assert_eq!(names, ["observe_cpu", "observe_memory", "observe_pressure"]);
        for name in names {
            let (tool_def, source, manifest) = catalog.load_pinned_payload(name).unwrap();
            assert!(tool_def.is_table());
            assert!(!source.is_empty());
            assert!(!manifest.is_empty());
        }
    }
}
