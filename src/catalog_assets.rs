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
const ROLE_LIMIT: u64 = 8 * 1024 * 1024;
const ROLE_FILES: usize = 256;
const ERROR: &str = "invalid or unavailable catalog assets";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) schema: u32,
    pub(crate) version: String,
    #[serde(deserialize_with = "unique_map")]
    pub(crate) presets: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "unique_map")]
    pub(crate) tools: BTreeMap<String, Template>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Template {
    pub(crate) definition: String,
    pub(crate) role: String,
    pub(crate) policy_required: bool,
    pub(crate) requires: Vec<String>,
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

pub(crate) struct Catalog {
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
    pub(crate) fn load(root: Option<&Path>) -> Result<Self, &'static str> {
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
        if manifest.schema != 1
            || manifest.version != "1"
            || manifest.tools.is_empty()
            || manifest.tools.len() > 1024
            || manifest.presets.len() > 64
        {
            return Err(ERROR);
        }
        for (name, template) in &manifest.tools {
            if !name_valid(name)
                || template.definition != format!("{name}.toml")
                || template.role != format!("roles/{name}")
                || template.requires.len() > 32
                || template
                    .requires
                    .iter()
                    .any(|requirement| !name_valid(requirement))
            {
                return Err(ERROR);
            }
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
    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub(crate) fn definition(&self, name: &str) -> Result<toml::Table, &'static str> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        let bytes = bounded_read(
            open_child(&self.directory, Path::new(&template.definition), false)?,
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
        if tools.len() != 1 || !tools.get(name).is_some_and(toml::Value::is_table) {
            return Err(ERROR);
        }
        Ok(table)
    }

    pub(crate) fn copy_role(&self, name: &str, destination: &Path) -> Result<(), &'static str> {
        self.manifest
            .tools
            .get(name)
            .ok_or("unknown catalog tool")?;
        if destination.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(ERROR);
        }
        let roles = open_child(&self.directory, Path::new("roles"), true)?;
        let directory = open_child(&roles, Path::new(name), true)?;
        let mut files = Vec::new();
        let mut remaining = ROLE_LIMIT;
        let mut entries = 0;
        collect_role(
            &directory,
            &self.root.join("roles").join(name),
            Path::new(""),
            &mut files,
            &mut remaining,
            &mut entries,
            0,
        )?;
        if !files
            .iter()
            .any(|(path, _)| path == Path::new("tasks/main.yml"))
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
