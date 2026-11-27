//! Reviewed catalog assets: the installed catalog manifest, tool definitions
//! and payload sources, loaded fail-closed and exported inert for review.
//!
//! Every failure is a `CatalogError` variant grouped by what an operator does
//! about it. Variants carry only safe context (a tool name or a relative asset
//! path), never file contents; the config boundary projects the static reason
//! into a `ConfigError`, and the catalog CLI emits the variant code plus the
//! context as an audit record.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};

#[cfg(unix)]
type DirHandle = File;
#[cfg(windows)]
type DirHandle = PathBuf;
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};

const MANIFEST_LIMIT: u64 = 256 * 1024;
const DEFINITION_LIMIT: u64 = 256 * 1024;
const PAYLOAD_LIMIT: u64 = 8 * 1024 * 1024;
const PAYLOAD_FILES: usize = 256;
const MAX_PATH_NAME: usize = 255;

/// Fixed arguments that carry site policy: allowlists, reviewed paths and
/// device sets only a site can truthfully state. Shipped definitions never
/// contain them, so nothing an operator did not review is inherited.
/// (`allowed_operations` is not here: the catalog ships the tool's full
/// operation set, which a site narrows through the key-by-key merge.)
const POLICY_FIXED_ARGS: [&str; 8] = [
    "allowed_entries",
    "allowed_packages",
    "allowed_units",
    "approved_keys",
    "approved_root",
    "configured_paths",
    "operator_policy",
    "reviewed_devices",
];

/// A catalog problem, grouped by what an operator does about it: fix the
/// installed files, re-review the catalog data, or enable a different name.
/// Context is always a tool name or a relative asset path, never contents.
#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalog file or directory missing: {asset}")]
    Missing { asset: String },
    #[error("catalog asset unreadable: {asset}")]
    Unreadable { asset: String },
    #[error("catalog asset exceeds its size limit: {asset}")]
    Oversized { asset: String },
    #[error("catalog asset has invalid JSON or TOML: {asset}")]
    Malformed { asset: String },
    #[error("catalog layout is not a safe regular file: {asset}")]
    UnsafePath { asset: String },
    #[error("catalog asset type or depth is not allowed: {asset}")]
    UnsupportedAsset { asset: String },
    #[error("unknown catalog tool: {tool}")]
    UnknownTool { tool: String },
    #[error("catalog manifest is invalid: {asset}")]
    InvalidManifest { asset: String },
    #[error("catalog definition is invalid for tool {tool}")]
    InvalidDefinition { tool: String },
    #[error("catalog definition overrides must be site policy for tool {tool}")]
    OverrideNotSitePolicy { tool: String },
    #[error("catalog definition requires site policy for tool {tool}")]
    SitePolicyRequired { tool: String },
    #[error("catalog definition requires targets for tool {tool}")]
    TargetsRequired { tool: String },
    #[error("no catalog found; run `estus catalog install`")]
    NotInstalled,
}

impl CatalogError {
    /// Stable code emitted by the catalog CLI and used as the `ConfigError`
    /// reason at the config boundary.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Missing { .. } => "catalog_missing_asset",
            Self::Unreadable { .. } => "catalog_asset_unreadable",
            Self::Oversized { .. } => "catalog_asset_oversized",
            Self::Malformed { .. } => "catalog_asset_malformed",
            Self::UnsafePath { .. } => "catalog_path_unsafe",
            Self::UnsupportedAsset { .. } => "catalog_asset_unsupported",
            Self::UnknownTool { .. } => "catalog_tool_unknown",
            Self::InvalidManifest { .. } => "catalog_manifest_invalid",
            Self::InvalidDefinition { .. } => "catalog_definition_invalid",
            Self::OverrideNotSitePolicy { .. } => "catalog_definition_override_not_site_policy",
            Self::SitePolicyRequired { .. } => "catalog_definition_requires_site_policy",
            Self::TargetsRequired { .. } => "catalog_definition_requires_targets",
            Self::NotInstalled => "catalog_not_installed",
        }
    }

    /// The safe context value (a tool name or relative asset path).
    pub(crate) fn detail(&self) -> &str {
        match self {
            Self::Missing { asset }
            | Self::Unreadable { asset }
            | Self::Oversized { asset }
            | Self::Malformed { asset }
            | Self::UnsafePath { asset }
            | Self::UnsupportedAsset { asset }
            | Self::InvalidManifest { asset } => asset,
            Self::UnknownTool { tool }
            | Self::InvalidDefinition { tool }
            | Self::OverrideNotSitePolicy { tool }
            | Self::SitePolicyRequired { tool }
            | Self::TargetsRequired { tool } => tool,
            Self::NotInstalled => "estus catalog install",
        }
    }

    /// The audit record the catalog CLI emits: a stable code plus the safe
    /// context. File contents never enter a diagnostic.
    pub(crate) fn payload(&self) -> serde_json::Value {
        serde_json::json!({
            "event": "error",
            "code": self.reason(),
            "detail": self.detail(),
        })
    }
}

fn bounded_name(path: &Path) -> String {
    let mut name = path.to_string_lossy().to_string();
    if name.len() > MAX_PATH_NAME {
        let end = (0..=MAX_PATH_NAME)
            .rfind(|index| name.is_char_boundary(*index))
            .expect("index 0 is a char boundary");
        name.truncate(end);
    }
    name
}

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

/// Where the catalog lives when no root is given: next to the executable, as
/// `<prefix>/bin/estus` with `<prefix>/share/estus/catalog` (what
/// `estus catalog install`, the packages and Nix produce). Inside a cargo
/// `target/` tree the repository's own `catalog/` is accepted too, for
/// development; it is never searched for elsewhere.
pub(crate) fn discover_default_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    let in_cargo_target = exe_dir
        .ancestors()
        .any(|dir| dir.file_name().is_some_and(|name| name == "target"));
    let development: &[&str] = if in_cargo_target {
        &["../../catalog", "../../../catalog"]
    } else {
        &[]
    };
    for relative in std::iter::once("../share/estus/catalog").chain(development.iter().copied()) {
        let candidate = exe_dir.join(relative);
        if candidate.join("catalog.json").is_file() {
            return candidate.canonicalize().ok();
        }
    }
    None
}

/// The directory `estus catalog install` fills by default: the first place
/// [`discover_default_root`] looks.
pub(crate) fn default_install_dir() -> Option<PathBuf> {
    Some(
        std::env::current_exe()
            .ok()?
            .parent()?
            .parent()?
            .join("share/estus/catalog"),
    )
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
/// are catalog data reviewed like any other definition; an optional authority
/// may only select the ordinary SSH identity.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkstationPolicy {
    /// Optional workstation authority; only the ordinary SSH identity is supported.
    #[serde(default)]
    pub authority: Option<String>,
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

#[derive(Debug)]
pub struct Catalog {
    root: PathBuf,
    directory: DirHandle,
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

#[cfg(unix)]
fn open_child_dir(directory: &DirHandle, name: &Path) -> Result<DirHandle, CatalogError> {
    open_child(directory, name, true)
}

#[cfg(windows)]
fn open_child_dir(directory: &DirHandle, name: &Path) -> Result<DirHandle, CatalogError> {
    if name.components().count() != 1
        || !matches!(
            name.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
    }
    let path = directory.join(name);
    let meta = fs::symlink_metadata(&path).map_err(|_| CatalogError::Missing {
        asset: bounded_name(name),
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
    }
    Ok(path)
}

#[cfg(unix)]
fn open_child(
    directory: &DirHandle,
    name: &Path,
    is_directory: bool,
) -> Result<File, CatalogError> {
    if name.components().count() != 1
        || !matches!(
            name.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
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
    let file = File::from(openat(directory, name, flags, Mode::empty()).map_err(|_| {
        CatalogError::Missing {
            asset: bounded_name(name),
        }
    })?);
    let metadata = file.metadata().map_err(|_| CatalogError::Unreadable {
        asset: bounded_name(name),
    })?;
    if (is_directory && !metadata.is_dir()) || (!is_directory && !metadata.is_file()) {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
    }
    Ok(file)
}

#[cfg(windows)]
fn open_child(
    directory: &DirHandle,
    name: &Path,
    _is_directory: bool,
) -> Result<File, CatalogError> {
    if name.components().count() != 1
        || !matches!(
            name.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
    }
    let path = directory.join(name);
    let meta = fs::symlink_metadata(&path).map_err(|_| CatalogError::Missing {
        asset: bounded_name(name),
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(CatalogError::Missing {
            asset: bounded_name(name),
        });
    }
    File::open(&path).map_err(|_| CatalogError::Unreadable {
        asset: bounded_name(name),
    })
}

fn bounded_read(file: File, asset: &str, limit: u64) -> Result<Vec<u8>, CatalogError> {
    if file
        .metadata()
        .map_err(|_| CatalogError::Unreadable {
            asset: asset.to_owned(),
        })?
        .len()
        > limit
    {
        return Err(CatalogError::Oversized {
            asset: asset.to_owned(),
        });
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CatalogError::Unreadable {
            asset: asset.to_owned(),
        })?;
    if bytes.len() as u64 > limit {
        return Err(CatalogError::Oversized {
            asset: asset.to_owned(),
        });
    }
    Ok(bytes)
}

impl Catalog {
    pub fn load(root: Option<&Path>) -> Result<Self, CatalogError> {
        let root = match root {
            Some(root) => root.to_path_buf(),
            None => std::env::var_os("ESTUS_CATALOG_ROOT")
                .map(PathBuf::from)
                .or_else(discover_default_root)
                .ok_or(CatalogError::NotInstalled)?,
        };
        let root_name = bounded_name(&root);
        if fs::symlink_metadata(&root)
            .map_err(|_| CatalogError::Missing {
                asset: root_name.clone(),
            })?
            .file_type()
            .is_symlink()
        {
            return Err(CatalogError::Missing { asset: root_name });
        }
        #[cfg(unix)]
        let directory: DirHandle = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&root)
            .map_err(|_| CatalogError::Missing {
                asset: root_name.clone(),
            })?;
        #[cfg(windows)]
        let directory: DirHandle = {
            if !root.is_dir() {
                return Err(CatalogError::Missing {
                    asset: root_name.clone(),
                });
            }
            root.clone()
        };
        let root =
            fs::canonicalize(&root).map_err(|_| CatalogError::Unreadable { asset: root_name })?;
        let bytes = bounded_read(
            open_child(&directory, Path::new("catalog.json"), false)?,
            "catalog.json",
            MANIFEST_LIMIT,
        )?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| CatalogError::Malformed {
                asset: "catalog.json".to_owned(),
            })?;
        if manifest.schema != 3
            || !name_valid(&manifest.version)
            || manifest.tools.is_empty()
            || manifest.tools.len() > 1024
            || manifest.presets.len() > 64
        {
            return Err(CatalogError::InvalidManifest {
                asset: "catalog.json".to_owned(),
            });
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
                // is required; site-policy templates stay out of open mode, and
                // an explicit workstation authority may only select ordinary SSH.
                || template.workstation.is_some() && template.policy_required
                || template
                    .workstation
                    .as_ref()
                    .and_then(|w| w.authority.as_deref())
                    .is_some_and(|authority| authority != "automation")
            {
                return Err(CatalogError::InvalidDefinition { tool: name.clone() });
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
                return Err(CatalogError::InvalidManifest {
                    asset: name.clone(),
                });
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
        directory: &DirHandle,
        name: &str,
        definition: &str,
    ) -> Result<toml::Table, CatalogError> {
        let bytes = bounded_read(
            open_child(directory, Path::new(definition), false)?,
            definition,
            DEFINITION_LIMIT,
        )?;
        let table: toml::Table = std::str::from_utf8(&bytes)
            .map_err(|_| CatalogError::Malformed {
                asset: definition.to_owned(),
            })?
            .parse()
            .map_err(|_| CatalogError::Malformed {
                asset: definition.to_owned(),
            })?;
        // A definition holds tool tables and nothing else: targets, authority
        // and policy belong to the site, never to the shipped asset.
        if table.keys().any(|key| key != "tools") {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        let tools = table
            .get("tools")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let tool = tools
            .get(name)
            .and_then(toml::Value::as_table)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        if tools.len() != 1 {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        let effects = tool
            .get("effects")
            .and_then(toml::Value::as_array)
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let mut effect_names = Vec::with_capacity(effects.len());
        for effect in effects {
            effect_names.push(
                effect
                    .as_str()
                    .ok_or_else(|| CatalogError::InvalidDefinition {
                        tool: name.to_owned(),
                    })?,
            );
        }
        if !risk_prefix_matches_effects(name, &effect_names) {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        if tool
            .get("fixed_args")
            .and_then(toml::Value::as_table)
            .is_some_and(|fixed| {
                fixed
                    .keys()
                    .any(|key| POLICY_FIXED_ARGS.contains(&key.as_str()))
            })
        {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        Ok(table)
    }

    pub fn definition(&self, name: &str) -> Result<toml::Table, CatalogError> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        Self::validate_definition(&self.directory, name, &template.definition)
    }

    /// The installed definition for `name`, wired to the installed payload
    /// directory and to the site's own targets.
    ///
    /// `overrides` is the config's `[tools.<name>]` table when it carries no
    /// `execution`. `fixed_args`, `constraints` and `limits` merge key by key
    /// over the installed values, so a site that restates one argument never
    /// drops the interpreter or manager scope beside it; `targets`,
    /// `authority`, `input_schema` and `input_map` replace the installed value
    /// wholly, because they name hosts, credentials and a contract only the
    /// site can state.
    ///
    /// `targets` and `constraints` never survive from the catalog, and shipped
    /// definitions carry no site policy at all: a collector that needs an
    /// allowlist fails closed until the site supplies one. A `policy_required`
    /// template must restate policy in `fixed_args`, `constraints` or
    /// `input_schema` (the caller enum is the allowlist for tools such as
    /// kernel-module or device selectors) before it is materialised.
    pub(crate) fn site_definition(
        &self,
        name: &str,
        overrides: Option<&toml::Table>,
        destinations: &[String],
    ) -> Result<toml::Value, CatalogError> {
        const SITE_KEYS: [&str; 7] = [
            "targets",
            "authority",
            "fixed_args",
            "constraints",
            "input_schema",
            "input_map",
            "limits",
        ];
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        if let Some(overrides) = overrides
            && overrides
                .keys()
                .any(|key| !SITE_KEYS.contains(&key.as_str()))
        {
            return Err(CatalogError::OverrideNotSitePolicy {
                tool: name.to_owned(),
            });
        }
        // Shipped definitions carry no site policy, so a policy-required
        // template is materialised only when the site states its own fixed
        // arguments, constraints or caller schema (the enum several tools use
        // as their allowlist).
        if template.policy_required
            && overrides.is_none_or(|table| {
                !["fixed_args", "constraints", "input_schema"]
                    .iter()
                    .any(|key| table.contains_key(*key))
            })
        {
            return Err(CatalogError::SitePolicyRequired {
                tool: name.to_owned(),
            });
        }
        let mut document = Self::validate_definition(&self.directory, name, &template.definition)?;
        let tools = document
            .remove("tools")
            .and_then(|value| value.try_into::<toml::Table>().ok())
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let mut definition = tools
            .into_iter()
            .next()
            .map(|(_, value)| value)
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let table = definition
            .as_table_mut()
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
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
                                .ok_or_else(|| CatalogError::InvalidDefinition {
                                    tool: name.to_owned(),
                                })?,
                        ),
                    ),
                ])),
            );
        }
        if let Some(overrides) = overrides {
            for (key, value) in overrides {
                match (key.as_str(), table.get_mut(key)) {
                    ("fixed_args" | "constraints" | "limits", Some(existing))
                        if existing.is_table() && value.is_table() =>
                    {
                        let merged = existing.as_table_mut().ok_or_else(|| {
                            CatalogError::InvalidDefinition {
                                tool: name.to_owned(),
                            }
                        })?;
                        for (argument, argument_value) in value.as_table().into_iter().flatten() {
                            merged.insert(argument.clone(), argument_value.clone());
                        }
                    }
                    _ => {
                        table.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        if !table.contains_key("targets") {
            if destinations.is_empty() {
                return Err(CatalogError::TargetsRequired {
                    tool: name.to_owned(),
                });
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
    ) -> Result<WorkstationEntry, CatalogError> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        let policy =
            template
                .workstation
                .as_ref()
                .ok_or_else(|| CatalogError::InvalidDefinition {
                    tool: name.to_owned(),
                })?;
        if matches!(template.qualification, Qualification::LaboratoryOnly) {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        let mut table = Self::validate_definition(&self.directory, name, &template.definition)?;
        let mut tools = table
            .remove("tools")
            .and_then(|v| v.try_into::<toml::Table>().ok())
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let mut definition = tools
            .remove(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        if !tools.is_empty() {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        let table = definition
            .as_table_mut()
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        if let Some(authority) = &policy.authority {
            if authority != "automation" {
                return Err(CatalogError::InvalidDefinition {
                    tool: name.to_owned(),
                });
            }
            table.insert("authority".into(), toml::Value::String(authority.clone()));
        }
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
                let payloads_dir = open_child_dir(&self.directory, Path::new("payloads"))?;
                let tool_dir = open_child_dir(&payloads_dir, Path::new(name))?;
                let source_bytes = bounded_read(
                    open_child(&tool_dir, Path::new("collector.py"), false)?,
                    &format!("payloads/{name}/collector.py"),
                    1_048_576,
                )?;
                let manifest_raw = bounded_read(
                    open_child(&tool_dir, Path::new("manifest.json"), false)?,
                    &format!("payloads/{name}/manifest.json"),
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

    /// Tools published under `--yolo`: every reviewed workstation tool plus
    /// wildcard-synthesizable operational templates. `laboratory_only` templates
    /// remain hidden unless `include_lab` is also passed.
    pub(crate) fn yolo_tool_names(&self, include_lab: bool) -> impl Iterator<Item = &str> {
        self.manifest
            .tools
            .iter()
            .filter_map(move |(name, template)| {
                if matches!(template.qualification, Qualification::LaboratoryOnly) && !include_lab {
                    return None;
                }
                // Collectors requiring site-specific alias maps with no wildcard form.
                if matches!(name.as_str(), "observe_device_attributes") {
                    return None;
                }
                Some(name.as_str())
            })
    }

    /// Build a `--yolo` entry: reuses the reviewed `workstation` block when
    /// present, otherwise loads the shipped definition and synthesizes wildcard
    /// policy arguments (`["*"]`, `allow_runtime_tuning = true`, etc.) for
    /// collectors whose `manifest.json` expects an operator policy input.
    pub(crate) fn load_yolo_entry(
        &self,
        name: &str,
        include_lab: bool,
    ) -> Result<WorkstationEntry, CatalogError> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        if matches!(template.qualification, Qualification::LaboratoryOnly) && !include_lab {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        if template.workstation.is_some()
            && !matches!(template.qualification, Qualification::LaboratoryOnly)
        {
            return self.load_workstation_entry(name);
        }
        let mut table = Self::validate_definition(&self.directory, name, &template.definition)?;
        let mut tools = table
            .remove("tools")
            .and_then(|v| v.try_into::<toml::Table>().ok())
            .ok_or_else(|| CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            })?;
        let mut definition = tools
            .remove(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        if !tools.is_empty() {
            return Err(CatalogError::InvalidDefinition {
                tool: name.to_owned(),
            });
        }
        let def_table =
            definition
                .as_table_mut()
                .ok_or_else(|| CatalogError::InvalidDefinition {
                    tool: name.to_owned(),
                })?;
        def_table.remove("constraints");
        match &template.executor {
            Executor::AnsibleModule { .. } => Ok(WorkstationEntry::Module { definition }),
            Executor::NativePayload { .. } => {
                let payloads_dir = open_child_dir(&self.directory, Path::new("payloads"))?;
                let tool_dir = open_child_dir(&payloads_dir, Path::new(name))?;
                let source_bytes = bounded_read(
                    open_child(&tool_dir, Path::new("collector.py"), false)?,
                    &format!("payloads/{name}/collector.py"),
                    1_048_576,
                )?;
                let manifest_raw = bounded_read(
                    open_child(&tool_dir, Path::new("manifest.json"), false)?,
                    &format!("payloads/{name}/manifest.json"),
                    262_144,
                )?;
                inject_yolo_fixed_args(name, def_table, &manifest_raw);
                Ok(WorkstationEntry::Payload {
                    definition,
                    source: source_bytes,
                    manifest: manifest_raw,
                })
            }
        }
    }

    pub fn copy_assets(&self, name: &str, destination: &Path) -> Result<(), CatalogError> {
        let template = self
            .manifest
            .tools
            .get(name)
            .ok_or_else(|| CatalogError::UnknownTool {
                tool: name.to_owned(),
            })?;
        let required: &[&str] = match &template.executor {
            Executor::NativePayload { .. } => &["collector.py", "manifest.json"],
            Executor::AnsibleModule { .. } => {
                return Err(CatalogError::InvalidDefinition {
                    tool: name.to_owned(),
                });
            }
        };
        if destination.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(CatalogError::UnsafePath {
                asset: bounded_name(destination),
            });
        }
        let payloads = open_child_dir(&self.directory, Path::new("payloads"))?;
        let directory = open_child_dir(&payloads, Path::new(name))?;
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
        if let Some(missing) = required
            .iter()
            .find(|req| !files.iter().any(|(path, _)| path == Path::new(*req)))
        {
            return Err(CatalogError::Missing {
                asset: format!("payloads/{name}/{missing}"),
            });
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut ancestor = Some(parent);
        while let Some(path) = ancestor {
            if !path.as_os_str().is_empty()
                && fs::symlink_metadata(path)
                    .map_err(|_| CatalogError::Unreadable {
                        asset: bounded_name(path),
                    })?
                    .file_type()
                    .is_symlink()
            {
                return Err(CatalogError::UnsafePath {
                    asset: bounded_name(path),
                });
            }
            ancestor = path.parent();
        }
        #[cfg_attr(windows, allow(unused_mut))]
        let mut dest_builder = fs::DirBuilder::new();
        #[cfg(unix)]
        dest_builder.mode(0o700);
        dest_builder
            .create(destination)
            .map_err(|_| CatalogError::UnsafePath {
                asset: bounded_name(destination),
            })?;
        let result = (|| {
            for (relative, bytes) in files {
                let output = destination.join(relative);
                if let Some(parent) = output.parent() {
                    let mut dir_builder = fs::DirBuilder::new();
                    dir_builder.recursive(true);
                    #[cfg(unix)]
                    dir_builder.mode(0o700);
                    dir_builder
                        .create(parent)
                        .map_err(|_| CatalogError::Unreadable {
                            asset: bounded_name(parent),
                        })?;
                }
                let output_name = bounded_name(&output);
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                options
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
                let mut file = options.open(output).map_err(|_| CatalogError::Unreadable {
                    asset: output_name.clone(),
                })?;
                file.write_all(&bytes)
                    .map_err(|_| CatalogError::Unreadable { asset: output_name })?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        result
    }
}

fn inject_yolo_fixed_args(name: &str, def_table: &mut toml::Table, manifest_raw: &[u8]) {
    let Ok(manifest_json) = serde_json::from_slice::<serde_json::Value>(manifest_raw) else {
        return;
    };
    let mut needed = BTreeSet::new();
    if let Some(argv) = manifest_json
        .get("argv")
        .and_then(serde_json::Value::as_array)
    {
        for item in argv {
            if let Some(arg_name) = item.get("name").and_then(serde_json::Value::as_str) {
                needed.insert(arg_name.to_owned());
            }
            if let Some(fields) = item.get("fields").and_then(serde_json::Value::as_object) {
                for field in fields.values() {
                    if let Some(arg_name) = field.get("name").and_then(serde_json::Value::as_str) {
                        needed.insert(arg_name.to_owned());
                    }
                }
            }
        }
    }
    let mapped: BTreeSet<String> = def_table
        .get("input_map")
        .and_then(toml::Value::as_table)
        .map(|table| {
            table
                .values()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let fixed = def_table
        .entry("fixed_args")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(fixed_table) = fixed.as_table_mut() else {
        return;
    };
    let wildcard_list = || toml::Value::Array(vec![toml::Value::String("*".to_owned())]);
    for key in ["allowed_units", "allowed_entries", "approved_keys"] {
        if needed.contains(key) && !mapped.contains(key) && !fixed_table.contains_key(key) {
            fixed_table.insert(key.to_owned(), wildcard_list());
        }
    }
    if needed.contains("approved_root")
        && !mapped.contains("approved_root")
        && !fixed_table.contains_key("approved_root")
    {
        fixed_table.insert(
            "approved_root".to_owned(),
            toml::Value::String("/system.slice".to_owned()),
        );
    }
    if needed.contains("configured_paths")
        && !mapped.contains("configured_paths")
        && !fixed_table.contains_key("configured_paths")
    {
        let mut paths = toml::Table::new();
        paths.insert("root".into(), toml::Value::String("/".into()));
        paths.insert("var".into(), toml::Value::String("/var".into()));
        paths.insert("tmp".into(), toml::Value::String("/tmp".into()));
        paths.insert("home".into(), toml::Value::String("/home".into()));
        fixed_table.insert("configured_paths".to_owned(), toml::Value::Table(paths));
    }
    if needed.contains("operator_policy")
        && !mapped.contains("operator_policy")
        && !fixed_table.contains_key("operator_policy")
    {
        let mut policy = toml::Table::new();
        if let Some(props) = manifest_json
            .pointer("/contract/schema/properties/operator_policy/properties")
            .and_then(serde_json::Value::as_object)
        {
            for (field, schema) in props {
                let field_type = schema.get("type").and_then(serde_json::Value::as_str);
                match field_type {
                    Some("string") => {
                        let value = schema
                            .get("enum")
                            .and_then(serde_json::Value::as_array)
                            .and_then(|values| values.first())
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("*");
                        policy.insert(field.clone(), toml::Value::String(value.to_owned()));
                    }
                    Some("boolean") => {
                        policy.insert(field.clone(), toml::Value::Boolean(true));
                    }
                    Some("array") => {
                        let item_type = schema
                            .pointer("/items/type")
                            .and_then(serde_json::Value::as_str);
                        match item_type {
                            Some("string") => {
                                let values = schema
                                    .pointer("/items/enum")
                                    .and_then(serde_json::Value::as_array)
                                    .map(|items| {
                                        items
                                            .iter()
                                            .filter_map(serde_json::Value::as_str)
                                            .map(|s| toml::Value::String(s.to_owned()))
                                            .collect::<Vec<_>>()
                                    })
                                    .filter(|v| !v.is_empty())
                                    .map_or_else(wildcard_list, toml::Value::Array);
                                policy.insert(field.clone(), values);
                            }
                            Some("integer") => {
                                policy.insert(
                                    field.clone(),
                                    toml::Value::Array(
                                        [22, 53, 80, 443, 8080, 8443]
                                            .into_iter()
                                            .map(toml::Value::Integer)
                                            .collect(),
                                    ),
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        let _ = name;
        fixed_table.insert("operator_policy".to_owned(), toml::Value::Table(policy));
    }
}

struct PayloadScan {
    files: Vec<(PathBuf, Vec<u8>)>,
    remaining: u64,
    entries: usize,
}

fn collect_payload(
    directory: &DirHandle,
    source: &Path,
    relative: &Path,
    scan: &mut PayloadScan,
    depth: usize,
) -> Result<(), CatalogError> {
    if depth > 16 {
        return Err(CatalogError::UnsupportedAsset {
            asset: bounded_name(source),
        });
    }
    let source_name = bounded_name(source);
    for entry in fs::read_dir(source).map_err(|_| CatalogError::Unreadable {
        asset: source_name.clone(),
    })? {
        let entry = entry.map_err(|_| CatalogError::Unreadable {
            asset: source_name.clone(),
        })?;
        scan.entries += 1;
        if scan.entries > PAYLOAD_FILES {
            return Err(CatalogError::UnsupportedAsset { asset: source_name });
        }
        let name = entry.file_name();
        let kind = entry.file_type().map_err(|_| CatalogError::Unreadable {
            asset: source_name.clone(),
        })?;
        let path = relative.join(&name);
        if kind.is_dir() {
            if name == "__pycache__" {
                continue;
            }
            let child = open_child_dir(directory, Path::new(&name))?;
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
                return Err(CatalogError::UnsupportedAsset {
                    asset: bounded_name(&path),
                });
            }
            let bytes = bounded_read(
                open_child(directory, Path::new(&name), false)?,
                &bounded_name(&path),
                scan.remaining,
            )?;
            scan.remaining -= bytes.len() as u64;
            scan.files.push((path, bytes));
        } else {
            return Err(CatalogError::UnsafePath {
                asset: bounded_name(&path),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod site_overlay_tests {
    use super::*;

    fn catalog_root() -> Catalog {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        Catalog::load(Some(&root)).expect("load catalog")
    }

    /// A site that restates one fixed argument keeps every sibling the catalog
    /// supplies; a full replacement would silently drop the interpreter and
    /// leave the collector unrunnable.
    #[test]
    fn fixed_args_merge_key_by_key_and_targets_replace_wholly() {
        let catalog = catalog_root();
        let mut overrides = toml::Table::new();
        overrides.insert(
            "fixed_args".into(),
            toml::Value::Table(toml::Table::from_iter([(
                "target_python".to_owned(),
                toml::Value::from("/opt/python3"),
            )])),
        );
        overrides.insert(
            "targets".into(),
            toml::Value::Array(vec![toml::Value::from("site")]),
        );
        let definition = catalog
            .site_definition(
                "observe_systemd_jobs",
                Some(&overrides),
                &["other".to_owned()],
            )
            .expect("site overlay");
        let fixed = &definition["fixed_args"];
        assert_eq!(fixed["target_python"].as_str(), Some("/opt/python3"));
        assert_eq!(fixed["manager_scope"].as_str(), Some("system"));
        assert_eq!(definition["targets"].as_array().map(Vec::len), Some(1));
        assert_eq!(definition["targets"][0].as_str(), Some("site"));
        assert_eq!(
            definition["execution"]["kind"].as_str(),
            Some("native_payload")
        );
    }

    /// Policy-required templates cannot be materialised from the catalog alone,
    /// and no shipped definition carries an allowlist an operator did not review.
    #[test]
    fn policy_required_templates_need_site_policy_and_shipped_files_carry_none() {
        let catalog = catalog_root();
        let names: Vec<String> = catalog.manifest().tools.keys().cloned().collect();
        let mut missing = Vec::new();
        for name in &names {
            let template = &catalog.manifest().tools[name];
            let definition = catalog.definition(name).expect("definition");
            let tool = definition["tools"][name].as_table().expect("tool table");
            assert_eq!(definition.len(), 1, "{name}: non-tool top-level keys");
            if let Some(fixed) = tool.get("fixed_args").and_then(toml::Value::as_table) {
                for key in fixed.keys() {
                    assert!(
                        !POLICY_FIXED_ARGS.contains(&key.as_str()),
                        "{name}: shipped definition carries site policy {key}"
                    );
                }
            }
            assert!(tool.get("targets").is_none(), "{name}: shipped targets");
            if template.policy_required
                && catalog
                    .site_definition(name, None, &["host".to_owned()])
                    .is_ok()
            {
                missing.push(name.clone());
            }
        }
        assert!(
            missing.is_empty(),
            "policy-required without site policy: {missing:?}"
        );
        // A caller enum is the allowlist for selector tools, so a site schema
        // alone is site policy; collectors still fail closed on missing lists.
        let schema_only = toml::Table::from_iter([(
            "input_schema".to_owned(),
            toml::Value::Table(toml::Table::new()),
        )]);
        assert!(
            catalog
                .site_definition(
                    "observe_kernel_module",
                    Some(&schema_only),
                    &["host".to_owned()]
                )
                .is_ok()
        );
        assert!(matches!(
            catalog
                .site_definition("observe_kernel_module", None, &["host".to_owned()])
                .unwrap_err(),
            CatalogError::SitePolicyRequired { .. }
        ));
    }
}

#[cfg(test)]
mod workstation_tests {
    use super::*;
    use crate::bindings::Bindings;
    use crate::config::Limits;

    #[test]
    fn yolo_catalog_entries_activate_with_and_without_lab() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = Catalog::load(Some(&root)).expect("load catalog");
        let limits = Limits::default();
        for include_lab in [false, true] {
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
            let mut count = 0usize;
            let mut failures = Vec::new();
            for name in catalog.yolo_tool_names(include_lab) {
                count += 1;
                let result = match catalog
                    .load_yolo_entry(name, include_lab)
                    .unwrap_or_else(|e| panic!("{name}: {}", e.reason()))
                {
                    WorkstationEntry::Payload {
                        definition,
                        source,
                        manifest,
                    } => bindings.push_dynamic_payload(
                        name.to_owned(),
                        definition,
                        source,
                        &manifest,
                        &limits,
                    ),
                    WorkstationEntry::Module { definition } => {
                        bindings.push_dynamic_ansible_module(name.to_owned(), definition, &limits)
                    }
                };
                if let Err(error) = result {
                    failures.push(format!("{name}: {error:?}"));
                }
            }
            assert!(
                failures.is_empty(),
                "include_lab={include_lab}:\n{}",
                failures.join("\n")
            );
            if include_lab {
                assert!(
                    count > 95,
                    "expected almost full catalog under --yolo --include-lab, got {count}"
                );
            } else {
                assert!(
                    count > 80,
                    "expected broad non-lab catalog under --yolo, got {count}"
                );
            }
        }
    }

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
                .unwrap_or_else(|e| panic!("{name}: {}", e.reason()))
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

    #[test]
    fn workstation_authority_rejects_elevated_and_unknown_values_at_load() {
        for bad_authority in ["automation:catalog", "automation:root", "sudo", ""] {
            let temporary = tempfile::tempdir().expect("tempdir");
            let root = temporary.path().canonicalize().expect("canonicalize");
            let payload = root.join("payloads/observe_cpu");
            fs::create_dir_all(&payload).expect("payload dir");
            fs::write(
                root.join("catalog.json"),
                serde_json::json!({
                    "schema": 3,
                    "version": "1",
                    "presets": {},
                    "tools": {
                        "observe_cpu": {
                            "definition": "observe_cpu.toml",
                            "executor": {"kind": "native_payload", "path": "payloads/observe_cpu"},
                            "qualification": "site_policy_template",
                            "policy_required": false,
                            "requires": ["linux"],
                            "workstation": {
                                "authority": bad_authority,
                                "fixed_args": {"target_python": "/usr/bin/python3"},
                                "input_schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": false},
                                "input_map": {}
                            }
                        }
                    }
                })
                .to_string(),
            )
            .expect("write catalog.json");
            fs::write(
                root.join("observe_cpu.toml"),
                "[tools.observe_cpu]\ndescription = 'fixture'\neffects = [\"read\"]\n",
            )
            .expect("write definition");
            fs::write(payload.join("collector.py"), "raise SystemExit(0)\n").expect("collector");
            fs::write(payload.join("manifest.json"), "{}\n").expect("manifest");
            assert!(
                matches!(
                    Catalog::load(Some(&root)),
                    Err(CatalogError::InvalidDefinition { ref tool }) if tool == "observe_cpu"
                ),
                "Catalog::load accepted invalid workstation.authority {bad_authority:?}"
            );
        }
    }
}

#[cfg(test)]
mod error_variant_tests {
    use super::*;

    fn small_catalog(root: &Path) {
        let payload = root.join("payloads/observe_cpu");
        fs::create_dir_all(&payload).expect("fixture directory");
        fs::write(
            root.join("catalog.json"),
            r#"{"schema":3,"version":"1","presets":{},"tools":{"observe_cpu":{"definition":"observe_cpu.toml","executor":{"kind":"native_payload","path":"payloads/observe_cpu"},"qualification":"site_policy_template","policy_required":false,"requires":["linux"]}}}"#,
        )
        .expect("fixture catalog.json");
        fs::write(
            root.join("observe_cpu.toml"),
            "[tools.observe_cpu]\ndescription = 'fixture'\neffects = [\"read\"]\n",
        )
        .expect("fixture observe_cpu.toml");
        fs::write(payload.join("collector.py"), "raise SystemExit(0)\n")
            .expect("fixture collector.py");
        fs::write(payload.join("manifest.json"), "{}\n").expect("fixture manifest.json");
    }

    #[test]
    fn error_variants_carry_safe_context_without_contents() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();

        // Missing: the catalog root itself is absent.
        let error = Catalog::load(Some(&root.join("missing"))).expect_err("absent root must fail");
        assert!(matches!(&error, CatalogError::Missing { .. }), "{error:?}");

        small_catalog(&root);
        let catalog = Catalog::load(Some(&root)).expect("fixture loads");

        // UnknownTool: a name that is not in the manifest.
        let error = catalog
            .definition("not_a_tool")
            .expect_err("unknown name must fail");
        assert!(
            error.to_string() == "unknown catalog tool: not_a_tool",
            "{error}"
        );
        assert!(error.reason() == "catalog_tool_unknown", "{}", error);

        // Oversized: the definition exceeds its limit; its contents stay out.
        let marker = "SECRET_MARKER_MUST_NOT_LEAK";
        let mut definition = vec![b'x'; DEFINITION_LIMIT as usize + 1];
        definition[1024..1024 + marker.len()].copy_from_slice(marker.as_bytes());
        fs::write(root.join("observe_cpu.toml"), &definition).unwrap();
        let error = catalog
            .definition("observe_cpu")
            .expect_err("oversized definition must fail");
        assert!(
            matches!(&error, CatalogError::Oversized { asset } if asset == "observe_cpu.toml"),
            "{error:?}"
        );
        assert!(!error.to_string().contains(marker));

        // Malformed: TOML that does not parse.
        fs::write(root.join("observe_cpu.toml"), "[not valid toml = =\n").unwrap();
        let error = catalog
            .definition("observe_cpu")
            .expect_err("malformed definition must fail");
        assert!(
            matches!(&error, CatalogError::Malformed { asset } if asset == "observe_cpu.toml"),
            "{error:?}"
        );
        assert!(!error.to_string().contains("not valid toml"));
        fs::write(
            root.join("observe_cpu.toml"),
            "[tools.observe_cpu]\ndescription = 'fixture'\neffects = [\"read\"]\n",
        )
        .unwrap();

        // UnsupportedAsset: a payload file type the catalog does not review.
        let payload = root.join("payloads/observe_cpu");
        fs::write(payload.join("extra.sh"), "#!/bin/sh\n").unwrap();
        let error = catalog
            .copy_assets("observe_cpu", &root.join("out"))
            .expect_err("unexpected payload type must fail");
        assert!(
            matches!(&error, CatalogError::UnsupportedAsset { asset } if asset.ends_with("extra.sh")),
            "{error:?}"
        );
        fs::remove_file(payload.join("extra.sh")).unwrap();

        // Missing: a payload without its mandatory files names the exact path.
        fs::remove_file(payload.join("collector.py")).unwrap();
        let error = catalog
            .copy_assets("observe_cpu", &root.join("out"))
            .expect_err("incomplete payload must fail");
        assert!(
            matches!(&error, CatalogError::Missing { asset } if asset == "payloads/observe_cpu/collector.py"),
            "{error:?}"
        );

        // The CLI audit record carries the stable code plus safe context only.
        let error = catalog
            .definition("not_a_tool")
            .expect_err("unknown name again");
        let record = error.payload();
        assert_eq!(record["event"], "error");
        assert_eq!(record["code"], "catalog_tool_unknown");
        assert_eq!(record["detail"], "not_a_tool");
        assert!(!record.to_string().contains("fixture"));
    }
}
