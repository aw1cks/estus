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
    workstation_adapted: bool,
}

const PINNED_DYNAMIC_PAYLOADS: &[PinnedDynamicPayload] = &[
    PinnedDynamicPayload {
        name: "inspect_processes",
        toml_sha256: "b8eb943622bb4b5727ffe005293b6f57f421c08e79b205ffd2a8f306459df4c3",
        source_sha256: "55116ba7c26c2fae296246afcc26c7247ce6122bc0cbacb4af94d4af7cbfd5ab",
        manifest_sha256: "6057feb1cb38b1779dab3123f415249cf566d24a1595a3973675799299e308a6",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "inspect_sockets",
        toml_sha256: "7935f68c69775859ea77c977bea139c7b4a19c65cb90bb74dadbd7c84e98dc70",
        source_sha256: "8221541c2274dcdfad554037844b5cf762ebfaa9287989e4f3c073f4aabb2347",
        manifest_sha256: "dc06e0988eaabfecbf8e4105678aa2768526822b69c9b900e21163c2ccb90697",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_cpu",
        toml_sha256: "dfaa4def61f1f3d2ae6383eaa2f6f6f09475910a35f306ced1294f5eac117200",
        source_sha256: "f8767fb99e075259f3b104f23e5cbff8478cf502f2c91308a9fd27b9117cef64",
        manifest_sha256: "6035fca16346ca8913557980e4f6925ff42fb3b271fb65a84a34fa80f8a7cbce",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_filesystem_usage",
        toml_sha256: "2ba61be0af96b8159436940d68c9759792f1c976ef4c011cdf4f212605d97001",
        source_sha256: "7b1c7c1b72b5e6bf11f8a14cd329fad5557532854e68e09ee39473e57c3e3930",
        manifest_sha256: "cd387051a7eb8d1a1b49919fe73bae740b5ac637a2889cf9a32f92bda6b630e3",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_kernel_modules",
        toml_sha256: "c21eb8a9a2fb06d8c7b7900cf0fc60e05b4624bc01f271d4a2d3e76a575304fb",
        source_sha256: "6310b9d1738cb4995869d86bbd849b9a5443ef8883fabfaf48bd515520394e01",
        manifest_sha256: "2c1795173447652afd471d32abed056b00610adb6e595e4c262b99c2ad704a34",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_kernel_state",
        toml_sha256: "55b660094ce9cacc140f96282674546ea4272386aa677d93f6ae5bd6a95fe903",
        source_sha256: "8ebfab3f0114bf8828bd7f8ee8e1307df218747f85b5028ceca222bdabe2beb8",
        manifest_sha256: "0455b24d107bea1c3c322177f9a099830d7ae0395b0ad974d4c5524e7d3b22ef",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_memory",
        toml_sha256: "75e97867765313558ad6257716c903fdb4f08944bef9557734b820b6c936ff0e",
        source_sha256: "eae9433cc26d1bb5ae810b9b680ef35acd120da960fadb9db205087d90814b27",
        manifest_sha256: "e88b7365b9c8afc9f8f2c4fba59b81fd4975a5e612e5291ab61623853d851811",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_network_addresses",
        toml_sha256: "80c7df78100a443b81277d9da32839e2f7105744e5706b052b4e2441d180480d",
        source_sha256: "ef4437b785e62981d7efdfb6aa530f31ad35bb2fcbc7d728da595c78481e0c35",
        manifest_sha256: "3164e652cdfa1b20abefeb491a9825e3551f891ab822e84a662a995dfea7412d",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_network_interface_stats",
        toml_sha256: "03746d2ab916c211dee501fe237ee38a0ffdb34156d77c6ff45b0d81e1563b72",
        source_sha256: "a84a9f194aace5824ffd3d9606af8acfeb3cc4104b7a379a2d93075f8ec9ecec",
        manifest_sha256: "7eedd026b1d3a08454d7511ad5b273fcbfb44a4716f4f885f2e94a844ccd1035",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_network_links",
        toml_sha256: "6a4e473a17bdf2ccb867c11d7eb2ad02a682db4f10e121f2525349e26b42a562",
        source_sha256: "cf1548cebfd20f9897af0b4831aab28de5ee665795760e67c013f8c5cd38d6aa",
        manifest_sha256: "ebaf11547572f2b9b2fba68a05b3640ae7889346b5bfb9fa80a407b81de69909",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_network_routes",
        toml_sha256: "c117178c0aa42afa378933966b2a97ee1a5e47f2f05f54ba898837e60cd13f5b",
        source_sha256: "2c53406cce4262b69e206175eb77cae07369704f386167484307cf8fef5cc75a",
        manifest_sha256: "c5f0432482c5c6acc29fc494cffdaa74cb06c1c511597715841be602281be072",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_pci_devices",
        toml_sha256: "3153077113d09ccb47ed0560229e4bb0cdb9449041d85e2490269fd179af44d2",
        source_sha256: "56312c1c3ec5bef4df87d1c6db9747edf3aa2adf4c5ee04ad86d95fcb825df35",
        manifest_sha256: "6a732c412db51140782856fd8adb03486a7ebd5a095f34c279046ffa2686547a",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_pci_topology",
        toml_sha256: "ad3d2d9b4b15f144056c0de6e77c032c97bbcc5c6d3553d1b507d2dd7910bdfc",
        source_sha256: "11f02d36676815324a2b234beed97c16e8887ed8753b46420a5eb03fa401420b",
        manifest_sha256: "e5e51166a3c930eae30ed4cdf662a20d157259fc61347d4aace7013e53aa5acc",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_pressure",
        toml_sha256: "7751ea63a765e676e7cf9c250e8aeb4855773230016aa93174a40ff2aad81476",
        source_sha256: "bf1e7663c14cd92cdaa8cc5e603007adea8c668a359ce7e22f907c83f88bdf9e",
        manifest_sha256: "3c38e3ea311dc50792f6d10684c6b16df1d0200d28005fb202eb934b8b459868",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_systemd_jobs",
        toml_sha256: "0793aeaa3d7c9c71c6784b65025237eb30ccc06100d7ffd4235e85ed357c8af4",
        source_sha256: "2d88cd269a15566130a5823d1f2c9880507a7530ca4d8f4c245c0094459a8f57",
        manifest_sha256: "c3350bf95c8626a5ab0e51bfcfed2769bc1e551766dd70a36f0d8775ebb08df3",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_systemd_sockets",
        toml_sha256: "e188a88f6bf68886e7fef7413b9662f6d52c52339b22af7e0fa37e9e067675ad",
        source_sha256: "9c1919e4aa7ec6933dbe9029fc6b0917c71884b6bc9d0ca4f140f87b9bbd8403",
        manifest_sha256: "41657219ba4886ac42ddafd7f45ca76b4918f58da27a072a045b8f2fa6c08e25",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_systemd_timers",
        toml_sha256: "5caa815b71654c03aaf7aec50572d896cfee43df62df6110efcd37a9e1bcbef1",
        source_sha256: "51a914545bb0a5d013466993adaacad56faebdff2651f251373706a113b4118b",
        manifest_sha256: "855f69d6a987768a039f58e4ee48ca184af002a1f46970ca939c9b05379a654f",
        workstation_adapted: false,
    },
    PinnedDynamicPayload {
        name: "observe_systemd_units",
        toml_sha256: "260395ced357942ee029e08904574368d1b232100657b7f8c43cc262e977bb73",
        source_sha256: "793438fbace6b73f6ab7f14a9a9c5281bf8f8baa4ac92ceee28679da7c9ca323",
        manifest_sha256: "051cf5f8c068fc5006a0d30d8e702904d3916c33a3e9a50abbb9d436b7f3a867",
        workstation_adapted: true,
    },
    PinnedDynamicPayload {
        name: "observe_time_sync",
        toml_sha256: "699bfba894bfaea288b6e9c0dff1ec5f7266809405bb33e7a252b01d8c791ef3",
        source_sha256: "a99e7d8104373bd2b9a522d3f0ac6ce90168b65c742f1b78a4247389f385247d",
        manifest_sha256: "c71f16b5f418682e1d5b7a659ac5d4c854c7312dd0e9278822b6f90edfe663ff",
        workstation_adapted: false,
    },
];

pub(crate) fn pinned_dynamic_payload_names() -> impl Iterator<Item = &'static str> {
    PINNED_DYNAMIC_PAYLOADS.iter().map(|p| p.name)
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
    match name {
        "observe_systemd_units" => {
            table
                .get_mut("fixed_args")
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?
                .insert("unit_pattern".into(), toml::Value::String("*".into()));
        }
        "observe_filesystem_usage" => {
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
            table
                .get_mut("fixed_args")
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?
                .insert("configured_paths".into(), toml::Value::Table(paths));
            table
                .get_mut("input_schema")
                .and_then(toml::Value::as_table_mut)
                .and_then(|s| s.get_mut("properties"))
                .and_then(toml::Value::as_table_mut)
                .and_then(|p| p.get_mut("path_id"))
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?
                .insert(
                    "enum".into(),
                    toml::Value::Array(
                        ["root", "var", "tmp", "home", "run"]
                            .into_iter()
                            .map(|s| toml::Value::String(s.into()))
                            .collect(),
                    ),
                );
        }
        "observe_network_links"
        | "observe_network_addresses"
        | "observe_network_interface_stats" => {
            table
                .get_mut("fixed_args")
                .and_then(toml::Value::as_table_mut)
                .and_then(|f| f.get_mut("operator_policy"))
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?
                .insert(
                    "interfaces".into(),
                    toml::Value::Array(vec![toml::Value::String("*".into())]),
                );
            let iface = table
                .get_mut("input_schema")
                .and_then(toml::Value::as_table_mut)
                .and_then(|s| s.get_mut("properties"))
                .and_then(toml::Value::as_table_mut)
                .and_then(|p| p.get_mut("interface"))
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?;
            iface.remove("enum");
            iface.insert("minLength".into(), toml::Value::Integer(1));
            iface.insert("maxLength".into(), toml::Value::Integer(15));
        }
        "observe_network_routes" => {
            let dest = table
                .get_mut("input_schema")
                .and_then(toml::Value::as_table_mut)
                .and_then(|s| s.get_mut("properties"))
                .and_then(toml::Value::as_table_mut)
                .and_then(|p| p.get_mut("destination"))
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?;
            dest.remove("enum");
            dest.insert("minLength".into(), toml::Value::Integer(1));
            dest.insert("maxLength".into(), toml::Value::Integer(64));
        }
        "inspect_sockets" => {
            let addr = table
                .get_mut("input_schema")
                .and_then(toml::Value::as_table_mut)
                .and_then(|s| s.get_mut("properties"))
                .and_then(toml::Value::as_table_mut)
                .and_then(|p| p.get_mut("address"))
                .and_then(toml::Value::as_table_mut)
                .ok_or(ERROR)?;
            addr.remove("enum");
            addr.insert("minLength".into(), toml::Value::Integer(1));
            addr.insert("maxLength".into(), toml::Value::Integer(64));
        }
        _ => {}
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
            || (template.policy_required && !pinned.workstation_adapted)
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
        let mut tool_def = tools.remove(name).ok_or(ERROR)?;
        if !tools.is_empty() {
            return Err(ERROR);
        }
        if pinned.workstation_adapted {
            adapt_workstation_definition(name, &mut tool_def)?;
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
        let mut scan = RoleScan {
            is_role: directory_name == "roles",
            files: Vec::new(),
            remaining: ROLE_LIMIT,
            entries: 0,
        };
        collect_role(
            &directory,
            &self.root.join(directory_name).join(name),
            Path::new(""),
            &mut scan,
            0,
        )?;
        let files = scan.files;
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
struct RoleScan {
    is_role: bool,
    files: Vec<(PathBuf, Vec<u8>)>,
    remaining: u64,
    entries: usize,
}

fn collect_role(
    directory: &File,
    source: &Path,
    relative: &Path,
    scan: &mut RoleScan,
    depth: usize,
) -> Result<(), &'static str> {
    if depth > 16 {
        return Err(ERROR);
    }
    for entry in fs::read_dir(source).map_err(|_| ERROR)? {
        let entry = entry.map_err(|_| ERROR)?;
        scan.entries += 1;
        if scan.entries > ROLE_FILES {
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
            if scan.is_role
                && depth == 0
                && !matches!(
                    name.to_str(),
                    Some("tasks" | "meta" | "files" | "defaults" | "vars" | "handlers")
                )
            {
                return Err(ERROR);
            }
            let child = open_child(directory, Path::new(&name), true)?;
            collect_role(&child, &source.join(&name), &path, scan, depth + 1)?;
        } else if kind.is_file() {
            if matches!(
                Path::new(&name)
                    .extension()
                    .and_then(|extension| extension.to_str()),
                Some("pyc" | "pyo")
            ) {
                continue;
            }
            if scan.is_role && depth == 0 {
                return Err(ERROR);
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
mod pinned_tests {
    use super::*;

    #[test]
    fn pinned_bundled_dynamic_payloads_match_manifest_and_hashes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let catalog = Catalog::load(Some(&root)).unwrap();
        let mut names: Vec<&str> = pinned_dynamic_payload_names().collect();
        names.sort_unstable();
        assert_eq!(names.len(), 19);
        assert!(names.contains(&"observe_cpu"));
        assert!(names.contains(&"observe_systemd_units"));
        assert!(names.contains(&"observe_filesystem_usage"));
        assert!(names.contains(&"observe_network_links"));
        assert!(names.contains(&"inspect_processes"));
        assert!(names.contains(&"inspect_sockets"));
        for name in names {
            let (tool_def, source, manifest) = catalog.load_pinned_payload(name).unwrap();
            assert!(tool_def.is_table());
            assert!(!source.is_empty());
            assert!(!manifest.is_empty());
        }
    }
}
