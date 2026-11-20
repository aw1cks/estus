//! Offline-compiled Ansible module bundle loader, virtual router, and CLI (`estus bundle`).
//!
//! Bundles are compiled outside the MCP server lifecycle (`estus bundle build`) so no
//! local Python or Ansible runtime is required during MCP server startup or tool execution.
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};
use tokio_util::sync::CancellationToken;

use crate::{
    contracts::module_schema,
    reply::{ErrorCode, ToolError},
    strict_json,
};

const BUILDER_PY: &str = include_str!("bundle/builder.py");
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_WRAPPER_BYTES: usize = 256 * 1024;
const MAX_ZIP_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOTAL_ZIP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Args)]
pub(crate) struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommand,
}

#[derive(Subcommand)]
enum BundleCommand {
    /// Compile an offline AnsiballZ module bundle pack using an external Python/Ansible environment.
    Build {
        /// Absolute path to Python interpreter with ansible-core (and optional collections) installed.
        #[arg(long)]
        python: PathBuf,
        /// Optional Ansible collections root directory (repeatable).
        #[arg(long = "collections-path")]
        collections_paths: Vec<PathBuf>,
        /// Module FQCN to include (repeatable; defaults to stock SRE module set).
        #[arg(long = "module")]
        modules: Vec<String>,
        /// New private output directory for bundle.json, wrapper.py, and modules/*.zip.
        #[arg(long)]
        output: PathBuf,
        /// Overall build deadline in seconds.
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout_secs: u64,
    },
    /// Verify and inspect an offline Ansible module bundle pack without Python or SSH.
    Inspect {
        /// Path to bundle directory (defaults to configured/installed bundle).
        #[arg(long)]
        bundle: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawModuleMeta {
    ansible_module: String,
    module_fqn: String,
    module_style: String,
    serialization_profile: String,
    check_mode_support: String,
    diff_mode_support: String,
    zip_sha256: String,
    zip_bytes: usize,
    import_closure_count: usize,
    external_imports: Vec<String>,
    document: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouterMeta {
    pub(crate) kind: String,
    pub(crate) routes: BTreeMap<String, String>,
    pub(crate) check_mode_support: String,
    pub(crate) diff_mode_support: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawBundleManifest {
    schema: u32,
    ansible_core_version: String,
    target_python_floor: [u32; 2],
    wrapper_sha256: String,
    modules: BTreeMap<String, RawModuleMeta>,
    #[serde(default)]
    routers: BTreeMap<String, RouterMeta>,
    bundle_sha256: String,
}

#[derive(Debug)]
pub(crate) struct BundledModule {
    pub(crate) fqcn: String,
    pub(crate) ansible_module: String,
    pub(crate) module_fqn: String,
    pub(crate) serialization_profile: String,
    pub(crate) zip_sha256: String,
    pub(crate) zip_bytes: Arc<[u8]>,
    pub(crate) contract: Value,
    pub(crate) check_mode_support: String,
}

#[derive(Debug)]
pub struct BundlePack {
    pub(crate) ansible_core_version: String,
    pub(crate) target_python_floor: [u32; 2],
    pub(crate) bundle_sha256: String,
    pub(crate) wrapper_sha256: String,
    pub(crate) wrapper_bytes: Arc<[u8]>,
    pub(crate) modules: BTreeMap<String, Arc<BundledModule>>,
    pub(crate) routers: BTreeMap<String, RouterMeta>,
}

#[derive(Clone, Serialize)]
pub(crate) struct BundleCheck {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ansible_core_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_count: Option<usize>,
}

impl BundleCheck {
    pub(crate) fn is_passed(&self) -> bool {
        self.status == "passed"
    }

    pub(crate) fn error_code(&self) -> Option<&'static str> {
        self.error_code
    }

    pub(crate) fn not_tested(code: &'static str) -> Self {
        Self {
            status: "not_tested",
            error_code: Some(code),
            ansible_core_version: None,
            bundle_sha256: None,
            module_count: None,
        }
    }

    pub(crate) fn failed(code: &'static str) -> Self {
        Self {
            status: "failed",
            error_code: Some(code),
            ansible_core_version: None,
            bundle_sha256: None,
            module_count: None,
        }
    }
}

fn read_regular_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "bundle_unavailable")?;
    let meta = file.metadata().map_err(|_| "bundle_unavailable")?;
    if !meta.is_file() {
        return Err("invalid_bundle_entry");
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "bundle_unavailable")?;
    if bytes.len() > limit {
        return Err("bundle_size_exceeded");
    }
    Ok(bytes)
}

fn valid_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, &'static str> {
    fn sort_value(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let sorted: BTreeMap<String, Value> = map
                    .iter()
                    .map(|(k, val)| (k.clone(), sort_value(val)))
                    .collect();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sort_value).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sort_value(value)).map_err(|_| "invalid_bundle_manifest")
}

fn virtual_package_contract() -> Result<Value, &'static str> {
    let schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "state"],
        "properties": {
            "name": {
                "type": "array",
                "minItems": 1,
                "maxItems": 32,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                }
            },
            "version": {
                "type": "string",
                "minLength": 1,
                "maxLength": 96,
            },
            "state": {
                "type": "string",
                "enum": ["present", "absent", "latest"],
            },
            "update_cache": {
                "type": "boolean",
            },
        },
    });
    module_schema::import_explicit_schema(&schema)
}

pub(crate) fn discover_default_bundle() -> Option<PathBuf> {
    if let Some(env_dir) = std::env::var_os("ESTUS_ANSIBLE_BUNDLE") {
        return Some(PathBuf::from(env_dir));
    }
    let exe = std::env::current_exe().ok()?;
    let exe_dir = exe.parent()?;
    for relative in ["../share/estus/bundle", "../../_bundle", "../_bundle"] {
        let candidate = exe_dir.join(relative);
        if candidate.join("bundle.json").is_file() {
            return Some(candidate);
        }
    }
    None
}

impl BundlePack {
    pub fn load(root: &Path) -> Result<Arc<Self>, &'static str> {
        let manifest_bytes = read_regular_bounded(&root.join("bundle.json"), MAX_MANIFEST_BYTES)?;
        let mut raw_value =
            strict_json::parse(&manifest_bytes).map_err(|_| "invalid_bundle_manifest")?;
        let manifest: RawBundleManifest =
            serde_json::from_value(raw_value.clone()).map_err(|_| "invalid_bundle_manifest")?;
        if manifest.schema != 1
            || manifest.ansible_core_version.is_empty()
            || manifest.ansible_core_version.len() > 64
            || manifest.target_python_floor[0] < 3
            || !valid_hex64(&manifest.wrapper_sha256)
            || !valid_hex64(&manifest.bundle_sha256)
            || manifest.modules.is_empty()
            || manifest.modules.len() > 128
        {
            return Err("invalid_bundle_manifest");
        }
        if let Some(obj) = raw_value.as_object_mut() {
            obj.remove("bundle_sha256");
        }
        let expected_bundle_digest = hex::encode(Sha256::digest(canonical_json_bytes(&raw_value)?));
        if expected_bundle_digest != manifest.bundle_sha256 {
            return Err("bundle_digest_mismatch");
        }

        let wrapper_vec = read_regular_bounded(&root.join("wrapper.py"), MAX_WRAPPER_BYTES)?;
        if hex::encode(Sha256::digest(&wrapper_vec)) != manifest.wrapper_sha256 {
            return Err("bundle_wrapper_drift");
        }

        let modules_dir = root.join("modules");
        let mut total_zip = 0usize;
        let mut compiled_modules = BTreeMap::new();
        for (fqcn, entry) in manifest.modules {
            if !module_schema::valid_fqcn(&fqcn)
                || entry.ansible_module.is_empty()
                || entry.module_fqn.is_empty()
                || !valid_hex64(&entry.zip_sha256)
            {
                return Err("invalid_bundle_module");
            }
            let zip_vec =
                read_regular_bounded(&modules_dir.join(format!("{fqcn}.zip")), MAX_ZIP_BYTES)?;
            if zip_vec.len() != entry.zip_bytes
                || hex::encode(Sha256::digest(&zip_vec)) != entry.zip_sha256
            {
                return Err("bundle_archive_drift");
            }
            total_zip = total_zip
                .checked_add(zip_vec.len())
                .filter(|&sum| sum <= MAX_TOTAL_ZIP_BYTES)
                .ok_or("bundle_size_exceeded")?;
            let contract = module_schema::import_document(&entry.document)
                .map_err(|_| "unsupported_bundle_module_contract")?;
            compiled_modules.insert(
                fqcn.clone(),
                Arc::new(BundledModule {
                    fqcn,
                    ansible_module: entry.ansible_module,
                    module_fqn: entry.module_fqn,
                    serialization_profile: entry.serialization_profile,
                    zip_sha256: entry.zip_sha256,
                    zip_bytes: Arc::from(zip_vec),
                    contract,
                    check_mode_support: entry.check_mode_support,
                }),
            );
        }

        for (router_name, router) in &manifest.routers {
            if !module_schema::valid_fqcn(router_name) || router.routes.is_empty() {
                return Err("invalid_bundle_router");
            }
            for target_fqcn in router.routes.values() {
                if !compiled_modules.contains_key(target_fqcn) {
                    return Err("invalid_bundle_router_target");
                }
            }
        }

        Ok(Arc::new(Self {
            ansible_core_version: manifest.ansible_core_version,
            target_python_floor: manifest.target_python_floor,
            bundle_sha256: manifest.bundle_sha256,
            wrapper_sha256: manifest.wrapper_sha256,
            wrapper_bytes: Arc::from(wrapper_vec),
            modules: compiled_modules,
            routers: manifest.routers,
        }))
    }

    pub(crate) fn contract_for(&self, module: &str) -> Result<Value, &'static str> {
        if module == "ansible.builtin.package" && self.routers.contains_key(module) {
            return virtual_package_contract();
        }
        self.modules
            .get(module)
            .map(|m| m.contract.clone())
            .ok_or("module_not_in_bundle")
    }

    pub(crate) fn supports_check_mode(&self, module: &str) -> bool {
        if let Some(router) = self.routers.get(module) {
            return router.check_mode_support != "none";
        }
        self.modules
            .get(module)
            .is_some_and(|m| m.check_mode_support != "none")
    }

    pub(crate) fn resolve_dispatch(
        &self,
        requested_module: &str,
        pkg_mgr: &str,
        args: &Value,
    ) -> Result<(Arc<BundledModule>, Value), ToolError> {
        if requested_module == "ansible.builtin.package" {
            let router = self.routers.get("ansible.builtin.package").ok_or_else(|| {
                ToolError::new(
                    ErrorCode::Unsupported,
                    "Generic package router is unavailable in bundle",
                    false,
                )
            })?;
            let normalized_mgr = match pkg_mgr {
                "yum" | "yum4" | "dnf4" => "dnf",
                other => other,
            };
            let target_fqcn = router.routes.get(normalized_mgr).ok_or_else(|| {
                ToolError::new(
                    ErrorCode::Unsupported,
                    "Target OS package manager is not supported by the active bundle",
                    false,
                )
            })?;
            let bundled = self.modules.get(target_fqcn).cloned().ok_or_else(|| {
                ToolError::new(
                    ErrorCode::Unsupported,
                    "Target package backend module is missing from bundle",
                    false,
                )
            })?;
            let mut rewritten = rewrite_generic_package_args(normalized_mgr, args)?;
            if matches!(normalized_mgr, "apt" | "dnf5")
                && let Some(arguments) = rewritten.as_object_mut()
            {
                arguments.insert("auto_install_module_deps".into(), Value::Bool(false));
            }
            return Ok((bundled, rewritten));
        }

        if let Some(router) = self.routers.get(requested_module)
            && router.kind == "dnf_backend"
        {
            let normalized_mgr = match pkg_mgr {
                "dnf5" => "dnf5",
                _ => "dnf",
            };
            if let Some(target_fqcn) = router
                .routes
                .get(normalized_mgr)
                .or_else(|| router.routes.get("dnf"))
                && let Some(bundled) = self.modules.get(target_fqcn)
            {
                let mut cleaned = args.clone();
                if let Some(obj) = cleaned.as_object_mut() {
                    obj.remove("use");
                    obj.remove("use_backend");
                    if target_fqcn == "ansible.builtin.dnf5" {
                        obj.insert("auto_install_module_deps".into(), Value::Bool(false));
                    }
                }
                return Ok((Arc::clone(bundled), cleaned));
            }
        }

        let bundled = self.modules.get(requested_module).cloned().ok_or_else(|| {
            ToolError::new(
                ErrorCode::Unsupported,
                "Requested Ansible module is not present in bundle",
                false,
            )
        })?;
        Ok((bundled, args.clone()))
    }
}

fn rewrite_generic_package_args(pkg_mgr: &str, args: &Value) -> Result<Value, ToolError> {
    let obj = args.as_object().ok_or_else(|| {
        ToolError::new(
            ErrorCode::InvalidArgument,
            "Package arguments must be an object",
            false,
        )
    })?;
    let state = obj
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("present");
    let version = obj
        .get("version")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    if version.is_some() && state != "present" {
        return Err(ToolError::new(
            ErrorCode::InvalidArgument,
            "Package version pin requires state=\"present\"",
            false,
        ));
    }
    let names: Vec<String> = match obj.get("name") {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(items)) if !items.is_empty() => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        ToolError::new(ErrorCode::InvalidArgument, "Invalid package name", false)
                    })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(ToolError::new(
                ErrorCode::InvalidArgument,
                "Package name must be a non-empty string or list",
                false,
            ));
        }
    };
    if version.is_some() && names.len() > 1 {
        return Err(ToolError::new(
            ErrorCode::InvalidArgument,
            "Exact version pin applies to a single package name",
            false,
        ));
    }
    let formatted_names: Vec<Value> = names
        .into_iter()
        .map(|name| {
            if let Some(ver) = version {
                match pkg_mgr {
                    "dnf" | "dnf5" | "zypper" => Value::String(format!("{name}-{ver}")),
                    _ => Value::String(format!("{name}={ver}")),
                }
            } else {
                Value::String(name)
            }
        })
        .collect();
    let mut out = serde_json::Map::new();
    out.insert("name".into(), Value::Array(formatted_names));
    out.insert("state".into(), Value::String(state.to_owned()));
    if let Some(update_cache) = obj.get("update_cache").and_then(Value::as_bool) {
        out.insert("update_cache".into(), Value::Bool(update_cache));
    }
    Ok(Value::Object(out))
}

pub(crate) fn check(reference: Option<PathBuf>) -> BundleCheck {
    let Some(path) = reference.or_else(discover_default_bundle) else {
        return BundleCheck::failed("runtime_unavailable");
    };
    match BundlePack::load(&path) {
        Ok(pack) => BundleCheck {
            status: "passed",
            error_code: None,
            ansible_core_version: Some(pack.ansible_core_version.clone()),
            bundle_sha256: Some(pack.bundle_sha256.clone()),
            module_count: Some(pack.modules.len()),
        },
        Err(code) => BundleCheck::failed(code),
    }
}

pub(crate) async fn run_cli(
    args: BundleArgs,
    configured_bundle: Option<PathBuf>,
    shutdown: CancellationToken,
) -> u8 {
    let (ok, payload) = match args.command {
        BundleCommand::Inspect { bundle } => {
            let check_res = check(bundle.or(configured_bundle));
            let passed = check_res.is_passed();
            (
                passed,
                serde_json::to_value(check_res).unwrap_or_else(|_| json!({"ok": false})),
            )
        }
        BundleCommand::Build {
            python,
            collections_paths,
            modules,
            output,
            timeout_secs,
        } => {
            build_bundle(
                &python,
                &collections_paths,
                &modules,
                &output,
                timeout_secs,
                &shutdown,
            )
            .await
        }
    };
    let mut encoded = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    encoded.push(b'\n');
    let write_out = async {
        let mut stdout = tokio::io::stdout();
        stdout.write_all(&encoded).await?;
        stdout.flush().await
    };
    if tokio::time::timeout(Duration::from_secs(1), write_out)
        .await
        .is_ok_and(|res| res.is_ok())
    {
        if ok { 0 } else { 1 }
    } else {
        1
    }
}

async fn build_bundle(
    python: &Path,
    collections_paths: &[PathBuf],
    modules: &[String],
    output: &Path,
    timeout_secs: u64,
    shutdown: &CancellationToken,
) -> (bool, Value) {
    if !python.is_absolute() || !python.is_file() {
        return (
            false,
            json!({"ok": false, "error_code": "invalid_python_executable", "phase": "bundle_build"}),
        );
    }
    if output.exists() {
        return (
            false,
            json!({"ok": false, "error_code": "bundle_output_exists", "phase": "bundle_build"}),
        );
    }
    if fs::DirBuilder::new().mode(0o700).create(output).is_err() {
        return (
            false,
            json!({"ok": false, "error_code": "bundle_output_unavailable", "phase": "bundle_build"}),
        );
    }
    let script_file = output.join(".estus-builder.py");
    if OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&script_file)
        .and_then(|mut f: File| f.write_all(BUILDER_PY.as_bytes()))
        .is_err()
    {
        let _ = fs::remove_dir_all(output);
        return (
            false,
            json!({"ok": false, "error_code": "bundle_builder_write_failed", "phase": "bundle_build"}),
        );
    }

    let mut cmd = Command::new(python);
    cmd.args(["-I", "-X", "utf8", "-B"])
        .arg(&script_file)
        .arg("--output")
        .arg(output)
        .env("LC_ALL", "C.UTF-8")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for col in collections_paths {
        cmd.arg("--collections-path").arg(col);
    }
    for m in modules {
        cmd.arg("--module").arg(m);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let run_res = tokio::select! {
        biased;
        _ = shutdown.cancelled() => Err("cancelled"),
        _ = tokio::time::sleep_until(deadline) => Err("timeout"),
        status = async { cmd.spawn().map_err(|_| "spawn_failed")?.wait().await.map_err(|_| "io_error") } => {
            match status {
                Ok(s) if s.success() => Ok(()),
                Ok(_) => Err("builder_failed"),
                Err(code) => Err(code),
            }
        }
    };
    let _ = fs::remove_file(&script_file);
    if let Err(code) = run_res {
        let _ = fs::remove_dir_all(output);
        return (
            false,
            json!({"ok": false, "error_code": code, "phase": "bundle_build"}),
        );
    }
    match BundlePack::load(output) {
        Ok(pack) => (
            true,
            json!({
                "ok": true,
                "ansible_core_version": pack.ansible_core_version,
                "target_python_floor": pack.target_python_floor,
                "bundle_sha256": pack.bundle_sha256,
                "modules": pack.modules.keys().collect::<Vec<_>>(),
                "routers": pack.routers.keys().collect::<Vec<_>>(),
            }),
        ),
        Err(code) => {
            let _ = fs::remove_dir_all(output);
            (
                false,
                json!({"ok": false, "error_code": code, "phase": "bundle_verify"}),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_package_args_format_version_per_package_manager_and_reject_invalid_combos() {
        let apt_args = rewrite_generic_package_args(
            "apt",
            &json!({"name": ["tmux"], "version": "3.4-1", "state": "present", "update_cache": true}),
        )
        .unwrap();
        assert_eq!(
            apt_args,
            json!({"name": ["tmux=3.4-1"], "state": "present", "update_cache": true})
        );

        let dnf_args = rewrite_generic_package_args(
            "dnf5",
            &json!({"name": "tmux", "version": "3.4", "state": "present"}),
        )
        .unwrap();
        assert_eq!(dnf_args, json!({"name": ["tmux-3.4"], "state": "present"}));

        assert!(
            rewrite_generic_package_args(
                "dnf",
                &json!({"name": ["tmux"], "version": "3.4", "state": "latest"})
            )
            .is_err()
        );
        assert!(
            rewrite_generic_package_args(
                "apt",
                &json!({"name": ["tmux", "htop"], "version": "1.0", "state": "present"})
            )
            .is_err()
        );
    }
}
