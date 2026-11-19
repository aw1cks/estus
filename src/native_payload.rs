//! Digest-approved controller payloads over owned SSH mux channels.
mod engine;
use crate::{
    config::ConfigError,
    contracts::{module_schema, projection},
    reply::ToolError,
    strict_json::parse,
};
pub(crate) use engine::{Engine, PayloadRun};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path, sync::Arc};

pub(crate) const MAX_SOURCE: usize = 1_048_576;
pub(crate) const MAX_INPUT: usize = 262_144;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Requirements {
    pub python_min: [u16; 2],
    #[serde(default)]
    pub interpreters: Vec<String>,
    pub modules: Vec<String>,
    pub executables: Vec<String>,
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub executable_candidates: std::collections::BTreeMap<String, Vec<String>>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub overlay: Value,
    pub result: Value,
    pub authority: String,
    pub no_log: bool,
    pub revision: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub manifest_sha256: String,
    pub schema: u32,
    pub protocol: u32,
    pub adapter_version: u32,
    pub change_policy: ChangePolicy,
    pub source_sha256: String,
    pub max_source_bytes: usize,
    pub argv: Vec<Arg>,
    pub requirements: Requirements,
    pub contract: Value,
    pub approval: Approval,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Arg {
    Fixed {
        value: String,
    },
    Argument {
        name: String,
        format: Format,
        #[serde(
            default,
            deserialize_with = "present_value",
            skip_serializing_if = "Option::is_none"
        )]
        default: Option<Value>,
        #[serde(default)]
        omit_if_absent: bool,
    },
    Object {
        fields: std::collections::BTreeMap<String, ArgumentValue>,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Format {
    Scalar,
    Json,
    PythonBool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArgumentValue {
    pub name: String,
    #[serde(
        default,
        deserialize_with = "present_value",
        skip_serializing_if = "Option::is_none"
    )]
    pub default: Option<Value>,
}
fn present_value<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChangePolicy {
    ReadOnly,
    MutationSuccess,
    ReportedChanged,
    MutationAttempted,
    BootSelection,
    RebootScheduled,
    KernelModules,
}
impl ChangePolicy {
    /// A negative receipt on failure never proves absence of mutation.
    pub(crate) fn evidence(&self, rc: i32, domain: Option<&Value>) -> Option<bool> {
        let observed = match self {
            Self::ReadOnly => return (rc == 0).then_some(false),
            Self::MutationSuccess => return (rc == 0).then_some(true),
            Self::ReportedChanged => domain?.get("changed")?.as_bool()?,
            Self::MutationAttempted => domain?.get("mutation_attempted")?.as_bool()?,
            Self::BootSelection => {
                let d = domain?;
                d.get("previous_selection")? != d.get("observed_selection")?
            }
            Self::RebootScheduled => domain?.get("outcome")?.as_str()? == "scheduled",
            Self::KernelModules => {
                let d = domain?;
                !d.get("added_modules")?.as_array()?.is_empty()
                    || !d.get("removed_modules")?.as_array()?.is_empty()
                    || d.get("taint_before")? != d.get("taint_after")?
            }
        };
        (observed || rc == 0).then_some(observed)
    }
}
fn invalid() -> ConfigError {
    ConfigError::new("tools", "Native payload approval is invalid or has drifted")
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ConfigError> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| invalid())?;
    if !file.metadata().map_err(|_| invalid())?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > limit {
        return Err(invalid());
    }
    Ok(bytes)
}
/// Explicit offline authoring only; activation never rewrites an approval.
pub(crate) fn prepare_manifest(
    source: &Path,
    snapshot: &Path,
    mut manifest: Manifest,
) -> Result<(), ConfigError> {
    let bytes = read_bounded(source, manifest.max_source_bytes.min(MAX_SOURCE))?;
    manifest.source_sha256 = digest(&bytes);
    manifest.approved = true;
    validate_manifest(&manifest)?;
    module_schema::compile_binding(&manifest.contract, &manifest.approval.overlay)
        .map_err(|_| invalid())?;
    manifest.manifest_sha256 = manifest_digest(&manifest)?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| invalid())?;
    if bytes.len() > MAX_INPUT {
        return Err(invalid());
    }
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(snapshot)
        .map_err(|_| invalid())?;
    file.write_all(&bytes).map_err(|_| invalid())
}
fn manifest_digest(manifest: &Manifest) -> Result<String, ConfigError> {
    let bytes = serde_json::to_vec(&(
        manifest.approved,
        manifest.schema,
        manifest.protocol,
        manifest.adapter_version,
        &manifest.change_policy,
        &manifest.source_sha256,
        manifest.max_source_bytes,
        &manifest.argv,
        &manifest.requirements,
        &manifest.contract,
        &manifest.approval,
    ))
    .map_err(|_| invalid())?;
    Ok(digest(&bytes))
}

fn validate_manifest(m: &Manifest) -> Result<(), ConfigError> {
    if m.schema != 1
        || m.protocol != 1
        || m.adapter_version != 1
        || m.max_source_bytes == 0
        || m.max_source_bytes > MAX_SOURCE
        || m.source_sha256.len() != 64
        || !m.source_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || m.argv.len() > 64
        || m.requirements.python_min < [3, 8]
        || m.requirements.python_min[0] != 3
    {
        return Err(invalid());
    }
    if m.requirements.interpreters.len() > 8
        || m.requirements
            .interpreters
            .iter()
            .any(|p| !p.starts_with('/') || p.len() > 4096 || p.contains('\0'))
    {
        return Err(invalid());
    }
    for list in [
        &m.requirements.modules,
        &m.requirements.executables,
        &m.requirements.paths,
    ] {
        if list.len() > 64
            || list
                .iter()
                .any(|s| s.is_empty() || s.len() > 4096 || s.contains('\0'))
        {
            return Err(invalid());
        }
    }
    if m.requirements.modules.iter().any(|s| {
        !s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
    }) {
        return Err(invalid());
    }
    if m.requirements.executable_candidates.len() > 64 {
        return Err(invalid());
    }
    let mut normalized_execs = std::collections::BTreeSet::new();
    for (name, candidates) in &m.requirements.executable_candidates {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(invalid());
        }
        let normalized = name.to_ascii_uppercase().replace('-', "_");
        if !normalized_execs.insert(normalized) {
            return Err(invalid());
        }
        if candidates.is_empty() || candidates.len() > 8 {
            return Err(invalid());
        }
        for candidate in candidates {
            if !candidate.starts_with('/')
                || candidate.len() > 4096
                || candidate.contains('\0')
                || Path::new(candidate).components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
                || Path::new(candidate).file_name().is_none()
                || !Path::new(candidate)
                    .parent()
                    .and_then(Path::to_str)
                    .is_some_and(|dir| {
                        matches!(
                            dir,
                            "/usr/sbin" | "/usr/bin" | "/sbin" | "/bin" | "/usr/lib/systemd"
                        )
                    })
            {
                return Err(invalid());
            }
        }
    }
    for arg in &m.argv {
        match arg {
            Arg::Fixed { value } if value.len() > 8192 || value.contains('\0') => {
                return Err(invalid());
            }
            Arg::Argument { name, .. } if name.is_empty() || name.len() > 128 => {
                return Err(invalid());
            }
            Arg::Object { fields }
                if fields.len() > 64
                    || fields.iter().any(|(key, v)| {
                        key.is_empty() || key.len() > 128 || v.name.is_empty() || v.name.len() > 128
                    }) =>
            {
                return Err(invalid());
            }
            _ => (),
        }
    }
    Ok(())
}
pub(crate) struct PayloadPlan {
    pub(crate) manifest: Manifest,
    pub(crate) source: Arc<[u8]>,
    binding: module_schema::CapabilityBinding,
    pub(crate) no_log: bool,
    pub(crate) projection: Option<Arc<projection::Plan>>,
}
impl std::fmt::Debug for PayloadPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PayloadPlan { approved: <private> }")
    }
}
pub(crate) struct PayloadApproval<'a> {
    pub(crate) snapshot: &'a Path,
    pub(crate) source: &'a Path,
    pub(crate) overlay: &'a Value,
    pub(crate) result: &'a Value,
    pub(crate) authority: &'a str,
    pub(crate) revision: &'a str,
    pub(crate) no_log: bool,
    pub(crate) projection: Option<Arc<projection::Plan>>,
}

pub(crate) struct PayloadApprovalInline<'a> {
    pub(crate) overlay: &'a Value,
    pub(crate) result: &'a Value,
    pub(crate) authority: &'a str,
    pub(crate) revision: &'a str,
    pub(crate) no_log: bool,
    pub(crate) projection: Option<Arc<projection::Plan>>,
}

impl PayloadPlan {
    pub(crate) fn load(approval: PayloadApproval<'_>) -> Result<Self, ConfigError> {
        let PayloadApproval {
            snapshot,
            source,
            overlay,
            result,
            authority,
            revision,
            no_log,
            projection,
        } = approval;
        let manifest: Manifest = parse(&read_bounded(snapshot, MAX_INPUT)?)
            .and_then(serde_json::from_value)
            .map_err(|_| invalid())?;
        validate_manifest(&manifest)?;
        if !manifest.approved || manifest.manifest_sha256 != manifest_digest(&manifest)? {
            return Err(invalid());
        }
        if manifest.approval.overlay != *overlay
            || manifest.approval.result != *result
            || manifest.approval.authority != authority
            || manifest.approval.revision != revision
            || manifest.approval.no_log != no_log
        {
            return Err(invalid());
        }
        let source = read_bounded(source, manifest.max_source_bytes)?;
        if digest(&source) != manifest.source_sha256 {
            return Err(invalid());
        }
        let binding =
            module_schema::compile_binding(&manifest.contract, overlay).map_err(|_| invalid())?;
        Ok(Self {
            manifest,
            source: source.into(),
            binding,
            no_log,
            projection,
        })
    }

    pub(crate) fn load_from_bytes(
        source: Vec<u8>,
        manifest_bytes: &[u8],
        approval: &PayloadApprovalInline<'_>,
    ) -> Result<Self, ConfigError> {
        let mut manifest: Manifest = parse(manifest_bytes)
            .and_then(serde_json::from_value)
            .map_err(|_| invalid())?;
        if source.is_empty() || source.len() > manifest.max_source_bytes.min(MAX_SOURCE) {
            return Err(invalid());
        }
        let computed_source = digest(&source);
        if !manifest.source_sha256.is_empty() && manifest.source_sha256 != computed_source {
            return Err(invalid());
        }
        manifest.source_sha256 = computed_source;
        manifest.approval = Approval {
            overlay: approval.overlay.clone(),
            result: approval.result.clone(),
            authority: approval.authority.to_owned(),
            no_log: approval.no_log,
            revision: approval.revision.to_owned(),
        };
        manifest.approved = true;
        validate_manifest(&manifest)?;
        manifest.manifest_sha256 = manifest_digest(&manifest)?;
        let binding = module_schema::compile_binding(&manifest.contract, approval.overlay)
            .map_err(|_| invalid())?;
        Ok(Self {
            manifest,
            source: source.into(),
            binding,
            no_log: approval.no_log,
            projection: approval.projection.clone(),
        })
    }
    pub(crate) fn arguments(&self, inputs: &Value) -> Result<Vec<String>, ToolError> {
        let args = self.binding.prepare(inputs).map_err(|_| {
            ToolError::new(
                "invalid_argument",
                "Payload inputs violate reviewed contract",
                false,
            )
        })?;
        adapt(&self.manifest.argv, &args)
    }
}
fn adapt(adapter: &[Arg], args: &Value) -> Result<Vec<String>, ToolError> {
    let invalid = || {
        ToolError::new(
            "invalid_argument",
            "Payload argv violates reviewed adapter",
            false,
        )
    };
    let mut output = Vec::with_capacity(adapter.len());
    let mut bytes = 0usize;
    for arg in adapter {
        let value = match arg {
            Arg::Fixed { value } => value.clone(),
            Arg::Object { fields } => {
                let mut object = serde_json::Map::new();
                for (key, field) in fields {
                    let value = args
                        .get(&field.name)
                        .or(field.default.as_ref())
                        .ok_or_else(invalid)?;
                    object.insert(key.clone(), value.clone());
                }
                serde_json::to_string(&object).map_err(|_| invalid())?
            }
            Arg::Argument {
                name,
                format,
                default,
                omit_if_absent,
            } => {
                let Some(value) = args.get(name).or(default.as_ref()) else {
                    if *omit_if_absent {
                        continue;
                    } else {
                        return Err(invalid());
                    }
                };
                match format {
                    Format::Json => serde_json::to_string(value).map_err(|_| invalid())?,
                    Format::Scalar => match value {
                        Value::String(s) => s.clone(),
                        Value::Bool(b) => b.to_string(),
                        Value::Number(n) => n.to_string(),
                        _ => return Err(invalid()),
                    },
                    Format::PythonBool => match value.as_bool() {
                        Some(true) => "True".into(),
                        Some(false) => "False".into(),
                        None => return Err(invalid()),
                    },
                }
            }
        };
        bytes += value.len();
        if bytes > MAX_INPUT || value.contains('\0') {
            return Err(invalid());
        }
        output.push(value);
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_ambiguous_output() {
        for bytes in [
            b"{\"x\":1,\"x\":2}".as_slice(),
            b"{\"a\":{\"x\":1,\"x\":2}}",
            b"NaN",
            b"{}x",
            b"{\"x\":",
        ] {
            assert!(parse(bytes).is_err());
        }
    }
    #[test]
    fn structured_literal_adapter() {
        let adapter:Vec<Arg>=serde_json::from_value(json!([{"kind":"argument","name":"x","format":"json"},{"kind":"argument","name":"optional","format":"scalar","default":""},{"kind":"argument","name":"gone","format":"scalar","omit_if_absent":true}])).unwrap();
        assert_eq!(
            adapt(&adapter, &json!({"x":{"literal":"{{ x }};\n☃"}})).unwrap(),
            vec!["{\"literal\":\"{{ x }};\\n☃\"}", ""]
        );
    }

    #[test]
    fn executable_candidates_validate_allowed_dirs_and_normalization_collisions() {
        let mut manifest: Manifest = serde_json::from_value(serde_json::json!({
            "approved": true,
            "manifest_sha256": "",
            "schema": 1,
            "protocol": 1,
            "adapter_version": 1,
            "change_policy": "read_only",
            "source_sha256": "0".repeat(64),
            "max_source_bytes": 1024,
            "argv": [],
            "requirements": {
                "python_min": [3, 8],
                "modules": ["json"],
                "executables": [],
                "paths": [],
                "executable_candidates": {
                    "apt-get": ["/usr/bin/apt-get", "/bin/apt-get"]
                }
            },
            "contract": {"schema":{"type":"object","properties":{"target_python":{"type":"string"}},"required":["target_python"],"additionalProperties":false},"aliases":{"aliases":{},"properties":{"target_python":{"aliases":{},"properties":{}}}},"defaults":{},"review_required":[]},
            "approval": {"overlay":{"input_schema":{"type":"object","properties":{},"additionalProperties":false,"required":[]},"fixed_args":{"target_python":"/usr/bin/python3"},"input_map":{}},"result":{"kind":"capability_projection","fields":{"ok":["mcp_result","ok"]},"max_bytes":128,"max_items":4,"max_depth":2,"schema":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"],"additionalProperties":false}},"authority":"ordinary","revision":"1","no_log":false}
        })).unwrap();
        assert!(validate_manifest(&manifest).is_ok());

        // Disallowed directory (/tmp) fails closed.
        manifest
            .requirements
            .executable_candidates
            .insert("bad".into(), vec!["/tmp/evil".into()]);
        assert!(validate_manifest(&manifest).is_err());
        manifest.requirements.executable_candidates.remove("bad");

        // Traversal (..) fails closed.
        manifest
            .requirements
            .executable_candidates
            .insert("bad".into(), vec!["/usr/bin/../sbin/ip".into()]);
        assert!(validate_manifest(&manifest).is_err());
        manifest.requirements.executable_candidates.remove("bad");

        // Normalization collision (apt-get vs apt_get) fails closed.
        manifest
            .requirements
            .executable_candidates
            .insert("apt_get".into(), vec!["/usr/bin/apt-get".into()]);
        assert!(validate_manifest(&manifest).is_err());
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn explicit_null_defaults_and_literal_objects() {
        let args:Vec<Arg>=serde_json::from_value(json!([{"kind":"object","fields":{"literal":{"name":"x"},"optional":{"name":"absent","default":null}}}])).unwrap();
        assert_eq!(
            adapt(&args, &json!({"x":["{{ executable }}","; shell"]})).unwrap(),
            vec!["{\"literal\":[\"{{ executable }}\",\"; shell\"],\"optional\":null}"]
        );
        assert!(adapt(&args, &json!({})).is_err());
    }
    #[test]
    fn failed_receipt_never_proves_unchanged() {
        assert_eq!(ChangePolicy::ReadOnly.evidence(0, None), Some(false));
        assert_eq!(ChangePolicy::ReadOnly.evidence(1, None), None);
        assert_eq!(ChangePolicy::MutationSuccess.evidence(1, None), None);
        assert_eq!(
            ChangePolicy::ReportedChanged.evidence(1, Some(&json!({"changed":false}))),
            None
        );
        assert_eq!(
            ChangePolicy::ReportedChanged.evidence(1, Some(&json!({"changed":true}))),
            Some(true)
        );
        assert_eq!(ChangePolicy::KernelModules.evidence(1,Some(&json!({"added_modules":["dummy"],"removed_modules":[],"taint_before":0,"taint_after":0}))),Some(true));
    }
}
