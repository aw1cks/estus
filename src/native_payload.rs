//! Reviewed controller payloads over owned SSH mux channels. The collector bytes
//! are pinned by the shipped manifest's `source_sha256`; nothing else about the
//! installation is treated as an integrity boundary.
mod engine;
use crate::{
    config::ConfigError,
    contracts::{module_schema, projection},
    reply::{ErrorCode, ToolError},
    strict_json::parse,
};
pub(crate) use engine::{BundleRun, Engine, PayloadRun, PreviewPrestateRequest};
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
pub(crate) struct Manifest {
    pub schema: u32,
    pub protocol: u32,
    pub adapter_version: u32,
    pub change_policy: ChangePolicy,
    pub source_sha256: String,
    pub max_source_bytes: usize,
    pub argv: Vec<Arg>,
    pub requirements: Requirements,
    pub contract: Value,
}
/// The reviewed adapter. Only the forms a shipped manifest uses may deserialize:
/// an unknown `kind` or `format` is a manifest authoring error, not a new capability.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Arg {
    Argument {
        name: String,
        format: Format,
        #[serde(
            default,
            deserialize_with = "present_value",
            skip_serializing_if = "Option::is_none"
        )]
        default: Option<Value>,
    },
    Object {
        fields: std::collections::BTreeMap<String, ArgumentValue>,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Format {
    /// A bare scalar string, passed through unchanged.
    Scalar,
    /// A JSON value the collector parses from typed input.
    Json,
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
    ConfigError::new(
        "tools",
        "Native payload manifest or collector bytes are invalid",
    )
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ConfigError> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| invalid())?;
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
        f.write_str("PayloadPlan { manifest: <private> }")
    }
}
/// The one integrity check that survives: collector bytes must match the
/// manifest's `source_sha256`. This catches an accidental edit or a partial
/// install, not an operator who can rewrite both files and the binary.
pub(crate) struct PayloadSource<'a> {
    pub(crate) source: &'a Path,
    pub(crate) overlay: &'a Value,
    pub(crate) no_log: bool,
    pub(crate) projection: Option<Arc<projection::Plan>>,
}

impl PayloadPlan {
    /// Load a payload from a collector file. One rule for shipped and custom
    /// tools: `manifest.json` sits beside `collector.py`.
    pub(crate) fn load(source: &PayloadSource<'_>) -> Result<Self, ConfigError> {
        let manifest_path = source
            .source
            .parent()
            .ok_or_else(invalid)?
            .join("manifest.json");
        let manifest_bytes = read_bounded(&manifest_path, MAX_INPUT)?;
        let bytes = read_bounded(source.source, MAX_SOURCE)?;
        Self::assemble(bytes, &manifest_bytes, source)
    }

    pub(crate) fn load_from_bytes(
        source: Vec<u8>,
        manifest_bytes: &[u8],
        policy: &PayloadSource<'_>,
    ) -> Result<Self, ConfigError> {
        Self::assemble(source, manifest_bytes, policy)
    }

    fn assemble(
        source: Vec<u8>,
        manifest_bytes: &[u8],
        policy: &PayloadSource<'_>,
    ) -> Result<Self, ConfigError> {
        let manifest: Manifest = parse(manifest_bytes)
            .and_then(serde_json::from_value)
            .map_err(|_| invalid().with_cause("manifest_schema", "payload_validation"))?;
        if source.is_empty() || source.len() > manifest.max_source_bytes.min(MAX_SOURCE) {
            return Err(invalid().with_cause("source_bounds", "payload_validation"));
        }
        if manifest.source_sha256 != digest(&source) {
            return Err(invalid().with_cause("source_digest", "payload_validation"));
        }
        validate_manifest(&manifest)
            .map_err(|error| error.with_cause("manifest_constraints", "payload_validation"))?;
        let binding = module_schema::compile_binding(&manifest.contract, policy.overlay)
            .map_err(|code| invalid().with_cause(code, "payload_binding"))?;
        Ok(Self {
            manifest,
            source: source.into(),
            binding,
            no_log: policy.no_log,
            projection: policy.projection.clone(),
        })
    }
    /// The request is the reviewed adapter evaluated to typed JSON values, in order.
    /// Nothing is stringified on the way out, so a scalar interface named "123"
    /// stays the string "123" instead of becoming a number at the collector.
    pub(crate) fn request_with_merged(
        &self,
        inputs: &Value,
    ) -> Result<(Vec<Value>, Value), ToolError> {
        let args = self.binding.prepare(inputs).map_err(|_| {
            ToolError::new(
                ErrorCode::InvalidArgument,
                "Payload inputs violate reviewed contract",
                false,
            )
        })?;
        let request = adapt(&self.manifest.argv, &args)?;
        Ok((request, args))
    }

    /// Operator policy for the target interpreter, taken from the reviewed
    /// fixed arguments rather than from the manifest.
    pub(crate) fn target_python(&self) -> Option<&str> {
        self.binding
            .fixed_args
            .get("target_python")
            .and_then(Value::as_str)
    }
}
fn adapt(adapter: &[Arg], args: &Value) -> Result<Vec<Value>, ToolError> {
    let invalid = || {
        ToolError::new(
            ErrorCode::InvalidArgument,
            "Payload adapter is invalid",
            false,
        )
    };
    let mut output = Vec::with_capacity(adapter.len());
    let mut bytes = 0usize;
    for arg in adapter {
        let value = match arg {
            Arg::Object { fields } => {
                let mut object = serde_json::Map::new();
                for (key, field) in fields {
                    let value = args
                        .get(&field.name)
                        .or(field.default.as_ref())
                        .ok_or_else(invalid)?;
                    object.insert(key.clone(), value.clone());
                }
                Value::Object(object)
            }
            Arg::Argument {
                name,
                format,
                default,
            } => {
                let value = args.get(name).or(default.as_ref()).ok_or_else(invalid)?;
                match format {
                    // Already a JSON value: parsed by the collector from typed input.
                    Format::Json => value.clone(),
                    // A bare scalar stays a string so target-side parsing cannot
                    // reinterpret the caller's value as a different JSON type.
                    Format::Scalar => match value {
                        Value::String(_) => value.clone(),
                        _ => return Err(invalid()),
                    },
                }
            }
        };
        let encoded = value.to_string();
        bytes += encoded.len();
        if bytes > MAX_INPUT || encoded.contains('\0') {
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

    /// Smallest value satisfying a reviewed schema fragment, for exercising
    /// prepare() with caller-required fields.
    fn sample(schema: &Value) -> Value {
        if let Some(value) = schema.get("const") {
            return value.clone();
        }
        if let Some(value) = schema
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
        {
            return value.clone();
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("string") => {
                // Honour the declared floor; several contracts pin exact lengths
                // (a 36-character boot id, a cursor) rather than just a pattern.
                let floor = schema
                    .get("minLength")
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .max(1) as usize;
                json!("x".repeat(floor))
            }
            Some("integer") | Some("number") => {
                schema.get("minimum").cloned().unwrap_or_else(|| json!(0))
            }
            Some("boolean") => json!(false),
            Some("array") => {
                let floor = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
                let item = schema
                    .get("items")
                    .map(sample)
                    .unwrap_or_else(|| json!("x"));
                Value::Array((0..floor).map(|_| item.clone()).collect())
            }
            Some("object") => {
                // Populate required children, and honour minProperties by adding
                // the first declared optional property for closed policy objects.
                let mut object = serde_json::Map::new();
                if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                    let required = schema
                        .get("required")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    for (key, child) in properties {
                        if required.iter().any(|name| name.as_str() == Some(key)) {
                            object.insert(key.clone(), sample(child));
                        }
                    }
                    let floor = schema
                        .get("minProperties")
                        .and_then(Value::as_u64)
                        .unwrap_or(0) as usize;
                    while object.len() < floor {
                        let Some((key, child)) = properties
                            .iter()
                            .find(|(key, _)| !object.contains_key(*key))
                        else {
                            break;
                        };
                        object.insert(key.clone(), sample(child));
                    }
                }
                Value::Object(object)
            }
            Some("null") => Value::Null,
            _ => json!("x"),
        }
    }

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
        let adapter:Vec<Arg>=serde_json::from_value(json!([{"kind":"argument","name":"x","format":"json"},{"kind":"argument","name":"optional","format":"scalar","default":""},{"kind":"argument","name":"gone","format":"json","default":null}])).unwrap();
        assert_eq!(
            adapt(&adapter, &json!({"x":{"literal":"{{ x }};\n☃"}})).unwrap(),
            vec![json!({"literal":"{{ x }};\n☃"}), json!(""), json!(null)]
        );
    }

    /// The adapter is evaluated against every shipped manifest's own reviewed
    /// defaults, so a format/schema mismatch fails here instead of on a target.
    #[test]
    fn shipped_manifest_adapters_accept_their_own_defaults() {
        use crate::contracts::module_schema::compile_binding;
        let catalog = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let mut checked = 0;
        for entry in std::fs::read_dir(catalog.join("payloads")).unwrap() {
            let name = entry.unwrap().file_name();
            let name = name.to_str().unwrap();
            let manifest_path = catalog.join("payloads").join(name).join("manifest.json");
            if !manifest_path.is_file() {
                continue;
            }
            let manifest: Manifest =
                serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
            // Shipped definitions omit site policy (allowlists, operator policy),
            // so stand in for the site: every contract-required or adapter-consumed
            // field that is neither fixed, caller-mapped nor defaulted gets a
            // schema-satisfying value.
            let definition = std::fs::read_to_string(catalog.join(format!("{name}.toml"))).unwrap();
            let mut overlay = crate::bindings::definition_overlay(&definition, name).unwrap();
            let mapped: Vec<String> = overlay
                .get("input_map")
                .and_then(Value::as_object)
                .map(|map| map.keys().cloned().collect())
                .unwrap_or_default();
            let contract = &manifest.contract["schema"];
            let adapter_needs = manifest.argv.iter().flat_map(|arg| match arg {
                Arg::Argument { name, default, .. } => {
                    vec![(name.as_str(), default.is_some())]
                }
                Arg::Object { fields } => fields
                    .values()
                    .map(|field| (field.name.as_str(), field.default.is_some()))
                    .collect(),
            });
            let required = contract["required"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|field| (field, false));
            let site_policy: Vec<(String, Value)> = required
                .chain(adapter_needs)
                .filter(|(field, defaulted)| {
                    !defaulted
                        && !mapped.iter().any(|key| key == field)
                        && overlay["fixed_args"].get(*field).is_none()
                })
                .map(|(field, _)| (field.to_owned(), sample(&contract["properties"][field])))
                .collect();
            let fixed = overlay
                .as_object_mut()
                .unwrap()
                .entry("fixed_args")
                .or_insert_with(|| json!({}));
            for (field, value) in site_policy {
                fixed[field] = value;
            }
            let binding = compile_binding(&manifest.contract, &overlay)
                .unwrap_or_else(|code| panic!("{}: {code}", manifest_path.display()));
            // Scalar format means "a bare string", so the reviewed schema must
            // agree and every default must already be a string.
            let properties = overlay
                .get("input_schema")
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object);
            let input_map = overlay.get("input_map").and_then(Value::as_object);
            for arg in &manifest.argv {
                let Arg::Argument {
                    name,
                    format,
                    default,
                } = arg
                else {
                    continue;
                };
                if let Format::Scalar = format {
                    // Scalar means "a bare string", so the reviewed contract must
                    // type the backend field as a string whether the value comes
                    // from the caller (input_map) or operator policy (fixed_args).
                    let declared = manifest
                        .contract
                        .get("schema")
                        .and_then(|schema| schema.get("properties"))
                        .and_then(|properties| properties.get(name))
                        .and_then(|schema| schema.get("type"))
                        .and_then(Value::as_str);
                    assert_eq!(
                        declared,
                        Some("string"),
                        "{}: scalar adapter {name} is typed {declared:?} in the reviewed contract",
                        manifest_path.display()
                    );
                    if let Some(default) = default {
                        assert!(
                            default.is_string(),
                            "{}: scalar adapter {name} has non-string default {default}",
                            manifest_path.display()
                        );
                    }
                    if let Some(fixed) = overlay.get("fixed_args").and_then(|fixed| fixed.get(name))
                    {
                        assert!(
                            fixed.is_string(),
                            "{}: scalar adapter {name} has non-string fixed_arg {fixed}",
                            manifest_path.display()
                        );
                    }
                    let _ = (&properties, &input_map);
                }
            }
            // Every adapter input must resolve: fixed_args, then the argument
            // default. Caller-required fields come from the input_map so the
            // real prepare() path is exercised, not reimplemented here.
            let mut inputs = serde_json::Map::new();
            if let Some(map) = overlay.get("input_map").and_then(Value::as_object) {
                for (backend, public) in map {
                    let Some(public) = public.as_str() else {
                        continue;
                    };
                    let Some(schema) = overlay
                        .get("input_schema")
                        .and_then(|schema| schema.get("properties"))
                        .and_then(|properties| properties.get(public))
                    else {
                        continue;
                    };
                    if overlay
                        .get("input_schema")
                        .and_then(|schema| schema.get("required"))
                        .and_then(Value::as_array)
                        .is_some_and(|required| {
                            required.iter().any(|field| field.as_str() == Some(public))
                        })
                    {
                        inputs.insert(public.to_owned(), sample(schema));
                    }
                    let _ = backend;
                }
            }
            let inputs = Value::Object(inputs);
            let prepared = binding
                .prepare(&inputs)
                .unwrap_or_else(|code| panic!("{}: {code}", manifest_path.display()));
            adapt(&manifest.argv, &prepared)
                .unwrap_or_else(|error| panic!("{}: {error:?}", manifest_path.display()));
            checked += 1;
        }
        assert!(
            checked >= 96,
            "expected every shipped manifest, saw {checked}"
        );
    }

    #[test]
    fn retired_adapter_variants_fail_to_parse() {
        // Only the shapes a shipped manifest uses may deserialize.
        for adapter in [
            json!([{"kind": "fixed", "value": "--now"}]),
            json!([{"kind": "argument", "name": "x", "format": "python_bool"}]),
            json!([{"kind": "argument", "name": "x", "format": "shell"}]),
            json!([{"kind": "constant", "value": "x"}]),
            json!([{"kind": "object", "fields": {}, "extra": 1}]),
        ] {
            assert!(
                serde_json::from_value::<Vec<Arg>>(adapter.clone()).is_err(),
                "{adapter} must not deserialize"
            );
        }
        // The shipped shapes still do.
        assert!(
            serde_json::from_value::<Vec<Arg>>(json!([
                {"kind": "object", "fields": {"unit": {"name": "unit"}}},
                {"kind": "argument", "name": "limit", "format": "scalar", "default": 8},
                {"kind": "argument", "name": "keys", "format": "json"},
            ]))
            .is_ok()
        );
    }

    #[test]
    fn scalar_strings_keep_their_type_through_the_adapter() {
        // A unit, interface or address that reads like JSON must not become one.
        let adapter: Vec<Arg> =
            serde_json::from_value(json!([{"kind":"argument","name":"unit","format":"scalar"}]))
                .unwrap();
        for literal in ["123", "true", "null", "1e3", "0123", "-1"] {
            assert_eq!(
                adapt(&adapter, &json!({"unit": literal})).unwrap(),
                vec![json!(literal)],
                "{literal} must stay a string"
            );
        }
        // Non-string scalars are rejected rather than coerced.
        for value in [json!(123), json!(true), json!(null), json!(["123"])] {
            assert!(adapt(&adapter, &json!({"unit": value})).is_err());
        }
    }

    #[test]
    fn executable_candidates_validate_allowed_dirs_and_normalization_collisions() {
        let mut manifest: Manifest = serde_json::from_value(serde_json::json!({
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
            "contract": {"schema":{"type":"object","properties":{"target_python":{"type":"string"}},"required":["target_python"],"additionalProperties":false},"aliases":{"aliases":{},"properties":{"target_python":{"aliases":{},"properties":{}}}},"defaults":{},"review_required":[]}
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
            vec![json!({"literal":["{{ executable }}","; shell"],"optional":null})]
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
