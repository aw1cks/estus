//! Shared authoring restrictions for the reviewed JSON Schema subsets.
//!
//! Module contracts and operator projections both accept a deliberately narrow,
//! closed subset: no references, regexes, coercion, defaults, open objects,
//! tuple arrays, or dialect-dependent keywords. One walker enforces the keyword
//! allowlist for both surfaces, with per-surface shape ceilings layered on top.
use std::collections::BTreeSet;

use serde_json::Value;

pub(crate) const SCHEMA: &str = "invalid_binding_schema";
/// Ceiling for every structural `min*`/`max*` keyword value.
const LIMIT: u64 = 256 * 1024;
/// Structural depth ceiling for contract schemas; `bounded()` already caps the
/// decoded JSON, so this never fires first for a schema that reached the walker.
const DEPTH: usize = 32;

pub(crate) fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

pub(crate) fn parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(i, c)| {
            c == b'_' || c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || c == b'-'))
        })
        && !value.starts_with('_')
        && !value.starts_with("ansible_")
}

/// Result members that never leave the controller, regardless of vendor naming.
pub(crate) fn source_key(value: &str, allow_diff: bool) -> bool {
    name(value)
        && !value.starts_with('_')
        && !matches!(
            value,
            "invocation"
                | "module_args"
                | "args"
                | "argv"
                | "cmd"
                | "env"
                | "environment"
                | "ansible_env"
        )
        && (allow_diff || value != "diff")
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Names {
    /// Ansible module argument names.
    Parameter,
    /// Projection source keys, which also hide private and transport detail.
    Projection { allow_diff: bool },
}

impl Names {
    fn accepts(self, key: &str) -> bool {
        match self {
            Self::Parameter => parameter(key),
            Self::Projection { allow_diff } => source_key(key, allow_diff),
        }
    }
}

/// Per-surface shape ceilings on top of the shared keyword allowlist.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Profile {
    pub(crate) names: Names,
    /// Structural depth ceiling counted from the root schema node. Conditional
    /// branches nest a schema without nesting the evaluated value, so they do
    /// not consume depth.
    pub(crate) depth: usize,
    /// Every evaluated node declares `type`; conditional assertions may be
    /// partial and are checked only when a value reaches them.
    pub(crate) concrete: bool,
    /// Concrete string nodes must declare a `maxLength` at or below this.
    pub(crate) max_length: Option<u64>,
    /// Concrete array nodes must declare a `maxItems` at or below this.
    pub(crate) max_items: Option<u64>,
    /// The root object's property names are restricted by the caller, which
    /// already bounds them through the plan's field map.
    pub(crate) open_root: bool,
}

impl Profile {
    pub(crate) const MODULE: Self = Self {
        names: Names::Parameter,
        depth: DEPTH,
        concrete: false,
        max_length: None,
        max_items: None,
        open_root: false,
    };
}

pub(crate) fn check(schema: &Value, profile: &Profile) -> Result<(), &'static str> {
    walk(schema, 0, true, true, profile)
}

fn walk(
    schema: &Value,
    depth: usize,
    concrete: bool,
    root: bool,
    profile: &Profile,
) -> Result<(), &'static str> {
    if depth > profile.depth {
        return Err(SCHEMA);
    }
    let object = schema.as_object().ok_or(SCHEMA)?;
    let kind = object.get("type").and_then(Value::as_str);
    if concrete && profile.concrete && kind.is_none() {
        return Err(SCHEMA);
    }
    for (key, value) in object {
        match key.as_str() {
            "type" => {
                if !matches!(
                    value.as_str(),
                    Some("object" | "array" | "string" | "integer" | "number" | "boolean" | "null")
                ) {
                    return Err(SCHEMA);
                }
            }
            "properties" => {
                for (key, value) in value.as_object().ok_or(SCHEMA)? {
                    if !(root && profile.open_root) && !profile.names.accepts(key) {
                        return Err(SCHEMA);
                    }
                    walk(value, depth + 1, true, false, profile)?;
                }
            }
            "required" => {
                let mut seen = BTreeSet::new();
                for key in value.as_array().ok_or(SCHEMA)? {
                    let key = key
                        .as_str()
                        .filter(|key| profile.names.accepts(key))
                        .ok_or(SCHEMA)?;
                    if !seen.insert(key) {
                        return Err(SCHEMA);
                    }
                }
            }
            "additionalProperties" => {
                if value != &Value::Bool(false) {
                    return Err(SCHEMA);
                }
            }
            "items" => walk(value, depth + 1, true, false, profile)?,
            "not" | "if" | "then" | "else" => walk(value, depth, false, root, profile)?,
            "allOf" | "anyOf" | "oneOf" => {
                let values = value.as_array().filter(|v| !v.is_empty()).ok_or(SCHEMA)?;
                for value in values {
                    walk(value, depth, false, root, profile)?;
                }
            }
            "enum" => {
                let values = value.as_array().filter(|v| !v.is_empty()).ok_or(SCHEMA)?;
                if values
                    .iter()
                    .enumerate()
                    .any(|(i, v)| values[..i].iter().any(|other| equal(other, v)))
                {
                    return Err(SCHEMA);
                }
            }
            "const" => (),
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(SCHEMA);
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" => {
                if value.as_u64().is_none_or(|n| n > LIMIT) {
                    return Err(SCHEMA);
                }
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    return Err(SCHEMA);
                }
            }
            "title" | "description" => {
                if !value.is_string() {
                    return Err(SCHEMA);
                }
            }
            _ => return Err(SCHEMA),
        }
    }
    if kind == Some("object") {
        let props = object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(SCHEMA)?;
        if object.get("additionalProperties") != Some(&Value::Bool(false)) {
            return Err(SCHEMA);
        }
        if let Some(required) = object.get("required")
            && required
                .as_array()
                .ok_or(SCHEMA)?
                .iter()
                .any(|v| v.as_str().is_none_or(|s| !props.contains_key(s)))
        {
            return Err(SCHEMA);
        }
    }
    if kind == Some("array") && !object.contains_key("items") {
        return Err(SCHEMA);
    }
    if (object.contains_key("then") || object.contains_key("else")) && !object.contains_key("if") {
        return Err(SCHEMA);
    }
    if let Some(limit) = profile.max_length.filter(|_| kind == Some("string"))
        && object
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_none_or(|n| n > limit)
    {
        return Err(SCHEMA);
    }
    if let Some(limit) = profile.max_items.filter(|_| kind == Some("array"))
        && object
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_none_or(|n| n > limit)
    {
        return Err(SCHEMA);
    }
    Ok(())
}

/// JSON Schema numeric equality: `1` and `1.0` are the same number.
pub(crate) fn equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|other| equal(v, other)))
        }
        _ => left == right,
    }
}

pub(crate) fn resolve_ref<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
        return node;
    };
    let Some(pointer) = reference.strip_prefix('#') else {
        return node;
    };
    root.pointer(pointer).unwrap_or(node)
}

/// Map one validator failure onto the fixed constraint vocabulary callers see.
pub(crate) fn classify(
    kind: &jsonschema::error::ValidationErrorKind,
    schema_path: &str,
    fallback: &'static str,
) -> &'static str {
    use jsonschema::error::ValidationErrorKind as K;
    match kind {
        K::AdditionalProperties { .. } | K::UnevaluatedProperties { .. } => "unknown_field",
        K::FalseSchema
            if schema_path.ends_with("/additionalProperties")
                || schema_path.ends_with("/unevaluatedProperties") =>
        {
            "unknown_field"
        }
        K::Required { .. } => "missing_field",
        K::Type { .. } => "invalid_type",
        K::Enum { .. } => "invalid_enum",
        K::Minimum { .. } | K::ExclusiveMinimum { .. } => "below_minimum",
        K::Maximum { .. } | K::ExclusiveMaximum { .. } => "above_maximum",
        K::MinLength { .. } | K::MinItems { .. } | K::MinProperties { .. } => "too_short",
        K::MaxLength { .. } | K::MaxItems { .. } | K::MaxProperties { .. } => "too_long",
        K::Pattern { .. } | K::BacktrackLimitExceeded { .. } | K::Format { .. } => {
            "pattern_mismatch"
        }
        K::Constant { .. } => "const_mismatch",
        K::AnyOf { context } | K::OneOfNotValid { context } => context
            .iter()
            .flatten()
            .find(|err| !matches!(err.kind(), K::Type { .. }))
            .map(|err| classify(err.kind(), err.schema_path().as_str(), fallback))
            .unwrap_or("invalid_type"),
        _ => fallback,
    }
}

pub(crate) fn classify_error(
    error: &jsonschema::ValidationError<'_>,
    fallback: &'static str,
) -> &'static str {
    classify(error.kind(), error.schema_path().as_str(), fallback)
}

/// Report only declared members and indices, following the schema's own shape
/// so an unexpected value can never echo its content or an undeclared key.
pub(crate) fn safe_path(
    root: &Value,
    error: &jsonschema::ValidationError<'_>,
    label: &str,
) -> String {
    use jsonschema::error::ValidationErrorKind as K;
    use jsonschema::paths::LocationSegment;

    let mut path = String::from(label);
    let mut cursor = resolve_ref(root, root);
    for segment in error.instance_path().iter() {
        cursor = resolve_ref(root, cursor);
        match segment {
            LocationSegment::Property(prop) => {
                if let Some(next) = cursor
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|props| props.get(prop.as_ref()))
                {
                    path.push('.');
                    path.push_str(prop.as_ref());
                    cursor = resolve_ref(root, next);
                } else {
                    return path;
                }
            }
            LocationSegment::Index(idx) => {
                let items = cursor.get("items").or_else(|| {
                    cursor
                        .get("anyOf")
                        .and_then(Value::as_array)
                        .and_then(|branches| {
                            branches
                                .iter()
                                .map(|branch| resolve_ref(root, branch))
                                .find_map(|branch| branch.get("items"))
                        })
                });
                if let Some(next) = items {
                    path.push('.');
                    path.push_str(&idx.to_string());
                    cursor = resolve_ref(root, next);
                } else {
                    return path;
                }
            }
        }
    }
    if let K::Required {
        property: Value::String(prop),
    } = error.kind()
    {
        cursor = resolve_ref(root, cursor);
        if cursor
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|props| props.contains_key(prop))
        {
            path.push('.');
            path.push_str(prop);
        }
    }
    path
}
