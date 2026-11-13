//! Public ansible-doc conversion and a deliberately bounded, closed schema subset.
//!
//! Documentation defaults are review metadata, never argument values. Public docs
//! do not describe all argument-spec or module-body constraints: review_required
//! records that gap; an operator can add ordinary conditional input constraints.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

const INVALID: &str = "unsupported_module_contract";
const SCHEMA: &str = "invalid_binding_schema";
const INPUT: &str = "invalid_binding_arguments";
const LIMIT: usize = 256 * 1024;
const DEPTH: usize = 32;
const NODES: usize = 8192;
const RESERVED: &[&str] = &[
    "host",
    "timeout_secs",
    "argv",
    "program",
    "cwd",
    "stdin",
    "user",
    "role",
    "authority",
    "execution",
    "profile",
    "env",
    "shell",
    "sudo",
    "command",
    "revision",
    "effects",
    "result",
    "input_schema",
    "enabled_tools",
    "delegate_to",
    "become",
    "become_user",
    "connection",
    "module",
    "module_name",
];

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

fn parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(i, c)| {
            c == b'_' || c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || c == b'-'))
        })
        && !value.starts_with('_')
        && !RESERVED.contains(&value)
        && !value.starts_with("ansible_")
}

pub(crate) fn valid_fqcn(value: &str) -> bool {
    value.len() <= 256
        && value.split('.').count() >= 3
        && value
            .split('.')
            .all(|part| name(part) && part.bytes().all(|c| !c.is_ascii_uppercase()))
}

// Limit numbers to binary64's exact integer magnitude range so bounds and
// JSON Schema numeric equality cannot collapse distinct integer values.
fn bounded(value: &Value) -> bool {
    fn walk(value: &Value, depth: usize, nodes: &mut usize, bytes: &mut usize) -> bool {
        *nodes += 1;
        if depth > DEPTH || *nodes > NODES {
            return false;
        }
        *bytes += match value {
            Value::String(s) => s.len(),
            _ => 8,
        };
        match value {
            Value::Object(m) => m.iter().all(|(k, v)| {
                *bytes += k.len();
                *bytes <= LIMIT && walk(v, depth + 1, nodes, bytes)
            }),
            Value::Array(a) => a.iter().all(|v| walk(v, depth + 1, nodes, bytes)),
            Value::Number(n) => {
                *bytes <= LIMIT
                    && n.as_f64()
                        .is_some_and(|n| n.abs() <= 9_007_199_254_740_991.0)
            }
            _ => *bytes <= LIMIT,
        }
    }
    walk(value, 0, &mut 0, &mut 0)
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Aliases {
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    properties: BTreeMap<String, Aliases>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    items: Option<Box<Aliases>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Contract {
    schema: Value,
    aliases: Aliases,
    defaults: BTreeMap<String, Value>,
    review_required: Vec<String>,
}

/// Import the single entry returned by public `ansible-doc --json`.
/// Only option semantics with an exact JSON representation are accepted.
pub(crate) fn import_document(document: &Value) -> Result<Value, &'static str> {
    if !bounded(document) {
        return Err(INVALID);
    }
    let doc = document
        .get("doc")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    // These argument-spec constructs have no public-doc conversion here.
    for key in [
        "mutually_exclusive",
        "required_together",
        "required_one_of",
        "required_if",
        "required_by",
    ] {
        if doc.contains_key(key) {
            return Err(INVALID);
        }
    }
    let options = doc
        .get("options")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut defaults = BTreeMap::new();
    let (mut schema, aliases) = import_options(options, "", &mut defaults)?;
    let mut prose = Vec::new();
    for key in ["description", "notes"] {
        if let Some(value) = doc.get(key) {
            prose.push(description(value)?);
        }
    }
    if !prose.is_empty() {
        schema
            .as_object_mut()
            .ok_or(INVALID)?
            .insert("description".to_owned(), Value::String(prose.join("\n\n")));
    }
    check_schema(&schema, true)?;
    let result = serde_json::to_value(Contract {
        schema, aliases, defaults,
        review_required: vec!["Public documentation is not the runtime argument specification and does not reliably expose required_if, mutual exclusions, coercions, or module-body constraints. Binding authors must review the preserved descriptions and supply conditional input_schema constraints or a narrower fixed/mapped surface; no prose rules are inferred or certified. Defaults are metadata only and are never injected.".to_owned()],
    }).map_err(|_| INVALID)?;
    if !bounded(&result) {
        return Err(INVALID);
    }
    Ok(result)
}

// Preserve prose for operator review, never classify it as validation authority.
fn description(value: &Value) -> Result<String, &'static str> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Array(paragraphs) => {
            let paragraphs = paragraphs
                .iter()
                .map(|v| v.as_str().ok_or(INVALID))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(paragraphs.join("\n\n"))
        }
        _ => Err(INVALID),
    }
}

fn import_options(
    options: &Map<String, Value>,
    path: &str,
    defaults: &mut BTreeMap<String, Value>,
) -> Result<(Value, Aliases), &'static str> {
    let mut properties = Map::new();
    let mut required = Vec::new();
    let mut aliases = Aliases::default();
    for (key, option) in options {
        if !parameter(key) {
            return Err(INVALID);
        }
        let option = option.as_object().ok_or(INVALID)?;
        // Ignore only known documentation-only annotations. Unknown semantics fail closed.
        if option.keys().any(|k| {
            ![
                "type",
                "elements",
                "suboptions",
                "required",
                "choices",
                "aliases",
                "default",
                "description",
                "version_added",
                "version_added_collection",
                "deprecated",
            ]
            .contains(&k.as_str())
        }) {
            return Err(INVALID);
        }
        let full = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if let Some(value) = option.get("default") {
            defaults.insert(full.clone(), value.clone());
        }
        if option.get("required").is_some_and(|v| !v.is_boolean()) {
            return Err(INVALID);
        }
        if option.get("required") == Some(&Value::Bool(true)) {
            required.push(Value::String(key.clone()));
        }
        let kind = option.get("type").and_then(Value::as_str).ok_or(INVALID)?;
        let (mut schema, node) = import_type(kind, option, &full, defaults)?;
        if let Some(prose) = option.get("description") {
            schema
                .as_object_mut()
                .ok_or(INVALID)?
                .insert("description".to_owned(), Value::String(description(prose)?));
        }
        if let Some(choices) = option.get("choices") {
            let choices = choices
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or(INVALID)?;
            let target = if kind == "list" {
                schema.get_mut("items").ok_or(INVALID)?
            } else {
                &mut schema
            };
            for choice in choices {
                validate(target, choice).map_err(|_| INVALID)?;
            }
            target
                .as_object_mut()
                .ok_or(INVALID)?
                .insert("enum".to_owned(), Value::Array(choices.clone()));
        }
        if let Some(values) = option.get("aliases") {
            for alias in values.as_array().ok_or(INVALID)? {
                let alias = alias.as_str().filter(|v| parameter(v)).ok_or(INVALID)?;
                if options.contains_key(alias)
                    || aliases
                        .aliases
                        .insert(alias.to_owned(), key.clone())
                        .is_some()
                {
                    return Err(INVALID);
                }
            }
        }
        aliases.properties.insert(key.clone(), node);
        properties.insert(key.clone(), schema);
    }
    Ok((
        json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
        aliases,
    ))
}

fn import_type(
    kind: &str,
    option: &Map<String, Value>,
    path: &str,
    defaults: &mut BTreeMap<String, Value>,
) -> Result<(Value, Aliases), &'static str> {
    let scalar = match kind {
        "str" | "path" => Some("string"),
        "bool" => Some("boolean"),
        "int" => Some("integer"),
        "float" => Some("number"),
        _ => None,
    };
    if let Some(kind) = scalar {
        if option.contains_key("suboptions") || option.contains_key("elements") {
            return Err(INVALID);
        }
        return Ok((json!({"type":kind}), Aliases::default()));
    }
    match kind {
        "dict" => {
            if option.contains_key("elements") {
                return Err(INVALID);
            }
            let sub = option
                .get("suboptions")
                .and_then(Value::as_object)
                .ok_or(INVALID)?;
            import_options(sub, path, defaults)
        }
        "list" => {
            let elements = option
                .get("elements")
                .and_then(Value::as_str)
                .ok_or(INVALID)?;
            if elements == "list" {
                return Err(INVALID);
            }
            let mut item = option.clone();
            item.remove("elements");
            let (schema, aliases) = import_type(elements, &item, &format!("{path}[]"), defaults)?;
            Ok((
                json!({"type":"array","items":schema}),
                Aliases {
                    items: Some(Box::new(aliases)),
                    ..Aliases::default()
                },
            ))
        }
        _ => Err(INVALID),
    }
}

// Ordinary JSON Schema subset, intentionally no references, regexes, coercion,
// defaults, open objects, tuple arrays, or dialect-dependent keywords.
fn check_schema(schema: &Value, root: bool) -> Result<(), &'static str> {
    if !bounded(schema) {
        return Err(SCHEMA);
    }
    check_schema_node(schema)?;
    if root && schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err(SCHEMA);
    }
    Ok(())
}

fn check_schema_node(schema: &Value) -> Result<(), &'static str> {
    let object = schema.as_object().ok_or(SCHEMA)?;
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
                    if !parameter(key) {
                        return Err(SCHEMA);
                    }
                    check_schema_node(value)?;
                }
            }
            "required" => {
                let mut seen = BTreeSet::new();
                for key in value.as_array().ok_or(SCHEMA)? {
                    let key = key.as_str().filter(|v| parameter(v)).ok_or(SCHEMA)?;
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
            "items" | "not" | "if" | "then" | "else" => check_schema_node(value)?,
            "allOf" | "anyOf" | "oneOf" => {
                let values = value.as_array().filter(|v| !v.is_empty()).ok_or(SCHEMA)?;
                for value in values {
                    check_schema_node(value)?;
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
                if value.as_u64().is_none_or(|n| n > LIMIT as u64) {
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
    if object.get("type").and_then(Value::as_str) == Some("object") {
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
    if object.get("type").and_then(Value::as_str) == Some("array") && !object.contains_key("items")
    {
        return Err(SCHEMA);
    }
    if (object.contains_key("then") || object.contains_key("else")) && !object.contains_key("if") {
        return Err(SCHEMA);
    }
    Ok(())
}

fn integral(value: &Value) -> bool {
    value.is_i64()
        || value.is_u64()
        || value
            .as_f64()
            .is_some_and(|n| n.is_finite() && n.fract() == 0.0)
}

fn equal(left: &Value, right: &Value) -> bool {
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

fn validate(schema: &Value, value: &Value) -> Result<(), &'static str> {
    let object = schema.as_object().ok_or(INPUT)?;
    if let Some(kind) = object.get("type").and_then(Value::as_str) {
        let valid = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => integral(value),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !valid {
            return Err(INPUT);
        }
    }
    if object.get("const").is_some_and(|v| !equal(v, value)) {
        return Err(INPUT);
    }
    if object
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.iter().any(|v| equal(v, value)))
    {
        return Err(INPUT);
    }
    if let Some(values) = value.as_object() {
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required
                .iter()
                .any(|k| k.as_str().is_none_or(|k| !values.contains_key(k)))
        {
            return Err(INPUT);
        }
        let props = object.get("properties").and_then(Value::as_object);
        for (key, value) in values {
            if let Some(schema) = props.and_then(|p| p.get(key)) {
                validate(schema, value)?;
            } else if object.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(INPUT);
            }
        }
        length(object, values.len(), "minProperties", "maxProperties")?;
    }
    if let Some(values) = value.as_array() {
        length(object, values.len(), "minItems", "maxItems")?;
        if let Some(items) = object.get("items") {
            for value in values {
                validate(items, value)?;
            }
        }
        if object.get("uniqueItems") == Some(&Value::Bool(true))
            && values
                .iter()
                .enumerate()
                .any(|(i, v)| values[..i].iter().any(|other| equal(other, v)))
        {
            return Err(INPUT);
        }
    }
    if let Some(value) = value.as_str() {
        length(object, value.chars().count(), "minLength", "maxLength")?;
    }
    if let Some(value) = value.as_f64() {
        for (key, exclusive, lower) in [
            ("minimum", false, true),
            ("maximum", false, false),
            ("exclusiveMinimum", true, true),
            ("exclusiveMaximum", true, false),
        ] {
            if let Some(limit) = object.get(key).and_then(Value::as_f64)
                && ((lower && (value < limit || (exclusive && value == limit)))
                    || (!lower && (value > limit || (exclusive && value == limit))))
            {
                return Err(INPUT);
            }
        }
    }
    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(schemas) = object.get(key).and_then(Value::as_array) {
            let matches = schemas
                .iter()
                .filter(|s| validate(s, value).is_ok())
                .count();
            if match key {
                "allOf" => matches != schemas.len(),
                "anyOf" => matches == 0,
                _ => matches != 1,
            } {
                return Err(INPUT);
            }
        }
    }
    if object
        .get("not")
        .is_some_and(|s| validate(s, value).is_ok())
    {
        return Err(INPUT);
    }
    if let Some(condition) = object.get("if") {
        let branch = if validate(condition, value).is_ok() {
            "then"
        } else {
            "else"
        };
        if let Some(schema) = object.get(branch) {
            validate(schema, value)?;
        }
    }
    Ok(())
}

fn length(
    object: &Map<String, Value>,
    length: usize,
    min: &str,
    max: &str,
) -> Result<(), &'static str> {
    if object
        .get(min)
        .and_then(Value::as_u64)
        .is_some_and(|n| (length as u64) < n)
        || object
            .get(max)
            .and_then(Value::as_u64)
            .is_some_and(|n| (length as u64) > n)
    {
        return Err(INPUT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reserved_keys_and_fqcn_boundaries() {
        for key in ["host", "execution", "ansible_connection", "_raw_params"] {
            assert!(import_document(&json!({"doc":{"options":{(key):{"type":"str"}}}})).is_err());
        }
        assert!(valid_fqcn("ansible.builtin.ping"));
        for name in ["ping", "a.b", "a.b.-option", "a.b.c;id", "a..c", "a.b.3bad"] {
            assert!(!valid_fqcn(name));
        }
    }

    #[test]
    fn descriptions_are_preserved_for_review_not_classified_as_rules() {
        let contract = import_document(&json!({"doc":{"options":{
            "value":{"type":"str","description":["Required when O(state=present).","Review this constraint."]}
        }}})).unwrap();
        assert_eq!(
            contract["schema"]["properties"]["value"]["description"],
            json!("Required when O(state=present).\n\nReview this constraint.")
        );
    }
}
