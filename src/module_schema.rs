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

fn check_aliases(schema: &Value, aliases: &Aliases) -> Result<(), &'static str> {
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => {
            let props = schema
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(INVALID)?;
            if aliases.items.is_some() || aliases.properties.len() != props.len() {
                return Err(INVALID);
            }
            for (alias, canonical) in &aliases.aliases {
                if !parameter(alias) || props.contains_key(alias) || !props.contains_key(canonical)
                {
                    return Err(INVALID);
                }
            }
            for (key, schema) in props {
                check_aliases(schema, aliases.properties.get(key).ok_or(INVALID)?)?;
            }
        }
        Some("array") => {
            if !aliases.aliases.is_empty() || !aliases.properties.is_empty() {
                return Err(INVALID);
            }
            check_aliases(
                schema.get("items").ok_or(INVALID)?,
                aliases.items.as_deref().ok_or(INVALID)?,
            )?;
        }
        _ => {
            if !aliases.aliases.is_empty()
                || !aliases.properties.is_empty()
                || aliases.items.is_some()
            {
                return Err(INVALID);
            }
        }
    }
    Ok(())
}

fn canonicalize(schema: &Value, aliases: &Aliases, value: &Value) -> Result<Value, &'static str> {
    match value {
        Value::Object(values) => {
            let props = schema
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(INPUT)?;
            let mut output = Map::new();
            for (key, value) in values {
                if !parameter(key) {
                    return Err(INPUT);
                }
                let key = aliases
                    .aliases
                    .get(key)
                    .map_or(key.as_str(), String::as_str);
                let schema = props.get(key).ok_or(INPUT)?;
                let node = aliases.properties.get(key).ok_or(INPUT)?;
                if output
                    .insert(key.to_owned(), canonicalize(schema, node, value)?)
                    .is_some()
                {
                    return Err(INPUT);
                }
            }
            Ok(Value::Object(output))
        }
        Value::Array(values) => {
            let schema = schema.get("items").ok_or(INPUT)?;
            let aliases = aliases.items.as_deref().ok_or(INPUT)?;
            Ok(Value::Array(
                values
                    .iter()
                    .map(|v| canonicalize(schema, aliases, v))
                    .collect::<Result<_, _>>()?,
            ))
        }
        _ => Ok(value.clone()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlay {
    input_schema: Value,
    fixed_args: Map<String, Value>,
    input_map: BTreeMap<String, String>,
}

pub(crate) struct CompiledModuleBinding {
    contract: Contract,
    input_schema: Value,
    fixed_args: Map<String, Value>,
    input_map: BTreeMap<String, String>,
}

pub(crate) fn compile_binding(
    contract: &Value,
    overlay: &Value,
) -> Result<CompiledModuleBinding, &'static str> {
    if !bounded(contract) || !bounded(overlay) {
        return Err(SCHEMA);
    }
    let contract: Contract = serde_json::from_value(contract.clone()).map_err(|_| INVALID)?;
    check_schema(&contract.schema, true)?;
    check_aliases(&contract.schema, &contract.aliases)?;
    for path in contract.defaults.keys() {
        let mut schema = &contract.schema;
        for segment in path.split('.') {
            let (key, array) = segment
                .strip_suffix("[]")
                .map_or((segment, false), |s| (s, true));
            schema = schema
                .get("properties")
                .and_then(|p| p.get(key))
                .ok_or(INVALID)?;
            if array {
                schema = schema.get("items").ok_or(INVALID)?;
            }
        }
    }
    let overlay: Overlay = serde_json::from_value(overlay.clone()).map_err(|_| SCHEMA)?;
    check_schema(&overlay.input_schema, true)?;
    let fixed = canonicalize(
        &contract.schema,
        &contract.aliases,
        &Value::Object(overlay.fixed_args),
    )?;
    let fixed_args = fixed.as_object().ok_or(SCHEMA)?.clone();
    let backend = contract
        .schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(SCHEMA)?;
    // Fixed subtrees must already be valid; only root requiredness is deferred.
    for (key, value) in &fixed_args {
        validate(backend.get(key).ok_or(SCHEMA)?, value)?;
    }
    let public = overlay
        .input_schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or(SCHEMA)?;
    let mut input_map = BTreeMap::new();
    let mut mapped = BTreeSet::new();
    for (target, input) in overlay.input_map {
        if !parameter(&target) || !parameter(&input) {
            return Err(SCHEMA);
        }
        let target = contract
            .aliases
            .aliases
            .get(&target)
            .cloned()
            .unwrap_or(target);
        let schema = backend.get(&target).ok_or(SCHEMA)?;
        let input_schema = public.get(&input).ok_or(SCHEMA)?;
        if fixed_args.contains_key(&target)
            || input_map.contains_key(&target)
            || !mapped.insert(input.clone())
        {
            return Err(SCHEMA);
        }
        compatible(
            input_schema,
            schema,
            contract.aliases.properties.get(&target).ok_or(SCHEMA)?,
        )?;
        input_map.insert(target, input);
    }
    if mapped.len() != public.len() {
        return Err(SCHEMA);
    }
    if let Some(required) = contract.schema.get("required").and_then(Value::as_array) {
        for key in required {
            let key = key.as_str().ok_or(SCHEMA)?;
            if !fixed_args.contains_key(key) {
                let input = input_map.get(key).ok_or(SCHEMA)?;
                if !is_required(&overlay.input_schema, input) {
                    return Err(SCHEMA);
                }
            }
        }
    }
    Ok(CompiledModuleBinding {
        contract,
        input_schema: overlay.input_schema,
        fixed_args,
        input_map,
    })
}

fn is_required(schema: &Value, key: &str) -> bool {
    schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(key)))
}

// Structural compatibility is conservative, not a general schema implication
// prover. Conditional narrowing is checked on actual requests as well.
fn compatible(input: &Value, backend: &Value, aliases: &Aliases) -> Result<(), &'static str> {
    let source = input.get("type").and_then(Value::as_str).ok_or(SCHEMA)?;
    let target = backend.get("type").and_then(Value::as_str).ok_or(SCHEMA)?;
    if source != target && !(source == "integer" && target == "number") {
        return Err(SCHEMA);
    }
    match source {
        "object" => {
            let props = input
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(SCHEMA)?;
            let targets = backend
                .get("properties")
                .and_then(Value::as_object)
                .ok_or(SCHEMA)?;
            let mut names = BTreeSet::new();
            for (key, schema) in props {
                let key = aliases
                    .aliases
                    .get(key)
                    .map_or(key.as_str(), String::as_str);
                if !names.insert(key) {
                    return Err(SCHEMA);
                }
                compatible(
                    schema,
                    targets.get(key).ok_or(SCHEMA)?,
                    aliases.properties.get(key).ok_or(SCHEMA)?,
                )?;
            }
            if let Some(required) = backend.get("required").and_then(Value::as_array) {
                for key in required {
                    let key = key.as_str().ok_or(SCHEMA)?;
                    if !props.keys().any(|k| {
                        aliases.aliases.get(k).map_or(k.as_str(), String::as_str) == key
                            && is_required(input, k)
                    }) {
                        return Err(SCHEMA);
                    }
                }
            }
        }
        "array" => compatible(
            input.get("items").ok_or(SCHEMA)?,
            backend.get("items").ok_or(SCHEMA)?,
            aliases.items.as_deref().ok_or(SCHEMA)?,
        )?,
        _ => (),
    }
    if let Some(choices) = input.get("enum").and_then(Value::as_array) {
        for value in choices {
            let canonical = canonicalize(backend, aliases, value)?;
            validate(backend, &canonical)?;
        }
    }
    if let Some(value) = input.get("const") {
        validate(backend, &canonicalize(backend, aliases, value)?)?;
    }
    Ok(())
}

impl CompiledModuleBinding {
    pub(crate) fn prepare(&self, input: &Value) -> Result<Value, &'static str> {
        if !bounded(input) {
            return Err(INPUT);
        }
        validate(&self.input_schema, input)?;
        let input = input.as_object().ok_or(INPUT)?;
        let mut output = self.fixed_args.clone();
        let props = self
            .contract
            .schema
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(INPUT)?;
        for (backend, public) in &self.input_map {
            if let Some(value) = input.get(public) {
                let schema = props.get(backend).ok_or(INPUT)?;
                let aliases = self.contract.aliases.properties.get(backend).ok_or(INPUT)?;
                if output
                    .insert(backend.clone(), canonicalize(schema, aliases, value)?)
                    .is_some()
                {
                    return Err(INPUT);
                }
            }
        }
        let output = Value::Object(output);
        if !bounded(&output) {
            return Err(INPUT);
        }
        validate(&self.contract.schema, &output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> Value {
        import_document(&json!({"doc":{"options":{
            "path":{"type":"path","required":true,"aliases":["dest"]},
            "follow":{"type":"bool","default":false,"aliases":["follow-link"]},
            "entries":{"type":"list","elements":"dict","suboptions":{
                "label":{"type":"str","required":true,"aliases":["name"],"choices":["a","b"]},
                "active":{"type":"bool","default":true}
            }}
        }}}))
        .unwrap()
    }

    fn overlay() -> Value {
        json!({"input_schema":{"type":"object","properties":{
            "location":{"type":"string"},
            "values":{"type":"array","items":{"type":"object","properties":{
                "name":{"type":"string","enum":["a","b"]}
            },"required":["name"],"additionalProperties":false}}
        },"required":["location"],"additionalProperties":false},
        "fixed_args":{},"input_map":{"dest":"location","entries":"values"}})
    }

    #[test]
    fn nested_aliases_canonicalize_and_defaults_remain_omitted() {
        let binding = compile_binding(&contract(), &overlay()).unwrap();
        assert_eq!(
            binding
                .prepare(&json!({"location":"/tmp","values":[{"name":"a"}]}))
                .unwrap(),
            json!({"path":"/tmp","entries":[{"label":"a"}]})
        );
        assert_eq!(
            binding.prepare(&json!({"location":"/tmp"})).unwrap(),
            json!({"path":"/tmp"})
        );
    }

    #[test]
    fn fixed_and_alias_overrides_are_rejected() {
        let mut value = overlay();
        value["fixed_args"] = json!({"path":"/fixed"});
        assert!(compile_binding(&contract(), &value).is_err());
        value["fixed_args"] = json!({"path":"/one","dest":"/two"});
        assert!(compile_binding(&contract(), &value).is_err());
        value = overlay();
        value["input_map"]["path"] = json!("location");
        assert!(compile_binding(&contract(), &value).is_err());
        value = overlay();
        value["fixed_args"] = json!({"follow-link":false});
        let binding = compile_binding(&contract(), &value).unwrap();
        assert_eq!(
            binding.prepare(&json!({"location":"/tmp"})).unwrap(),
            json!({"path":"/tmp","follow":false})
        );
    }

    #[test]
    fn final_backend_choices_and_recursive_unknowns_are_enforced() {
        let binding = compile_binding(&contract(), &overlay()).unwrap();
        for input in [
            json!({"location":"/tmp","values":[{"name":"c"}]}),
            json!({"location":"/tmp","values":[{"name":"a","active":true}]}),
            json!({"location":"/tmp","path":"/override"}),
            json!({}),
        ] {
            assert!(binding.prepare(&input).is_err(), "{input}");
        }
        let mut value = overlay();
        value["input_schema"]["properties"]["values"]["items"]["properties"]["name"]
            .as_object_mut()
            .unwrap()
            .remove("enum");
        let binding = compile_binding(&contract(), &value).unwrap();
        assert!(
            binding
                .prepare(&json!({"location":"/tmp","values":[{"name":"c"}]}))
                .is_err()
        );
    }

    #[test]
    fn ordinary_conditional_overlay_is_applied() {
        let mut value = overlay();
        value["input_schema"]["if"] =
            json!({"properties":{"location":{"const":"/special"}},"required":["location"]});
        value["input_schema"]["then"] = json!({"required":["values"]});
        value["input_schema"]["else"] = json!({"not":{"required":["values"]}});
        let binding = compile_binding(&contract(), &value).unwrap();
        assert!(binding.prepare(&json!({"location":"/special"})).is_err());
        assert!(
            binding
                .prepare(&json!({"location":"/ordinary","values":[]}))
                .is_err()
        );
        assert!(
            binding
                .prepare(&json!({"location":"/special","values":[]}))
                .is_ok()
        );
        assert!(binding.prepare(&json!({"location":"/ordinary"})).is_ok());
    }

    #[test]
    fn malformed_and_unsupported_semantics_fail_closed() {
        for option in [
            json!({"type":"raw"}),
            json!({"type":"dict"}),
            json!({"type":"list"}),
            json!({"type":"str","required":"yes"}),
            json!({"type":"str","required_if":[]}),
            json!({"type":"str","choices":[]}),
        ] {
            assert!(import_document(&json!({"doc":{"options":{"value":option}}})).is_err());
        }
        for key in ["default", "$ref", "pattern", "unknown"] {
            let mut value = overlay();
            value["input_schema"][key] = json!("ignored?");
            assert!(compile_binding(&contract(), &value).is_err());
        }
        let mut value = overlay();
        value["extra"] = json!(true);
        assert!(compile_binding(&contract(), &value).is_err());
    }

    #[test]
    fn nested_alias_collision_and_missing_required_mapping_fail_compile() {
        let mut value = overlay();
        value["input_schema"]["properties"]["values"]["items"]["properties"]["label"] =
            json!({"type":"string"});
        assert!(compile_binding(&contract(), &value).is_err());
        value = overlay();
        value["input_schema"]["required"] = json!([]);
        assert!(compile_binding(&contract(), &value).is_err());
    }

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
    fn list_choices_constrain_items_not_the_entire_array() {
        let contract = import_document(&json!({"doc":{"options":{
            "filter":{"type":"list","elements":"str","choices":["a","b"],"default":["a"]}
        }}}))
        .unwrap();
        let overlay = json!({
            "input_schema":{"type":"object","properties":{
                "selected":{"type":"array","items":{"type":"string"}}
            },"additionalProperties":false},
            "fixed_args":{},"input_map":{"filter":"selected"}
        });
        let binding = compile_binding(&contract, &overlay).unwrap();
        assert_eq!(binding.prepare(&json!({})).unwrap(), json!({}));
        assert_eq!(
            binding.prepare(&json!({"selected":["a","b"]})).unwrap(),
            json!({"filter":["a","b"]})
        );
        assert!(binding.prepare(&json!({"selected":["c"]})).is_err());
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

    #[test]
    fn numeric_equality_and_conditional_combinators_follow_json_schema() {
        assert!(validate(&json!({"enum":[1]}), &json!(1.0)).is_ok());
        assert!(check_schema(&json!({"enum":[1,1.0]}), false).is_err());
        assert!(validate(&json!({"uniqueItems":true}), &json!([1, 1.0])).is_err());
        let schema = json!({"allOf":[{"minimum":1},{"maximum":4}],
            "anyOf":[{"const":1},{"const":2},{"const":3}],
            "oneOf":[{"const":1},{"const":2}]});
        assert!(validate(&schema, &json!(1)).is_ok());
        assert!(validate(&schema, &json!(3)).is_err());
        assert!(validate(&schema, &json!(5)).is_err());
        assert!(!bounded(&json!(9_007_199_254_740_992u64)));
    }

    #[test]
    fn incompatible_mapped_types_and_unmapped_inputs_fail_compile() {
        let mut value = overlay();
        value["input_schema"]["properties"]["location"] = json!({"type":"integer"});
        assert!(compile_binding(&contract(), &value).is_err());
        value = overlay();
        value["input_schema"]["properties"]["unused"] = json!({"type":"string"});
        assert!(compile_binding(&contract(), &value).is_err());
        value = overlay();
        value["fixed_args"] = json!({"entries":[{}]});
        assert!(compile_binding(&contract(), &value).is_err());
    }

    #[test]
    fn tampered_contract_and_excessive_depth_are_rejected() {
        let mut value = contract();
        value["aliases"]["aliases"]["dest"] = json!("nonexistent");
        assert!(compile_binding(&value, &overlay()).is_err());
        let mut deep = json!(null);
        for _ in 0..40 {
            deep = json!([deep]);
        }
        assert!(!bounded(&deep));
    }
}
