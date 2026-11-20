//! Operator-owned selection policy; no request can alter paths, schemas or limits.
use std::{collections::BTreeMap, io};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const INVALID: &str = "invalid_projection";
const MAX_PLAN_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionViolation {
    pub schema_path: String,
    pub constraint: &'static str,
}

fn classify_jsonschema_error(error: &jsonschema::ValidationError<'_>) -> &'static str {
    use jsonschema::error::ValidationErrorKind as K;
    let schema_path = error.schema_path().as_str();
    match error.kind() {
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
        _ => "schema_violation",
    }
}

fn safe_projection_path(root: &Value, error: &jsonschema::ValidationError<'_>) -> String {
    use jsonschema::error::ValidationErrorKind as K;
    use jsonschema::paths::LocationSegment;
    let mut path = String::from("result");
    let mut cursor = root;
    for segment in error.instance_path().iter() {
        match segment {
            LocationSegment::Property(prop) => {
                if let Some(next) = cursor
                    .get("properties")
                    .and_then(Value::as_object)
                    .and_then(|props| props.get(prop.as_ref()))
                {
                    path.push('.');
                    path.push_str(prop.as_ref());
                    cursor = next;
                } else {
                    return path;
                }
            }
            LocationSegment::Index(idx) => {
                if let Some(next) = cursor.get("items") {
                    path.push('.');
                    path.push_str(&idx.to_string());
                    cursor = next;
                } else {
                    return path;
                }
            }
        }
    }
    if let K::Required {
        property: Value::String(prop),
    } = error.kind()
        && cursor
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|props| props.contains_key(prop))
    {
        path.push('.');
        path.push_str(prop);
    }
    path
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub fields: BTreeMap<String, Vec<String>>,
    pub schema: Value,
    pub max_bytes: usize,
    pub max_items: usize,
    pub max_depth: usize,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

fn source_key(value: &str, allow_diff: bool) -> bool {
    identifier(value)
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

pub fn compile(config: Value) -> Result<Plan, &'static str> {
    compile_with_diff(config, false)
}

pub(crate) fn compile_with_diff(config: Value, allow_diff: bool) -> Result<Plan, &'static str> {
    let plan: Plan = serde_json::from_value(config).map_err(|_| INVALID)?;
    if !(64..=262_144).contains(&plan.max_bytes)
        || !(1..=4096).contains(&plan.max_items)
        || !(1..=8).contains(&plan.max_depth)
        || plan.fields.is_empty()
        || plan.fields.len() > 16
        || plan.fields.iter().any(|(alias, path)| {
            !identifier(alias)
                || path.is_empty()
                || path.len() > 8
                || path.iter().any(|key| !source_key(key, allow_diff))
        })
    {
        return Err(INVALID);
    }
    serde_json::to_writer(
        ByteLimit {
            remaining: MAX_PLAN_BYTES,
        },
        &plan,
    )
    .map_err(|_| INVALID)?;
    crate::contracts::module_schema::check_projection_schema(&plan.schema).map_err(|_| INVALID)?;
    let properties = plan.schema["properties"].as_object().ok_or(INVALID)?;
    if properties.len() != plan.fields.len()
        || plan.fields.keys().any(|key| !properties.contains_key(key))
    {
        return Err(INVALID);
    }
    check_node(&plan.schema, 0, true, true, allow_diff)?;
    Ok(plan)
}

// Assertions may be partial schemas; every actual property/item has a concrete,
// recursively bounded shape independent of conditional assertions. These hard
// shape ceilings are independent of the plan's aggregate value budgets, which
// may deliberately produce schema-valid prefixes or omit optional branches.
fn check_node(
    schema: &Value,
    depth: usize,
    concrete: bool,
    root: bool,
    allow_diff: bool,
) -> Result<(), &'static str> {
    if depth > 8 {
        return Err(INVALID);
    }
    let kind = schema.get("type").and_then(Value::as_str);
    if concrete && kind.is_none() {
        return Err(INVALID);
    }
    if kind == Some("string")
        && schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_none_or(|n| n > 65536)
    {
        return Err(INVALID);
    }
    if kind == Some("array")
        && schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_none_or(|n| n > 1024)
    {
        return Err(INVALID);
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, child) in properties {
            if !root && !source_key(key, allow_diff) {
                return Err(INVALID);
            }
            check_node(child, depth + 1, true, false, allow_diff)?;
        }
    }
    if let Some(items) = schema.get("items") {
        check_node(items, depth + 1, true, false, allow_diff)?;
    }
    for key in ["if", "then", "else", "not"] {
        if let Some(child) = schema.get(key) {
            check_node(child, depth, false, root, allow_diff)?;
        }
    }
    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(children) = schema.get(key).and_then(Value::as_array) {
            for child in children {
                check_node(child, depth, false, root, allow_diff)?;
            }
        }
    }
    Ok(())
}

struct ByteLimit {
    remaining: usize,
}
impl io::Write for ByteLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(INVALID));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Plan {
    #[cfg(test)]
    pub(crate) fn validate_value(&self, value: &Value) -> Result<(), &'static str> {
        self.validate_value_detailed(value).map_err(|_| INVALID)
    }

    pub(crate) fn validate_value_detailed(&self, value: &Value) -> Result<(), ProjectionViolation> {
        fn walk(
            value: &Value,
            depth: usize,
            nodes: &mut usize,
            path: &str,
            plan: &Plan,
        ) -> Result<(), ProjectionViolation> {
            *nodes += 1;
            if depth > plan.max_depth {
                return Err(ProjectionViolation {
                    schema_path: path.to_owned(),
                    constraint: "max_depth",
                });
            }
            if *nodes > plan.max_items {
                return Err(ProjectionViolation {
                    schema_path: path.to_owned(),
                    constraint: "max_items",
                });
            }
            match value {
                Value::Object(values) => {
                    for (key, child) in values {
                        let child_path = format!("{path}.{key}");
                        walk(child, depth + 1, nodes, &child_path, plan)?;
                    }
                }
                Value::Array(values) => {
                    for (idx, child) in values.iter().enumerate() {
                        let child_path = format!("{path}.{idx}");
                        walk(child, depth + 1, nodes, &child_path, plan)?;
                    }
                }
                Value::Number(n)
                    if n.as_f64()
                        .is_none_or(|n| !n.is_finite() || n.abs() > 9_007_199_254_740_991.0) =>
                {
                    return Err(ProjectionViolation {
                        schema_path: path.to_owned(),
                        constraint: "integer_range",
                    });
                }
                _ => (),
            }
            Ok(())
        }
        walk(value, 0, &mut 0, "result", self)?;
        serde_json::to_writer(
            ByteLimit {
                remaining: self.max_bytes,
            },
            value,
        )
        .map_err(|_| ProjectionViolation {
            schema_path: "result".to_owned(),
            constraint: "max_bytes",
        })?;
        if crate::contracts::module_schema::validate(&self.schema, value).is_err() {
            if let Ok(validator) = jsonschema::validator_for(&self.schema)
                && let Some((schema_path, constraint)) = validator
                    .iter_errors(value)
                    .map(|err| {
                        (
                            safe_projection_path(&self.schema, &err),
                            classify_jsonschema_error(&err),
                        )
                    })
                    .min()
            {
                return Err(ProjectionViolation {
                    schema_path,
                    constraint,
                });
            }
            return Err(ProjectionViolation {
                schema_path: "result".to_owned(),
                constraint: "schema_violation",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Value {
        json!({"fields":{"platform":["ansible_facts","ansible_system"]},
            "schema":{"type":"object","additionalProperties":false,"required":["platform"],
                "properties":{"platform":{"type":"string","maxLength":64}}},
            "max_bytes":128,"max_items":4,"max_depth":2})
    }

    #[test]
    fn consumer_validates_selected_values_without_coercion_or_extra_members() {
        let plan = compile(config()).unwrap();
        assert!(plan.validate_value(&json!({"platform":"Linux"})).is_ok());
        for value in [
            json!({}),
            json!({"platform":false}),
            json!({"platform":"x".repeat(65)}),
            json!({"platform":"Linux","env":{}}),
        ] {
            assert!(plan.validate_value(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn policy_rejects_unbounded_shapes_and_private_sources() {
        for key in [
            "invocation",
            "module_args",
            "args",
            "argv",
            "cmd",
            "env",
            "environment",
            "ansible_env",
            "diff",
            "_private",
        ] {
            let mut value = config();
            value["fields"]["platform"] = json!(["ansible_facts", key]);
            assert!(compile(value).is_err(), "{key}");
        }
        let mut value = config();
        value["schema"]["properties"]["platform"]
            .as_object_mut()
            .unwrap()
            .remove("maxLength");
        assert!(compile(value).is_err());
        let mut value = config();
        value["fields"]["platform"] = json!([]);
        assert!(compile(value).is_err());
        let mut value = config();
        value["max_items"] = json!(0);
        assert!(compile(value).is_err());
    }

    #[test]
    fn value_caps_include_root_nodes_depth_and_escaped_json_bytes() {
        let mut value = config();
        value["max_items"] = json!(1);
        let plan = compile(value).unwrap();
        assert!(plan.validate_value(&json!({"platform":"Linux"})).is_err());
        let mut value = config();
        value["max_bytes"] = json!(64);
        let plan = compile(value).unwrap();
        assert!(
            plan.validate_value(&json!({"platform":"\n".repeat(40)}))
                .is_err()
        );
    }

    #[test]
    fn finite_shape_ceilings_are_independent_of_aggregate_value_budgets() {
        let mut config = config();
        config["schema"]["properties"]["platform"]["maxLength"] = json!(256);
        config["max_bytes"] = json!(64);
        let scalar = compile(config.clone()).unwrap();
        assert!(scalar.validate_value(&json!({"platform":"Linux"})).is_ok());
        assert!(
            scalar
                .validate_value(&json!({"platform":"x".repeat(64)}))
                .is_err()
        );

        config["schema"]["properties"]["platform"] = json!({
            "type":"array","maxItems":16,"items":{"type":"string","maxLength":256}
        });
        config["max_items"] = json!(5);
        config["max_depth"] = json!(2);
        let array = compile(config.clone()).unwrap();
        assert!(
            array
                .validate_value(&json!({"platform":["a","b","c"]}))
                .is_ok()
        );
        assert!(
            array
                .validate_value(&json!({"platform":["a","b","c","d"]}))
                .is_err()
        );

        // A deep optional branch can be omitted without changing the schema.
        config["schema"]["required"] = json!([]);
        config["max_depth"] = json!(1);
        let shallow = compile(config).unwrap();
        assert!(shallow.validate_value(&json!({})).is_ok());
        assert!(shallow.validate_value(&json!({"platform":["a"]})).is_err());
    }

    #[test]
    fn nested_source_properties_are_minimized_and_schema_assertions_remain_authoritative() {
        let mut value = config();
        value["schema"]["properties"]["platform"] = json!({
            "type":"object","additionalProperties":false,
            "properties":{"ansible_system":{"type":"string","maxLength":16}}
        });
        let plan = compile(value.clone()).unwrap();
        assert!(
            plan.validate_value(&json!({"platform":{"ansible_system":"Linux"}}))
                .is_ok()
        );
        value["schema"]["properties"]["platform"]["properties"]["env"] =
            json!({"type":"string","maxLength":16});
        assert!(compile(value).is_err());
        let mut value = config();
        value["schema"]["properties"]["platform"]["enum"] = json!(["Linux"]);
        let plan = compile(value).unwrap();
        assert!(plan.validate_value(&json!({"platform":"Darwin"})).is_err());
    }

    #[test]
    fn entire_serialized_plan_has_a_fixed_metadata_bound() {
        let mut value = config();
        let base_bytes = serde_json::to_vec(&value).unwrap().len();
        // The schema alone remains smaller than 16 KiB; fields and limits also
        // count toward the operator-owned plan's metadata budget.
        value["schema"]["description"] = json!("x".repeat(MAX_PLAN_BYTES - base_bytes));
        assert!(serde_json::to_vec(&value["schema"]).unwrap().len() < MAX_PLAN_BYTES);
        assert!(compile(value).is_err());
    }

    #[test]
    fn detailed_validation_reports_exact_field_path_and_constraint() {
        let mut value = config();
        value["schema"]["required"] = json!(["platform"]);
        value["schema"]["properties"]["platform"]["enum"] = json!(["Linux"]);
        let plan = compile(value).unwrap();
        let err = plan.validate_value_detailed(&json!({})).unwrap_err();
        assert_eq!(err.schema_path, "result.platform");
        assert_eq!(err.constraint, "missing_field");

        let err = plan
            .validate_value_detailed(&json!({"platform": "Darwin"}))
            .unwrap_err();
        assert_eq!(err.schema_path, "result.platform");
        assert_eq!(err.constraint, "invalid_enum");
    }
}
