//! Operator-owned selection policy; no request can alter paths, schemas or limits.
use std::{collections::BTreeMap, io};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const INVALID: &str = "invalid_projection";
const MAX_PLAN_BYTES: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
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

fn source_key(value: &str) -> bool {
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
                | "diff"
        )
}

pub(crate) fn compile(config: Value) -> Result<Plan, &'static str> {
    let plan: Plan = serde_json::from_value(config).map_err(|_| INVALID)?;
    if !(64..=4096).contains(&plan.max_bytes)
        || !(1..=256).contains(&plan.max_items)
        || !(1..=8).contains(&plan.max_depth)
        || plan.fields.is_empty()
        || plan.fields.len() > 16
        || plan.fields.iter().any(|(alias, path)| {
            !identifier(alias)
                || path.is_empty()
                || path.len() > 8
                || path.iter().any(|key| !source_key(key))
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
    crate::module_schema::check_projection_schema(&plan.schema).map_err(|_| INVALID)?;
    let properties = plan.schema["properties"].as_object().ok_or(INVALID)?;
    if properties.len() != plan.fields.len()
        || plan.fields.keys().any(|key| !properties.contains_key(key))
    {
        return Err(INVALID);
    }
    check_node(&plan.schema, 0, true, true)?;
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
            .is_none_or(|n| n > 4096)
    {
        return Err(INVALID);
    }
    if kind == Some("array")
        && schema
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_none_or(|n| n > 256)
    {
        return Err(INVALID);
    }
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        for (key, child) in properties {
            if !root && !source_key(key) {
                return Err(INVALID);
            }
            check_node(child, depth + 1, true, false)?;
        }
    }
    if let Some(items) = schema.get("items") {
        check_node(items, depth + 1, true, false)?;
    }
    for key in ["if", "then", "else", "not"] {
        if let Some(child) = schema.get(key) {
            check_node(child, depth, false, root)?;
        }
    }
    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(children) = schema.get(key).and_then(Value::as_array) {
            for child in children {
                check_node(child, depth, false, root)?;
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
    pub(crate) fn validate_value(&self, value: &Value) -> Result<(), &'static str> {
        fn walk(
            value: &Value,
            depth: usize,
            nodes: &mut usize,
            plan: &Plan,
        ) -> Result<(), &'static str> {
            *nodes += 1;
            if depth > plan.max_depth || *nodes > plan.max_items {
                return Err(INVALID);
            }
            match value {
                Value::Object(values) => {
                    for value in values.values() {
                        walk(value, depth + 1, nodes, plan)?;
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        walk(value, depth + 1, nodes, plan)?;
                    }
                }
                Value::Number(n)
                    if n.as_f64()
                        .is_none_or(|n| !n.is_finite() || n.abs() > 9_007_199_254_740_991.0) =>
                {
                    return Err(INVALID);
                }
                _ => (),
            }
            Ok(())
        }
        walk(value, 0, &mut 0, self)?;
        serde_json::to_writer(
            ByteLimit {
                remaining: self.max_bytes,
            },
            value,
        )
        .map_err(|_| INVALID)?;
        crate::module_schema::validate(&self.schema, value).map_err(|_| INVALID)
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
}
