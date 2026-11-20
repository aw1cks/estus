use std::sync::Arc;

use rmcp::model::JsonObject;
use schemars::JsonSchema;

use crate::reply::ToolReply;

// Keep the envelope and execution evidence generated from the actual reply types.
// Only the operator-reviewed payload schema is binding-specific.
pub(super) fn automation_output_schema(
    plan: Option<&crate::contracts::projection::Plan>,
) -> Arc<JsonObject> {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .for_serialize()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator()
        .into_root_schema_for::<ToolReply<crate::reply::AutomationData>>();
    let mut schema = serde_json::to_value(schema).expect("generated reply schema serializes");
    fn specialize(node: &mut serde_json::Value, plan: Option<&crate::contracts::projection::Plan>) {
        match node {
            serde_json::Value::Object(object) => {
                if let Some(properties) = object
                    .get_mut("properties")
                    .and_then(serde_json::Value::as_object_mut)
                    && let Some(projection) = properties.get_mut("projection")
                {
                    if plan.is_some() {
                        // Generate the non-optional enum itself: an enabled
                        // projection always has one of its five states.
                        let mut generator = schemars::generate::SchemaSettings::draft2020_12()
                            .for_serialize()
                            .with(|settings| settings.inline_subschemas = true)
                            .into_generator();
                        *projection = serde_json::to_value(
                            crate::reply::ModuleProjection::json_schema(&mut generator),
                        )
                        .expect("generated projection schema serializes");
                        fn payload(node: &mut serde_json::Value, schema: &serde_json::Value) {
                            match node {
                                serde_json::Value::Object(object) => {
                                    if let Some(value) = object
                                        .get_mut("properties")
                                        .and_then(serde_json::Value::as_object_mut)
                                        .and_then(|p| p.get_mut("value"))
                                    {
                                        *value = schema.clone();
                                    } else {
                                        for child in object.values_mut() {
                                            payload(child, schema);
                                        }
                                    }
                                }
                                serde_json::Value::Array(array) => {
                                    for child in array {
                                        payload(child, schema);
                                    }
                                }
                                _ => (),
                            }
                        }
                        let value_ref = serde_json::json!({ "$ref": "#/$defs/ProjectedValue" });
                        payload(projection, &value_ref);
                    } else {
                        properties.remove("projection");
                    }
                    if plan.is_some() {
                        let required = object
                            .entry("required")
                            .or_insert_with(|| serde_json::json!([]))
                            .as_array_mut()
                            .expect("generated required is an array");
                        if !required.iter().any(|name| name == "projection") {
                            required.push(serde_json::json!("projection"));
                        }
                    }
                    return;
                }
                for child in object.values_mut() {
                    specialize(child, plan);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    specialize(child, plan);
                }
            }
            _ => (),
        }
    }
    specialize(&mut schema, plan);
    if let Some(plan) = plan {
        schema
            .as_object_mut()
            .expect("reply schema is an object")
            .entry("$defs")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .expect("$defs is an object")
            .insert("ProjectedValue".into(), plan.schema.clone());
    }
    Arc::new(
        schema
            .as_object()
            .expect("reply schema is an object")
            .clone(),
    )
}

#[cfg(test)]
mod projection_metadata_tests {
    use super::*;
    use serde_json::{Value, json};

    fn occurrences(value: &Value, expected: &Value) -> usize {
        usize::from(value == expected)
            + match value {
                Value::Object(object) => object.values().map(|v| occurrences(v, expected)).sum(),
                Value::Array(array) => array.iter().map(|v| occurrences(v, expected)).sum(),
                _ => 0,
            }
    }

    #[test]
    fn output_contract_specializes_both_values_without_changing_evidence() {
        let selected = json!({"type":"object","additionalProperties":false,
            "required":["platform"],"properties":{"platform":{"type":"string","maxLength":64}}});
        let plan = crate::contracts::projection::compile(json!({
            "fields":{"platform":["ansible_facts","ansible_system"]},"schema":selected,
            "max_bytes":1024,"max_items":32,"max_depth":4
        }))
        .unwrap();
        let projected = Value::Object((*automation_output_schema(Some(&plan))).clone());
        assert_eq!(occurrences(&projected, &selected), 1);
        assert_eq!(
            occurrences(&projected, &json!({ "$ref": "#/$defs/ProjectedValue" })),
            2
        );
        assert_eq!(projected["$defs"]["ProjectedValue"], selected);
        fn data_schema(node: &Value) -> Option<&JsonObject> {
            match node {
                Value::Object(object) => {
                    if object
                        .get("properties")
                        .and_then(Value::as_object)
                        .is_some_and(|properties| properties.contains_key("projection"))
                    {
                        Some(object)
                    } else {
                        object.values().find_map(data_schema)
                    }
                }
                Value::Array(array) => array.iter().find_map(data_schema),
                _ => None,
            }
        }
        let data = data_schema(&projected).expect("projected data schema exists");
        assert!(
            data["required"]
                .as_array()
                .unwrap()
                .contains(&json!("projection"))
        );
        let projection = &data["properties"]["projection"];
        let variants = projection
            .get("oneOf")
            .or_else(|| projection.get("anyOf"))
            .and_then(Value::as_array)
            .expect("projection is a tagged union");
        assert_eq!(variants.len(), 5);
        assert!(
            variants.iter().all(|variant| {
                variant["properties"]["status"].is_object()
                    && variant.get("type").is_none_or(|kind| kind == "object")
            }),
            "projection must not admit null or a missing state"
        );
        let summary = Value::Object((*automation_output_schema(None)).clone());
        assert_eq!(occurrences(&summary, &selected), 0);
        assert!(
            !serde_json::to_string(&summary)
                .unwrap()
                .contains("\"projection\"")
        );
        assert!(
            serde_json::to_string(&projected)
                .unwrap()
                .contains("\"runner_rc\"")
        );
        assert!(
            serde_json::to_string(&projected)
                .unwrap()
                .contains("\"owned_group_cleanup\"")
        );
    }
}
