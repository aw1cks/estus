//! Offline role argument-spec conversion into the shared closed binding contract.
//! Role defaults are never input values, and importing metadata never runs a role.
use serde_json::{Map, Value, json};

use crate::module_schema;

const INVALID: &str = "unsupported_role_contract";
const DEPENDENCIES: &str = "Role dependencies can execute before upstream role argument-spec validation. Rust prevalidation is the approval boundary, not upstream execution order; importing this contract does not execute tasks or dependencies or certify their behavior.";

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

pub(crate) fn valid_role(role: &str) -> bool {
    role.len() <= 256
        && matches!(role.split('.').count(), 1 | 3)
        && role
            .split('.')
            .all(|part| identifier(part) && part.bytes().all(|c| !c.is_ascii_uppercase()))
}

pub(crate) fn valid_entry_point(entry_point: &str) -> bool {
    identifier(entry_point)
}

pub(crate) fn is_collection_role(role: &str) -> bool {
    valid_role(role) && role.split('.').count() == 3
}

// Rename only the known role nesting key. Everything else passes to the shared
// importer unchanged, whose strict allowlist rejects unknown option semantics.
fn normalize_options(options: &Map<String, Value>) -> Result<Map<String, Value>, &'static str> {
    options
        .iter()
        .map(|(name, value)| {
            let source = value.as_object().ok_or(INVALID)?;
            // suboptions is public module documentation syntax, not role argspec.
            if source.contains_key("suboptions") {
                return Err(INVALID);
            }
            let mut option = Map::new();
            for (key, value) in source {
                if key == "options" {
                    option.insert(
                        "suboptions".to_owned(),
                        Value::Object(normalize_options(value.as_object().ok_or(INVALID)?)?),
                    );
                } else {
                    option.insert(key.clone(), value.clone());
                }
            }
            // Ansible's argument validator defaults an omitted type to str.
            option.entry("type").or_insert_with(|| json!("str"));
            Ok((name.clone(), Value::Object(option)))
        })
        .collect()
}

pub(crate) fn import_document(
    document: &Value,
    entry_point: &str,
    explicit_schema: Option<&Value>,
) -> Result<Value, &'static str> {
    if !valid_entry_point(entry_point) {
        return Err("invalid_role_entry_point");
    }
    if !module_schema::bounded(document) {
        return Err(INVALID);
    }
    let envelope = document.as_object().ok_or(INVALID)?;
    if envelope
        .keys()
        .any(|key| !matches!(key.as_str(), "role" | "collection" | "entry_points"))
        || envelope
            .get("role")
            .is_some_and(|value| value.as_str().is_none_or(|role| !valid_role(role)))
        || envelope
            .get("collection")
            .is_some_and(|value| !value.is_null() && !value.is_string())
    {
        return Err(INVALID);
    }
    let entries = document
        .get("entry_points")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut contract = if entries.is_empty() {
        let schema = explicit_schema.ok_or("role_schema_required")?;
        let mut contract = module_schema::import_explicit_schema(schema)?;
        contract["review_required"] = json!([
            "Public role documentation exposes no argument-specification entry. The explicit closed schema is an operator-reviewed approval boundary, not a contract inferred from role defaults, tasks, or prose. Defaults are never injected."
        ]);
        contract
    } else {
        // Never silently replace or relax an available upstream argspec.
        if explicit_schema.is_some() {
            return Err(INVALID);
        }
        let entry = entries
            .get(entry_point)
            .and_then(Value::as_object)
            .ok_or(INVALID)?;
        if entry.keys().any(|key| {
            !matches!(
                key.as_str(),
                "options"
                    | "short_description"
                    | "description"
                    | "author"
                    | "version_added"
                    | "version_added_collection"
            )
        }) {
            return Err(INVALID);
        }
        let options = entry
            .get("options")
            .and_then(Value::as_object)
            .ok_or(INVALID)?;
        let mut doc = Map::new();
        doc.insert(
            "options".to_owned(),
            Value::Object(normalize_options(options)?),
        );
        let mut prose = Vec::new();
        for key in ["short_description", "description"] {
            if let Some(value) = entry.get(key) {
                match value {
                    Value::String(text) => prose.push(Value::String(text.clone())),
                    Value::Array(paragraphs) if paragraphs.iter().all(Value::is_string) => {
                        prose.extend(paragraphs.iter().cloned());
                    }
                    _ => return Err(INVALID),
                }
            }
        }
        if !prose.is_empty() {
            doc.insert("description".to_owned(), Value::Array(prose));
        }
        let mut contract =
            module_schema::import_document(&json!({"doc":doc})).map_err(|_| INVALID)?;
        contract["review_required"] = json!([
            "Role argument specifications do not certify task-body behavior, coercions, or prose constraints. Review preserved descriptions and supply ordinary conditional input_schema constraints or a narrower fixed/mapped surface. No prose rules are inferred; argument-spec defaults are review metadata only and are never injected."
        ]);
        contract
    };
    contract["review_required"]
        .as_array_mut()
        .ok_or(INVALID)?
        .push(Value::String(DEPENDENCIES.to_owned()));
    if !module_schema::bounded(&contract) {
        return Err(INVALID);
    }
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_schema::compile_binding;

    fn document(options: Value) -> Value {
        json!({"entry_points":{"main":{"options":options}}})
    }

    fn overlay(schema: &Value) -> Value {
        let mapping: Map<String, Value> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|key| (key.clone(), json!(key)))
            .collect();
        json!({"input_schema":schema,"fixed_args":{},"input_map":mapping})
    }

    #[test]
    fn identifiers_reject_paths_options_and_nonexact_collection_names() {
        for role in ["probe", "example.tools.probe", "role_2"] {
            assert!(valid_role(role), "{role}");
        }
        for role in [
            "", "a.b", "a.b.c.d", "../role", "-role", "a.b.Role", "r/name", "a..b", "1role",
        ] {
            assert!(!valid_role(role), "{role}");
        }
        assert!(is_collection_role("example.tools.probe"));
        assert!(!is_collection_role("probe"));
        for entry in ["main.yml", "../main", "--main", "main/other", "", "1main"] {
            assert!(!valid_entry_point(entry), "{entry}");
        }
        assert!(valid_entry_point("alternate_2"));
    }

    #[test]
    fn nested_aliases_defaults_required_choices_and_types_share_binding_policy() {
        let contract = import_document(
            &document(json!({
                "config":{"type":"dict","required":true,"aliases":["settings"],"options":{
                    "count":{"type":"int","required":true,"aliases":["number"]},
                    "enabled":{"type":"bool","default":true}
                }},
                "entries":{"type":"list","elements":"dict","options":{
                    "label":{"required":true,"aliases":["name"],"choices":["a","b"]},
                    "active":{"type":"bool","default":false}
                }}
            })),
            "main",
            None,
        )
        .unwrap();
        assert_eq!(contract["defaults"]["config.enabled"], json!(true));
        assert_eq!(contract["defaults"]["entries[].active"], json!(false));
        let surface = json!({"type":"object","properties":{
            "settings":{"type":"object","properties":{"number":{"type":"integer"}},
                "required":["number"],"additionalProperties":false},
            "entries":{"type":"array","items":{"type":"object","properties":{
                "name":{"type":"string","enum":["a","b"]}},
                "required":["name"],"additionalProperties":false}}
        },"required":["settings"],"additionalProperties":false});
        let binding = compile_binding(
            &contract,
            &json!({"input_schema":surface,
            "fixed_args":{},"input_map":{"settings":"settings","entries":"entries"}}),
        )
        .unwrap();
        assert_eq!(
            binding
                .prepare(&json!({"settings":{"number":2},"entries":[{"name":"a"}]}))
                .unwrap(),
            json!({"config":{"count":2},"entries":[{"label":"a"}]})
        );
        assert_eq!(
            binding.prepare(&json!({"settings":{"number":2}})).unwrap(),
            json!({"config":{"count":2}})
        );
        for input in [
            json!({}),
            json!({"settings":{}}),
            json!({"settings":{"number":"2"}}),
            json!({"settings":{"number":2,"extra":1}}),
            json!({"settings":{"number":2},"extra":1}),
            json!({"settings":{"number":2},"entries":[{"name":"c"}]}),
            json!({"settings":{"number":2},"entries":[{}]}),
        ] {
            assert!(binding.prepare(&input).is_err(), "{input}");
        }
    }

    #[test]
    fn collisions_unknown_semantics_and_conditionals_fail_closed() {
        for options in [
            json!({"one":{"type":"str","aliases":["two"]},"two":{"type":"str"}}),
            json!({"one":{"type":"str","aliases":["same"]},"two":{"type":"str","aliases":["same"]}}),
            json!({"obj":{"type":"dict","options":{"x":{"type":"int","aliases":["y"]},"y":{"type":"int"}}}}),
            json!({"one":{"type":"str","required_if":[["two",true,["one"]]]}}),
            json!({"one":{"type":"dict","apply_defaults":true,"options":{}}}),
            json!({"one":{"type":"str","unknown_constraint":true}}),
            json!({"one":{"type":"str","options":{}}}),
        ] {
            assert_eq!(
                import_document(&document(options), "main", None),
                Err(INVALID)
            );
        }
        for key in [
            "required_if",
            "required_one_of",
            "required_together",
            "required_by",
            "mutually_exclusive",
            "unknown_constraint",
        ] {
            let mut doc = document(json!({}));
            doc["entry_points"]["main"][key] = json!([]);
            assert_eq!(import_document(&doc, "main", None), Err(INVALID), "{key}");
        }
        assert_eq!(
            import_document(&document(json!({})), "other", None),
            Err(INVALID)
        );
    }

    #[test]
    fn explicit_schema_requires_closed_typed_recursive_structure() {
        let missing = json!({"entry_points":{}});
        assert_eq!(
            import_document(&missing, "main", None),
            Err("role_schema_required")
        );
        for schema in [
            json!({"type":"object","properties":{}}),
            json!({"type":"object","properties":{},"additionalProperties":true}),
            json!({"type":"object","properties":{"nested":{"type":"object","properties":{}}},"additionalProperties":false}),
            json!({"type":"object","properties":{"unknown":{}},"additionalProperties":false}),
            json!({"type":"object","properties":{"values":{"type":"array","items":{"type":"object","properties":{}}}},"additionalProperties":false}),
            json!({"type":"object","properties":{},"additionalProperties":false,"required":["missing"]}),
        ] {
            assert!(
                import_document(&missing, "main", Some(&schema)).is_err(),
                "{schema}"
            );
        }
        let closed = json!({"type":"object","properties":{},"additionalProperties":false});
        assert_eq!(
            import_document(&document(json!({})), "main", Some(&closed)),
            Err(INVALID)
        );
    }

    #[test]
    fn explicit_schema_identity_aliases_and_conditional_overlay_are_enforced() {
        let schema = json!({"type":"object","properties":{
            "mode":{"type":"string","enum":["safe","custom"]},
            "entries":{"type":"array","items":{"type":"object","properties":{
                "count":{"type":"integer"}},"required":["count"],"additionalProperties":false}}
        },"required":["mode"],"additionalProperties":false});
        let contract = import_document(&json!({"entry_points":{}}), "main", Some(&schema)).unwrap();
        assert_eq!(contract["defaults"], json!({}));
        let mut binding_overlay = overlay(&schema);
        binding_overlay["input_schema"]["if"] =
            json!({"properties":{"mode":{"const":"custom"}},"required":["mode"]});
        binding_overlay["input_schema"]["then"] = json!({"required":["entries"]});
        let binding = compile_binding(&contract, &binding_overlay).unwrap();
        assert_eq!(
            binding.prepare(&json!({"mode":"safe"})).unwrap(),
            json!({"mode":"safe"})
        );
        assert_eq!(
            binding
                .prepare(&json!({"mode":"custom","entries":[{"count":2}]}))
                .unwrap(),
            json!({"mode":"custom","entries":[{"count":2}]})
        );
        for input in [
            json!({}),
            json!({"mode":"custom"}),
            json!({"mode":"other"}),
            json!({"mode":"safe","extra":1}),
            json!({"mode":"safe","entries":[{}]}),
            json!({"mode":"safe","entries":[{"count":"2"}]}),
            json!({"mode":"safe","entries":[{"count":2,"extra":1}]}),
        ] {
            assert!(binding.prepare(&input).is_err(), "{input}");
        }
        let mut conditional_schema = schema.clone();
        conditional_schema["if"] = binding_overlay["input_schema"]["if"].clone();
        conditional_schema["then"] = binding_overlay["input_schema"]["then"].clone();
        let conditional_contract = import_document(
            &json!({"entry_points":{}}),
            "main",
            Some(&conditional_schema),
        )
        .unwrap();
        let binding = compile_binding(&conditional_contract, &overlay(&schema)).unwrap();
        assert!(binding.prepare(&json!({"mode":"custom"})).is_err());
        assert!(binding.prepare(&json!({"mode":"safe"})).is_ok());
    }
}
