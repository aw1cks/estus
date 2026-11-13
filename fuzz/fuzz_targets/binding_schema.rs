#![no_main]
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use serde_json::{Value, json};

#[path = "../../src/module_schema.rs"]
mod module_schema;
#[path = "../../src/strict_json.rs"]
mod strict_json;

const RAW_LIMIT: usize = 16 * 1024;
const JSON_LIMIT: usize = 256 * 1024;
const MAX_TEXT: usize = 512;
const MAX_ROWS: usize = 16;
// Each wrapper level adds four JSON nesting levels around the base option
// (option -> suboptions -> child -> suboptions -> value), and the base
// option's own alias array bottoms out nine levels below the document root:
// deepest node = 9 + 4*depth. The production bound (module_schema::DEPTH = 32)
// therefore rejects depth 6 (33) while the deepest valid fixture, depth 5,
// still exercises six live alias levels including the array/dict alternation.
const MAX_ALIAS_DEPTH: usize = 5;

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Fixture {
    RawSchema {
        schema: Value,
        overlay: Value,
        input: Value,
    },
    RawDocument {
        document: Value,
        overlay: Value,
        input: Value,
    },
    RawContract {
        contract: Value,
        overlay: Value,
        input: Value,
    },
    Known {
        text: String,
        rows: usize,
        depth: usize,
        include: bool,
        variant: u8,
    },
    Numeric {
        value: Value,
        branch: bool,
        detail: Option<String>,
    },
    Resource {
        atom: String,
        repeat: usize,
        depth: usize,
    },
}

// This is the production value budget, not an invented JSON-schema validator.
// The serialized bound is checked separately (escaping costs more than UTF-8).
fn emitted(value: &Value) {
    assert!(module_schema::bounded(value));
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= JSON_LIMIT);
    assert_eq!(strict_json::parse(&bytes).unwrap(), *value);
}

fn raw(contract: Result<Value, &'static str>, overlay: &Value, input: &Value) {
    let Ok(contract) = contract else { return };
    // Raw artifacts originate in a <=16KiB envelope; even escaped output is
    // bounded by that envelope plus the small real importer's review metadata.
    // A raw contract is deliberately allowed to be invalid before compilation.
    if module_schema::bounded(&contract) {
        emitted(&contract);
    }
    let _ = module_schema::validate_overlay(overlay);
    if let Ok(binding) = module_schema::compile_binding(&contract, overlay)
        && let Ok(output) = binding.prepare(input)
    {
        emitted(&output);
    }
}

fn closed(properties: Value, required: Value) -> Value {
    json!({"type":"object", "properties":properties, "required":required,
        "additionalProperties":false})
}

fn known(text: String, rows: usize, depth: usize, include: bool, variant: u8) {
    if text.len() > MAX_TEXT || rows > MAX_ROWS || depth > MAX_ALIAS_DEPTH {
        return;
    }
    // Check expansion before cloning the atom into recursive rows. Each level
    // wraps, never multiplies, and all schema/path counts are bounded above.
    let Some(expanded) = text
        .len()
        .checked_add(128)
        .and_then(|n| n.checked_mul(rows.max(1)))
        .and_then(|n| n.checked_mul(depth + 1))
    else {
        return;
    };
    if expanded > 96 * 1024 {
        return;
    }

    let mut option = json!({"type":"dict", "suboptions":{
        "label":{"type":"str","aliases":["name"],"required":true},
        "active":{"type":"bool","default":true}
    }});
    let mut public = closed(json!({"name":{"type":"string"}}), json!(["name"]));
    let mut caller = json!({"name":text});
    let mut canonical = json!({"label":text});
    for level in 0..depth {
        // Alternating list/dict wrappers exercises recursive alias trees rather
        // than just renaming a root property. Exact output is built independently.
        let list = level % 2 == 0;
        option = if list {
            json!({"type":"list","elements":"dict","suboptions":{
                "child":{"type": "dict", "aliases":["kid"],"required":true,
                    "suboptions":{"value":option}}
            }})
        } else {
            json!({"type":"dict","suboptions":{
                "child":{"type":"dict","aliases":["kid"],"required":true,
                    "suboptions":{"value":option}}
            }})
        };
        public = closed(
            json!({"kid":closed(json!({"value":public}),json!([]))}),
            json!(["kid"]),
        );
        caller = json!({"kid":{"value":caller}});
        canonical = json!({"child":{"value":canonical}});
        if list {
            public = json!({"type":"array","items":public});
            caller = json!([caller]);
            canonical = json!([canonical]);
        }
    }
    let document = json!({"doc":{"options":{
        "locked":{"type":"str","aliases":["pin"],"required":true},
        "entries":{"type":"list","elements":"dict","suboptions":{
            "tree":option
        }},
        "argv":{"type":"list","elements":"str"},
        "stdin":{"type":"str","default":"documentation-only"},
        "host":{"type":"str"},
        "omitted":{"type":"bool","default":true}
    }}});
    let contract = module_schema::import_document(&document).unwrap();
    assert_eq!(contract["defaults"]["omitted"], json!(true));
    let row_schema = closed(json!({"tree":public}), json!([]));
    let schema = closed(
        json!({
            "values":{"type":"array","items":row_schema},
            "args":{"type":"array","items":{"type":"string"}},
            "data":{"type":"string"},"destination":{"type":"string"}
        }),
        json!([]),
    );
    let mut overlay = json!({"input_schema":schema,"fixed_args":{"pin":"operator-fixed"},
        "input_map":{"entries":"values","argv":"args","stdin":"data","host":"destination"}});
    let mut input = json!({"args":[text],"data":text,"destination":text});
    let mut expected = json!({"locked":"operator-fixed","argv":[text],"stdin":text,"host":text});
    if include {
        input["values"] = Value::Array((0..rows).map(|_| json!({"tree":caller})).collect());
        expected["entries"] = Value::Array((0..rows).map(|_| json!({"tree":canonical})).collect());
    }
    let binding = module_schema::compile_binding(&contract, &overlay).unwrap();
    assert_eq!(binding.prepare(&input).unwrap(), expected);
    emitted(&expected);
    // Backend argv/stdin/host are domain data: no transport denylist is applied
    // to output. Defaults, including nested active, must remain absent.
    match variant % 12 {
        0 => {
            input["locked"] = json!(text);
            assert!(binding.prepare(&input).is_err());
        }
        1 => {
            input["pin"] = json!(text);
            assert!(binding.prepare(&input).is_err());
        }
        2 => {
            overlay["input_map"]["locked"] = json!("data");
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
        }
        3 => {
            overlay["fixed_args"]["locked"] = json!("second assignment");
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
        }
        4 => {
            overlay["input_map"]["pin"] = json!("data");
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
        }
        5 => {
            // Duplicate aliases in a nested caller schema must fail compilation,
            // even if the corresponding optional caller input is absent.
            let mut collision = closed(
                json!({"label":{"type":"string"},"name":{"type":"string"}}),
                json!(["name"]),
            );
            collision = json!({"type":"array","items":closed(json!({"tree":collision}),json!([]))});
            overlay["input_schema"]["properties"]["values"] = collision;
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
            if depth == 0 {
                // Remove the mapping so failure cannot be explained by a
                // fixed/mapped collision: even equal nested assignments clash.
                overlay["input_schema"]["properties"]
                    .as_object_mut()
                    .unwrap()
                    .remove("values");
                overlay["input_map"]
                    .as_object_mut()
                    .unwrap()
                    .remove("entries");
                overlay["fixed_args"]["entries"] = json!([{"tree":{"label":text,"name":text}}]);
                assert!(module_schema::compile_binding(&contract, &overlay).is_err());
            }
        }
        6 => {
            input["args"] = json!(text);
            assert!(binding.prepare(&input).is_err());
        }
        7 => {
            input["values"] = json!([{"tree":{}}]);
            assert!(binding.prepare(&input).is_err());
        }
        8 => {
            overlay["input_schema"]["properties"]["data"]["default"] = json!("injected");
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
        }
        9 => {
            overlay["input_schema"]["properties"]["data"]["$ref"] = json!("#");
            assert!(module_schema::compile_binding(&contract, &overlay).is_err());
        }
        10 => {
            overlay["input_schema"]["required"] = json!(["data"]);
            let binding = module_schema::compile_binding(&contract, &overlay).unwrap();
            input.as_object_mut().unwrap().remove("data");
            assert!(binding.prepare(&input).is_err());
        }
        _ => {
            let mut duplicate = document;
            duplicate["doc"]["options"]["locked"]["aliases"] = json!(["pin", "pin"]);
            assert!(module_schema::import_document(&duplicate).is_err());
        }
    }
    // These are representative authority/options fields, not a copied policy
    // table. Adding any one to a caller schema must not promote it to authority.
    for control in [
        "host",
        "authority",
        "execution",
        "env",
        "module",
        "timeout_secs",
        "ansible_connection",
        "_raw_params",
    ] {
        let injected = json!({"input_schema":closed(json!({(control):{"type":"string"}}),json!([])),
            "fixed_args":{"pin":"operator-fixed"},"input_map":{"stdin":control}});
        assert!(module_schema::compile_binding(&contract, &injected).is_err());
        assert!(
            binding
                .prepare(&json!({(control):"caller-override"}))
                .is_err()
        );
    }
}

fn numeric(value: Value, branch: bool, detail: Option<String>) {
    if detail.as_ref().is_some_and(|s| s.len() > MAX_TEXT) {
        return;
    }
    let backend = closed(
        json!({
            "amount":{"type":"number","minimum":-2,"exclusiveMaximum":4},
            "selected":{"type":"boolean"},"note":{"type":"string"}
        }),
        json!(["amount", "selected"]),
    );
    let contract = module_schema::import_explicit_schema(&backend).unwrap();
    let mut schema = closed(
        json!({
            "n":{"type":"number","minimum":-3,"maximum":5,
                "allOf":[{"minimum":-2}],"anyOf":[{"maximum":0},{"minimum":2}],
                "oneOf":[{"maximum":2},{"minimum":2}],"not":{"const":3}},
            "flag":{"type":"boolean"},"detail":{"type":"string","minLength":1,"maxLength":8}
        }),
        json!(["n", "flag"]),
    );
    schema["if"] = json!({"properties":{"flag":{"const":true}},"required":["flag"]});
    schema["then"] = json!({"required":["detail"]});
    schema["else"] = json!({"not":{"required":["detail"]}});
    let overlay = json!({"input_schema":schema,"fixed_args":{},
        "input_map":{"amount":"n","selected":"flag","note":"detail"}});
    let binding = module_schema::compile_binding(&contract, &overlay).unwrap();
    let mut input = json!({"n":value,"flag":branch});
    if let Some(detail) = &detail {
        input["detail"] = json!(detail);
    }
    // This is a hand-worked oracle for this one literal schema, not a second
    // generic validator. oneOf excludes exactly 2; final backend excludes >=4.
    let valid_number = value
        .as_f64()
        .is_some_and(|n| (-2.0..4.0).contains(&n) && (n <= 0.0 || n > 2.0) && n != 3.0);
    let valid_detail = if branch {
        detail
            .as_ref()
            .is_some_and(|s| (1..=8).contains(&s.chars().count()))
    } else {
        detail.is_none()
    };
    let output = binding.prepare(&input);
    assert_eq!(output.is_ok(), valid_number && valid_detail);
    // Conditional/choice/bound failures are policy errors, not shape errors.
    assert_eq!(
        module_schema::validate_input_shape(&overlay["input_schema"], &input).is_ok(),
        value.is_number()
    );
    if let Ok(output) = output {
        let mut expected = json!({"amount":value,"selected":branch});
        if let Some(detail) = detail {
            expected["note"] = json!(detail);
        }
        assert_eq!(output, expected);
        emitted(&output);
    }
}

fn resource(atom: String, repeat: usize, depth: usize) {
    // ASCII x gives an exact independent byte budget and avoids confusing JSON
    // escaping with the production UTF-8/node budget. Check before allocation.
    if atom.len() > 256 || atom.bytes().any(|b| b != b'x') || depth > 40 {
        return;
    }
    let Some(size) = atom.len().checked_mul(repeat) else {
        return;
    };
    if repeat > JSON_LIMIT + 1 || size > JSON_LIMIT + 1 {
        return;
    }
    let mut input = json!({"text":atom.repeat(repeat)});
    let schema = closed(json!({"payload":{"type":"string"}}), json!([]));
    let contract = module_schema::import_explicit_schema(&schema).unwrap();
    let overlay = json!({"input_schema":closed(json!({"text":{"type":"string"}}),json!([])),
        "fixed_args":{},"input_map":{"payload":"text"}});
    let binding = module_schema::compile_binding(&contract, &overlay).unwrap();
    let output = binding.prepare(&input);
    // root object=8, backend key=7, string=size; input key is only 4.
    assert_eq!(output.is_ok(), size <= JSON_LIMIT - 15);
    if let Ok(output) = output {
        emitted(&output);
    }
    for _ in 0..depth {
        input = json!([input]);
    }
    if depth > 32 {
        assert!(!module_schema::bounded(&input));
    }
    // The same controlled depth reaches real schema import, not just bounded().
    let mut schema = json!({"type":"string"});
    for _ in 0..depth {
        schema = json!({"type":"array","items":schema});
    }
    let schema = closed(json!({"nested":schema}), json!([]));
    let _ = module_schema::import_explicit_schema(&schema);
}

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > RAW_LIMIT {
        return;
    }
    let Ok(value) = strict_json::parse(bytes) else {
        return;
    };
    // Also exercise a bare artifact without requiring a structured envelope.
    if value.get("mode").is_none() {
        let _ = module_schema::import_document(&value);
        let _ = module_schema::import_explicit_schema(&value);
        return;
    }
    let Ok(fixture) = serde_json::from_value::<Fixture>(value) else {
        return;
    };
    match fixture {
        Fixture::RawSchema {
            schema,
            overlay,
            input,
        } => raw(
            module_schema::import_explicit_schema(&schema),
            &overlay,
            &input,
        ),
        Fixture::RawDocument {
            document,
            overlay,
            input,
        } => raw(module_schema::import_document(&document), &overlay, &input),
        Fixture::RawContract {
            contract,
            overlay,
            input,
        } => raw(Ok(contract), &overlay, &input),
        Fixture::Known {
            text,
            rows,
            depth,
            include,
            variant,
        } => known(text, rows, depth, include, variant),
        Fixture::Numeric {
            value,
            branch,
            detail,
        } => numeric(value, branch, detail),
        Fixture::Resource {
            atom,
            repeat,
            depth,
        } => resource(atom, repeat, depth),
    }
});
