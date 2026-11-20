use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

use crate::command::Invocation;

use super::*;

fn projection_result() -> toml::Value {
    toml::Value::try_from(json!({
        "kind":"ansible_projection","fields":{"platform":["ansible_facts","ansible_system"]},
        "schema":{"type":"object","additionalProperties":false,"required":["platform"],
            "properties":{"platform":{"type":"string","maxLength":64}}},
        "max_bytes":1024,"max_items":32,"max_depth":4
    }))
    .unwrap()
}

#[test]
fn projected_binding_has_fixed_policy_and_rejects_request_selectors() {
    let mut raw = module_definition();
    raw["result"] = projection_result();
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert_eq!(binding.result_kind(), "ansible_projection");
    assert_eq!(
        binding.projection().unwrap().fields["platform"],
        ["ansible_facts", "ansible_system"]
    );
    assert!(
        binding
            .parse_request(
                json!({"host":"server","inputs":{"nested":{"items":[]}},
        "fields":{"platform":["env"]}})
                .as_object()
                .unwrap()
                .clone()
            )
            .is_err()
    );
    let mut native = definition();
    native["result"] = projection_result();
    assert!(compile(native).is_err());
}

#[test]
fn native_and_summary_result_kinds_reject_unknown_options() {
    for kind in ["command", "controller_command", "ansible_summary"] {
        let value = toml::Value::try_from(json!({"kind":kind,"unexpected":true})).unwrap();
        let result: Result<RawResult, _> = value.try_into();
        assert!(
            result.is_err(),
            "result kind {kind} accepted an unknown option"
        );
    }
}

#[test]
fn disabled_projection_rejects_unknown_fields_and_unbounded_schema() {
    for invalid_result in [
        {
            let mut v = projection_result();
            v.as_table_mut()
                .unwrap()
                .insert("unexpected".into(), true.into());
            v
        },
        {
            let mut v = projection_result();
            v["schema"]["properties"]["platform"]
                .as_table_mut()
                .unwrap()
                .remove("maxLength");
            v
        },
        {
            let mut v = projection_result();
            v["fields"]["platform"] = toml::Value::try_from(json!(["env"])).unwrap();
            v
        },
    ] {
        let mut raw = module_definition();
        raw["result"] = invalid_result;
        assert!(
            Bindings::compile(
                BTreeMap::from([("observe".into(), raw)]),
                &[],
                &Limits::default(),
                |_| true,
                None,
                true
            )
            .is_err()
        );
    }
}

#[test]
fn module_domain_assertions_remain_nested_and_unmodified() {
    let mut raw = module_definition();
    let schema = json!({
        "type":"object","additionalProperties":false,"maxProperties":1,
        "required":["nested"],
        "properties":{"nested":{"type":"object","additionalProperties":false,
            "required":["items"],"properties":{"items":{"type":"array",
                "items":{"type":"string"}}}}},
        "const":{"nested":{"items":["approved"]}},
        "enum":[{"nested":{"items":["approved"]}}],
        "if":{"properties":{"nested":{"type":"object","additionalProperties":false,
            "properties":{"items":{"type":"array","items":{"type":"string"}}}}}},
        "then":{"type":"object","additionalProperties":false,
            "properties":{"nested":{"type":"object","additionalProperties":false,
                "properties":{"items":{"type":"array","items":{"type":"string"}}}}}}
    });
    raw["input_schema"] = toml::Value::try_from(schema.clone()).unwrap();
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert_eq!(binding.input_schema["properties"]["inputs"], schema);
    assert_eq!(binding.input_schema["required"], json!(["host", "inputs"]));
    assert_eq!(
        binding.input_schema["properties"]
            .as_object()
            .unwrap()
            .len(),
        3
    );
    assert!(
        binding
            .parse_request(
                json!({
                    "host":"server","inputs":{"nested":{"items":["not approved"]}}
                })
                .as_object()
                .unwrap()
                .clone()
            )
            .is_ok()
    );
}

#[test]
fn module_request_shape_is_recursive_but_bounds_remain_policy() {
    let bindings = compile(module_definition()).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    for input in [
        json!({"host":"server"}),
        json!({"host":"server","inputs":[]}),
        json!({"host":"server","inputs":{}}),
        json!({"host":"server","inputs":{"nested":{}}}),
        json!({"host":"server","inputs":{"nested":{"items":[false]}}}),
        json!({"host":"server","inputs":{"nested":{"items":[],"extra":true}}}),
        json!({"host":"server","inputs":{"nested":{"items":[]}},"extra":true}),
        json!({"host":"server","nested":{"items":[]}}),
    ] {
        assert!(
            binding
                .parse_request(input.as_object().unwrap().clone())
                .is_err()
        );
    }
    for items in [json!(["a", "b", "c"]), json!(["x".repeat(33)])] {
        assert!(
            binding
                .parse_request(
                    json!({
                        "host":"server","inputs":{"nested":{"items":items}}
                    })
                    .as_object()
                    .unwrap()
                    .clone()
                )
                .is_ok()
        );
    }
}

#[test]
fn automation_envelopes_reject_output_retention_even_when_false() {
    for mut raw in [
        module_definition(),
        role_definition(),
        playbook_definition(),
    ] {
        raw["input_schema"]["properties"]["nested"]["properties"]
            .as_table_mut()
            .unwrap()
            .insert(
                "retain_output".into(),
                toml::Value::try_from(json!({"type":"boolean"})).unwrap(),
            );
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(
            !binding.input_schema["properties"]
                .as_object()
                .unwrap()
                .contains_key("retain_output")
        );
        let arguments = json!({
            "host":"server","inputs":{"nested":{"items":[],"retain_output":true}}
        });
        let BindingCall::Automation(request) = binding
            .parse_request(arguments.as_object().unwrap().clone())
            .unwrap()
        else {
            panic!("expected automation request")
        };
        assert_eq!(request.inputs, arguments["inputs"]);
        for value in [json!(true), json!(false), Value::Null, json!("true")] {
            let mut arguments = arguments.clone();
            arguments["retain_output"] = value;
            assert!(
                binding
                    .parse_request(arguments.as_object().unwrap().clone())
                    .is_err()
            );
        }
    }
}

fn module_definition() -> toml::Value {
    let mut raw = definition();
    raw["authority"] = "automation".into();
    raw["result"]["kind"] = "ansible_summary".into();
    raw["execution"] =
        toml::from_str("kind='ansible_module'\nsnapshot='/unavailable/reviewed.json'").unwrap();
    raw["input_schema"] = toml::Value::try_from(json!({
        "type":"object","additionalProperties":false,"required":["nested"],
        "properties":{"nested":{"type":"object","additionalProperties":false,
            "required":["items"],"properties":{"items":{"type":"array","maxItems":2,
                "items":{"type":"string","maxLength":32}}}}}
    }))
    .unwrap();
    raw.as_table_mut().unwrap().insert(
        "input_map".into(),
        toml::from_str("nested='nested'").unwrap(),
    );
    raw
}

fn role_definition() -> toml::Value {
    let mut raw = module_definition();
    raw["execution"] = toml::from_str(
        "kind='ansible_role'\nsnapshot='/unavailable/role.json'\nrole_path='/unavailable/role'",
    )
    .unwrap();
    raw
}

fn playbook_definition() -> toml::Value {
    let mut raw = module_definition();
    raw["execution"] = toml::from_str(
        "kind='ansible_playbook'\nsnapshot='/unavailable/playbook.json'\nproject_root='/unavailable/project'",
    )
    .unwrap();
    raw
}

#[test]
fn playbook_compilation_is_source_free_and_keeps_controls_private() {
    for enabled in [Vec::new(), vec!["observe".into()]] {
        let bindings = Bindings::compile(
            BTreeMap::from([("observe".into(), playbook_definition())]),
            &enabled,
            &Limits::default(),
            |_| true,
            None,
            false,
        )
        .unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert_eq!(binding.executor_kind(), "ansible_playbook");
        assert!(!binding.automation_activated());
        let published = serde_json::to_string(&binding.input_schema).unwrap();
        assert!(!published.contains("/unavailable"));
        for control in [
            "playbook",
            "project_root",
            "inventory",
            "tags",
            "extra_vars",
        ] {
            let mut arguments = json!({"host":"server","inputs":{"nested":{"items":[]}}});
            arguments[control] = json!("caller");
            assert!(
                binding
                    .parse_request(arguments.as_object().unwrap().clone())
                    .is_err()
            );
        }
    }
    for control in ["role_path", "playbook", "inventory", "tags", "extra_vars"] {
        let mut raw = playbook_definition();
        raw["execution"]
            .as_table_mut()
            .unwrap()
            .insert(control.into(), "caller".into());
        assert!(
            compile(raw).is_err(),
            "accepted execution control {control}"
        );
    }
    let mut raw = playbook_definition();
    raw["execution"]["project_root"] = "relative".into();
    assert!(compile(raw).is_err());
}

#[test]
fn playbook_backend_controls_are_rejected_without_activation() {
    for name in [
        "playbook",
        "project_root",
        "ansible_connection",
        "ansible_python_interpreter",
        "inventory",
        "tags",
        "become",
        "connection",
        "interpreter",
        "estus_arguments",
    ] {
        for field in ["fixed_args", "input_map"] {
            let mut raw = playbook_definition();
            raw.as_table_mut().unwrap().insert(
                field.into(),
                toml::Value::try_from(json!({name:"nested"})).unwrap(),
            );
            assert!(
                compile(raw).is_err(),
                "accepted {field} playbook control {name}"
            );
        }
    }
}

#[test]
fn playbook_projection_requires_concrete_domain_members() {
    for path in [
        vec!["ansible_facts", "platform"],
        vec!["mcp_result"],
        vec!["mcp_result", "platform"],
    ] {
        let mut raw = playbook_definition();
        let mut result = projection_result();
        result["fields"]["platform"] = toml::Value::Array(
            path.iter()
                .map(|part| toml::Value::String((*part).into()))
                .collect(),
        );
        raw["result"] = result;
        assert_eq!(
            compile(raw).is_ok(),
            path.len() == 2 && path[0] == "mcp_result"
        );
    }
}

#[test]
fn role_compilation_keeps_source_private_and_caller_controls_closed() {
    let bindings = compile(role_definition()).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert_eq!(binding.executor_kind(), "ansible_role");
    assert_eq!(binding.result_kind(), "ansible_summary");
    assert!(binding.is_automation());
    assert!(!binding.automation_activated());
    let published = serde_json::to_string(&binding.input_schema).unwrap();
    assert!(!published.contains("/unavailable"));
    for control in ["role", "entry_point", "role_path", "extra_vars"] {
        let mut arguments = json!({"host":"server","inputs":{"nested":{"items":[]}}});
        arguments[control] = json!("caller");
        assert!(
            binding
                .parse_request(arguments.as_object().unwrap().clone())
                .is_err()
        );
        let mut raw = role_definition();
        raw["execution"]
            .as_table_mut()
            .unwrap()
            .insert(control.into(), "caller".into());
        assert!(compile(raw).is_err());
    }
}

#[test]
fn role_projection_requires_a_concrete_mcp_result_member() {
    for path in [
        vec!["ansible_facts", "platform"],
        vec!["mcp_result"],
        vec!["mcp_result", "platform"],
    ] {
        let mut raw = role_definition();
        let mut result = projection_result();
        result["fields"]["platform"] = toml::Value::Array(
            path.iter()
                .map(|part| toml::Value::String((*part).into()))
                .collect(),
        );
        raw["result"] = result;
        assert_eq!(
            compile(raw).is_ok(),
            path.len() == 2 && path[0] == "mcp_result"
        );
    }
}

#[test]
fn role_backend_controls_are_rejected_even_without_activation() {
    for name in [
        "mcp_result",
        "estus_arguments",
        "ansible_connection",
        "connection",
        "become_user",
        "hostvars",
        "inventory_file",
        "callback_plugins",
        "role_path",
        "tasks_from",
        "tags",
        "no_log",
    ] {
        let mut raw = role_definition();
        raw.as_table_mut().unwrap().insert(
            "fixed_args".into(),
            toml::Value::try_from(json!({name:"value"})).unwrap(),
        );
        assert!(compile(raw).is_err(), "accepted fixed role control {name}");
        let mut raw = role_definition();
        raw["input_map"] = toml::Value::try_from(json!({name:"nested"})).unwrap();
        assert!(compile(raw).is_err(), "accepted mapped role control {name}");
    }
    let mut raw = role_definition();
    raw["execution"]["role_path"] = "relative/role".into();
    assert!(compile(raw).is_err());
}

#[test]
fn module_compilation_is_lazy_and_preserves_recursive_public_domain() {
    let bindings = compile(module_definition()).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert!(binding.is_automation());
    assert_eq!(binding.executor_kind(), "ansible_module");
    assert_eq!(binding.result_kind(), "ansible_summary");
    assert!(
        binding.input_schema["properties"]["inputs"]["properties"]["nested"]["properties"]["items"]
            .is_object()
    );
    let input = json!({"host":"server","inputs":{"nested":{"items":["{{ literal }}"]}}});
    let BindingCall::Automation(request) = binding
        .parse_request(input.as_object().unwrap().clone())
        .unwrap()
    else {
        panic!("module request expected");
    };
    assert_eq!(
        request.inputs,
        json!({"nested":{"items":["{{ literal }}"]}})
    );
    let target = crate::config::AutomationTarget {
        destination: "fixed".into(),
        python: "/python".into(),
    };
    assert!(
        binding
            .prepare_automation(
                &request,
                &Limits::default(),
                AutomationTransport {
                    authority: crate::config::ResolvedAutomation {
                        target: std::borrow::Cow::Borrowed(&target),
                        ssh_config: None,
                        ssh_executable: Path::new("/usr/bin/ssh"),
                        r#become: None,
                        agent: crate::config::AutomationAgent::Inherit,
                        dynamic_python: false,
                    },
                    scratch_bytes: 1024,
                    scratch_files: 10,
                    started: std::time::Instant::now(),
                }
            )
            .is_err()
    );
}

#[test]
fn module_authority_result_and_native_overlay_boundaries_are_strict() {
    for authority in ["ordinary", "controller"] {
        let mut raw = module_definition();
        raw["authority"] = authority.into();
        assert!(compile(raw).is_err());
    }
    let mut raw = module_definition();
    raw["result"]["kind"] = "command".into();
    assert!(compile(raw).is_err());
    let mut raw = definition();
    raw.as_table_mut()
        .unwrap()
        .insert("fixed_args".into(), toml::Value::Table(Default::default()));
    assert!(compile(raw).is_err());
    let mut raw = module_definition();
    raw["input_schema"]["properties"]
        .as_table_mut()
        .unwrap()
        .insert("host".into(), toml::from_str("type='string'").unwrap());
    assert!(compile(raw).is_err());
}

#[test]
fn active_controller_rejects_unavailable_and_unverified_prerequisites() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"abc").unwrap();
    let good = controller_definition(&source);
    for (field, value) in [
        ("program", "/unavailable/private-runtime"),
        ("program", "/"),
        ("program", "/dev/null"),
    ] {
        let mut raw = good.clone();
        raw["execution"]["interpreter"][field] = value.into();
        assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
    }
    let mut raw = good.clone();
    raw["execution"]
        .as_table_mut()
        .unwrap()
        .insert("cwd".into(), "/unavailable/private-cwd".into());
    assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
    let mut raw = good.clone();
    raw["execution"]["source"]["path"] = dir.path().to_str().unwrap().into();
    assert!(controller_compile(raw, true, true, Some(dir.path())).is_err());
    for bytes in [b"abd".as_slice(), b"abcd", b"\xff", b"a\0c"] {
        fs::write(&source, bytes).unwrap();
        let error = controller_compile(good.clone(), true, true, Some(dir.path()))
            .err()
            .unwrap();
        assert!(!error.to_string().contains(dir.path().to_str().unwrap()));
    }
    fs::remove_file(&source).unwrap();
    assert!(controller_compile(good.clone(), true, true, Some(dir.path())).is_err());
    assert!(controller_compile(good, false, true, Some(dir.path())).is_ok());
}

#[test]
fn configured_controller_environment_obeys_entry_value_and_aggregate_bounds() {
    assert!(
        controller_environment(BTreeMap::from([("MCP_VALUE".into(), "x".repeat(4096))])).is_ok()
    );
    assert!(
        controller_environment(BTreeMap::from([("MCP_VALUE".into(), "x".repeat(4097))])).is_err()
    );
    assert!(
        controller_environment(
            (0..32)
                .map(|i| (format!("MCP_{i}"), String::new()))
                .collect()
        )
        .is_ok()
    );
    assert!(
        controller_environment(
            (0..33)
                .map(|i| (format!("MCP_{i}"), String::new()))
                .collect()
        )
        .is_err()
    );
    assert!(
        controller_environment(BTreeMap::from([
            ("MCP_A".into(), "x".repeat(4096)),
            ("MCP_B".into(), "x".repeat(4086)),
        ]))
        .is_ok()
    );
    assert!(
        controller_environment(BTreeMap::from([
            ("MCP_A".into(), "x".repeat(4096)),
            ("MCP_B".into(), "x".repeat(4087)),
        ]))
        .is_err()
    );
}

fn controller_definition(source: &Path) -> toml::Value {
    let shell = std::env::split_paths(&std::env::var_os("PATH").expect("test utility PATH"))
        .map(|directory| directory.join("sh"))
        .find(|path| path.is_file())
        .expect("declared POSIX interpreter is available");
    let mut raw = definition();
    raw.as_table_mut().unwrap().remove("targets");
    raw["authority"] = "controller".into();
    raw["result"]["kind"] = "controller_command".into();
    raw["execution"] = toml::from_str(&format!(
        "kind='controller_script'\nsource={{path={:?},content_sha256='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',max_bytes=3}}\ninterpreter={{program={:?},argv=[]}}",
        source.to_str().unwrap(), shell.to_str().unwrap())).unwrap();
    raw
}

fn controller_compile(
    raw: toml::Value,
    enabled: bool,
    permitted: bool,
    root: Option<&Path>,
) -> Result<Bindings, ConfigError> {
    let selected = enabled.then(|| "observe".to_owned());
    Bindings::compile(
        BTreeMap::from([("observe".into(), raw)]),
        selected.as_slice(),
        &Limits::default(),
        |_| false,
        root.map(|p| p.to_str().unwrap()),
        permitted,
    )
}

#[test]
fn inactive_controller_declarations_do_not_open_runtime_source_or_root() {
    let raw = controller_definition(Path::new("/unavailable/source"));
    for (enabled, permitted) in [(false, true), (true, false), (false, false)] {
        let mut raw = raw.clone();
        raw["execution"]["interpreter"]["program"] = "/unavailable/runtime".into();
        assert!(
            controller_compile(
                raw,
                enabled,
                permitted,
                Some(Path::new("/unavailable/root"))
            )
            .is_ok()
        );
    }
    assert!(controller_compile(raw.clone(), true, true, None).is_err());
    for targets in [vec![], vec!["server".into()]] {
        let mut raw = raw.clone();
        put(&mut raw, "targets", toml::Value::Array(targets));
        assert!(controller_compile(raw, false, true, None).is_err());
    }
    for (name, value) in [
        ("HOME", "private"),
        ("MCP_", "x"),
        ("MCP_lower", "x"),
        ("PATH", "bad\0value"),
    ] {
        let mut raw = raw.clone();
        raw["execution"].as_table_mut().unwrap().insert(
            "environment".into(),
            toml::Value::Table(toml::Table::from_iter([(name.into(), value.into())])),
        );
        assert!(
            controller_compile(raw, false, true, None).is_err(),
            "{name}"
        );
    }
}

#[test]
fn controller_pins_source_and_rejects_host_controls() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"abc").unwrap();
    let bindings =
        controller_compile(controller_definition(&source), true, true, Some(dir.path())).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    fs::write(&source, b"changed").unwrap();
    for arguments in [
        json!({"value":"ok","host":"server"}),
        json!({"value":"ok","cwd":"/"}),
        json!({"value":"ok","retain_output":null}),
        json!({"value":"ok","retain_output":"true"}),
    ] {
        assert!(
            binding
                .parse_request(arguments.as_object().unwrap().clone())
                .is_err()
        );
    }
    let BindingCall::Controller(request) = binding
        .parse_request(
            json!({"value":"$(not shell) ☃\n","timeout_secs":1,"retain_output":true})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap()
    else {
        panic!("expected controller request")
    };
    assert!(request.retain_output);
    let prepared = binding
        .prepare_controller(&request, &Limits::default())
        .unwrap();
    assert_eq!(prepared.plan.source, "abc");
    assert_eq!(
        serde_json::from_slice::<Value>(&prepared.input_json).unwrap(),
        json!({"value":"$(not shell) ☃\n"})
    );
    for mode in [0o755, 0o770, 0o1700] {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            controller_compile(controller_definition(&source), true, true, Some(dir.path()))
                .is_err()
        );
    }
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn controller_json_limit_counts_actual_escaped_payload() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"abc").unwrap();
    let mut raw = controller_definition(&source);
    let names: Vec<_> = ('a'..='p').map(|c| c.to_string()).collect();
    raw["input_schema"]["required"] =
        toml::Value::Array(names.iter().cloned().map(Into::into).collect());
    raw["input_schema"]["properties"] = toml::Value::Table(
        names
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    toml::from_str("type='string'\nmaxLength=4096").unwrap(),
                )
            })
            .collect(),
    );
    let bindings = controller_compile(raw, true, true, Some(dir.path())).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    let mut arguments: JsonObject = names
        .iter()
        .map(|name| {
            (
                name.clone(),
                Value::String("x".repeat(if name == "p" { 3983 } else { 4096 })),
            )
        })
        .collect();
    let BindingCall::Controller(request) = binding.parse_request(arguments.clone()).unwrap() else {
        panic!("expected controller request")
    };
    assert_eq!(
        binding
            .prepare_controller(&request, &Limits::default())
            .unwrap()
            .input_json
            .len(),
        65_536
    );
    arguments.insert(
        "p".into(),
        Value::String("\n".to_owned() + &"x".repeat(3982)),
    );
    let BindingCall::Controller(request) = binding.parse_request(arguments).unwrap() else {
        panic!("expected controller request")
    };
    assert_eq!(
        binding
            .prepare_controller(&request, &Limits::default())
            .err()
            .unwrap()
            .code(),
        "resource_limit"
    );
}

fn definition() -> toml::Value {
    toml::from_str(r#"
description = "Literal observation"
revision = "review-1"
targets = ["server"]
authority = "ordinary"
effects = ["read"]
execution = { kind = "native_argv", program = "/usr/bin/printf", argv = ["--", { input = "value" }] }
input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 4096 } } }
result = { kind = "command" }
"#).unwrap()
}
fn compile(value: toml::Value) -> Result<Bindings, ConfigError> {
    Bindings::compile(
        BTreeMap::from([("observe".into(), value)]),
        &["observe".into()],
        &Limits::default(),
        |v| v == "server",
        None,
        true,
    )
}
fn request(binding: &CompiledBinding, value: Value) -> BindingRequest {
    let BindingCall::Remote(request) = binding
        .parse_request(
            json!({"host":"server", "value":value})
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap()
    else {
        panic!("expected remote request")
    };
    request
}
fn property(raw: &mut toml::Value) -> &mut toml::Value {
    &mut raw["input_schema"]["properties"]["value"]
}
fn put(table: &mut toml::Value, key: &str, value: toml::Value) {
    table.as_table_mut().unwrap().insert(key.into(), value);
}

#[test]
fn native_retention_stays_outside_fixed_command_inputs() {
    let ordinary = definition();
    let mut sudo = definition();
    sudo["authority"] = toml::from_str("sudo = 'root'").unwrap();
    let mut remote_script = definition();
    remote_script["execution"] = toml::Value::try_from(json!({
        "kind":"remote_script",
        "source":{"path":"/fixed/script","content_sha256":"00".repeat(32)},
        "interpreter":{"program":"/bin/sh","argv":[]},
        "argv":["--",{"input":"value"}]
    }))
    .unwrap();
    assert!(compile(remote_script).is_err());
    for raw in [ordinary, sudo] {
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert_eq!(
            binding.input_schema["properties"]["retain_output"],
            json!({"type":"boolean","default":false})
        );
        assert!(
            !binding.input_schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("retain_output"))
        );
        assert!(!request(binding, json!("literal")).retain_output);
        for retain_output in [false, true] {
            let BindingCall::Remote(request) = binding
                .parse_request(
                    json!({"host":"server","value":"literal","retain_output":retain_output})
                        .as_object()
                        .unwrap()
                        .clone(),
                )
                .unwrap()
            else {
                panic!("expected remote request")
            };
            assert_eq!(request.retain_output, retain_output);
            let prepared = binding.prepare(&request, &Limits::default()).unwrap();
            let arguments = match prepared.invocation {
                Invocation::BoundArgv { arguments, .. }
                | Invocation::BoundSudo { arguments, .. } => arguments,
                _ => panic!("expected fixed invocation"),
            };
            assert_eq!(arguments, [Cow::Borrowed("--"), Cow::Borrowed("literal")]);
        }
        for value in [Value::Null, json!(1), json!("true"), json!([]), json!({})] {
            assert!(
                binding
                    .parse_request(
                        json!({"host":"server","value":"literal","retain_output":value})
                            .as_object()
                            .unwrap()
                            .clone()
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn fixed_sudo_borrows_literal_inputs_without_exposing_authority_controls() {
    let mut raw = definition();
    raw["authority"] = toml::from_str("sudo = 'root'").unwrap();
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert!(binding.read_only());
    let text = "-n ' \"$();\\\n雪";
    let request = request(binding, json!(text));
    let prepared = binding.prepare(&request, &Limits::default()).unwrap();
    match prepared.invocation {
        Invocation::BoundSudo {
            program,
            arguments,
            user,
        } => {
            assert_eq!(program, "/usr/bin/printf");
            assert_eq!(user, "root");
            assert_eq!(arguments, [Cow::Borrowed("--"), Cow::Borrowed(text)]);
            assert!(arguments.iter().all(|v| matches!(v, Cow::Borrowed(_))));
        }
        _ => panic!("Expected fixed sudo invocation"),
    }
    for key in ["user", "authority", "program"] {
        let mut arguments = json!({"host":"server", "value":"ok"})
            .as_object()
            .unwrap()
            .clone();
        arguments.insert(key.into(), json!("root"));
        assert_eq!(
            binding.parse_request(arguments).err().unwrap().code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
    }
}

#[test]
fn literal_slots_borrow_and_preserve_adversarial_text() {
    let mut raw = definition();
    put(
        &mut raw["execution"],
        "cwd",
        "/tmp/quotes ' and spaces".into(),
    );
    raw["execution"]["argv"]
        .as_array_mut()
        .unwrap()
        .insert(1, "fixed '$()`;\n".into());
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    let text = "-a ' \"$()`;\\\n雪";
    let request = request(binding, json!(text));
    let prepared = binding.prepare(&request, &Limits::default()).unwrap();
    match prepared.invocation {
        Invocation::BoundArgv {
            program,
            arguments,
            cwd,
        } => {
            assert_eq!(program, "/usr/bin/printf");
            assert_eq!(cwd, Some("/tmp/quotes ' and spaces"));
            assert_eq!(
                arguments.iter().map(Cow::as_ref).collect::<Vec<_>>(),
                ["--", "fixed '$()`;\n", text]
            );
        }
        _ => panic!("Expected bound argv"),
    }
}

#[test]
fn closed_shape_and_types_reject_before_preparation() {
    let bindings = compile(definition()).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    for arguments in [
        json!({"host":"server"}),
        json!({"host":42, "value":"ok"}),
        json!({"host":"server", "value":1}),
        json!({"host":"server", "value":"ok", "program":"/bin/sh"}),
        json!({"host":"server", "value":"ok", "timeout_secs":-1}),
        json!({"host":"server", "value":"ok", "timeout_secs":null}),
        json!({"host":"server", "value":"ok", "env":{}}),
    ] {
        let error = binding
            .parse_request(arguments.as_object().unwrap().clone())
            .err()
            .unwrap();
        assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
    }
}

#[test]
fn string_bounds_count_characters_and_enum_is_enforced() {
    let mut raw = definition();
    *property(&mut raw) = toml::from_str("type='string'\nminLength=1\nmaxLength=2").unwrap();
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    for (text, accepted) in [
        ("", false),
        ("雪", true),
        ("雪雪", true),
        ("雪雪雪", false),
        ("\0", false),
    ] {
        let request = request(binding, json!(text));
        let result = binding.prepare(&request, &Limits::default());
        assert_eq!(result.is_ok(), accepted, "{text:?}");
        if let Err(error) = result {
            assert_eq!(error.code(), "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }
    let mut raw = definition();
    put(
        property(&mut raw),
        "enum",
        toml::Value::Array(vec!["approved".into()]),
    );
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    assert!(
        binding
            .prepare(&request(binding, json!("approved")), &Limits::default())
            .is_ok()
    );
    assert!(
        binding
            .prepare(&request(binding, json!("other")), &Limits::default())
            .is_err()
    );
}

#[test]
fn integer_and_boolean_domains_render_exactly() {
    for (schema, values) in [
        (
            "type='integer'\nminimum=-2\nmaximum=2",
            vec![
                (json!(-2), Some("-2")),
                (json!(2), Some("2")),
                (json!(3), None),
            ],
        ),
        (
            "type='boolean'\nenum=[true]",
            vec![(json!(true), Some("true")), (json!(false), None)],
        ),
        (
            "type='integer'\nminimum=-9223372036854775808\nmaximum=9223372036854775807",
            vec![
                (json!(i64::MIN), Some("-9223372036854775808")),
                (json!(i64::MAX), Some("9223372036854775807")),
            ],
        ),
    ] {
        let mut raw = definition();
        *property(&mut raw) = toml::from_str(schema).unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for (value, expected) in values {
            let request = request(binding, value);
            let result = binding.prepare(&request, &Limits::default());
            if let Some(expected) = expected {
                match result.unwrap().invocation {
                    Invocation::BoundArgv { arguments, .. } => {
                        assert_eq!(arguments[1], expected)
                    }
                    _ => panic!("Expected bound argv"),
                }
            } else {
                assert!(result.is_err());
            }
        }
        for wrong in [json!("1"), json!(1.5), json!([])] {
            assert!(
                binding
                    .parse_request(
                        json!({"host":"server","value":wrong})
                            .as_object()
                            .unwrap()
                            .clone()
                    )
                    .is_err()
            );
        }
    }
}

#[test]
fn option_safety_depends_on_fixed_separator_or_closed_domain() {
    for (schema, accepted) in [
        ("type='string'\nmaxLength=32", false),
        ("type='string'\nmaxLength=32\nenum=['--version']", true),
        ("type='integer'\nminimum=-1\nmaximum=5", false),
        ("type='integer'\nminimum=-1\nmaximum=5\nenum=[-1,2]", true),
        ("type='integer'\nminimum=0\nmaximum=5", true),
        ("type='boolean'", true),
    ] {
        let mut raw = definition();
        raw["execution"]["argv"].as_array_mut().unwrap().remove(0);
        *property(&mut raw) = toml::from_str(schema).unwrap();
        assert_eq!(compile(raw).is_ok(), accepted, "{schema}");
    }
    let mut raw = definition();
    raw["execution"]["argv"].as_array_mut().unwrap().swap(0, 1);
    assert!(
        compile(raw).is_err(),
        "A later separator must not authorize an earlier free slot"
    );
}

#[test]
fn unsupported_schemas_and_bad_mappings_fail_even_when_disabled() {
    for schema in [
        "type='string'",
        "type='string'\nmaxLength=4097",
        "type='string'\nmaxLength=2\nminLength=3",
        "type='string'\nmaxLength=2\npattern='.*'",
        "type='string'\nmaxLength=2\ndefault='x'",
        "type='object'\nproperties={}",
        "type='integer'\nminimum=0",
        "type='integer'\nminimum=2\nmaximum=1",
        "type='integer'\nminimum=0\nmaximum=2\nenum=['1']",
        "type='boolean'\nenum=[]",
        "type='boolean'\nenum=[true,true]",
        "type='boolean'\nmaximum=2",
    ] {
        let mut raw = definition();
        *property(&mut raw) = toml::from_str(schema).unwrap();
        assert!(
            Bindings::compile(
                BTreeMap::from([("observe".into(), raw)]),
                &[],
                &Limits::default(),
                |_| true,
                None,
                true
            )
            .is_err(),
            "{schema}"
        );
    }
    for name in RESERVED
        .iter()
        .copied()
        .chain(["_hidden", "bad-name", "1value"])
    {
        let mut raw = definition();
        let properties = raw["input_schema"]["properties"].as_table_mut().unwrap();
        let value = properties.remove("value").unwrap();
        properties.insert(name.into(), value);
        raw["input_schema"]["required"] = toml::Value::Array(vec![name.into()]);
        raw["execution"]["argv"][1]["input"] = name.into();
        assert!(compile(raw).is_err(), "{name}");
    }
    for argv in [
        vec![],
        vec![toml::Value::String("--".into())],
        vec![toml::from_str("input='unknown'").unwrap()],
        vec![toml::from_str("input='value'\nfixed='override'").unwrap()],
    ] {
        let mut raw = definition();
        raw["execution"]["argv"] = toml::Value::Array(argv);
        assert!(compile(raw).is_err());
    }
    for required in [vec![], vec!["value", "value"], vec!["missing"]] {
        let mut raw = definition();
        raw["input_schema"]["required"] =
            toml::Value::Array(required.into_iter().map(Into::into).collect());
        assert!(compile(raw).is_err());
    }
}

#[test]
fn limits_targets_revision_and_enablement_are_enforced() {
    let mut raw = definition();
    put(
        &mut raw,
        "limits",
        toml::from_str("timeout_secs=3\nmax_output_bytes=7").unwrap(),
    );
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    let mut request = request(binding, json!("ok"));
    let prepared = binding.prepare(&request, &Limits::default()).unwrap();
    assert_eq!(prepared.duration, Duration::from_secs(3));
    assert_eq!(prepared.max_output_bytes, 7);
    for timeout in [0, 4] {
        request.timeout_secs = Some(timeout);
        assert!(binding.prepare(&request, &Limits::default()).is_err());
    }
    request.timeout_secs = Some(2);
    assert_eq!(
        binding
            .prepare(&request, &Limits::default())
            .unwrap()
            .duration,
        Duration::from_secs(2)
    );
    request.host = "arbitrary.example".into();
    assert!(binding.prepare(&request, &Limits::default()).is_err());
    for revision in ["", "not secret!", "☃"] {
        let mut raw = definition();
        raw["revision"] = revision.into();
        assert!(compile(raw).is_err());
    }
    for targets in [vec![], vec!["server", "server"], vec!["unknown"]] {
        let mut raw = definition();
        raw["targets"] = toml::Value::Array(targets.into_iter().map(Into::into).collect());
        assert!(compile(raw).is_err());
    }
    for limits in [
        "timeout_secs=0",
        "timeout_secs=601",
        "max_output_bytes=0",
        "max_output_bytes=1048577",
    ] {
        let mut raw = definition();
        put(&mut raw, "limits", toml::from_str(limits).unwrap());
        assert!(compile(raw).is_err());
    }
    for enabled in [
        vec!["missing".into()],
        vec!["observe".into(), "observe".into()],
    ] {
        assert!(
            Bindings::compile(
                BTreeMap::from([("observe".into(), definition())]),
                &enabled,
                &Limits::default(),
                |_| true,
                None,
                true
            )
            .is_err()
        );
    }
    let disabled = Bindings::compile(
        BTreeMap::from([("observe".into(), definition())]),
        &[],
        &Limits::default(),
        |_| true,
        None,
        true,
    )
    .unwrap();
    assert!(!disabled.get(BindingId(0)).unwrap().enabled());
}

#[test]
fn actual_expansion_obeys_exact_encoded_command_boundary() {
    // The fixed prefix "command -- /x --" is 16 bytes; sixteen references
    // contribute 65504 bytes at 4093 bytes each plus their leading spaces.
    // A 15-byte literal plus its leading space reaches exactly 65536.
    let mut raw = definition();
    raw["execution"]["program"] = "/x".into();
    let mut argv = vec![
        toml::Value::String("--".into()),
        toml::Value::String("x".repeat(15)),
    ];
    argv.extend((0..16).map(|_| toml::from_str("input='value'").unwrap()));
    raw["execution"]["argv"] = toml::Value::Array(argv);
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    let exact = request(binding, json!("x".repeat(4093)));
    let prepared = binding.prepare(&exact, &Limits::default()).unwrap();
    assert_eq!(prepared.invocation.encoded_len().unwrap(), 65536);
    let over = request(binding, json!("x".repeat(4094)));
    let error = binding.prepare(&over, &Limits::default()).err().unwrap();
    assert_eq!(error.code(), "invalid_argument");
    assert!(!error.remote_state_unknown);
}

#[test]
fn static_layout_and_metadata_bounds_reject_overflow() {
    for (field, value) in [
        ("program", Value::String("relative".into())),
        ("program", Value::String("/bin/".into())),
        ("program", Value::String("/".to_owned() + &"x".repeat(4096))),
        ("cwd", Value::String("relative".into())),
    ] {
        let mut raw = definition();
        put(&mut raw["execution"], field, value.as_str().unwrap().into());
        assert!(compile(raw).is_err());
    }
    let mut raw = definition();
    raw["execution"]["argv"]
        .as_array_mut()
        .unwrap()
        .push("x".repeat(4097).into());
    assert!(compile(raw).is_err());
    let mut raw = definition();
    raw["execution"]["argv"]
        .as_array_mut()
        .unwrap()
        .extend((0..63).map(|_| "x".into()));
    assert!(compile(raw).is_err(), "More than 64 slots");
    let mut raw = definition();
    raw["execution"]["argv"]
        .as_array_mut()
        .unwrap()
        .extend((0..32).map(|_| "x".repeat(4096).into()));
    assert!(
        compile(raw).is_err(),
        "Fixed-only command must fit before any request"
    );
    let mut raw = definition();
    put(
        property(&mut raw),
        "enum",
        toml::Value::Array(
            (0..5)
                .map(|i| format!("{i}{}", "x".repeat(4000)).into())
                .collect(),
        ),
    );
    assert!(compile(raw).is_err(), "Aggregate enum text is bounded");
    let ok_raw = (0..256)
        .map(|i| (format!("tool_{i}"), definition()))
        .collect();
    assert!(Bindings::compile(ok_raw, &[], &Limits::default(), |_| true, None, true).is_ok());
    let raw = (0..257)
        .map(|i| (format!("tool_{i}"), definition()))
        .collect();
    assert!(Bindings::compile(raw, &[], &Limits::default(), |_| true, None, true).is_err());
}

#[test]
fn effect_annotations_are_conservative_and_unique() {
    for (effects, read_only) in [
        (vec!["read", "sensitive_read"], true),
        (vec!["read", "probe"], false),
        (vec!["runtime_write"], false),
        (vec!["persistent_write"], false),
        (vec!["availability"], false),
        (vec!["unknown"], false),
    ] {
        let mut raw = definition();
        raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
        let bindings = compile(raw).unwrap();
        assert_eq!(bindings.get(BindingId(0)).unwrap().read_only(), read_only);
    }
    for effects in [vec![], vec!["read", "read"], vec!["invented"]] {
        let mut raw = definition();
        raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
        assert!(compile(raw).is_err());
    }
}

#[test]
fn integer_schema_normalizes_integral_numbers_without_truncating() {
    let mut raw = definition();
    *property(&mut raw) =
        toml::from_str("type='integer'\nminimum=-2\nmaximum=2\nenum=[1,2]").unwrap();
    let bindings = compile(raw).unwrap();
    let binding = bindings.get(BindingId(0)).unwrap();
    for (token, expected) in [("1", "1"), ("1.0", "1"), ("1e0", "1"), ("2.0", "2")] {
        let value: Value = serde_json::from_str(token).unwrap();
        let BindingCall::Remote(request) = binding
            .parse_request(
                json!({
                    "host":"server", "value":value, "timeout_secs":1.0
                })
                .as_object()
                .unwrap()
                .clone(),
            )
            .unwrap()
        else {
            panic!("expected remote request")
        };
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        assert_eq!(prepared.duration, Duration::from_secs(1));
        match prepared.invocation {
            Invocation::BoundArgv { arguments, .. } => assert_eq!(arguments[1], expected),
            _ => panic!("wrong native invocation"),
        }
    }
    for token in ["1.5", "1e100", "3.0"] {
        let value: Value = serde_json::from_str(token).unwrap();
        if let Ok(BindingCall::Remote(request)) = binding.parse_request(
            json!({
                "host":"server", "value":value
            })
            .as_object()
            .unwrap()
            .clone(),
        ) {
            assert!(binding.prepare(&request, &Limits::default()).is_err());
        }
    }
    let mut raw = definition();
    *property(&mut raw) =
        toml::from_str("type='integer'\nminimum=0\nmaximum=2\nenum=[1,1.0]").unwrap();
    assert!(
        compile(raw).is_err(),
        "numeric enum aliases must not become distinct choices"
    );
}

#[test]
fn generated_host_enums_share_the_complete_input_schema_budget() {
    for (target, choices) in [
        ("x".repeat(MAX_SCHEMA_BYTES + 1), None),
        (
            "x".repeat(MAX_SCHEMA_BYTES - 1024),
            Some(vec!["a".repeat(1000), "b".repeat(1000)]),
        ),
    ] {
        let mut raw = definition();
        raw["targets"] = toml::Value::Array(vec![target.into()]);
        if let Some(choices) = choices {
            put(
                property(&mut raw),
                "enum",
                toml::Value::Array(choices.into_iter().map(toml::Value::String).collect()),
            );
        }
        let result = Bindings::compile(
            BTreeMap::from([("observe".into(), raw)]),
            &["observe".into()],
            &Limits::default(),
            |_| true,
            None,
            true,
        );
        assert!(
            result.is_err(),
            "generated host choices escaped the schema cap"
        );
    }
}

#[test]
fn site_constraints_derive_both_allowed_units_and_unit_enum_and_reject_duplication() {
    let raw: toml::Value = toml::from_str(
        r#"
description = "Restart reviewed unit"
revision = "1"
targets = ["server"]
authority = "automation"
effects = ["runtime_write", "read"]
execution = { kind = "native_payload", snapshot = "/etc/estus/change_systemd_restart.payload.json", source = "/etc/estus/payloads/change_systemd_restart/collector.py", no_log = false }
fixed_args = { target_python = "/usr/bin/python3", manager_scope = "system" }
input_map = { unit = "unit" }
constraints = { allowed_units = ["nginx.service", "caddy.service"] }
input_schema = { type = "object", properties = { unit = { type = "string", maxLength = 128 } }, required = ["unit"], additionalProperties = false }
result = { kind = "capability_projection", fields = { unit = ["mcp_result", "unit"] }, max_bytes = 4096, max_items = 64, max_depth = 4, schema = { type = "object", properties = { unit = { type = "string", maxLength = 128 } }, required = ["unit"], additionalProperties = false } }
"#,
    )
    .unwrap();
    let compiled = Bindings::compile(
        BTreeMap::from([("change_systemd_restart".into(), raw.clone())]),
        &["change_systemd_restart".into()],
        &Limits::default(),
        |target| target == "server",
        None,
        true,
    )
    .unwrap();
    let (_, binding) = compiled.entries().next().unwrap();
    assert_eq!(
        binding.input_schema["properties"]["inputs"]["properties"]["unit"]["enum"],
        json!(["nginx.service", "caddy.service"])
    );
    if let Execution::Payload(state) = &binding.execution {
        let overlay = state.overlay();
        assert_eq!(
            overlay["fixed_args"]["allowed_units"],
            json!(["nginx.service", "caddy.service"])
        );
    } else {
        panic!("expected payload binding");
    }

    // Duplicated manual allowed_units alongside constraints.allowed_units must reject.
    let mut dup = raw;
    dup.as_table_mut()
        .unwrap()
        .get_mut("fixed_args")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "allowed_units".into(),
            toml::Value::Array(vec!["nginx.service".into()]),
        );
    assert!(
        Bindings::compile(
            BTreeMap::from([("systemd_unit_restart".into(), dup)]),
            &["systemd_unit_restart".into()],
            &Limits::default(),
            |target| target == "server",
            None,
            true,
        )
        .is_err()
    );
}

#[test]
fn risk_prefix_effects_invariant_rejects_mismatches_and_preview_maps_to_preview_tier() {
    let mut bad_observe = definition();
    bad_observe["effects"] = toml::Value::Array(vec!["read".into(), "sensitive_read".into()]);
    assert!(
        Bindings::compile(
            BTreeMap::from([("observe_bad".into(), bad_observe)]),
            &["observe_bad".into()],
            &Limits::default(),
            |_| true,
            None,
            true,
        )
        .is_err()
    );

    let mut bad_inspect = definition();
    bad_inspect["effects"] = toml::Value::Array(vec!["read".into()]);
    assert!(
        Bindings::compile(
            BTreeMap::from([("inspect_bad".into(), bad_inspect)]),
            &["inspect_bad".into()],
            &Limits::default(),
            |_| true,
            None,
            true,
        )
        .is_err()
    );

    let mut bad_change = definition();
    bad_change["effects"] = toml::Value::Array(vec!["read".into()]);
    assert!(
        Bindings::compile(
            BTreeMap::from([("change_bad".into(), bad_change)]),
            &["change_bad".into()],
            &Limits::default(),
            |_| true,
            None,
            true,
        )
        .is_err()
    );

    let mut preview = definition();
    preview["effects"] = toml::Value::Array(vec!["read".into(), "sensitive_read".into()]);
    let compiled = Bindings::compile(
        BTreeMap::from([("preview_plan".into(), preview)]),
        &["preview_plan".into()],
        &Limits::default(),
        |_| true,
        None,
        true,
    )
    .unwrap();
    let (_, binding) = compiled.entries().next().unwrap();
    assert_eq!(
        crate::config::risk_tier_for_binding(binding),
        crate::config::RiskTier::Preview
    );
}

#[test]
fn site_constraints_propagate_keys_interfaces_and_packages_to_schema_and_fixed_args() {
    let mut sysctl_schema = json!({
        "type": "object",
        "properties": { "key": { "type": "string" }, "value": { "type": "integer" } }
    });
    let mut sysctl_fixed = json!({ "target_python": "/usr/bin/python3" });
    apply_site_constraints(
        &mut sysctl_schema,
        &mut sysctl_fixed,
        Some(&SiteConstraints {
            allowed_keys: Some(vec!["vm.swappiness".into(), "net.ipv4.ip_forward".into()]),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        sysctl_schema["properties"]["key"]["enum"],
        json!(["vm.swappiness", "net.ipv4.ip_forward"])
    );
    assert_eq!(
        sysctl_fixed["approved_keys"],
        json!(["vm.swappiness", "net.ipv4.ip_forward"])
    );

    let mut net_schema = json!({
        "type": "object",
        "properties": { "interface": { "type": "string" } }
    });
    let mut net_fixed = json!({ "operator_policy": { "interfaces": ["lo"] } });
    apply_site_constraints(
        &mut net_schema,
        &mut net_fixed,
        Some(&SiteConstraints {
            allowed_interfaces: Some(vec!["eth0".into(), "bond0".into()]),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        net_schema["properties"]["interface"]["enum"],
        json!(["eth0", "bond0"])
    );
    assert_eq!(
        net_fixed["operator_policy"]["interfaces"],
        json!(["eth0", "bond0"])
    );

    let mut pkg_schema = json!({
        "type": "object",
        "properties": { "package": { "type": "string" } }
    });
    let mut pkg_fixed = json!({ "target_python": "/usr/bin/python3" });
    apply_site_constraints(
        &mut pkg_schema,
        &mut pkg_fixed,
        Some(&SiteConstraints {
            allowed_packages: Some(vec!["htop".into(), "strace".into()]),
            ..Default::default()
        }),
    )
    .unwrap();
    assert_eq!(
        pkg_schema["properties"]["package"]["enum"],
        json!(["htop", "strace"])
    );
    assert_eq!(pkg_fixed["approved_packages"], json!(["htop", "strace"]));
}
