//! Named tools, fixed sudo tools and remote script definitions. No SSH.
#[path = "support/stdio.rs"]
#[allow(dead_code)]
// Shared helpers used by other suites are inert here.
mod stdio;
use stdio::*;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_tools_publish_reviewed_metadata_and_freeze_startup_selection() -> Result<()> {
    let config = NAMED_TOOL_CONFIG.replacen("capabilities = { named = true }\n", "", 1);
    let (mut server, directory) = named_tools_server(&config)?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        binding_public_only(&serde_json::to_vec(&listed)?)?;
        let tools = listed["result"]["tools"].as_array().context("named tools")?;
        let mut names: Vec<_> = tools.iter().map(|tool| tool["name"].as_str().context("tool name")).collect::<Result<_>>()?;
        names.sort_unstable();
        ensure!(names == ["change_account", "change_target_quarantine_clear", "inspect_account", "inspect_output", "observe_targets"]);
        for (name, revision, effects, tier, read_only, destructive) in [
            ("inspect_account", "review-1", json!(["read", "sensitive_read"]), "inspect", true, false),
            ("change_account", "change-2", json!(["persistent_write"]), "change", false, true),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("binding metadata")?;
            ensure!(tool["_meta"] == json!({
                "risk_tier": tier,
                "revision": revision,
                "authority": "ordinary",
                "effects": effects,
                "result": "command",
                "executor": "native_argv",
                "execution_location": "remote",
                "trusted_controller_code": false,
                "restriction_boundary": {
                    "mcp": "request_policy", "os": "service_account_and_remote_identity",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                },
            }));
            ensure!(tool["annotations"]["readOnlyHint"] == read_only);
            ensure!(tool["annotations"]["destructiveHint"] == destructive);
            ensure!(tool["annotations"]["idempotentHint"] == false);
            ensure!(tool["outputSchema"]["type"] == "object");
            ensure!(tool["outputSchema"]["properties"]["data"].is_object());
            ensure!(tool["outputSchema"]["properties"]["error"].is_object());
        }
        for name in ["inspect_account", "change_account"] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("native binding")?;
            output_control_schema(&tool["inputSchema"])?;
        }
        let observe = tools.iter().find(|tool| tool["name"] == "inspect_account").context("observe tool")?;
        let schema = &observe["inputSchema"];
        ensure!(schema["type"] == "object" && schema["additionalProperties"] == false);
        let hosts = schema["properties"]["host"]["enum"].as_array().context("declared binding hosts")?;
        ensure!(hosts.len() == 3);
        for host in ["base", "read", "files"] {
            ensure!(hosts.contains(&json!(host)));
        }
        ensure!(schema["properties"]["timeout_secs"]["maximum"] == 2);
        ensure!(schema["properties"]["account"]["enum"] == json!(["root", "operator"]));
        ensure!(schema["properties"]["count"]["minimum"] == -2);
        ensure!(schema["properties"]["count"]["maximum"] == 4);
        ensure!(schema["properties"]["verbose"]["type"] == "boolean");
        let required = schema["required"].as_array().context("required binding inputs")?;
        ensure!(required.len() == 4);
        for name in ["host", "account", "count", "verbose"] {
            ensure!(required.contains(&json!(name)));
        }
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        let discovered = server.response(3).await?;
        binding_public_only(&serde_json::to_vec(&discovered)?)?;
        let rows = discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("binding target rows")?;
        for (name, expected) in [
            ("base", json!(["change_account", "inspect_account"])),
            ("read", json!([])),
            ("files", json!([])),
            ("other", json!([])),
        ] {
            let row = rows.iter().find(|row| row["name"] == name).context("binding target")?;
            ensure!(row["permitted_operations"] == expected, "{row}");
        }
        std::fs::write(
            directory.path().join("operator.toml"),
            config
                .replace("[\"inspect_account\", \"change_account\"]", "[\"disabled_account\"]")
                .replace("review-1", "review-99"),
        )?;
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})).await?;
        ensure!(server.response(4).await?["result"] == listed["result"]);
        for (index, tool) in ["disabled_account", "exec_command", "exec_argv", "exec_sudo"].into_iter().enumerate() {
            let arguments = if tool == "disabled_account" { json!({"host":"base"}) } else { profile_call_arguments(tool, "base") };
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    binding_public_only(&stderr)?;
    ensure!(!directory.path().join("binding-must-not-probe").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_tool_validation_and_target_policy_precede_ssh() -> Result<()> {
    let (mut server, directory) = named_tools_server(NAMED_TOOL_CONFIG)?;
    let scenario = async {
        server.initialize().await?;
        let valid = json!({"host":"base","account":"root","count":0,"verbose":false});
        let mut cases = Vec::new();
        for (field, value) in [
            ("extra", json!("BINDING_INPUT_SECRET")),
            ("account", json!(42)),
            ("count", json!("BINDING_INPUT_SECRET")),
            ("count", json!(1.5)),
            ("verbose", json!("BINDING_INPUT_SECRET")),
            ("host", json!(false)),
            ("timeout_secs", json!("BINDING_INPUT_SECRET")),
            ("retain_output", json!("BINDING_INPUT_SECRET")),
            ("retain_output", Value::Null),
        ] {
            let mut arguments = valid.clone();
            arguments[field] = value;
            cases.push((arguments, None));
        }
        for reserved in ["argv", "program", "cwd", "stdin", "user", "role", "authority", "execution", "profile", "env", "shell", "sudo", "command", "revision", "effects", "result", "input_schema", "enabled_tools", "_internal"] {
            let mut arguments = valid.clone();
            arguments[reserved] = json!("BINDING_INPUT_SECRET");
            cases.push((arguments, None));
        }
        for missing in ["host", "account", "count", "verbose"] {
            let mut arguments = valid.clone();
            arguments.as_object_mut().context("arguments object")?.remove(missing);
            cases.push((arguments, None));
        }
        for (field, value) in [
            ("account", json!("BINDING_INPUT_SECRET")),
            ("account", json!("")),
            ("account", json!("roo\u{0}t")),
            ("account", json!("--help")),
            ("count", json!(-3)),
            ("count", json!(5)),
            ("timeout_secs", json!(0)),
            ("timeout_secs", json!(3)),
        ] {
            let mut arguments = valid.clone();
            arguments[field] = value;
            cases.push((arguments, Some("invalid_argument")));
        }
        for host in ["other", "read", "files", "private-binding-elevated.invalid", "unconfigured.invalid"] {
            let mut arguments = valid.clone();
            arguments["host"] = json!(host);
            cases.push((arguments, Some("policy_denied")));
        }
        for (index, (arguments, code)) in cases.into_iter().enumerate() {
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"inspect_account","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            binding_public_only(&serde_json::to_vec(&response)?)?;
            if let Some(code) = code {
                let result = &response["result"];
                ensure!(result["isError"] == true, "case {index}: {response}");
                ensure!(result["structuredContent"]["data"].is_null());
                ensure!(result["structuredContent"]["error"]["code"] == code, "case {index}: {response}");
                ensure!(result["structuredContent"]["error"]["remote_state_unknown"] == false);
                let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().context("binding error text")?)?;
                ensure!(text == result["structuredContent"]);
            } else {
                ensure!(response["error"]["code"] == -32602, "case {index}: {response}");
            }
        }
        server.send(json!({"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        discovery_data(&server.response(200).await?["result"], "configured")?;
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    binding_public_only(&stderr)?;
    let mut audited_rejections = 0;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        if record["tool"] == "inspect_account" {
            audited_rejections += 1;
            ensure!(record["identity_role"] == "ordinary");
            ensure!(record["event"] == "reject");
            ensure!(record["remote_state_unknown"] == false);
            ensure!(record.get("program").is_none());
            ensure!(record["binding_revision"] == "review-1");
            ensure!(record["executor"] == "native_argv");
        }
    }
    ensure!(
        audited_rejections > 0,
        "binding rejections were not audited"
    );
    ensure!(!directory.path().join("binding-must-not-probe").exists());
    Ok(())
}

#[tokio::test]
async fn file_profiles_do_not_publish_enabled_native_bindings() -> Result<()> {
    for caps in [
        "capabilities = { file_read = true }",
        "capabilities = { file_read = true, file_write = true }",
    ] {
        let config = NAMED_TOOL_CONFIG.replace("capabilities = { named = true }", caps);
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("profile tools")?;
            for name in ["inspect_account", "change_account", "disabled_account"] {
                ensure!(!tools.iter().any(|tool| tool["name"] == name));
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_account","arguments":{"host":"base","account":"root","count":0,"verbose":false}}})).await?;
            ensure!(server.response(3).await?["error"]["code"] == -32602);
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
            let response = server.response(4).await?;
            for row in discovery_data(&response["result"], "configured")?["targets"].as_array().context("profile rows")? {
                let operations = row["permitted_operations"].as_array().context("profile operations")?;
                ensure!(!operations.contains(&json!("inspect_account")));
                ensure!(!operations.contains(&json!("change_account")));
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        no_remote_dispatch(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test]
async fn invalid_named_tool_definitions_fail_before_mcp_without_private_values() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-binding-config.toml");
    std::fs::write(directory.path().join("replacement.conf"), "")?;
    let mut invalid = Vec::new();
    for (from, to) in [
        (
            "[\"inspect_account\", \"change_account\"]",
            "[\"BINDING_CONFIG_SECRET\"]",
        ),
        (
            "[\"inspect_account\", \"change_account\"]",
            "[\"inspect_account\", \"inspect_account\"]",
        ),
        (
            "authority = \"ordinary\"",
            "authority = \"BINDING_CONFIG_SECRET\"",
        ),
        ("kind = \"native_argv\"", "kind = \"BINDING_CONFIG_SECRET\""),
        (
            "revision = \"review-1\"",
            "revision = \"BINDING_CONFIG_SECRET value\"",
        ),
        (
            "targets = [\"base\", \"read\", \"files\"]",
            "targets = [\"BINDING_CONFIG_SECRET\"]",
        ),
        (
            "program = \"/private/binding-program\"",
            "program = \"BINDING_CONFIG_SECRET\"",
        ),
        (
            "program = \"/private/binding-program\"",
            "program = \"\\u0000BINDING_CONFIG_SECRET\"",
        ),
        (
            "effects = [\"persistent_write\"]",
            "effects = [\"BINDING_CONFIG_SECRET\"]",
        ),
        (
            "additionalProperties = false",
            "additionalProperties = true",
        ),
        (
            "required = [\"account\", \"count\", \"verbose\"]",
            "required = [\"account\", \"count\"]",
        ),
        ("enum = [\"root\", \"operator\"]", "enum = [\"root\", 17]"),
        ("maxLength = 16", "maxLength = 4097"),
        ("minimum = -2, maximum = 4", "minimum = 5, maximum = 4"),
        ("timeout_secs = 2", "timeout_secs = 6"),
        ("max_output_bytes = 1024", "max_output_bytes = 4097"),
        ("\"private-binding-fixed\", \"--\", ", ""),
        (
            "{ input = \"account\" }",
            "{ input = \"BINDING_CONFIG_SECRET\" }",
        ),
        (
            "account = { type = \"string\"",
            "account = { default = \"BINDING_CONFIG_SECRET\", type = \"string\"",
        ),
        ("[tools.disabled_account]", "[tools.exec_command]"),
        ("[tools.disabled_account]", "[tools.exec_sudo]"),
        ("[tools.disabled_account]", "[tools.observe_targets]"),
        (
            "program = \"/private/binding-disabled\"",
            "program = \"BINDING_CONFIG_SECRET\"",
        ),
    ] {
        invalid.push(NAMED_TOOL_CONFIG.replace(from, to));
    }
    invalid.push(NAMED_TOOL_CONFIG.replace("account", "sudo"));
    for (index, config) in invalid.into_iter().enumerate() {
        std::fs::write(&path, config)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(
            !output.status.success(),
            "accepted invalid binding case {index}"
        );
        ensure!(
            output.stdout.is_empty(),
            "invalid binding started MCP in case {index}"
        );
        binding_public_only(&output.stderr)?;
        let stderr = std::str::from_utf8(&output.stderr)?;
        ensure!(!stderr.contains("BINDING_CONFIG_SECRET"));
        ensure!(!stderr.contains(path.to_str().context("config path")?));
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_config",
            "case {index}: {diagnostic}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn named_tool_output_schema_matches_the_actual_command_route() -> Result<()> {
    for (fixture, names) in [
        (NAMED_TOOL_CONFIG, ["inspect_account", "change_account"]),
        (FIXED_SUDO_TOOL_CONFIG, ["fixed_id", "fixed_printf"]),
    ] {
        let config = fixture.replace(
            "capabilities = { named = true }",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
        );
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server
                .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
                .await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"]
                .as_array()
                .context("baseline tools")?;
            let command_schema = &tools
                .iter()
                .find(|tool| tool["name"] == "exec_argv")
                .context("actual command route")?["outputSchema"];
            ensure!(command_schema.is_object());
            for name in names {
                let tool = tools
                    .iter()
                    .find(|tool| tool["name"] == name)
                    .context("named command route")?;
                ensure!(
                    tool["outputSchema"] == *command_schema,
                    "wrong command result schema for {name}"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        no_remote_dispatch(&stderr)?;
        binding_public_only(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_sudo_tools_publish_safe_authority_and_independent_effects() -> Result<()> {
    let (mut server, directory) = named_tools_server(FIXED_SUDO_TOOL_CONFIG)?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        binding_public_only(&serde_json::to_vec(&listed)?)?;
        let tools = listed["result"]["tools"].as_array().context("fixed sudo tools")?;
        let mut names: Vec<_> = tools.iter().map(|tool| tool["name"].as_str().context("tool name")).collect::<Result<_>>()?;
        names.sort_unstable();
        ensure!(names == ["change_target_quarantine_clear", "fixed_id", "fixed_printf", "inspect_output", "observe_targets"]);
        for (name, revision, effects, read_only, destructive) in [
            ("fixed_id", "id-1", json!(["read"]), true, false),
            ("fixed_printf", "printf-1", json!(["persistent_write"]), false, true),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("fixed sudo metadata")?;
            ensure!(tool["_meta"] == json!({
                "risk_tier": "exec",
                "revision": revision,
                "authority": {"sudo": "root"},
                "effects": effects,
                "executor": "native_argv",
                "result": "command",
                "execution_location": "remote",
                "trusted_controller_code": false,
                "restriction_boundary": {
                    "mcp": "request_policy", "os": "service_account_and_remote_identity",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                },
            }));
            ensure!(tool["annotations"]["readOnlyHint"] == read_only);
            ensure!(tool["annotations"]["destructiveHint"] == destructive);
            ensure!(tool["annotations"]["idempotentHint"] == false);
            let schema = &tool["inputSchema"];
            ensure!(schema["type"] == "object" && schema["additionalProperties"] == false);
            let properties = schema["properties"].as_object().context("fixed sudo properties")?;
            let expected_fields = if name == "fixed_id" { 3 } else { 4 };
            ensure!(properties.len() == expected_fields);
            ensure!(properties.contains_key("host") && properties.contains_key("timeout_secs"));
            ensure!(schema["properties"]["timeout_secs"]["maximum"] == 5);
            output_control_schema(schema)?;
            let hosts = schema["properties"]["host"]["enum"].as_array().context("fixed sudo hosts")?;
            ensure!(hosts.len() == 4);
            for host in ["base", "same", "read", "files"] {
                ensure!(hosts.contains(&json!(host)));
            }
            let required = schema["required"].as_array().context("fixed sudo required fields")?;
            ensure!(required.contains(&json!("host")));
            if name == "fixed_id" {
                ensure!(required.len() == 1);
            } else {
                ensure!(required.len() == 2 && required.contains(&json!("value")));
            }
            for fixed in ["user", "program", "authority", "argv", "cwd", "role", "sudo"] {
                ensure!(!properties.contains_key(fixed));
                ensure!(tool["_meta"].get(fixed).is_none() || fixed == "authority");
            }
            let public = serde_json::to_string(tool)?;
            ensure!(!public.contains("/usr/bin/id") && !public.contains("/usr/bin/printf"));
        }
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        let discovered = server.response(3).await?;
        binding_public_only(&serde_json::to_vec(&discovered)?)?;
        let rows = discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("fixed sudo target rows")?;
        for (host, operations) in [
            ("base", json!(["fixed_id", "fixed_printf"])),
            ("same", json!(["fixed_id", "fixed_printf"])),
            ("read", json!([])),
            ("files", json!([])),
            ("other", json!([])),
        ] {
            let row = rows.iter().find(|row| row["name"] == host).context("fixed sudo target")?;
            ensure!(row["permitted_operations"] == operations, "{row}");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    binding_public_only(&stderr)?;
    ensure!(!directory.path().join("binding-must-not-probe").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_sudo_controls_and_target_policy_reject_before_ssh() -> Result<()> {
    let (mut server, directory) = named_tools_server(FIXED_SUDO_TOOL_CONFIG)?;
    let scenario = async {
        server.initialize().await?;
        let mut id = 2;
        for tool in ["exec_command", "exec_argv", "exec_sudo"] {
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":profile_call_arguments(tool, "base")}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
            id += 1;
        }
        for host in ["base", "same", "read", "private-binding-elevated.invalid"] {
            for (field, value) in [
                ("user", json!("BINDING_INPUT_SECRET")),
                ("authority", json!({"sudo":"BINDING_INPUT_SECRET"})),
                ("program", json!("/private/binding-override")),
                ("argv", json!(["BINDING_INPUT_SECRET"])),
                ("cwd", json!("/private/binding-cwd")),
                ("role", json!("elevated")),
                ("retain_output", json!("BINDING_INPUT_SECRET")),
            ] {
                let mut arguments = json!({"host":host});
                arguments[field] = value;
                server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"fixed_id","arguments":arguments}})).await?;
                let response = server.response(id).await?;
                ensure!(response["error"]["code"] == -32602, "{host}/{field}: {response}");
                binding_public_only(&serde_json::to_vec(&response)?)?;
                id += 1;
            }
        }
        for host in ["read", "files", "other", "private-binding-elevated.invalid", "unconfigured.invalid"] {
            for (tool, arguments) in [
                ("fixed_id", json!({"host":host})),
                ("fixed_printf", json!({"host":host,"value":"BINDING_INPUT_SECRET"})),
            ] {
                server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}})).await?;
                let response = server.response(id).await?;
                profile_policy_denied(&response)?;
                binding_public_only(&serde_json::to_vec(&response)?)?;
                id += 1;
            }
        }
        server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        discovery_data(&server.response(id).await?["result"], "configured")?;
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    binding_public_only(&stderr)?;
    ensure!(!directory.path().join("binding-must-not-probe").exists());
    Ok(())
}

#[tokio::test]
async fn fixed_sudo_file_profiles_hide_routes_and_reject_direct_calls() -> Result<()> {
    for caps in [
        "capabilities = { file_read = true }",
        "capabilities = { file_read = true, file_write = true }",
    ] {
        let config = FIXED_SUDO_TOOL_CONFIG.replacen("capabilities = { named = true }", caps, 1);
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("file profile tools")?;
            for (index, name) in ["fixed_id", "fixed_printf", "exec_sudo"].into_iter().enumerate() {
                ensure!(!tools.iter().any(|tool| tool["name"] == name));
                let id = 3 + index as u64;
                let arguments = match name {
                    "fixed_printf" => json!({"host":"base","value":"BINDING_INPUT_SECRET"}),
                    "exec_sudo" => profile_call_arguments(name, "base"),
                    _ => json!({"host":"base"}),
                };
                server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
                let response = server.response(id).await?;
                ensure!(response["error"]["code"] == -32602);
                binding_public_only(&serde_json::to_vec(&response)?)?;
            }
            server.send(json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
            let discovered = server.response(6).await?;
            for row in discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("file profile target rows")? {
                let operations = row["permitted_operations"].as_array().context("file profile operations")?;
                ensure!(!operations.contains(&json!("fixed_id")));
                ensure!(!operations.contains(&json!("fixed_printf")));
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        no_remote_dispatch(&stderr)?;
        binding_public_only(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test]
async fn fixed_sudo_invalid_or_unauthorized_definitions_fail_sanitized_startup() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-binding-config.toml");
    std::fs::write(directory.path().join("replacement.conf"), "")?;
    let mut cases = Vec::new();
    for (label, authority) in [
        ("string sudo", "\"sudo\""),
        ("empty authority", "{}"),
        (
            "extra authority key",
            "{ sudo = \"root\", extra = \"BINDING_CONFIG_SECRET\" }",
        ),
        ("numeric account", "{ sudo = \"0\" }"),
        ("option account", "{ sudo = \"--BINDING_CONFIG_SECRET\" }"),
        (
            "NUL account",
            "{ sudo = \"root\\u0000BINDING_CONFIG_SECRET\" }",
        ),
        (
            "wrong account type",
            "{ sudo = [\"BINDING_CONFIG_SECRET\"] }",
        ),
    ] {
        cases.push((
            label,
            FIXED_SUDO_TOOL_CONFIG.replace(
                "authority = { sudo = \"root\" }",
                &format!("authority = {authority}"),
            ),
        ));
    }
    cases.push((
        "long account",
        FIXED_SUDO_TOOL_CONFIG.replace(
            "authority = { sudo = \"root\" }",
            &format!("authority = {{ sudo = \"{}\" }}", "a".repeat(65)),
        ),
    ));
    for (label, from, to) in [
        (
            "elevated cwd",
            "program = \"/usr/bin/id\", argv",
            "program = \"/usr/bin/id\", cwd = \"/private/binding-cwd\", argv",
        ),
        (
            "disabled sudo",
            "[targets.read.sudo]\nmode = \"same-account\"",
            "[targets.read.sudo]\nmode = \"disabled\"",
        ),
        (
            "missing permitted user",
            "users = [\"root\"]",
            "users = [\"operator\"]",
        ),
        (
            "empty program policy",
            "programs = [\"/usr/bin/id\", \"/usr/bin/printf\"]",
            "programs = []",
        ),
        (
            "same basename wrong path",
            "program = \"/usr/bin/id\"",
            "program = \"/private/binding/id\"",
        ),
        (
            "one unauthorized target",
            "[targets.read.sudo]\nmode = \"same-account\"",
            "[targets.read.sudo]\nmode = \"same-account\"\nprograms = []",
        ),
    ] {
        cases.push((label, FIXED_SUDO_TOOL_CONFIG.replace(from, to)));
    }
    let unauthorized =
        FIXED_SUDO_TOOL_CONFIG.replace("users = [\"root\"]", "users = [\"operator\"]");
    cases.push((
        "disabled unauthorized definition",
        unauthorized.replace("allow = [\"fixed_id\", \"fixed_printf\"]", "allow = []"),
    ));
    cases.push((
        "profile-hidden unauthorized definition",
        unauthorized.replacen(
            "capabilities = { named = true }",
            "capabilities = { file_read = true, file_write = true }",
            1,
        ),
    ));
    cases.push((
        "disabled malformed definition",
        FIXED_SUDO_TOOL_CONFIG
            .replace("allow = [\"fixed_id\", \"fixed_printf\"]", "allow = []")
            .replace(
                "authority = { sudo = \"root\" }",
                "authority = { sudo = \"BINDING_CONFIG_SECRET value\" }",
            ),
    ));
    for (label, config) in cases {
        std::fs::write(&path, config)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(!output.status.success(), "accepted {label}");
        ensure!(output.stdout.is_empty(), "started MCP for {label}");
        binding_public_only(&output.stderr)?;
        let stderr = std::str::from_utf8(&output.stderr)?;
        ensure!(!stderr.contains("BINDING_CONFIG_SECRET"), "{label}");
        ensure!(
            !stderr.contains(path.to_str().context("config path")?),
            "{label}"
        );
        ensure!(
            !stderr.contains("/usr/bin/id") && !stderr.contains("/usr/bin/printf"),
            "{label}"
        );
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_config",
            "{label}: {diagnostic}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn remote_script_definitions_fail_sanitized_startup_before_mcp() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-binding-script-config.toml");
    std::fs::write(
        directory.path().join("replacement.conf"),
        "Host *\n  ProxyCommand false\n",
    )?;
    let config = indoc::indoc! {r#"
        capabilities = { named = true }
        [selection]
        allow = ["observe_script"]
        [ssh]
        config_file = "replacement.conf"
        [targets.base]
        ssh_host = "private-binding-script-host.invalid"
        [tools.observe_script]
        description = "Retired remote script."
        revision = "script-1"
        targets = ["base"]
        authority = "ordinary"
        effects = ["read"]
        execution = { kind = "remote_script", source = { path = "/private/binding-script-source", content_sha256 = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF", max_bytes = 4096 }, interpreter = { program = "/private/binding-script-interpreter", argv = ["-s", "--"] }, argv = [{ input = "value" }] }
        input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 64 } } }
        result = { kind = "command" }
    "#};
    std::fs::write(&path, config)?;
    let output = timeout(
        Duration::from_secs(5),
        command(&["--config", path.to_str().context("config path")?]).output(),
    )
    .await??;
    ensure!(!output.status.success(), "accepted retired remote_script");
    ensure!(output.stdout.is_empty());
    let stderr = std::str::from_utf8(&output.stderr)?;
    for secret in [
        path.to_str().context("config path")?,
        "/private/binding-script-source",
        "/private/binding-script-interpreter",
        "0123456789abcdef0123456789ABCDEF",
    ] {
        ensure!(!stderr.contains(secret));
    }
    let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
    ensure!(diagnostic["code"] == "invalid_config");
    Ok(())
}
