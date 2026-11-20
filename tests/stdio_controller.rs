//! Hostless controller tools, typed results and sanitized startup. No SSH.
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

fn controller_no_remote_fields(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for field in ["remote_state_unknown", "remote_may_still_be_running"] {
                ensure!(!object.contains_key(field), "controller includes {field}");
            }
            for child in object.values() {
                controller_no_remote_fields(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                controller_no_remote_fields(child)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_tools_publish_hostless_private_contract_and_actual_typed_result() -> Result<()>
{
    for (profile, caps) in [
        (
            "baseline",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
        ),
        ("actions-only", "capabilities = { named = true }"),
    ] {
        let fixture = ControllerProtocolFixture::new()?;
        let config = fixture
            .config
            .replace("capabilities = { named = true }", caps);
        let mut server = fixture.start(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            fixture.public_only(&serde_json::to_vec(&listed)?)?;
            let tools = listed["result"]["tools"].as_array().context("controller tools")?;
            let tool = tools.iter().find(|tool| tool["name"] == "observe_controller").context("controller route")?;
            ensure!(tool["_meta"] == json!({
                "risk_tier":"observe",
                "revision":"review-controller-1", "authority":"controller", "effects":["read"],
                "executor":"controller_script", "result":"controller_command", "execution_location":"controller",
                "trusted_controller_code": true,
                "restriction_boundary": {
                    "mcp": "request_policy", "os": "service_account",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                }
            }));
            ensure!(tool["annotations"]["readOnlyHint"] == true);
            ensure!(tool["annotations"]["destructiveHint"] == false);
            let input = &tool["inputSchema"];
            ensure!(input["additionalProperties"] == false);
            let properties = input["properties"].as_object().context("controller properties")?;
            ensure!(properties.len() == 5);
            output_control_schema(input)?;
            for field in ["label", "count", "verbose", "timeout_secs", "retain_output"] {
                ensure!(properties.contains_key(field), "missing {field}");
            }
            let required = input["required"].as_array().context("controller required inputs")?;
            ensure!(required.len() == 3);
            for field in ["label", "count", "verbose"] {
                ensure!(required.contains(&json!(field)));
            }
            let output = &tool["outputSchema"];
            ensure!(output["type"] == "object");
            for field in ["data", "error", "stdout", "stderr", "exit_code", "signal", "termination", "owned_group_cleanup"] {
                ensure!(schema_has_property(output, field), "missing controller output {field}");
            }
            for field in ["remote_state_unknown", "remote_may_still_be_running"] {
                ensure!(!schema_has_property(output, field), "remote schema field {field}");
            }
            if profile == "baseline" {
                let native = tools.iter().find(|tool| tool["name"] == "exec_argv").context("native command")?;
                ensure!(native["outputSchema"] != *output);
                ensure!(schema_has_property(&native["outputSchema"], "remote_may_still_be_running"));
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
            let discovered = server.response(3).await?;
            fixture.public_only(&serde_json::to_vec(&discovered)?)?;
            let targets = discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("targets")?;
            ensure!(targets.len() == 1 && targets[0]["name"] == "base");
            ensure!(!targets[0]["permitted_operations"].as_array().context("operations")?.contains(&json!("observe_controller")));
            let marker = fixture.directory.path().join("caller-must-not-execute");
            let arguments = json!({
                "label":format!("CONTROLLER_INPUT_SECRET 雪 '; touch {}; $(false)\n", marker.display()),
                "count":-2, "verbose":true
            });
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"observe_controller","arguments":arguments}})).await?;
            let response = server.response(4).await?;
            ensure!(response["result"]["isError"] != true, "{response}");
            let structured = &response["result"]["structuredContent"];
            controller_no_remote_fields(structured)?;
            ensure!(structured["error"].is_null());
            let data = &structured["data"];
            ensure!(data.get("output").is_none(), "default call retained output");
            ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
            ensure!(data["owned_group_cleanup"] == "signalled_and_reaped");
            let echoed: Value = serde_json::from_str(data["stdout"].as_str().context("controller stdout")?)?;
            ensure!(echoed == arguments, "typed private object changed");
            let text: Value = serde_json::from_str(response["result"]["content"][0]["text"].as_str().context("controller text")?)?;
            ensure!(text == *structured);
            ensure!(!marker.exists(), "caller data executed as shell source");
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        fixture.public_only(&stderr)?;
        no_remote_dispatch(&stderr)?;
        let mut completion = false;
        for line in stderr.split_inclusive(|&byte| byte == b'\n') {
            let record: Value = serde_json::from_slice(line)?;
            if record["tool"] == "observe_controller" {
                controller_no_remote_fields(&record)?;
                ensure!(record["identity_role"] == "controller");
                for field in ["host", "sudo", "user", "program"] {
                    ensure!(
                        record.get(field).is_none_or(Value::is_null),
                        "local attribution {field}"
                    );
                }
                completion |= record["owned_group_cleanup"] == "signalled_and_reaped";
            }
        }
        ensure!(completion, "controller cleanup outcome missing from audit");
        ensure!(
            std::fs::read_dir(&fixture.root)?.next().is_none(),
            "operation workspace leaked"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_inputs_reject_host_and_execution_controls_without_dispatch() -> Result<()> {
    let fixture = ControllerProtocolFixture::new()?;
    let mut server = fixture.start(&fixture.config)?;
    let scenario = async {
        server.initialize().await?;
        let valid = json!({"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":false});
        let mut id = 2;
        for (field, value) in [
            ("host", json!("base")), ("targets", json!([])),
            ("source", json!({"path":"CONTROLLER_INPUT_SECRET"})),
            ("path", json!("CONTROLLER_INPUT_SECRET")), ("content_sha256", json!("CONTROLLER_INPUT_SECRET")),
            ("interpreter", json!({"program":"CONTROLLER_INPUT_SECRET"})),
            ("program", json!("CONTROLLER_INPUT_SECRET")), ("argv", json!(["CONTROLLER_INPUT_SECRET"])),
            ("stdin", json!("CONTROLLER_INPUT_SECRET")), ("environment", json!({"MCP_VALUE":"CONTROLLER_INPUT_SECRET"})),
            ("cwd", json!("CONTROLLER_INPUT_SECRET")), ("workspace_root", json!("CONTROLLER_INPUT_SECRET")),
            ("authority", json!("ordinary")), ("execution", json!({"kind":"native_argv"})),
            ("sudo", json!(true)), ("user", json!("root")), ("role", json!("controller")),
            ("profile", json!("baseline")), ("enabled_tools", json!(["observe_controller"])),
            ("label", json!({"input":"CONTROLLER_INPUT_SECRET"})), ("count", json!("1")),
            ("verbose", json!(1)), ("timeout_secs", json!("1")),
            ("retain_output", json!("CONTROLLER_INPUT_SECRET")),
            ("retain_output", Value::Null),
        ] {
            let mut arguments = valid.clone();
            arguments[field] = value;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_controller","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            ensure!(response["error"]["code"] == -32602, "{field}: {response}");
            fixture.public_only(&serde_json::to_vec(&response)?)?;
            id += 1;
        }
        for field in ["label", "count", "verbose"] {
            let mut arguments = valid.clone();
            arguments.as_object_mut().context("arguments")?.remove(field);
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_controller","arguments":arguments}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602, "missing {field}");
            id += 1;
        }
        for seconds in [0, 3] {
            let mut arguments = valid.clone();
            arguments["timeout_secs"] = json!(seconds);
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_controller","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            ensure!(response["result"]["isError"] == true);
            let structured = &response["result"]["structuredContent"];
            ensure!(structured["error"]["code"] == "invalid_argument");
            controller_no_remote_fields(structured)?;
            fixture.public_only(&serde_json::to_vec(&response)?)?;
            id += 1;
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    fixture.public_only(&stderr)?;
    ensure!(std::fs::read_dir(&fixture.root)?.next().is_none());
    Ok(())
}

#[tokio::test]
async fn controller_enablement_profiles_and_inactive_native_independence() -> Result<()> {
    for (profile, caps, selection) in [
        (
            "actions-only",
            "capabilities = { named = true }",
            Some("allow = []"),
        ),
        (
            "baseline",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
            None,
        ),
        (
            "files-only",
            "capabilities = { file_read = true, file_write = true }",
            Some("allow = [\"observe_controller\"]"),
        ),
        (
            "read-only-files",
            "capabilities = { file_read = true }",
            Some("allow = [\"observe_controller\"]"),
        ),
    ] {
        let fixture = ControllerProtocolFixture::new()?;
        // Availability is deliberately broken only after all real fixtures
        // exist. Inactive declarations must not activate any of them.
        std::fs::remove_file(&fixture.source)?;
        std::fs::remove_file(&fixture.interpreter)?;
        std::fs::remove_dir(&fixture.root)?;
        let mut config = fixture
            .config
            .replace("capabilities = { named = true }", caps)
            .replace("allow = [\"observe_controller\"]", selection.unwrap_or(""));
        if selection.is_none() {
            let root_line = format!(
                "workspace_root = {}\n",
                serde_json::to_string(fixture.root.to_str().context("root path")?)?
            );
            config = config.replace(&root_line, "");
        }
        let mut server = fixture.start(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("inactive tools")?;
            ensure!(!tools.iter().any(|tool| tool["name"] == "observe_controller"));
            ensure!(tools.iter().any(|tool| tool["name"] == "observe_targets"));
            if profile == "baseline" {
                ensure!(tools.iter().any(|tool| tool["name"] == "exec_argv"), "native route depends on inactive controller");
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_controller","arguments":{"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":true}}})).await?;
            ensure!(server.response(3).await?["error"]["code"] == -32602);
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
            let discovered = server.response(4).await?;
            for row in discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("inactive targets")? {
                ensure!(!row["permitted_operations"].as_array().context("operations")?.contains(&json!("observe_controller")));
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success(), "{profile}");
        no_remote_dispatch(&stderr)?;
        fixture.public_only(&stderr)?;
    }
    Ok(())
}

#[tokio::test]
async fn controller_malformed_definitions_fail_sanitized_startup_even_when_inactive() -> Result<()>
{
    let fixture = ControllerProtocolFixture::new()?;
    for (label, from, to) in [
        (
            "wrong result",
            "kind = \"controller_command\"",
            "kind = \"command\"",
        ),
        (
            "wrong authority",
            "authority = \"controller\"",
            "authority = \"ordinary\"",
        ),
        (
            "sudo authority",
            "authority = \"controller\"",
            "authority = { sudo = \"root\" }",
        ),
        (
            "empty targets",
            "authority = \"controller\"",
            "targets = []\nauthority = \"controller\"",
        ),
        (
            "remote targets",
            "authority = \"controller\"",
            "targets = [\"base\"]\nauthority = \"controller\"",
        ),
        (
            "caller argv map",
            "kind = \"controller_script\",",
            "kind = \"controller_script\", argv = [{ input = \"label\" }],",
        ),
        (
            "stdin control",
            "kind = \"controller_script\",",
            "kind = \"controller_script\", stdin = \"CONTROLLER_CONFIG_SECRET\",",
        ),
        (
            "host control",
            "kind = \"controller_script\",",
            "kind = \"controller_script\", host = \"base\",",
        ),
        (
            "unknown source field",
            "max_bytes = 4096",
            "max_bytes = 4096, owner = \"CONTROLLER_CONFIG_SECRET\"",
        ),
        ("zero source bound", "max_bytes = 4096", "max_bytes = 0"),
        (
            "source bound above global",
            "max_bytes = 4096",
            "max_bytes = 8193",
        ),
        ("missing interpreter argv", "argv = []", "ignored = []"),
        ("ambient environment", "MCP_APPLICATION =", "LD_PRELOAD ="),
        ("managed environment", "MCP_APPLICATION =", "HOME ="),
        (
            "invalid environment name",
            "MCP_APPLICATION =",
            "MCP_lowercase =",
        ),
        ("built-in collision", "observe_controller", "exec_argv"),
        (
            "duplicate selection",
            "allow = [\"observe_controller\"]",
            "allow = [\"observe_controller\", \"observe_controller\"]",
        ),
    ] {
        let config = fixture.config.replace(from, to);
        fixture.rejects_startup(label, &config).await?;
        fixture
            .rejects_startup(
                &format!("inactive {label}"),
                &config.replace(
                    "capabilities = { named = true }",
                    "capabilities = { file_read = true, file_write = true }",
                ),
            )
            .await?;
    }
    fixture
        .rejects_startup(
            "bad pin",
            &fixture
                .config
                .replace(&fixture.hash, "CONTROLLER_CONFIG_SECRET"),
        )
        .await?;
    fixture
        .rejects_startup(
            "disabled bad pin",
            &fixture
                .config
                .replace(&fixture.hash, "CONTROLLER_CONFIG_SECRET")
                .replace("allow = [\"observe_controller\"]", "allow = []"),
        )
        .await?;
    let source_path = serde_json::to_string(fixture.source.to_str().context("source path")?)?;
    let interpreter_path =
        serde_json::to_string(fixture.interpreter.to_str().context("interpreter path")?)?;
    for (label, config) in [
        (
            "relative source",
            fixture
                .config
                .replace(&format!("path = {source_path}"), "path = \"relative\""),
        ),
        (
            "relative interpreter",
            fixture.config.replace(
                &format!("program = {interpreter_path}"),
                "program = \"relative\"",
            ),
        ),
        (
            "reserved domain host",
            fixture
                .config
                .replace("\"label\"", "\"host\"")
                .replace("label = {", "host = {"),
        ),
        (
            "missing controller authority",
            fixture.config.replace("authority = \"controller\"\n", ""),
        ),
        (
            "missing result",
            fixture
                .config
                .replace("result = { kind = \"controller_command\" }\n", ""),
        ),
    ] {
        fixture.rejects_startup(label, &config).await?;
        fixture
            .rejects_startup(
                &format!("disabled {label}"),
                &config.replace("allow = [\"observe_controller\"]", "allow = []"),
            )
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn active_controller_requires_secure_explicit_root_source_and_interpreter() -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;

    let fixture = ControllerProtocolFixture::new()?;
    let root_line = format!(
        "workspace_root = {}\n",
        serde_json::to_string(fixture.root.to_str().context("root path")?)?
    );
    fixture
        .rejects_startup("absent root", &fixture.config.replace(&root_line, ""))
        .await?;
    fixture
        .rejects_startup(
            "relative root",
            &fixture
                .config
                .replace(&root_line, "workspace_root = \"relative\"\n"),
        )
        .await?;
    let missing_cwd = fixture.directory.path().join("unavailable-private-cwd");
    let cwd = serde_json::to_string(missing_cwd.to_str().context("cwd path")?)?;
    fixture
        .rejects_startup(
            "unavailable fixed cwd",
            &fixture.config.replace(
                "kind = \"controller_script\",",
                &format!("kind = \"controller_script\", cwd = {cwd},"),
            ),
        )
        .await?;
    for mode in [0o755, 0o770, 0o777] {
        std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(mode))?;
        fixture
            .rejects_startup("insecure root", &fixture.config)
            .await?;
    }
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))?;
    std::fs::remove_dir(&fixture.root)?;
    fixture
        .rejects_startup("missing root", &fixture.config)
        .await?;
    std::fs::write(&fixture.root, b"not a directory")?;
    fixture
        .rejects_startup("regular-file root", &fixture.config)
        .await?;
    std::fs::remove_file(&fixture.root)?;
    std::fs::create_dir(&fixture.root)?;
    std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))?;
    let source = std::fs::read(&fixture.source)?;
    for (label, bytes) in [
        ("non-UTF8 source", vec![0xff, 0xfe]),
        ("source exceeds reviewed bound", vec![b'x'; 4097]),
    ] {
        std::fs::write(&fixture.source, &bytes)?;
        let pin = hex::encode(Sha256::digest(std::fs::read(&fixture.source)?));
        fixture
            .rejects_startup(label, &fixture.config.replace(&fixture.hash, &pin))
            .await?;
    }
    std::fs::write(&fixture.source, b"CONTROLLER_CONFIG_SECRET")?;
    fixture
        .rejects_startup("source digest mismatch", &fixture.config)
        .await?;
    std::fs::remove_file(&fixture.source)?;
    fixture
        .rejects_startup("missing source", &fixture.config)
        .await?;
    std::fs::create_dir(&fixture.source)?;
    fixture
        .rejects_startup("directory source", &fixture.config)
        .await?;
    std::fs::remove_dir(&fixture.source)?;
    std::fs::write(&fixture.source, source)?;
    std::fs::set_permissions(&fixture.interpreter, std::fs::Permissions::from_mode(0o600))?;
    fixture
        .rejects_startup("non-executable interpreter", &fixture.config)
        .await?;
    std::fs::remove_file(&fixture.interpreter)?;
    fixture
        .rejects_startup("missing interpreter", &fixture.config)
        .await?;
    std::fs::create_dir(&fixture.interpreter)?;
    fixture
        .rejects_startup("directory interpreter", &fixture.config)
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_transport_failure_never_executes_controller_source_as_fallback() -> Result<()> {
    let fixture = ControllerProtocolFixture::new()?;
    let marker = fixture.directory.path().join("remote-must-not-run-locally");
    let marker_quoted = format!("'{}'", marker.to_string_lossy().replace('\'', "'\\''"));
    let script = format!("printf forbidden > {marker_quoted}");
    let interpreter = serde_json::to_string(
        fixture
            .interpreter
            .to_str()
            .context("fixture interpreter UTF-8")?,
    )?;
    let script_json = serde_json::to_string(&script)?;
    let execution = format!(
        "kind = \"native_argv\", program = {interpreter}, argv = [\"-c\", {script_json}, \"--\", {{ input = \"label\" }}, {{ input = \"count\" }}, {{ input = \"verbose\" }}]"
    );
    let config = fixture
        .config
        .replace("allow = [\"observe_controller\"]", "allow = [\"remote_only\"]")
        .replace("[tools.observe_controller]", "[tools.remote_only]")
        .replace(
            "authority = \"controller\"",
            "targets = [\"base\"]\nauthority = \"ordinary\"",
        )
        .replace(
            "capabilities = { file_read = true }",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
        )
        .replace(
            &format!(
                "kind = \"controller_script\", source = {{ path = {}, content_sha256 = \"{}\", max_bytes = 4096 }}, interpreter = {{ program = {interpreter}, argv = [] }}, environment = {{ MCP_APPLICATION = \"CONTROLLER_CONFIG_SECRET\" }}",
                serde_json::to_string(fixture.source.to_str().context("source UTF-8")?)?,
                fixture.hash
            ),
            &execution,
        )
        .replace("kind = \"controller_command\"", "kind = \"command\"");
    let mut server = fixture.start(&config)?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        ensure!(listed["result"]["tools"].as_array().context("remote tools")?.iter().any(|tool| tool["name"] == "remote_only"));
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"remote_only","arguments":{"host":"base","label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":false}}})).await?;
        let response = server.response(3).await?;
        ensure!(response.get("error").is_none(), "remote call rejected before transport: {response}");
        ensure!(response["result"]["isError"] == true, "{response}");
        ensure!(response["result"]["structuredContent"]["error"]["code"] == "ssh_connect_failed", "{response}");
        ensure!(!marker.exists(), "remote failure executed source locally");
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    fixture.public_only(&stderr)?;
    ensure!(!marker.exists());
    ensure!(std::fs::read_dir(&fixture.root)?.next().is_none());
    Ok(())
}
