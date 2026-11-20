//! Discovery, metadata, published schemas, configuration and guidance resources. No SSH.
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

#[tokio::test]
async fn configured_discovery_preserves_authority_boundaries() -> Result<()> {
    for override_limits in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator-private-marker.toml");
        let replacement = directory.path().join("ssh-private-marker.conf");
        let probe = directory.path().join("discovery-must-not-probe");
        let credential = directory.path().join("credential-private-marker");
        std::fs::write(
            &replacement,
            format!(
                "Host *\n  IdentityFile '{}'\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                credential.display(),
                probe.display()
            ),
        )?;
        std::fs::write(
            &path,
            indoc::indoc! {"
            capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
            [ssh]
            config_file = 'ssh-private-marker.conf'
            [limits]
            connect_timeout_secs = 7
            operation_timeout_secs = 9
            max_timeout_secs = 20
            max_output_bytes = 1234
            max_file_bytes = 2345
            [targets.zeta]
            ssh_host = 'ordinary-zeta-private.invalid'
            [targets.zeta.sudo]
            mode = 'separate-identity'
            ssh_host = 'privileged-zeta-private.invalid'
            [targets.gamma]
            ssh_host = 'ordinary-gamma-private.invalid'
            [targets.gamma.sudo]
            mode = 'separate-identity'
            ssh_host = 'privileged-gamma-private.invalid'
            programs = ['/private/program-marker']
            [targets.epsilon]
            ssh_host = 'ordinary-epsilon-private.invalid'
            [targets.epsilon.sudo]
            mode = 'same-account'
            [targets.delta]
            ssh_host = 'ordinary-delta-private.invalid'
            [targets.delta.sudo]
            mode = 'separate-identity'
            ssh_host = 'privileged-delta-private.invalid'
            programs = []
            [targets.beta]
            ssh_host = 'ordinary-beta-private.invalid'
            description = ''
            [targets.beta.sudo]
            mode = 'same-account'
            programs = []
            [targets.alpha]
            ssh_host = 'ordinary-alpha-private.invalid'
            description = 'Operator-authored café: advisory, not observed'
            [targets.alpha.labels]
            environment = 'synthetic-production'
            ssh_sudo = 'allowed'
        "},
        )?;
        let mut child = command(&["--config", path.to_str().context("config path")?]);
        if override_limits {
            child.envs([
                ("ESTUS_CONNECT_TIMEOUT_SECS", "11"),
                ("ESTUS_OPERATION_TIMEOUT_SECS", "13"),
                ("ESTUS_MAX_TIMEOUT_SECS", "17"),
                ("ESTUS_MAX_OUTPUT_BYTES", "33554432"),
                ("ESTUS_MAX_FILE_BYTES", "33554433"),
            ]);
        }
        let mut server = Server::from_command(child)?;
        let scenario = async {
            if !override_limits {
                server.initialize().await?;
            }
            let id = 2;
            let modern = override_limits;
            let params = json!({"name":"observe_targets","arguments":{}});
            let request = if modern {
                modern_request(json!(id), "tools/call", params, MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
            };
            server.send(request).await?;
            let response = server.response(id).await?;
            let data = discovery_data(&response["result"], "configured")?;
            let rows = data["targets"].as_array().context("configured targets")?;
            ensure!(rows.len() == 6);
            for (index, (name, sudo_mode, permits_sudo)) in [
                ("alpha", "disabled", false),
                ("beta", "same-account", false),
                ("delta", "separate-identity", false),
                ("epsilon", "same-account", true),
                ("gamma", "separate-identity", true),
                ("zeta", "separate-identity", true),
            ]
            .into_iter()
            .enumerate()
            {
                let row = &rows[index];
                ensure!(row["name"] == name && row["sudo_mode"] == sudo_mode);
                ensure!(row["observed_capabilities"] == "unknown");
                let expected = if permits_sudo {
                    json!([
                        "change_directory_remove",
                        "change_file_remove",
                        "change_file_replace",
                        "change_file_write",
                        "change_mkdir",
                        "change_rename",
                        "exec_argv",
                        "exec_command",
                        "exec_sudo",
                        "inspect_directory",
                        "inspect_file",
                        "observe_stat"
                    ])
                } else {
                    json!([
                        "change_directory_remove",
                        "change_file_remove",
                        "change_file_replace",
                        "change_file_write",
                        "change_mkdir",
                        "change_rename",
                        "exec_argv",
                        "exec_command",
                        "inspect_directory",
                        "inspect_file",
                        "observe_stat"
                    ])
                };
                ensure!(row["permitted_operations"] == expected, "policy for {name}");
                if index > 1 {
                    ensure!(row.get("description") == Some(&Value::Null));
                }
                if index > 0 {
                    ensure!(row["labels"] == json!({}));
                }
            }
            ensure!(rows[0]["description"] == "Operator-authored café: advisory, not observed");
            ensure!(
                rows[0]["labels"]
                    == json!({
                        "environment":"synthetic-production", "ssh_sudo":"allowed"
                    })
            );
            ensure!(rows[1]["description"] == "");
            let limits = &data["limits"];
            let expected = if override_limits {
                [11, 13, 17, 33_554_432, 33_554_433]
            } else {
                [7, 9, 20, 1234, 2345]
            };
            for (field, expected) in [
                "connect_timeout_secs",
                "operation_timeout_secs",
                "max_timeout_secs",
                "max_output_bytes",
                "max_file_bytes",
            ]
            .into_iter()
            .zip(expected)
            {
                ensure!(limits[field] == expected, "effective {field}");
            }
            let encoded = serde_json::to_string(&response)?;
            for secret in [
                "ordinary-",
                "privileged-",
                "private-marker",
                "/private/program-marker",
                path.to_str().context("operator path")?,
                replacement.to_str().context("replacement path")?,
                credential.to_str().context("credential path")?,
            ] {
                ensure!(
                    !encoded.contains(secret),
                    "discovery exposed private configuration"
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
        ensure!(
            !probe.exists(),
            "discovery executed replacement-config Match exec"
        );
        let audit = std::str::from_utf8(&stderr)?;
        for secret in [
            "ordinary-",
            "privileged-",
            "private-marker",
            "/private/program-marker",
        ] {
            ensure!(
                !audit.contains(secret),
                "audit exposed private configuration"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn discovery_metadata_schema_and_bounds_fail_before_mcp_without_secrets() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("secret_marker.toml");
    let mut cases = vec![
        (
            "description type",
            "description = ['secret_marker']".to_owned(),
        ),
        ("labels table", "labels = ['secret_marker']".to_owned()),
        (
            "label value type",
            "labels = { secret_marker = 42 }".to_owned(),
        ),
        (
            "empty label key",
            "labels = { '' = 'secret_marker' }".to_owned(),
        ),
        (
            "description bytes",
            format!("description = '{}x'", "é".repeat(512)),
        ),
        (
            "label key bytes",
            format!("labels = {{ '{}x' = 'secret_marker' }}", "é".repeat(32)),
        ),
        (
            "label value bytes",
            format!("labels = {{ secret_marker = '{}x' }}", "é".repeat(128)),
        ),
    ];
    let labels = (0..17)
        .map(|index| format!("secret_marker_{index} = 'private-value'"))
        .collect::<Vec<_>>()
        .join(", ");
    cases.push(("label count", format!("labels = {{ {labels} }}")));
    for (case, metadata) in cases {
        std::fs::write(
            &path,
            format!("[targets.secret_marker]\nssh_host = 'secret_marker.invalid'\n{metadata}\n"),
        )?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(
            !output.status.success(),
            "{case}: accepted invalid metadata"
        );
        ensure!(
            output.stdout.is_empty(),
            "{case}: started MCP before rejecting metadata"
        );
        let stderr = std::str::from_utf8(&output.stderr)?;
        for secret in [
            "secret_marker",
            "private-value",
            "é",
            path.to_str().context("config path")?,
        ] {
            ensure!(!stderr.contains(secret), "{case}: reflected operator input");
        }
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_config",
            "{case}: wrong startup diagnostic"
        );
    }
    Ok(())
}

#[tokio::test]
async fn discovery_metadata_exact_caps_respect_aggregate_and_response_wire_bounds() -> Result<()> {
    // Ten full 6144-byte targets, plus one 4096-byte target, total 65536.
    // All lengths are UTF-8 bytes, not character counts.
    let description = "é".repeat(512);
    let value = "é".repeat(128);
    let tail_value = "v".repeat(128);
    let mut text = String::new();
    for target in 0..11 {
        text.push_str(&format!(
            "[targets.target{target:02}]\nssh_host = 'private-boundary-{target}.invalid'\ndescription = '{description}'\n[targets.target{target:02}.labels]\n"
        ));
        for label in 0..if target == 10 { 10 } else { 16 } {
            let key = format!("{label:02}{}", "é".repeat(31));
            let label_value = if target == 10 && label == 9 {
                &tail_value
            } else {
                &value
            };
            text.push_str(&format!("'{key}' = '{label_value}'\n"));
        }
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(&path, &text)?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let response = server.response(2).await?;
        let data = discovery_data(&response["result"], "configured")?;
        let rows = data["targets"].as_array().context("boundary targets")?;
        ensure!(rows.len() == 11);
        ensure!(rows[0]["description"] == description);
        let labels = rows[0]["labels"].as_object().context("boundary labels")?;
        ensure!(labels.len() == 16);
        ensure!(labels.keys().all(|key| key.len() == 64));
        ensure!(
            labels
                .values()
                .all(|entry| entry.as_str() == Some(value.as_str()))
        );
        ensure!(!serde_json::to_string(&response)?.contains("private-boundary-"));
        // The same real metadata fits a normal response but not one carrying
        // this ID. The SDK must return a complete bounded error, then recover.
        const MESSAGE_LIMIT: usize = 16_777_216;
        let id = json!("i".repeat(MESSAGE_LIMIT - 65_536));
        let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}});
        ensure!(serde_json::to_vec(&request)?.len() + 1 < MESSAGE_LIMIT);
        server.send(request).await?;
        let (rejected, bytes) = server.response_with_id(&id).await?;
        ensure!(rejected["error"]["code"] == -32602);
        ensure!(rejected.get("result").is_none());
        ensure!(bytes <= MESSAGE_LIMIT);
        drop(rejected);
        drop(id);
        server
            .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let healthy = server.response(4).await?;
        ensure!(
            discovery_data(&healthy["result"], "configured")? == data,
            "request-ID wire pressure changed resolved discovery policy"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    // One additional byte, still below every per-target/per-label cap.
    text.push_str("'x' = ''\n");
    std::fs::write(&path, text)?;
    let output = timeout(
        Duration::from_secs(5),
        command(&["--config", path.to_str().context("config path")?]).output(),
    )
    .await??;
    ensure!(
        !output.status.success(),
        "accepted aggregate metadata overflow"
    );
    ensure!(output.stdout.is_empty());
    let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
    ensure!(diagnostic["code"] == "invalid_config");
    let stderr = std::str::from_utf8(&output.stderr)?;
    for secret in [
        "target00",
        "private-boundary-",
        "é",
        path.to_str().context("config path")?,
    ] {
        ensure!(
            !stderr.contains(secret),
            "aggregate error reflected operator input"
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_configuration_fails_before_mcp_without_echoing_secrets() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator-secret_marker.toml");
    for (text, code, location) in [
        (
            "[ssh]\nsecret_marker='secret_marker'",
            "invalid_config",
            None,
        ),
        (
            "[limits]\noperation_timeout_secs='secret_marker'",
            "invalid_config",
            None,
        ),
        (
            "[targets.secret_marker]\nssh_host='ordinary'\n[targets.secret_marker.sudo]\nmode='secret_marker'",
            "invalid_config",
            None,
        ),
        (
            "[ssh]\n# secret_marker\nmax_idle_secs = @",
            "invalid_toml",
            Some((3, 17)),
        ),
        ("# secret_marker\n\"雪\" = @", "invalid_toml", Some((2, 7))),
    ] {
        std::fs::write(&path, text)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(output.status.code() == Some(1) && output.stdout.is_empty());
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("secret_marker"));
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(diagnostic["code"] == code, "{diagnostic}");
        if let Some((line, column)) = location {
            ensure!(
                diagnostic["phase"] == "config_parse"
                    && diagnostic["schema_path"] == "config"
                    && diagnostic["location"] == json!({"line":line,"column":column}),
                "syntax location was lost: {diagnostic}"
            );
        } else {
            // Unknown keys are reported by serde at the file root; the fixed
            // code/phase and the guarantee that no key or value is echoed stay.
            ensure!(
                diagnostic["schema_path"] == "config",
                "unknown key lost its fixed schema path: {diagnostic}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn cli_parse_errors_are_private_and_help_hides_environment_values() -> Result<()> {
    for args in [
        vec!["--secret_marker"],
        vec![
            "doctor",
            "--runtime",
            "ansible",
            "--timeout-secs",
            "secret_marker",
        ],
        vec!["catalog", "export", "--tool", "secret_marker"],
    ] {
        let output = command(&args).output().await?;
        ensure!(output.status.code() == Some(2) && output.stdout.is_empty());
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("secret_marker"));
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_cli_arguments"
                && diagnostic["phase"] == "cli_parse"
                && diagnostic["schema_path"] == "cli"
        );
    }
    let output = command(&["--help"])
        .env("ESTUS_CONFIG", "/secret_marker/config")
        .env("ESTUS_SSH", "/secret_marker/ssh")
        .env("ESTUS_SSH_CONFIG", "/secret_marker/ssh-config")
        .output()
        .await?;
    ensure!(output.status.success() && output.stderr.is_empty());
    let help = std::str::from_utf8(&output.stdout)?;
    ensure!(help.contains("--config") && !help.contains("secret_marker"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_builtin_schemas_match_resolved_limits_and_pre_ssh_validation() -> Result<()> {
    for configured_limits in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator-private-schema.toml");
        let probe = directory.path().join("must-not-probe-schema");
        std::fs::write(
            directory.path().join("replacement.conf"),
            format!(
                "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                probe.display()
            ),
        )?;
        let limits = if configured_limits {
            "[limits]\nconnect_timeout_secs=1\noperation_timeout_secs=2\nmax_timeout_secs=3\nmax_file_bytes=8\n"
        } else {
            ""
        };
        std::fs::write(
            &path,
            format!(
                "capabilities = {{ named = true, file_read = true, file_write = true, exec = true, sudo = true }}\n[ssh]\nconfig_file='replacement.conf'\n{limits}\
                 [targets.allowed]\nssh_host='private-schema-backend.invalid'\n\
                 [targets.allowed.sudo]\nmode='same-account'\nprograms=['/SCHEMA_INPUT_SECRET']\n"
            ),
        )?;
        let max_timeout = if configured_limits { 3 } else { 600 };
        let max_file_bytes = if configured_limits { 8 } else { 1_048_576 };
        let handle = "0123456789abcdef0123456789abcdef";
        let hash = "A".repeat(64);
        let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("published builtin schemas")?;
            let mut names: Vec<_> = tools.iter()
                .map(|tool| tool["name"].as_str().context("builtin name"))
                .collect::<Result<_>>()?;
            names.sort_unstable();
            ensure!(names == [
                "change_directory_remove", "change_file_remove", "change_file_replace",
                "change_file_write", "change_mkdir", "change_rename",
                "change_target_quarantine_clear", "exec_argv", "exec_command", "exec_sudo",
                "inspect_directory", "inspect_file", "inspect_output", "observe_stat",
                "observe_targets",
            ]);
            for tool in tools {
                ensure!(tool["_meta"]["risk_tier"].is_string(), "missing risk_tier on {}", tool["name"]);
            }
            let mut id = 10;
            for tool in tools {
                let name = tool["name"].as_str().context("builtin name")?;
                // Compile the actual consumer-visible schema, including its local
                // references. Cargo disables both HTTP and file retrieval.
                let validator = jsonschema::validator_for(&tool["inputSchema"])
                    .with_context(|| format!("invalid published inputSchema for {name}"))?;
                if name == "observe_targets" {
                    ensure!(validator.is_valid(&json!({})));
                    ensure!(!validator.is_valid(&json!({"extra":true})));
                    continue;
                }
                if name == "change_target_quarantine_clear" {
                    ensure!(validator.is_valid(&json!({"host":"unconfigured","acknowledge_remote_state_reconciled":true})));
                    ensure!(!validator.is_valid(&json!({"host":"unconfigured","acknowledge_remote_state_reconciled":false})));
                    ensure!(!validator.is_valid(&json!({"host":"unconfigured"})));
                    continue;
                }
                let mut base = if name == "inspect_output" {
                    json!({"handle":handle,"stream":"stdout","max_bytes":1})
                } else {
                    profile_call_arguments(name, "unconfigured")
                };
                for field in ["path", "source", "destination"] {
                    if base.get(field).is_some() {
                        base[field] = json!(format!("/private/SCHEMA_INPUT_SECRET/{field}"));
                    }
                }
                if base.get("content").is_some() {
                    base["content"] = json!("");
                }
                if base.get("argv").is_some() {
                    base["argv"] = json!(["/SCHEMA_INPUT_SECRET", ""]);
                }
                if name == "exec_command" {
                    base["command"] = json!("SCHEMA_INPUT_SECRET");
                }
                let expected = if name == "inspect_output" { "not_found" } else { "policy_denied" };
                let mut cases = vec![(base.clone(), true, expected)];
                if name != "inspect_output" {
                    for (seconds, valid) in [
                        (0, false), (1, true), (max_timeout, true), (max_timeout + 1, false),
                    ] {
                        let mut arguments = base.clone();
                        arguments["timeout_secs"] = json!(seconds);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                    // A value accepted under defaults must not bypass a smaller
                    // resolved operator limit in the published schema.
                    let mut arguments = base.clone();
                    arguments["timeout_secs"] = json!(4);
                    cases.push((arguments, !configured_limits, if configured_limits { "invalid_argument" } else { expected }));
                }
                for field in ["path", "source", "destination"] {
                    if base.get(field).is_some() {
                        for invalid in ["", "SCHEMA_INPUT_SECRET\0path"] {
                            let mut arguments = base.clone();
                            arguments[field] = json!(invalid);
                            cases.push((arguments, false, "invalid_argument"));
                        }
                    }
                }
                if matches!(name, "exec_argv" | "exec_sudo") {
                    for invalid in [json!([]), json!([""]), json!(["/SCHEMA_INPUT_SECRET", "bad\0argument"])] {
                        let mut arguments = base.clone();
                        arguments["argv"] = invalid;
                        cases.push((arguments, false, "invalid_argument"));
                    }
                }
                if name == "inspect_directory" {
                    ensure!(tool["annotations"]["readOnlyHint"] == true);
                    ensure!(tool["annotations"]["idempotentHint"] == true);
                    for (entries, valid) in [(0, false), (1, true), (1000, true), (1001, false)] {
                        let mut arguments = base.clone();
                        arguments["max_entries"] = json!(entries);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                }
                if matches!(name, "inspect_file" | "inspect_output") {
                    for (bytes, valid) in [
                        (0, false), (1, true), (max_file_bytes, true), (max_file_bytes + 1, false),
                        (9, !configured_limits),
                    ] {
                        let mut arguments = base.clone();
                        arguments["max_bytes"] = json!(bytes);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                    let mut arguments = base.clone();
                    arguments["offset"] = json!(u64::MAX);
                    cases.push((arguments, true, expected));
                }
                if name == "inspect_file" {
                    for (digest, valid) in [
                        (hash.clone(), true), (String::new(), false),
                        ("a".repeat(63), false), ("a".repeat(65), false), ("g".repeat(64), false),
                    ] {
                        let mut arguments = base.clone();
                        arguments["expected_content_sha256"] = json!(digest);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                }
                if name == "inspect_output" {
                    for invalid in ["".to_owned(), "a".repeat(31), "a".repeat(33), "F".repeat(32), "g".repeat(32)] {
                        let mut arguments = base.clone();
                        arguments["handle"] = json!(invalid);
                        cases.push((arguments, false, "invalid_argument"));
                    }
                }
                if name == "change_file_replace" {
                    let mut arguments = base.clone();
                    arguments["overwrite"] = json!(false);
                    cases.push((arguments, false, "invalid_argument"));
                    let mut arguments = base.clone();
                    arguments.as_object_mut().context("replace arguments")?.remove("overwrite");
                    cases.push((arguments, false, "invalid_params"));
                }
                if name == "change_rename" {
                    let mut arguments = base.clone();
                    arguments.as_object_mut().context("rename arguments")?.remove("overwrite");
                    cases.push((arguments, false, "invalid_params"));
                }
                if configured_limits && matches!(name, "exec_argv" | "change_file_write" | "change_file_replace") {
                    let mut arguments = base.clone();
                    let field = if name == "exec_argv" { "stdin" } else { "content" };
                    // JSON Schema string lengths count characters, not UTF-8
                    // bytes. Runtime byte budgets remain authoritative.
                    arguments[field] = json!("λ".repeat(5));
                    cases.push((arguments, true, "invalid_argument"));
                }
                for (index, (mut arguments, schema_valid, code)) in cases.into_iter().enumerate() {
                    // Let invalid inputs reach their validator: an unconfigured
                    // host must not mask a missing limit check with policy denial.
                    if name != "inspect_output" && matches!(code, "invalid_argument" | "invalid_params") {
                        arguments["host"] = json!("allowed");
                    }
                    ensure!(
                        validator.is_valid(&arguments) == schema_valid,
                        "{name} case {index}: published schema acceptance differs (configured limits: {configured_limits})"
                    );
                    // Dispatch is tested independently, even for schema-invalid
                    // requests: publishing a schema does not enforce it.
                    server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                        "params":{"name":name,"arguments":arguments}})).await?;
                    let response = server.response(id).await?;
                    if code == "invalid_params" {
                        ensure!(response["error"]["code"] == -32602, "{name} case {index}: {response}");
                        ensure!(response.get("result").is_none());
                    } else {
                        ensure!(response.get("error").is_none(), "{name} case {index}: {response}");
                        ensure!(response["result"]["isError"] == true, "{name} case {index}: {response}");
                        let structured = &response["result"]["structuredContent"];
                        ensure!(structured["data"].is_null());
                        ensure!(structured["error"]["code"] == code, "{name} case {index}: {response}");
                        ensure!(structured["error"]["remote_state_unknown"] == false);
                        let text: Value = serde_json::from_str(
                            response["result"]["content"][0]["text"].as_str().context("schema acceptance error text")?
                        )?;
                        ensure!(text == *structured);
                    }
                    let encoded = serde_json::to_string(&response)?;
                    for private in ["SCHEMA_INPUT_SECRET", "private-schema-backend", handle, hash.as_str()] {
                        ensure!(!encoded.contains(private), "{name} case {index}: private error data");
                    }
                    ensure!(!probe.exists(), "{name} case {index}: schema acceptance probed SSH");
                    id += 1;
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        for line in stderr.split_inclusive(|&byte| byte == b'\n') {
            let record: Value = serde_json::from_slice(line)?;
            ensure!(
                record["event"] != "master_start",
                "schema acceptance launched SSH"
            );
            if record["tool"] == "inspect_output" {
                ensure!(matches!(record["event"].as_str(), Some("start" | "finish")));
            } else {
                ensure!(
                    record["event"] == "reject",
                    "schema acceptance passed pre-dispatch rejection: {record}"
                );
            }
        }
        let audit = std::str::from_utf8(&stderr)?;
        for private in [
            "SCHEMA_INPUT_SECRET",
            "private-schema-backend",
            handle,
            hash.as_str(),
            directory
                .path()
                .to_str()
                .context("private schema directory")?,
        ] {
            ensure!(
                !audit.contains(private),
                "schema acceptance leaked private diagnostics"
            );
        }
        ensure!(!probe.exists());
    }
    Ok(())
}

#[tokio::test]
async fn directory_listing_schema_is_consumer_visible() -> Result<()> {
    let (mut server, directory) =
        server_with_config("capabilities = { file_read = true }\n[targets]\n")?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        let response = server.response(2).await?;
        let data = discovery_data(&response["result"], "configured")?;
        ensure!(data["limits"]["max_directory_page_bytes"] == 1_048_576);
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})).await?;
        let response = server.response(3).await?;
        let tool = response["result"]["tools"].as_array().context("tools")?
            .iter().find(|tool| tool["name"] == "inspect_directory").context("listing route")?;
        ensure!(tool["annotations"]["readOnlyHint"] == true);
        ensure!(tool["annotations"]["idempotentHint"] == true);
        let input = jsonschema::validator_for(&tool["inputSchema"])?;
        ensure!(input.is_valid(&json!({"host":"allowed","path":"/literal"})));
        ensure!(!input.is_valid(&json!({"host":"allowed","path":"/literal","continuation":"PRIVATE_BAD_TOKEN"})));
        let output = jsonschema::validator_for(&tool["outputSchema"])?;
        for data in [
            json!({"entries":[],"truncated":false}),
            json!({"entries":[],"truncated":true}),
        ] {
            ensure!(output.is_valid(&json!({"data":data,"error":null})), "published schema rejects directory response metadata");
        }
        ensure!(!output.is_valid(&json!({"data":{"entries":[],"truncated":true,"continuation":"0123456789abcdef0123456789abcdef"},"error":null})), "published schema still accepts continuation");
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    ensure!(!std::str::from_utf8(&stderr)?.contains("PRIVATE_BAD_TOKEN"));
    directory.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guidance_prompts_resources_and_sudo_redaction_work_without_ssh() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("operator.toml");
    let base_toml = r#"
mode = "headless"
capabilities = { named = true, file_read = true, sudo = true }
[ssh]
config_file = "replacement.conf"
[targets.prod-web]
ssh_host = "private-ssh-target.invalid"
description = "Production web node"
max_tier = "inspect"
require_preview = true
[targets.prod-web.sudo]
mode = "same-account"
users = ["PRIVATE_SUDO_USER"]
programs = ["/usr/local/bin/PRIVATE_SUDO_PROG"]
"#;
    std::fs::write(directory.path().join("replacement.conf"), "")?;
    std::fs::write(&config_path, base_toml)?;
    let mut server = Server::start(&["--config", config_path.to_str().context("config")?])?;
    let scenario = async {
        server.initialize().await?;

        server.send(json!({"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}})).await?;
        let prompts = server.response(2).await?;
        let prompt_names: Vec<_> = prompts["result"]["prompts"]
            .as_array()
            .context("prompts")?
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        ensure!(prompt_names == ["triage_host", "diagnose_service", "safe_change", "network_triage"]);

        server.send(json!({
            "jsonrpc":"2.0","id":3,"method":"prompts/get",
            "params":{"name":"diagnose_service","arguments":{"host":"prod-web","unit":"nginx.service"}}
        })).await?;
        let prompt = server.response(3).await?;
        let text = prompt["result"]["messages"][0]["content"]["text"]
            .as_str()
            .context("prompt text")?;
        ensure!(text.contains("prod-web") && text.contains("nginx.service"));
        ensure!(text.contains("\"max_tier\": \"inspect\"") && text.contains("\"require_preview\": true"));
        ensure!(!text.contains("observe_systemd_unit`") && !text.contains("inspect_journal`"));
        ensure!(text.contains("`observe_stat`") && text.contains("`inspect_file`"));
        ensure!(!text.contains("private-ssh-target.invalid"));
        ensure!(!text.contains("PRIVATE_SUDO_USER") && !text.contains("PRIVATE_SUDO_PROG"));
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"resources/list","params":{}})).await?;
        let resources = server.response(4).await?;
        let uris: Vec<_> = resources["result"]["resources"]
            .as_array()
            .context("resources")?
            .iter()
            .filter_map(|r| r["uri"].as_str())
            .collect();
        for expected in [
            "estus://guides/systemd",
            "estus://guides/linux-memory",
            "estus://guides/networking",
            "estus://guides/uncertainty-reconciliation",
            "estus://targets/prod-web/policy",
        ] {
            ensure!(uris.contains(&expected), "missing resource {expected}");
        }

        server.send(json!({"jsonrpc":"2.0","id":5,"method":"resources/templates/list","params":{}})).await?;
        let templates = server.response(5).await?;
        ensure!(templates["result"]["resourceTemplates"][0]["uriTemplate"] == "estus://targets/{host}/policy");

        server.send(json!({"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"estus://targets/prod-web/policy"}})).await?;
        let policy_res = server.response(6).await?;
        let policy_text = policy_res["result"]["contents"][0]["text"]
            .as_str()
            .context("policy resource text")?;
        let policy: Value = serde_json::from_str(policy_text)?;
        ensure!(policy["sudo_policy"] == "redacted");
        ensure!(policy.get("sudo_users").is_none() && policy.get("sudo_programs").is_none());
        ensure!(!policy_text.contains("private-ssh-target.invalid"));
        ensure!(!policy_text.contains("PRIVATE_SUDO_USER"));

        server.send(json!({"jsonrpc":"2.0","id":8,"method":"resources/read","params":{"uri":"estus://targets/unknown-host/policy"}})).await?;
        ensure!(server.response(8).await?["error"]["code"] == -32002);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, _) = finished?;
    ensure!(status.success());

    // When disclose_sudo_policy = true, sudo allowlist is published while ssh_host remains private.
    std::fs::write(
        &config_path,
        format!("disclose_sudo_policy = true\n{base_toml}"),
    )?;
    let mut disclosed_server =
        Server::start(&["--config", config_path.to_str().context("config")?])?;
    let disclosed_res = async {
        disclosed_server.initialize().await?;
        disclosed_server.send(json!({"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"estus://targets/prod-web/policy"}})).await?;
        let reply = disclosed_server.response(2).await?;
        let policy: Value = serde_json::from_str(reply["result"]["contents"][0]["text"].as_str().unwrap())?;
        ensure!(policy["sudo_policy"] == "disclosed");
        ensure!(policy["sudo_users"] == json!(["PRIVATE_SUDO_USER"]));
        ensure!(policy["sudo_programs"] == json!(["/usr/local/bin/PRIVATE_SUDO_PROG"]));
        ensure!(!reply.to_string().contains("private-ssh-target.invalid"));
        Ok::<_, anyhow::Error>(())
    }.await;
    let fin = disclosed_server.finish().await;
    disclosed_res?;
    ensure!(fin?.0.success());
    Ok(())
}
