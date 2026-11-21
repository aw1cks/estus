//! MCP protocol, lifecycle, framing and malformed-input isolation. No SSH.
#[path = "support/stdio.rs"]
#[allow(dead_code)]
// Shared helpers used by other suites are inert here.
mod stdio;
use stdio::*;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn lifecycle_discovery_and_eof_keep_stdout_protocol_only() -> Result<()> {
    let mut server = Server::start(&["--workstation"])?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools list")?;
        let mut names: Vec<&str> = tools.iter()
            .map(|tool| tool["name"].as_str().context("default tool name"))
            .collect::<Result<_>>()?;
        names.sort_unstable();
        for expected_builtin in [
            "change_target_quarantine_clear",
            "exec_command",
            "inspect_directory",
            "change_mkdir",
            "inspect_file",
            "inspect_output",
            "change_directory_remove",
            "change_file_remove",
            "change_rename",
            "change_file_replace",
            "exec_argv",
            "observe_stat",
            "observe_targets",
            "change_file_write",
        ] {
            ensure!(names.contains(&expected_builtin), "missing workstation builtin {expected_builtin}: {names:?}");
        }
        ensure!(!names.contains(&"exec_sudo"), "no-config workstation exposed ssh_sudo");
        let is_builtin = |name: &&str| matches!(
            *name,
            "change_target_quarantine_clear"
                | "exec_command"
                | "inspect_directory"
                | "change_mkdir"
                | "inspect_file"
                | "inspect_output"
                | "change_directory_remove"
                | "change_file_remove"
                | "change_rename"
                | "change_file_replace"
                | "exec_argv"
                | "observe_stat"
                | "observe_targets"
                | "change_file_write"
        );
        // No ESTUS_ANSIBLE_BUNDLE is set, so a catalog template is only a
        // workstation candidate when it declares a reviewed policy; nothing is
        // eligible by name or qualification alone. Open destinations have no
        // per-target grant to authorize a named automation authority, so the
        // console publishes the ordinary-identity subset only.
        let published: std::collections::BTreeSet<String> = names
            .iter()
            .filter(|name| !is_builtin(name))
            .map(|name| (*name).to_string())
            .collect();
        ensure!(!published.is_empty(), "no-config workstation published nothing");
        // Representative ordinary overlays, by explicit name, including ones
        // added for host, storage, package and NIC inventory. They need no
        // elevation, so open mode must publish every one of them.
        for name in [
            "inspect_journal",
            "inspect_processes",
            "observe_cpu",
            "observe_host_summary",
            "observe_hardware_system",
            "observe_kernel_state",
            "observe_memory",
            "observe_network_device",
            "observe_nic_stats",
            "observe_packages",
            "observe_pci",
            "observe_pressure",
            "observe_storage_devices",
            "observe_storage_mounts",
            "observe_systemd_units",
            "observe_time_sync",
        ] {
            ensure!(
                published.contains(name),
                "open workstation mode withheld ordinary tool {name}: {published:?}"
            );
        }
        // Named-authority overlays read through an identity that a target must
        // authorize. Open mode has no such target, so publication must not
        // silently fall back to the ordinary connection: the tool is absent.
        for named in [
            "inspect_hardware_identifiers",
            "inspect_journal_record",
            "inspect_kernel_log",
            "inspect_process",
            "inspect_process_fds",
            "observe_boot_entries",
            "observe_boot_status",
            "observe_hardware_memory",
            "observe_hardware_slots",
            "observe_journal_boots",
            "observe_journal_usage",
        ] {
            ensure!(
                !published.contains(named),
                "open workstation mode exposed named-authority tool {named}: {published:?}"
            );
        }
        // Structurally, nothing policy-required, laboratory-only or
        // non-payload may appear: those have no reviewed open-mode contract.
        let catalog_json_path = stdio::bundled_catalog_json();
        let catalog_dir = catalog_json_path.parent().context("catalog dir")?;
        let catalog_text =
            std::fs::read_to_string(&catalog_json_path).context("read bundled catalog.json")?;
        let catalog: Value = serde_json::from_str(&catalog_text).context("parse catalog.json")?;
        let catalog_tools = catalog["tools"]
            .as_object()
            .context("catalog.json tools object")?;
        let mut expected = std::collections::BTreeSet::new();
        for (name, template) in catalog_tools {
            let Some(workstation) = template.get("workstation") else {
                continue;
            };
            if template["policy_required"] != false
                || template["qualification"] == "laboratory_only"
                || template["executor"]["kind"] != "native_payload"
            {
                continue;
            }
            let effective_authority = match workstation.get("authority").and_then(Value::as_str) {
                Some(authority) => authority.to_owned(),
                None => {
                    let def_name = template["definition"]
                        .as_str()
                        .context("definition filename")?;
                    let def_text = std::fs::read_to_string(catalog_dir.join(def_name))
                        .with_context(|| format!("read {def_name}"))?;
                    let def: toml::Value = toml::from_str(&def_text)?;
                    def["tools"][name]["authority"]
                        .as_str()
                        .unwrap_or("automation")
                        .to_owned()
                }
            };
            if effective_authority == "automation" {
                expected.insert(name.clone());
            }
        }
        ensure!(
            published == expected,
            "open workstation mode published {published:?}, expected exact ordinary-authority set {expected:?}"
        );
        for (name, valid, invalid) in [
            ("inspect_journal", json!({"limit": 500, "until": 4102444800_u64, "priority": 3}), json!({"limit": 501})),
            ("observe_network_device", json!({"interface": "eth0"}), json!({"interface": ""})),
            ("observe_systemd_units", json!({"view": "loaded", "unit_type": "service", "state": "failed", "unit_pattern": "*"}), json!({"view": "loaded", "unit_type": "service", "state": "broken", "unit_pattern": "*"})),
            ("observe_packages", json!({"limit": 100}), json!({"limit": 101})),
            ("observe_nic_stats", json!({"interface": "eth0"}), json!({"interface": ""})),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("workstation tool")?;
            ensure!(tool["_meta"]["authority"] == "automation", "{name} must use the ordinary SSH identity");
            let validator = jsonschema::validator_for(&tool["inputSchema"]).context("workstation input schema")?;
            ensure!(validator.is_valid(&json!({"host": "host", "inputs": valid})), "{name} rejects valid inputs");
            ensure!(!validator.is_valid(&json!({"host": "host", "inputs": invalid})), "{name} accepts invalid inputs");
        }
        for extra in &published {
            let tool = tools.iter().find(|t| t["name"] == *extra).unwrap();
            ensure!(
                tool["inputSchema"]["properties"]["host"]
                    == json!({"type": "string", "minLength": 1, "maxLength": 256}),
                "workstation dynamic tool {extra} had unexpected host schema: {}",
                tool["inputSchema"]["properties"]["host"]
            );
            // Every published catalog overlay is the ordinary-identity subset;
            // a named authority would need a configured target to authorize it.
            ensure!(
                tool["_meta"]["authority"] == "automation",
                "published {extra} must not claim an elevated authority: {}",
                tool["_meta"]["authority"]
            );
        }
        // Privileged catalog templates are never published in open mode: they
        // have no per-target sudo grant to check.
        for denied in [
            "change_sysctl_runtime",
            "change_systemd_unit",
            "observe_filesystem_usage",
            "observe_network",
            "inspect_sockets",
            "change_host_reboot",
            "change_boot_clear_oneshot",
            "change_kernel_module_load",
            "observe_kernel_module",
            "observe_nic_fec",
        ] {
            ensure!(
                !names.contains(&denied),
                "open workstation mode exposed {denied}: {names:?}"
            );
        }
        // The name is absent, not merely refused: a client that forgot the
        // elevation target must not reach a named collector at all.
        server.send(json!({"jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{"name":"inspect_process","arguments":{"host":"DO_NOT_CONNECT.invalid",
                "inputs":{"pid":1,"boot_id":"00000000-0000-0000-0000-000000000000",
                    "start_ticks":0}}}})).await?;
        let withheld = server.response(6).await?;
        ensure!(
            withheld["error"]["code"] == -32602,
            "unpublished inspect_process routed: {withheld}"
        );
        ensure!(withheld.get("result").is_none());
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
        let called = server.response(3).await?;
        let result = &called["result"];
        ensure!(discovery_data(result, "open")?["targets"] == json!([]));
        ensure!(result["isError"] != true);
        let content = result["content"].as_array().context("text compatibility content")?;
        ensure!(content.len() == 1);
        let text: Value = serde_json::from_str(content[0]["text"].as_str().context("text")?)?;
        ensure!(text == result["structuredContent"]);
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"observe_targets","arguments":{"extra":true}}})).await?;
        ensure!(server.response(4).await?["error"]["code"] == -32602);
        server.send(json!({"jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{"name":"exec_sudo","arguments":profile_call_arguments("exec_sudo", "DO_NOT_CONNECT.invalid")}})).await?;
        let denied = server.response(5).await?;
        ensure!(denied["error"]["code"] == -32602, "exec_sudo: {denied}");
        ensure!(denied.get("result").is_none());
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    no_remote_dispatch(&stderr)?;
    ensure!(status.success(), "server exit status: {status}");
    Ok(())
}

#[tokio::test]
async fn no_config_without_opt_in_exposes_no_execution_or_write_tools() -> Result<()> {
    let mut server = Server::start(&[])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools list")?;
        let names: std::collections::BTreeSet<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().context("default tool name"))
            .collect::<Result<_>>()?;
        ensure!(
            names == std::collections::BTreeSet::from([
                "observe_targets",
                "inspect_output",
                "change_target_quarantine_clear",
            ]),
            "headless default published {names:?}"
        );
        for denied in [
            "exec_command",
            "exec_argv",
            "exec_sudo",
            "change_file_write",
            "change_mkdir",
            "change_rename",
            "change_file_remove",
            "change_directory_remove",
            "change_file_replace",
            "inspect_file",
            "observe_stat",
            "inspect_directory",
            "change_sysctl_runtime",
            "observe_cpu",
        ] {
            ensure!(!names.contains(denied), "headless default exposed {denied}");
        }
        server
            .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let called = server.response(3).await?;
        ensure!(discovery_data(&called["result"], "configured")?["targets"] == json!([]));
        server
            .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"exec_command","arguments":profile_call_arguments("exec_command","DO_NOT_CONNECT.invalid")}}))
            .await?;
        let unpublished = server.response(4).await?;
        ensure!(
            unpublished["error"]["code"] == -32602,
            "unpublished exec_command must not route: {unpublished}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    no_remote_dispatch(&stderr)?;
    ensure!(status.success(), "server exit status: {status}");
    Ok(())
}

#[tokio::test]
async fn sigterm_closes_initialized_server() -> Result<()> {
    let mut server = Server::start(&[])?;
    let scenario = async {
        server.initialize().await?;
        server.sigterm().await
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    finished?;
    Ok(())
}

#[tokio::test]
async fn eof_before_initialize_exits_cleanly() -> Result<()> {
    let server = Server::start(&[])?;
    let (status, _) = server.finish().await?;
    ensure!(status.success(), "early EOF failed: {status}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initialization_failure_with_closed_stderr_does_not_panic() -> Result<()> {
    let mut server = Server::start(&[])?;
    let scenario = async {
        // No request has been sent, so the server cannot report a handshake
        // failure until after the pipe's read end has actually been dropped.
        server.close_stderr().await?;
        server
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        // Keep stdin open until the invalid handshake exits; EOF would instead
        // be a successful lifecycle and would not exercise failure reporting.
        let status = timeout(Duration::from_secs(5), server.child.wait())
            .await
            .context("closed stderr stranded initialization failure")??;
        ensure!(
            status.code() == Some(1),
            "expected failure, not panic: {status}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, _) = finished?;
    ensure!(status.code() == Some(1));
    Ok(())
}

fn local_only_server() -> Result<(Server, tempfile::TempDir)> {
    server_with_config("[targets]\n")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_discovery_calls_and_version_rejection_need_no_initialize() -> Result<()> {
    let (mut server, directory) = server_with_config(
        "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[targets]\n",
    )?;
    let scenario = async {
        server.send(modern_request(json!("discover"), "server/discover", json!({}), MODERN_VERSION)).await?;
        let discovered = server.response_with_id(&json!("discover")).await?.0;
        ensure!(discovered["error"].is_null());
        let versions = discovered["result"]["supportedVersions"].as_array().context("supported versions")?;
        ensure!(versions.contains(&json!(MODERN_VERSION)));
        ensure!(versions.contains(&json!("2025-11-25")));
        let capabilities = &discovered["result"]["capabilities"];
        ensure!(capabilities["tools"].is_object());
        ensure!(capabilities["prompts"].is_object());
        ensure!(capabilities["resources"].is_object());
        for unsupported in ["tasks", "logging"] {
            ensure!(capabilities.get(unsupported).is_none());
        }

        // These hit distinct admission paths: bootstrap and an established inline session.
        server.send(modern_request(json!("rejected-bootstrap"), "tools/call", json!({
            "name":"exec_command","arguments":{"host":"must-not-connect.invalid","command":"printf NEVER"}
        }), "2099-01-01")).await?;
        let rejected = server.response_with_id(&json!("rejected-bootstrap")).await?.0;
        ensure!(rejected["error"]["code"] == -32022);
        ensure!(rejected.get("result").is_none());
        ensure!(rejected["error"]["data"]["requested"] == "2099-01-01");

        server.send(modern_request(json!("tools"), "tools/list", json!({}), MODERN_VERSION)).await?;
        let listed = server.response_with_id(&json!("tools")).await?.0;
        let tools = listed["result"]["tools"].as_array().context("modern tool catalog")?;
        for name in ["observe_targets", "exec_command", "exec_argv", "inspect_file", "inspect_output", "observe_stat", "inspect_directory", "change_mkdir", "change_directory_remove", "change_file_remove", "change_rename", "change_file_replace", "change_file_write"] {
            ensure!(tools.iter().any(|tool| tool["name"] == name));
        }
        ensure!(!tools.iter().any(|tool| tool["name"] == "exec_sudo"));
        let run = tools.iter().find(|tool| tool["name"] == "exec_argv")
            .context("run absent from modern discovery")?;
        ensure!(run["annotations"]["readOnlyHint"] == false);
        ensure!(run["annotations"]["destructiveHint"] == true);
        ensure!(run["annotations"]["idempotentHint"] == false);
        let write = tools.iter().find(|tool| tool["name"] == "change_file_write")
            .context("write absent from modern discovery")?;
        ensure!(write["annotations"]["readOnlyHint"] == false);
        ensure!(write["annotations"]["destructiveHint"] == true);

        // Both are outstanding before either response is read; correlate by ID,
        // never assume handler completion order.
        server.send(modern_request(json!("targets"), "tools/call", json!({
            "name":"observe_targets","arguments":{}
        }), MODERN_VERSION)).await?;
        server.send(modern_request(json!(17), "tools/call", json!({
            "name":"observe_targets","arguments":{"extra":true}
        }), MODERN_VERSION)).await?;
        let mut replies = [None, None];
        for _ in 0..2 {
            let frame = server.frame().await?.context("inline session closed")?.0;
            let index = if frame["id"] == "targets" { 0 } else if frame["id"] == 17 { 1 } else {
                bail!("uncorrelated modern response ID");
            };
            ensure!(replies[index].replace(frame).is_none(), "duplicate response ID");
        }
        let [Some(called), Some(invalid)] = replies else { bail!("missing modern response") };
        let result = &called["result"];
        ensure!(result["resultType"] == "complete");
        ensure!(discovery_data(result, "configured")?["targets"] == json!([]));
        ensure!(result["isError"] != true);
        let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().context("text result")?)?;
        ensure!(text == result["structuredContent"]);
        ensure!(invalid["error"]["code"] == -32602);

        server.send(modern_request(json!("rejected-inline"), "tools/call", json!({
            "name":"exec_command","arguments":{"host":"must-not-connect.invalid","command":"printf NEVER"}
        }), "2099-01-01")).await?;
        let rejected = server.response_with_id(&json!("rejected-inline")).await?.0;
        ensure!(rejected["error"]["code"] == -32022 && rejected.get("result").is_none());
        server.send(modern_request(json!("still-usable"), "server/discover", json!({}), MODERN_VERSION)).await?;
        let healthy = server.response_with_id(&json!("still-usable")).await?.0;
        ensure!(healthy["error"].is_null());
        ensure!(healthy["result"]["capabilities"] == *capabilities);
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_closes_a_handshake_free_session_with_stdin_open() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
    let scenario = async {
        server
            .send(modern_request(
                json!(1),
                "tools/call",
                json!({
                    "name":"observe_targets","arguments":{}
                }),
                MODERN_VERSION,
            ))
            .await?;
        let called = server.response(1).await?;
        ensure!(called["result"]["structuredContent"]["data"]["mode"] == "configured");
        server.sigterm().await
    }
    .await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fragmented_utf8_request_survives_multiple_pipe_writes() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
    let scenario = async {
        server.initialize().await?;
        let frame = serde_json::to_vec(&json!({
            "jsonrpc":"2.0","id":"fragmented","method":"tools/call",
            "params":{"name":"observe_targets","arguments":{},"_meta":{
                "h07/a-padding":"x".repeat(131_072),"h07/z-unicode":"🙂"
            }}
        }))?;
        let unicode = frame
            .windows(4)
            .position(|bytes| bytes == "🙂".as_bytes())
            .context("raw UTF-8 test character")?;
        // The large prefix requires the child to read partial input before
        // completing the write; split inside a codepoint, with no delimiter.
        server.send_raw(&frame[..unicode + 1]).await?;
        server.send_raw(&frame[unicode + 1..]).await?;
        server.send_raw(b"\n").await?;
        let called = server.response_with_id(&json!("fragmented")).await?.0;
        ensure!(discovery_data(&called["result"], "configured")?["targets"] == json!([]));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_input_is_isolated_and_following_requests_still_correlate() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
    let scenario = async {
        server.initialize().await?;
        // Syntax errors have no correlatable request; a well-formed but invalid
        // message gets Invalid Request with no ID, as the modern MCP schema permits.
        server.send_raw(b"{\"MALFORMED_PAYLOAD_NO_ECHO\":\n").await?;
        server.send_raw(
            b"{\"jsonrpc\":\"2.0\",\"id\":\"invalid\",\"method\":false,\"params\":{\"marker\":\"MALFORMED_PAYLOAD_NO_ECHO\"}}\n",
        ).await?;
        let rejected = server.frame().await?.context("missing invalid-request reply")?.0;
        ensure!(rejected.get("id").is_none());
        ensure!(rejected["error"]["code"] == -32600 && rejected.get("result").is_none());
        server.send(json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}})).await?;
        let healthy = server.response(7).await?;
        ensure!(healthy["result"]["structuredContent"]["data"]["mode"] == "configured");
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    ensure!(
        !stderr
            .windows(b"MALFORMED_PAYLOAD_NO_ECHO".len())
            .any(|bytes| bytes == b"MALFORMED_PAYLOAD_NO_ECHO")
    );
    no_remote_dispatch(&stderr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_tool_arguments_expose_only_fixed_diagnostics_and_rejection_audit() -> Result<()>
{
    let (mut server, directory) = server_with_config(
        "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[output]\nenabled = true\n[targets.fixture]\nssh_host = 'never-connected.invalid'\n[targets.fixture.sudo]\nmode = 'same-account'\nusers = ['root']\nprograms = ['/usr/bin/true']\n",
    )?;
    let cases = [
        (
            "observe_targets",
            json!({"A12_PRIVATE_UNKNOWN_KEY":"/private/A12_PRIVATE_VALUE"}),
            "arguments",
            "unknown_field",
        ),
        (
            "exec_command",
            json!({"host":"A12_PRIVATE_HOST","command":["A12_PRIVATE_VALUE"]}),
            "arguments.command",
            "invalid_type",
        ),
        (
            "exec_command",
            json!({"host":"A12_PRIVATE_HOST"}),
            "arguments.command",
            "missing_field",
        ),
        (
            "exec_sudo",
            json!({
                "host":"A12_PRIVATE_HOST","user":"A12_PRIVATE_USER",
                "argv":["/private/A12_PRIVATE_PROGRAM",{"A12_PRIVATE_UNKNOWN_KEY":"A12_PRIVATE_VALUE"}]
            }),
            "arguments.argv.1",
            "invalid_type",
        ),
        (
            "inspect_output",
            json!({
                "handle":"0123456789abcdef0123456789abcdef","stream":"A12_PRIVATE_STREAM"
            }),
            "arguments.stream",
            "invalid_enum",
        ),
        (
            "inspect_output",
            json!({
                "handle":"0123456789abcdef0123456789abcdef","stream":"stdout","offset":-1
            }),
            "arguments.offset",
            "below_minimum",
        ),
        (
            "exec_command",
            json!({
                "host":"A12_PRIVATE_HOST","command":"true","timeout_secs":-1
            }),
            "arguments.timeout_secs",
            "below_minimum",
        ),
    ];
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({
                "jsonrpc":"2.0","id":2,"method":"tools/list","params":{}
            }))
            .await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"]
            .as_array()
            .context("published tools")?;
        for (index, (name, arguments, expected_path, expected_constraint)) in
            cases.iter().enumerate()
        {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == *name)
                .with_context(|| format!("published tool {name}"))?;
            let validator = jsonschema::validator_for(&tool["inputSchema"])?;
            ensure!(
                !validator.is_valid(arguments),
                "{name}: malformed arguments match published schema"
            );
            let id = 10 + index as u64;
            server
                .send(json!({
                    "jsonrpc":"2.0","id":id,"method":"tools/call",
                    "params":{"name":name,"arguments":arguments}
                }))
                .await?;
            let response = server.response(id).await?;
            ensure!(
                response.get("result").is_none(),
                "{name}: shape error became a tool result"
            );
            ensure!(
                response["error"]
                    == json!({
                        "code":-32602,
                        "message":"Arguments do not match the tool input schema",
                        "data":{
                            "code":"invalid_argument",
                            "phase":"argument_shape",
                            "schema_path":expected_path,
                            "constraint":expected_constraint,
                        }
                    }),
                "{name}: unsafe or incomplete argument diagnostic: {response}"
            );
            ensure!(
                !response.to_string().contains("A12_PRIVATE"),
                "{name}: reflected malformed input"
            );
        }
        // Shape failures do not poison the session or change valid empty input.
        let targets = tools
            .iter()
            .find(|tool| tool["name"] == "observe_targets")
            .context("targets tool")?;
        ensure!(jsonschema::validator_for(&targets["inputSchema"])?.is_valid(&json!({})));
        server
            .send(json!({
                "jsonrpc":"2.0","id":30,"method":"tools/call",
                "params":{"name":"observe_targets","arguments":{}}
            }))
            .await?;
        let healthy = server.response(30).await?;
        let discovered = discovery_data(&healthy["result"], "configured")?;
        ensure!(
            discovered["targets"][0]["name"] == "fixture"
                && discovered["targets"]
                    .as_array()
                    .context("target inventory")?
                    .len()
                    == 1
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    ensure!(
        !std::str::from_utf8(&stderr)?.contains("A12_PRIVATE"),
        "audit disclosed malformed arguments"
    );
    let mut rejected = vec![false; cases.len()];
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["event"] != "master_start",
            "shape rejection launched SSH"
        );
        for (index, (name, _, _, _)) in cases.iter().enumerate() {
            if record["request_id"] == 10 + index as u64 {
                ensure!(!rejected[index], "duplicate shape rejection audit");
                ensure!(
                    record["event"] == "reject" && record["tool"] == *name,
                    "{record}"
                );
                ensure!(record["error_code"] == "invalid_argument");
                ensure!(record["remote_state_unknown"] == false);
                ensure!(
                    record["identity_role"]
                        == if *name == "exec_sudo" {
                            "elevated"
                        } else {
                            "ordinary"
                        }
                );
                for field in ["host", "user", "program", "binding_revision", "executor"] {
                    ensure!(
                        record.get(field).is_none(),
                        "shape rejection retained {field}: {record}"
                    );
                }
                rejected[index] = true;
            }
        }
    }
    ensure!(
        rejected.into_iter().all(|seen| seen),
        "missing shape rejection audit"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_discards_unterminated_requests_without_dispatch_or_response() -> Result<()> {
    for incomplete_json in [false, true] {
        let (mut server, directory) = server_with_config(
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[targets]\n",
        )?;
        let scenario = async {
            server.initialize().await?;
            let mut frame = serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":"truncated","method":"tools/call",
                "params":{"name":"exec_command","arguments":{
                    "host":"must-not-connect.invalid","command":"printf TRUNCATED_PAYLOAD_NO_ECHO"
                }}
            }))?;
            if incomplete_json {
                frame.pop();
            }
            // Even syntactically complete JSON is an incomplete stdio frame
            // without its newline. No partial tool call may reach the handler.
            server.send_raw(&frame).await
        }
        .await;
        let finished = server.finish().await;
        let removed = directory.close();
        scenario?;
        let (status, stderr) = finished?;
        removed?;
        ensure!(
            status.success(),
            "truncated-input shutdown failed: {status}"
        );
        ensure!(
            !stderr
                .windows(b"TRUNCATED_PAYLOAD_NO_ECHO".len())
                .any(|bytes| bytes == b"TRUNCATED_PAYLOAD_NO_ECHO")
        );
        no_remote_dispatch(&stderr)?;
    }
    Ok(())
}
