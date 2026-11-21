//! Target selection, tier ceilings, startup profiles and preview policy. No SSH.
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
async fn workstation_named_observations_require_target_elevation() -> Result<()> {
    for (sudo, allowed) in [
        ("", false),
        (
            "[targets.one.sudo]\nmode = 'same-account'\nprograms = ['/usr/bin/id']\n",
            false,
        ),
        ("[targets.one.sudo]\nmode = 'same-account'\n", true),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator.toml");
        std::fs::write(
            &path,
            format!(
                "mode = 'workstation'\ncapabilities = {{ named = true, sudo = true }}\n[targets.one]\nssh_host = 'host.invalid'\n{sudo}"
            ),
        )?;
        let mut command = stdio::command(&["--config", path.to_str().context("config path")?]);
        command.env(
            "ESTUS_CATALOG_ROOT",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"),
        );
        let mut server = Server::from_command(command)?;
        let scenario = async {
            server.initialize().await?;
            server
                .send(json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}))
                .await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("tools list")?;
            for name in [
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
                let tool = tools.iter().find(|tool| tool["name"] == name);
                ensure!(
                    tool.is_some() == allowed,
                    "{name} publication under {sudo:?}: {tool:?}"
                );
                if let Some(tool) = tool {
                    ensure!(
                        tool["_meta"]["authority"] == "automation:catalog",
                        "unexpected authority: {tool}"
                    );
                }
            }
            if allowed {
                server
                    .send(json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{
                        "name":"observe_hardware_memory", "arguments":{"host":"unlisted.invalid", "inputs":{}}
                    }}))
                    .await?;
                let denied = server.response(3).await?;
                ensure!(
                    denied["result"]["structuredContent"]["error"]["code"] == "policy_denied",
                    "unlisted host was not denied: {denied}"
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
    }
    Ok(())
}

#[tokio::test]
async fn empty_sudo_program_policy_keeps_route_but_denies_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
        capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
        [targets.one]
        ssh_host = 'private-empty-policy.invalid'
        [targets.one.sudo]
        mode = 'same-account'
        programs = []
    "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(2).await?;
        ensure!(
            listed["result"]["tools"]
                .as_array()
                .context("tool list")?
                .iter()
                .any(|tool| tool["name"] == "exec_sudo")
        );
        server
            .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let response = server.response(3).await?;
        let data = discovery_data(&response["result"], "configured")?;
        let target = &data["targets"][0];
        ensure!(target["sudo_mode"] == "same-account");
        ensure!(
            !target["permitted_operations"]
                .as_array()
                .context("target operations")?
                .iter()
                .any(|operation| operation == "exec_sudo")
        );
        server
            .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"exec_sudo","arguments":{"host":"one","argv":["/usr/bin/id"]}}}))
            .await?;
        let denied = server.response(4).await?;
        ensure!(
            denied.get("error").is_none(),
            "registered route rejected before target policy"
        );
        ensure!(denied["result"]["isError"] == true);
        let reply = &denied["result"]["structuredContent"];
        ensure!(reply["data"].is_null());
        ensure!(reply["error"]["code"] == "policy_denied");
        ensure!(reply["error"]["remote_state_unknown"] == false);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    ensure!(!String::from_utf8_lossy(&stderr).contains("private-empty-policy"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_profiles_publish_exact_routes_and_matching_discovery() -> Result<()> {
    let ordinary = [
        "exec_command",
        "inspect_directory",
        "change_mkdir",
        "inspect_file",
        "change_directory_remove",
        "change_file_remove",
        "change_rename",
        "change_file_replace",
        "exec_argv",
        "observe_stat",
        "exec_sudo",
        "change_file_write",
    ];
    for (profile, caps, expected) in [
        (
            "baseline",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
            ordinary.as_slice(),
        ),
        (
            "read-only-files",
            "capabilities = { file_read = true }",
            &["inspect_directory", "inspect_file", "observe_stat"][..],
        ),
        (
            "files-only",
            "capabilities = { file_read = true, file_write = true }",
            &[
                "inspect_directory",
                "change_mkdir",
                "inspect_file",
                "change_directory_remove",
                "change_file_remove",
                "change_rename",
                "change_file_replace",
                "observe_stat",
                "change_file_write",
            ][..],
        ),
        ("actions-only", "capabilities = { named = true }", &[][..]),
    ] {
        // An empty configured target set must not change global publication.
        for target_kind in ["sudo", "ordinary", "empty"] {
            for modern in [false, true] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("operator.toml");
                let replacement = directory.path().join("replacement.conf");
                let probe = directory.path().join("must-not-probe");
                std::fs::write(
                    &replacement,
                    format!(
                        "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                        probe.display()
                    ),
                )?;
                let target = match target_kind {
                    "sudo" => {
                        "[targets.one]\nssh_host = 'private-backend.invalid'\n[targets.one.sudo]\nmode = 'same-account'\n"
                    }
                    "ordinary" => "[targets.one]\nssh_host = 'private-backend.invalid'\n",
                    _ => "[targets]\n",
                };
                std::fs::write(
                    &path,
                    format!("{caps}\n[ssh]\nconfig_file = 'replacement.conf'\n{target}"),
                )?;
                let mut server =
                    Server::start(&["--config", path.to_str().context("config path")?])?;
                let scenario = async {
                    if !modern {
                        server.initialize().await?;
                    }
                    let mut expected_operations: Vec<&str> = expected
                        .iter()
                        .copied()
                        .filter(|name| *name != "exec_sudo" || target_kind == "sudo")
                        .collect();
                    expected_operations.sort_unstable();
                    let mut expected_routes = expected_operations.clone();
                    if matches!(profile, "baseline" | "files-only" | "actions-only") {
                        expected_routes.push("change_target_quarantine_clear");
                    }
                    expected_routes.push("observe_targets");
                    expected_routes.push("inspect_output");
                    expected_routes.sort_unstable();
                    let params = json!({});
                    let request = if modern {
                        modern_request(json!(2), "tools/list", params, MODERN_VERSION)
                    } else {
                        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":params})
                    };
                    server.send(request).await?;
                    let listed = server.response(2).await?;
                    let mut names: Vec<&str> = listed["result"]["tools"]
                        .as_array()
                        .context("profile tool list")?
                        .iter()
                        .map(|tool| tool["name"].as_str().context("tool name"))
                        .collect::<Result<_>>()?;
                    names.sort_unstable();
                    ensure!(
                        names == expected_routes,
                        "{profile}/{target_kind}/{modern}: {names:?}"
                    );
                    for tool in listed["result"]["tools"].as_array().context("profile annotations")? {
                        if tool["name"] == "exec_argv" || tool["name"] == "change_file_write" {
                            ensure!(tool["annotations"]["readOnlyHint"] == false);
                            ensure!(tool["annotations"]["destructiveHint"] == true);
                            ensure!(tool["annotations"]["idempotentHint"] == false);
                        }
                    }
                    let params = json!({"name":"observe_targets","arguments":{}});
                    let request = if modern {
                        modern_request(json!(3), "tools/call", params, MODERN_VERSION)
                    } else {
                        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":params})
                    };
                    server.send(request).await?;
                    let discovered = server.response(3).await?;
                    let data = discovery_data(&discovered["result"], "configured")?;
                    if target_kind == "empty" {
                        ensure!(data["targets"] == json!([]));
                    } else {
                        ensure!(data["targets"].as_array().context("targets")?.len() == 1);
                        ensure!(
                            data["targets"][0]["permitted_operations"]
                                == json!(expected_operations)
                        );
                        ensure!(data["targets"][0]["observed_capabilities"] == "unknown");
                    }
                    let params = json!({"name":"inspect_output","arguments":{"handle":"0123456789abcdef0123456789abcdef","stream":"stdout","max_bytes":1}});
                    let request = if modern {
                        modern_request(json!(4), "tools/call", params, MODERN_VERSION)
                    } else {
                        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":params})
                    };
                    server.send(request).await?;
                    let read = server.response(4).await?;
                    ensure!(read["result"]["structuredContent"]["error"]["code"] == "not_found", "{profile}: {read}");
                    ensure!(read["result"]["structuredContent"]["error"]["remote_state_unknown"] == false);
                    for (index, tool) in ordinary.iter().enumerate() {
                        if expected_routes.contains(tool) {
                            continue;
                        }
                        let id = 10 + index as u64;
                        let params =
                            json!({"name":tool,"arguments":profile_call_arguments(tool, "one")});
                        let request = if modern {
                            modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                        } else {
                            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                        };
                        server.send(request).await?;
                        let rejected = server.response(id).await?;
                        ensure!(
                            rejected["error"]["code"] == -32602,
                            "{profile}/{tool}: {rejected}"
                        );
                        ensure!(rejected.get("result").is_none());
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                let finished = server.finish().await;
                scenario?;
                let (status, stderr) = finished?;
                ensure!(status.success());
                no_remote_dispatch(&stderr)?;
                ensure!(!probe.exists(), "hidden route probed SSH");
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn target_profiles_intersect_policy_before_ssh_without_granting_sudo() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    let replacement = directory.path().join("replacement.conf");
    let probe = directory.path().join("profile-probe");
    std::fs::write(
        &replacement,
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    std::fs::write(
        &path,
        indoc::indoc! {"
        capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
        [ssh]
        config_file = 'replacement.conf'
        [limits]
        connect_timeout_secs = 1
        operation_timeout_secs = 2
        [targets.read]
        ssh_host = 'private-backend-read.invalid'
        max_tier = 'inspect'
        [targets.read.sudo]
        mode = 'separate-identity'
        ssh_host = 'private-identity.invalid'
        [targets.files]
        ssh_host = 'private-backend-files.invalid'
        max_tier = 'change'
        [targets.files.sudo]
        mode = 'same-account'
        [targets.actions]
        ssh_host = 'private-backend-actions.invalid'
        selection = {}
        [targets.actions.sudo]
        mode = 'same-account'
        [targets.base]
        ssh_host = 'private-backend-base.invalid'
        [targets.empty]
        ssh_host = 'private-backend-empty.invalid'
        [targets.empty.sudo]
        mode = 'same-account'
        programs = []
    "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(2).await?;
        ensure!(listed["result"]["tools"].as_array().context("tools")?.len() == 15);
        server
            .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let discovered = server.response(3).await?;
        let rows = discovery_data(&discovered["result"], "configured")?["targets"]
            .as_array()
            .context("target rows")?;
        for (name, expected) in [
            ("actions", json!([])),
            (
                "base",
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
                ]),
            ),
            (
                "empty",
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
                ]),
            ),
            (
                "files",
                json!([
                    "change_directory_remove",
                    "change_file_remove",
                    "change_file_replace",
                    "change_file_write",
                    "change_mkdir",
                    "change_rename",
                    "inspect_directory",
                    "inspect_file",
                    "observe_stat"
                ]),
            ),
            (
                "read",
                json!(["inspect_directory", "inspect_file", "observe_stat"]),
            ),
        ] {
            let row = rows
                .iter()
                .find(|row| row["name"] == name)
                .context("target row")?;
            ensure!(row["permitted_operations"] == expected, "{name}: {row}");
        }
        let mut id = 10;
        for (host, forbidden) in [
            (
                "read",
                &[
                    "exec_command",
                    "exec_argv",
                    "change_file_write",
                    "change_mkdir",
                    "change_directory_remove",
                    "change_file_remove",
                    "change_rename",
                    "change_file_replace",
                    "exec_sudo",
                ][..],
            ),
            ("files", &["exec_command", "exec_argv", "exec_sudo"][..]),
            (
                "actions",
                &[
                    "exec_command",
                    "exec_argv",
                    "change_file_write",
                    "exec_sudo",
                    "inspect_file",
                    "observe_stat",
                    "inspect_directory",
                    "change_mkdir",
                    "change_directory_remove",
                    "change_file_remove",
                    "change_rename",
                    "change_file_replace",
                ][..],
            ),
            ("base", &["exec_sudo"][..]),
            ("empty", &["exec_sudo"][..]),
        ] {
            for tool in forbidden {
                server
                    .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                    "params":{"name":tool,"arguments":profile_call_arguments(tool,host)}}))
                    .await?;
                profile_policy_denied(&server.response(id).await?)?;
                ensure!(!probe.exists(), "{host}/{tool}: denied request probed SSH");
                id += 1;
            }
        }
        // Positive dispatch is exercised against real sshd/SFTP by the native
        // profile scenario. Sandboxed checks must never launch SSH.
        ensure!(!probe.exists(), "denied requests probed SSH configuration");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    for line in stderr
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["event"] != "master_start",
            "profile denial launched SSH"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_profile_cannot_be_selected_by_mcp_or_reloaded() -> Result<()> {
    let (mut server, directory) =
        server_with_config("capabilities = { named = true }\n[targets]\n")?;
    let scenario = async {
        server.initialize().await?;
        for (index, arguments) in [
            json!({"profile":"baseline"}),
            json!({"host":"one","command":"true","profile":"baseline"}),
        ]
        .into_iter()
        .enumerate()
        {
            let tool = if index == 0 {
                "observe_targets"
            } else {
                "exec_command"
            };
            let id = 10 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":tool,"arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        std::fs::write(
            directory.path().join("operator.toml"),
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[targets]\n",
        )?;
        server
            .send(json!({"jsonrpc":"2.0","id":20,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(20).await?;
        let tools = listed["result"]["tools"]
            .as_array()
            .context("immutable tool list")?;
        ensure!(tools.len() == 3);
        for name in ["change_target_quarantine_clear", "inspect_output", "observe_targets"] {
            ensure!(tools.iter().any(|tool| tool["name"] == name));
        }
        for (index, tool) in [
            "exec_command",
            "exec_argv",
            "exec_sudo",
            "inspect_file",
            "observe_stat",
            "inspect_directory",
            "change_file_write",
            "change_mkdir",
            "change_directory_remove",
            "change_file_remove",
            "change_rename",
            "change_file_replace",
        ]
        .into_iter()
        .enumerate()
        {
            let id = 30 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":tool,"arguments":profile_call_arguments(tool,"one")}}))
                .await?;
            let response = server.response(id).await?;
            ensure!(response["error"]["code"] == -32602 && response.get("result").is_none());
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    Ok(())
}

#[tokio::test]
async fn invalid_startup_profiles_fail_before_mcp_without_secrets() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-profile-config.toml");
    for (target, value, field) in [
        (false, "'private-profile-secret'", "config"),
        (true, "'private-profile-secret'", "targets.*.profile"),
    ] {
        let text = if target {
            format!(
                "[targets.private_profile_secret]\nssh_host = 'private-backend.invalid'\nprofile = {value}\n"
            )
        } else {
            format!("profile = {value}\n[targets]\n")
        };
        std::fs::write(&path, text)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(!output.status.success(), "accepted legacy profile {value}");
        ensure!(output.stdout.is_empty(), "invalid profile started MCP");
        let stderr = std::str::from_utf8(&output.stderr)?;
        for secret in [
            "private-profile-secret",
            "private_profile_secret",
            "private-backend",
            path.to_str().context("config path")?,
        ] {
            ensure!(
                !stderr.contains(secret),
                "profile diagnostic reflected private input"
            );
        }
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(diagnostic["code"] == "invalid_config");
        ensure!(
            diagnostic["schema_path"] == field && diagnostic["phase"] == "config_validation",
            "wrong profile diagnostic context: {diagnostic}"
        );
    }
    for (text, field) in [
        (
            "capabilities = { exec = 'private-profile-secret' }\n",
            "config",
        ),
        ("mode = 'private-profile-secret'\n", "config"),
        ("[rules.'*']\nunknown_rule_key = true\n", "rules"),
        ("enabled_tools = ['private-profile-secret']\n", "selection"),
        (
            "[targets.secret]\nssh_host='private-backend.invalid'\ncapabilities = { file_read = true }\n",
            "targets.*.selection",
        ),
    ] {
        std::fs::write(&path, text)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(!output.status.success());
        ensure!(output.stdout.is_empty());
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(diagnostic["code"] == "invalid_config");
        ensure!(diagnostic["schema_path"] == field);
        ensure!(!std::str::from_utf8(&output.stderr)?.contains("private-profile-secret"));
    }
    Ok(())
}

#[tokio::test]
async fn empty_config_defaults_to_headless_named_only() -> Result<()> {
    let (mut server, _directory) = server_with_config("")?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(2).await?;
        let mut names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .context("headless tools")?
            .iter()
            .map(|t| t["name"].as_str().context("tool name"))
            .collect::<Result<_>>()?;
        names.sort_unstable();
        ensure!(
            names
                == [
                    "change_target_quarantine_clear",
                    "inspect_output",
                    "observe_targets"
                ]
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, _) = finished?;
    ensure!(status.success());
    Ok(())
}

#[tokio::test]
async fn target_tier_denies_above_the_ceiling_before_ssh() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let probe = directory.path().join("rules-probe");
    let replacement = directory.path().join("replacement.conf");
    std::fs::write(
        &replacement,
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    let config_path = directory.path().join("operator.toml");
    std::fs::write(
        &config_path,
        r#"
mode = "headless"
capabilities = { named = true, file_read = true, file_write = true, exec = true }
[ssh]
config_file = "replacement.conf"
[targets.prod-web]
ssh_host = "prod-web.invalid"
max_tier = "inspect"
"#,
    )?;
    let mut server = Server::start(&["--config", config_path.to_str().context("config")?])?;
    let scenario = async {
        server.initialize().await?;
        // Above the ceiling: denied before transport.
        for (id, name, arguments) in [
            (2, "exec_command", json!({"host": "prod-web", "command": "true"})),
            (3, "change_file_write", json!({"host": "prod-web", "path": "/tmp/a", "content": "x"})),
        ] {
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
                .await?;
            let reply = server.response(id).await?;
            profile_policy_denied(&reply)?;
        }
        // At or below the ceiling: policy allows it, so the call proceeds to
        // transport. There is no per-host argument filtering left to apply, so
        // any path on an `inspect`-tier tool reaches SSH.
        server
            .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"inspect_file","arguments":{"host":"prod-web","path":"/etc/shadow"}}}))
            .await?;
        let reply = server.response(4).await?;
        ensure!(
            reply["result"]["structuredContent"]["error"]["code"] == "ssh_connect_failed",
            "tier-permitted call did not reach transport: {reply}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    // Only the tier-permitted call may acquire a transport; no denial may.
    let masters = stderr
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter(|record| record["event"] == "master_start")
        .count();
    ensure!(
        masters == 1,
        "expected one transport for the permitted call, saw {masters}"
    );
    Ok(())
}

#[tokio::test]
async fn require_preview_rejects_unqualified_mutations_without_connecting() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("require-preview.toml");
    std::fs::write(
        &config_path,
        indoc::indoc! {r#"
            capabilities = { named = true, file_read = true, file_write = true, exec = true }
            [selection]
            allow = ["change_ping"]
            [targets.alpha]
            ssh_host = "alpha.invalid"
            require_preview = true
            [tools.change_ping]
            description = "Unqualified native argv mutation."
            revision = "1"
            targets = ["alpha"]
            authority = "ordinary"
            effects = ["runtime_write"]
            execution = { kind = "native_argv", program = "/bin/true", argv = [] }
            input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
            result = { kind = "command" }
        "#},
    )?;
    let mut server = Server::start(&["--config", config_path.to_str().context("config")?])?;
    let scenario = async {
        server.initialize().await?;
        for (id, name, arguments) in [
            (
                2,
                "change_file_write",
                json!({"host":"alpha","path":"/tmp/estus-never","content":"x"}),
            ),
            (3, "exec_command", json!({"host":"alpha","command":"true"})),
            (4, "change_ping", json!({"host":"alpha"})),
        ] {
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
                .await?;
            let reply = server.response(id).await?;
            ensure!(
                reply["result"]["structuredContent"]["error"]["code"] == "preview_required",
                "{name} did not fail closed with preview_required: {reply}"
            );
        }
        server
            .send(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"observe_stat","arguments":{"host":"alpha","path":"/tmp/x"}}}))
            .await?;
        let obs = server.response(5).await?;
        ensure!(
            obs["result"]["structuredContent"]["error"]["code"] != "preview_required",
            "read-only observe_stat was blocked by require_preview: {obs}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let fin = server.finish().await;
    scenario?;
    ensure!(fin?.0.success());
    Ok(())
}
