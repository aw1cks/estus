//! Command output read contracts, retained handles and budgets. No SSH.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_output_read_contract_validation_and_privacy_need_no_ssh() -> Result<()> {
    for modern in [false, true] {
        let directory = tempfile::tempdir()?;
        let probe = directory.path().join("must-not-probe-output");
        std::fs::write(
            directory.path().join("replacement.conf"),
            format!(
                "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                probe.display()
            ),
        )?;
        let path = directory.path().join("operator.toml");
        std::fs::write(
            &path,
            "capabilities = { named = true }\n[ssh]\nconfig_file='replacement.conf'\n[limits]\nmax_file_bytes=33554432\n[targets]\n",
        )?;
        let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
        let scenario = async {
            if !modern {
                server.initialize().await?;
            }
            let request = if modern {
                modern_request(json!(2), "tools/list", json!({}), MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
            };
            server.send(request).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("output catalog")?;
            let tool = tools.iter().find(|tool| tool["name"] == "inspect_output").context("read output route")?;
            ensure!(tool["annotations"]["readOnlyHint"] == true);
            ensure!(tool["annotations"]["destructiveHint"] == false);
            let schema = &tool["inputSchema"];
            ensure!(schema["type"] == "object" && schema["additionalProperties"] == false);
            let mut fields: Vec<_> = schema["properties"].as_object().context("output inputs")?.keys().map(String::as_str).collect();
            fields.sort_unstable();
            ensure!(fields == ["encoding", "handle", "max_bytes", "offset", "stream"]);
            let mut required: Vec<_> = schema["required"].as_array().context("output required inputs")?.iter().map(|field| field.as_str().context("required field")).collect::<Result<_>>()?;
            required.sort_unstable();
            ensure!(required == ["handle", "stream"]);
            for field in ["content", "bytes_read", "next_offset", "eof", "content_sha256"] {
                ensure!(schema_has_property(&tool["outputSchema"], field), "missing read result {field}");
            }
            let handle = "0123456789abcdef0123456789abcdef";
            let valid = json!({"handle":handle,"stream":"stdout","max_bytes":1});
            let mut cases = vec![
                (valid.clone(), Some("not_found")),
                (json!({"handle":handle,"stream":"stderr","offset":u64::MAX,"max_bytes":1}), Some("not_found")),
                (json!({"handle":"","stream":"stdout","max_bytes":1}), Some("invalid_argument")),
                (json!({"handle":"/private/OUTPUT_PATH_SECRET","stream":"stdout","max_bytes":1}), Some("invalid_argument")),
                (json!({"handle":"F".repeat(32),"stream":"stdout","max_bytes":1}), Some("invalid_argument")),
                (json!({"handle":handle,"stream":"stdout","max_bytes":0}), Some("invalid_argument")),
                (json!({"handle":handle,"stream":"stdout","max_bytes":33_554_433u64}), Some("invalid_argument")),
                (json!({"handle":handle,"stream":"stdout","max_bytes":3_000_000}), Some("invalid_argument")),
                (json!({"handle":handle,"stream":"stdout","max_bytes":8_000_000,"encoding":"base64"}), Some("invalid_argument")),
                (json!({"handle":handle,"stream":"combined","max_bytes":1}), None),
                (json!({"handle":handle,"stream":"stdout","max_bytes":1,"encoding":"hex"}), None),
                (json!({"handle":true,"stream":"stdout","max_bytes":1}), None),
                (json!({"handle":handle,"stream":"stdout","offset":-1,"max_bytes":1}), None),
                (json!({"handle":handle,"stream":"stdout","max_bytes":"1"}), None),
            ];
            for field in ["host", "path", "directory", "sudo", "retain_output", "expected_content_sha256"] {
                let mut arguments = valid.clone();
                arguments[field] = json!("OUTPUT_PATH_SECRET");
                cases.push((arguments, None));
            }
            for missing in ["handle", "stream"] {
                let mut arguments = valid.clone();
                arguments.as_object_mut().context("output arguments")?.remove(missing);
                cases.push((arguments, None));
            }
            for (index, (arguments, code)) in cases.into_iter().enumerate() {
                let id = 10 + index as u64;
                let params = json!({"name":"inspect_output","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let response = server.response(id).await?;
                if let Some(code) = code {
                    ensure!(response["result"]["isError"] == true, "case {index}: {response}");
                    let structured = &response["result"]["structuredContent"];
                    ensure!(structured["data"].is_null());
                    ensure!(structured["error"]["code"] == code, "case {index}: {response}");
                    ensure!(structured["error"]["remote_state_unknown"] == false);
                    let text: Value = serde_json::from_str(response["result"]["content"][0]["text"].as_str().context("output error text")?)?;
                    ensure!(text == *structured);
                } else {
                    ensure!(response["error"]["code"] == -32602, "case {index}: {response}");
                }
                let encoded = serde_json::to_string(&response)?;
                ensure!(!encoded.contains(handle) && !encoded.contains("OUTPUT_PATH_SECRET"));
                ensure!(!probe.exists(), "local output read probed SSH");
            }
            // The range fits operator limits and an ordinary request ID, but not
            // this request's remaining response budget. Lookup must not mask it.
            let id = json!("r".repeat(16_777_216 - 2048));
            let params = json!({"name":"inspect_output","arguments":{"handle":handle,"stream":"stdout","max_bytes":1024,"encoding":"base64"}});
            let request = if modern {
                modern_request(id.clone(), "tools/call", params, MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
            };
            ensure!(serde_json::to_vec(&request)?.len() + 1 < 16_777_216);
            server.send(request).await?;
            let (response, bytes) = server.response_with_id(&id).await?;
            ensure!(bytes <= 16_777_216);
            ensure!(response["result"]["structuredContent"]["error"]["code"] == "invalid_argument", "{response}");
            ensure!(response["result"]["structuredContent"]["error"]["remote_state_unknown"] == false);
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        no_remote_dispatch(&stderr)?;
        let audit = std::str::from_utf8(&stderr)?;
        ensure!(
            !audit.contains("OUTPUT_PATH_SECRET")
                && !audit.contains("0123456789abcdef0123456789abcdef")
        );
        ensure!(!audit.contains(directory.path().to_str().context("private directory")?));
        ensure!(!probe.exists());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_output_optional_receipt_is_local_readable_and_private() -> Result<()> {
    use sha2::{Digest, Sha256};

    let fixture = ControllerProtocolFixture::new()?;
    let probe = fixture.directory.path().join("output-must-not-probe");
    std::fs::write(
        fixture.directory.path().join("replacement.conf"),
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    let mut server = fixture.start(&fixture.config)?;
    let mut private_receipts = Vec::new();
    let scenario = async {
        server.initialize().await?;
        for (index, retain) in [None, Some(false), Some(true)].into_iter().enumerate() {
            let mut arguments = json!({"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":false});
            if let Some(retain) = retain {
                arguments["retain_output"] = json!(retain);
            }
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_controller","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            ensure!(response["result"]["isError"] != true, "{response}");
            let data = &response["result"]["structuredContent"]["data"];
            ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
            let stdout = data["stdout"].as_str().context("controller stdout")?;
            let echoed: Value = serde_json::from_str(stdout)?;
            ensure!(echoed == json!({"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":false}), "retention control reached domain input");
            if retain != Some(true) {
                ensure!(data.get("output").is_none(), "unrequested output field was serialized");
                continue;
            }
            let receipt = &data["output"];
            ensure!(receipt["status"] == "ready", "{receipt}");
            let handle = receipt["handle"].as_str().context("output handle")?;
            ensure!(handle.len() == 32 && handle.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            ensure!(receipt["expires_in_secs"].as_u64().is_some_and(|ttl| ttl > 0));
            ensure!(receipt["stdout"] == json!({"bytes_retained":stdout.len(),"total_bytes":stdout.len(),"truncated":false}));
            ensure!(receipt["stderr"] == json!({"bytes_retained":0,"total_bytes":0,"truncated":false}));
            private_receipts.push(handle.to_owned());
            server.send(json!({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"inspect_output","arguments":{"handle":handle,"stream":"stdout","max_bytes":1024}}})).await?;
            let read = server.response(30).await?;
            ensure!(read["result"]["isError"] != true, "{read}");
            let read_data = &read["result"]["structuredContent"]["data"];
            ensure!(read_data["content"] == stdout);
            ensure!(read_data["bytes_read"] == stdout.len());
            ensure!(read_data["next_offset"] == stdout.len() && read_data["eof"] == true);
            ensure!(read_data["content_sha256"] == hex::encode(Sha256::digest(stdout.as_bytes())));
            server.send(json!({"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"inspect_output","arguments":{"handle":handle,"stream":"stderr","max_bytes":1,"encoding":"base64"}}})).await?;
            let empty = server.response(31).await?;
            ensure!(empty["result"]["isError"] != true);
            let empty_data = &empty["result"]["structuredContent"]["data"];
            ensure!(empty_data["content"] == "" && empty_data["bytes_read"] == 0);
            ensure!(empty_data["next_offset"] == 0 && empty_data["eof"] == true);
            ensure!(!probe.exists(), "retention or local read probed SSH");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    fixture.public_only(&stderr)?;
    no_remote_dispatch(&stderr)?;
    let audit = std::str::from_utf8(&stderr)?;
    for handle in private_receipts {
        ensure!(!audit.contains(&handle), "audit disclosed capability");
    }
    for line in audit.lines() {
        let record: Value = serde_json::from_str(line)?;
        if record["tool"] == "inspect_output" {
            for field in ["host", "path", "handle", "stdout", "stderr", "content"] {
                ensure!(
                    record.get(field).is_none_or(Value::is_null),
                    "read audit disclosed {field}"
                );
            }
        }
    }
    ensure!(!probe.exists());
    ensure!(std::fs::read_dir(&fixture.root)?.next().is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_output_actual_id_receipt_budget_precedes_dispatch() -> Result<()> {
    let fixture = ControllerProtocolFixture::new()?;
    let marker = fixture
        .directory
        .path()
        .join("controller-output-dispatched");
    let interpreter = std::fs::read_to_string(&fixture.interpreter)?;
    let marker_path = marker
        .to_str()
        .context("marker path")?
        .replace('\'', "'\\''");
    std::fs::write(
        &fixture.interpreter,
        interpreter.replace("\nexec ", &format!("\nprintf x > '{marker_path}'\nexec ")),
    )?;
    let mut server = fixture.start(&fixture.config)?;
    let scenario = async {
        server.initialize().await?;
        for retain in [false, true] {
            let id = json!("b".repeat(16_777_216 - 1536));
            let request = modern_request(id.clone(), "tools/call", json!({
                "name":"observe_controller",
                "arguments":{"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":false,"retain_output":retain}
            }), MODERN_VERSION);
            ensure!(serde_json::to_vec(&request)?.len() + 1 < 16_777_216);
            server.send(request).await?;
            let (response, bytes) = server.response_with_id(&id).await?;
            ensure!(bytes <= 16_777_216);
            if retain {
                ensure!(response["error"]["code"] == -32602 && response.get("result").is_none());
                ensure!(!marker.exists(), "metadata-budget rejection executed controller");
            } else {
                ensure!(response["result"]["isError"] != true, "default budget changed");
                ensure!(response["result"]["structuredContent"]["data"].get("output").is_none());
                ensure!(marker.is_file(), "default call did not dispatch");
                std::fs::remove_file(&marker)?;
            }
        }
        server.send(modern_request(json!("usable"), "tools/call", json!({
            "name":"inspect_output","arguments":{"handle":"0123456789abcdef0123456789abcdef","stream":"stdout","max_bytes":1}
        }), MODERN_VERSION)).await?;
        ensure!(server.response_with_id(&json!("usable")).await?.0["result"]["structuredContent"]["error"]["code"] == "not_found");
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    fixture.public_only(&stderr)?;
    no_remote_dispatch(&stderr)?;
    ensure!(std::fs::read_dir(&fixture.root)?.next().is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_output_native_controls_are_strict_and_budgeted_before_dispatch() -> Result<()> {
    let builtin = "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[ssh]\nconfig_file='replacement.conf'\n[targets.base]\nssh_host='private-binding-backend.invalid'\n[targets.base.sudo]\nmode='same-account'\n";
    for (config, calls) in [
        (
            builtin,
            vec![
                ("exec_command", json!({"host":"base","command":"true"})),
                ("exec_argv", json!({"host":"base","argv":["/usr/bin/true"]})),
                ("exec_sudo", json!({"host":"base","argv":["/usr/bin/true"]})),
            ],
        ),
        (
            NAMED_TOOL_CONFIG,
            vec![
                (
                    "inspect_account",
                    json!({"host":"base","account":"root","count":0,"verbose":false}),
                ),
                ("change_account", json!({"host":"base"})),
            ],
        ),
        (
            FIXED_SUDO_TOOL_CONFIG,
            vec![
                ("fixed_id", json!({"host":"base"})),
                (
                    "fixed_printf",
                    json!({"host":"base","value":"BINDING_INPUT_SECRET"}),
                ),
            ],
        ),
    ] {
        let (mut server, directory) = named_tools_server(config)?;
        let scenario = async {
            server.initialize().await?;
            let mut id = 10;
            for (name, valid) in calls {
                for retain in [false, true] {
                    let mut arguments = valid.clone();
                    arguments["host"] = json!("unconfigured.invalid");
                    arguments["retain_output"] = json!(retain);
                    server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
                    profile_policy_denied(&server.response(id).await?)?;
                    id += 1;
                }
                for retain in [Value::Null, json!(0), json!("true"), json!({}), json!([])] {
                    let mut arguments = valid.clone();
                    arguments["retain_output"] = retain;
                    server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
                    let response = server.response(id).await?;
                    ensure!(response["error"]["code"] == -32602, "{name}: nonboolean retention accepted");
                    id += 1;
                }
                // All authority and domain inputs are valid. Only the actual
                // response ID leaves too little room for the requested receipt.
                let budget_id = json!("n".repeat(16_777_216 - 512));
                let mut arguments = valid;
                arguments["retain_output"] = json!(true);
                let request = modern_request(budget_id.clone(), "tools/call", json!({
                    "name":name,"arguments":arguments
                }), MODERN_VERSION);
                ensure!(serde_json::to_vec(&request)?.len() + 1 < 16_777_216, "{name}: incoming request exceeds limit");
                server.send(request).await?;
                let (response, bytes) = server.response_with_id(&budget_id).await?;
                ensure!(response["error"]["code"] == -32602 && response.get("result").is_none(), "{name}: receipt budget reached execution");
                ensure!(bytes <= 16_777_216);
                ensure!(!directory.path().join("binding-must-not-probe").exists(), "{name}: rejected output request probed SSH");
            }
            server.send(json!({"jsonrpc":"2.0","id":500,"method":"tools/call","params":{"name":"observe_targets","arguments":{}}})).await?;
            ensure!(server.response(500).await?["result"]["isError"] != true);
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
                "rejected output control launched SSH"
            );
        }
        binding_public_only(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_retained_output_calls_reclaim_handles_for_later_reads() -> Result<()> {
    let fixture = ControllerProtocolFixture::new()?;
    let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|path| path.join("sleep"))
        .chain([std::path::PathBuf::from("/bin/sleep")])
        .find(|path| path.is_file())
        .context("sleep executable is required")?;
    let sleep_q = format!("'{}'", sleep.to_string_lossy().replace('\'', "'\\''"));
    let marker_dir = fixture.directory.path().join("markers");
    std::fs::create_dir(&marker_dir)?;
    let marker_dir_q = format!(
        "'{}'",
        marker_dir
            .to_str()
            .context("marker dir UTF-8")?
            .replace('\'', "'\\''")
    );
    let release = fixture.directory.path().join("release");
    let release_q = format!(
        "'{}'",
        release
            .to_str()
            .context("release path UTF-8")?
            .replace('\'', "'\\''")
    );
    let script = format!(
        r#"IFS= read -r payload < "$1" || :
case "$payload" in
  *'"count":1'*) idx=1 ;;
  *'"count":2'*) idx=2 ;;
  *'"count":3'*) idx=3 ;;
  *'"count":4'*) idx=4 ;;
  *) idx=0 ;;
esac
if [ "$idx" != 0 ]; then
  printf 'PARTIAL_OUT'
  : > {marker_dir_q}/started-"$idx"
  i=0
  while [ ! -f {release_q} ] && [ "$i" -lt 200 ]; do
    {sleep_q} 0.05
    i=$((i+1))
  done
else
  printf '%s' "$payload"
fi
"#
    );
    std::fs::write(&fixture.source, script.as_bytes())?;
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(std::fs::read(&fixture.source)?));
    let config = fixture.config.replace(&fixture.hash, &hash);

    let mut server = fixture.start(&config)?;
    let scenario = async {
        server.initialize().await?;
        // 4 immediate/pre-dispatch cancellations (count: -1) and 4 mid-stream cancellations (count: 1..=4).
        for id in 10..=13 {
            server
                .send(modern_request(
                    json!(id),
                    "tools/call",
                    json!({
                        "name": "observe_controller",
                        "arguments": {"label": "CONTROLLER_CANCEL_SECRET", "count": -1, "verbose": false, "retain_output": true}
                    }),
                    MODERN_VERSION,
                ))
                .await?;
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": id, "reason": "pre-dispatch cancel"}
                }))
                .await?;
        }
        for idx in 1..=4 {
            let id = 20 + idx;
            server
                .send(modern_request(
                    json!(id),
                    "tools/call",
                    json!({
                        "name": "observe_controller",
                        "arguments": {"label": "CONTROLLER_CANCEL_SECRET", "count": idx, "verbose": false, "retain_output": true}
                    }),
                    MODERN_VERSION,
                ))
                .await?;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        for idx in 1..=4 {
            let marker = marker_dir.join(format!("started-{idx}"));
            while !marker.exists() {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "mid-stream controller {idx} did not start"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        for idx in 1..=4 {
            let id = 20 + idx;
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": id, "reason": "mid-stream cancel"}
                }))
                .await?;
        }
        // Ensure all cancelled controller workspaces have finished cleanup before the 9th call.
        let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_dir(&fixture.root)?.next().is_some() {
            ensure!(
                tokio::time::Instant::now() < cleanup_deadline,
                "cancelled controller workspaces remained"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 9th normal call under default max_handles = 8 must retain and be readable.
        server
            .send(modern_request(
                json!(99),
                "tools/call",
                json!({
                    "name": "observe_controller",
                    "arguments": {"label": "CONTROLLER_INPUT_SECRET", "count": 0, "verbose": false, "retain_output": true}
                }),
                MODERN_VERSION,
            ))
            .await?;
        let response = server.response(99).await?;
        ensure!(response["result"]["isError"] != true, "9th call failed: {response}");
        let data = &response["result"]["structuredContent"]["data"];
        let receipt = &data["output"];
        ensure!(receipt["status"] == "ready", "9th call handle exhausted: {receipt}");
        let handle = receipt["handle"].as_str().context("output handle")?;
        server
            .send(modern_request(
                json!(100),
                "tools/call",
                json!({
                    "name": "inspect_output",
                    "arguments": {"handle": handle, "stream": "stdout", "max_bytes": 1024}
                }),
                MODERN_VERSION,
            ))
            .await?;
        let read = server.response(100).await?;
        ensure!(read["result"]["isError"] != true, "inspect_output failed: {read}");
        ensure!(
            read["result"]["structuredContent"]["data"]["content"] == data["stdout"],
            "read output mismatch"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = std::fs::write(&release, b"done");
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    fixture.public_only(&stderr)?;
    no_remote_dispatch(&stderr)?;
    ensure!(!std::str::from_utf8(&stderr)?.contains("CONTROLLER_CANCEL_SECRET"));
    Ok(())
}
