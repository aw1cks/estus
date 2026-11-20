//! File tool validation, policy and privacy before any SSH dispatch. No SSH.
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
async fn read_validation_precedes_ssh_and_cannot_raise_the_wire_ceiling() -> Result<()> {
    let (mut server, directory) = server_with_config(
        "capabilities = { file_read = true }\n[limits]\nmax_file_bytes=33554432\n[targets]\n",
    )?;
    let scenario = async {
        server.initialize().await?;
        for (index, (arguments, code)) in [
            (json!({"host":"denied","path":""}), "invalid_argument"),
            (json!({"host":"denied","path":"a\0b"}), "invalid_argument"),
            (
                json!({"host":"denied","path":"file","max_bytes":0}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"file","max_bytes":33_554_433u64}),
                "invalid_argument",
            ),
            // Both fit the configured file cap, but not a lossless worst-case
            // UTF-8/base64 reply. No allocation/connection may precede refusal.
            (
                json!({"host":"denied","path":"file","max_bytes":3_000_000}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"file","max_bytes":8_000_000,"encoding":"base64"}),
                "invalid_argument",
            ),
            // Offset width is not an arbitrary public limit; policy is reached.
            (
                json!({"host":"denied","path":"file","offset":u64::MAX,"max_bytes":1}),
                "policy_denied",
            ),
            (
                json!({"host":"denied","path":"file","expected_content_sha256":"sha256:abc"}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"file","expected_content_sha256":"g".repeat(64)}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"file","expected_content_sha256":"0".repeat(63)}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"file","expected_content_sha256":
                    "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}),
                "policy_denied",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 100 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"inspect_file","arguments":arguments}}))
                .await?;
            let called = server.response(id).await?;
            let result = &called["result"];
            ensure!(result["isError"] == true);
            let reply = &result["structuredContent"];
            ensure!(reply["data"].is_null() && reply["error"]["code"] == code);
            ensure!(reply["error"]["remote_state_unknown"] == false);
        }
        for (id, arguments) in [
            (200, json!({"host":"denied","path":"file","encoding":"hex"})),
            (201, json!({"host":"denied","path":"file","sudo":true})),
            (
                202,
                json!({"host":"denied","path":"file","expected_content_sha256":true}),
            ),
            (
                203,
                json!({"host":"denied","path":"file","retry_on_connection_loss":true}),
            ),
        ] {
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"inspect_file","arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        ensure!(
            server.response(300).await?["result"]["structuredContent"]["data"]["mode"]
                == "configured"
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
    no_remote_dispatch(&stderr)?;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["tool"] != "inspect_file" || record["event"] == "reject",
            "invalid read was accepted before validation"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stat_validation_and_policy_precede_any_ssh_dispatch() -> Result<()> {
    let (mut server, directory) =
        server_with_config("capabilities = { file_read = true }\n[targets]\n")?;
    let scenario = async {
        server.initialize().await?;
        for (index, (arguments, code)) in [
            (json!({"host":"denied","path":""}), "invalid_argument"),
            (json!({"host":"denied","path":"a\0b"}), "invalid_argument"),
            (
                json!({"host":"denied","path":"file","timeout_secs":0}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"literal~$*' \n"}),
                "policy_denied",
            ),
            (
                json!({"host":"denied","path":"file","follow_symlinks":true}),
                "policy_denied",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 100 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"observe_stat","arguments":arguments}}))
                .await?;
            let called = server.response(id).await?;
            let result = &called["result"];
            ensure!(result["isError"] == true);
            ensure!(result["structuredContent"]["data"].is_null());
            ensure!(result["structuredContent"]["error"]["code"] == code);
            ensure!(result["structuredContent"]["error"]["remote_state_unknown"] == false);
        }
        for (id, arguments) in [
            (
                200,
                json!({"host":"denied","path":"file","follow_symlinks":"true"}),
            ),
            (201, json!({"host":"denied","path":"file","sudo":true})),
        ] {
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"observe_stat","arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        ensure!(
            server.response(300).await?["result"]["structuredContent"]["data"]["mode"]
                == "configured"
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
    no_remote_dispatch(&stderr)?;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["tool"] != "observe_stat" || record["event"] == "reject",
            "invalid stat was accepted before validation"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_limits_and_policy_reject_before_ssh_dispatch() -> Result<()> {
    let (mut server, directory) =
        server_with_config("capabilities = { file_read = true }\n[targets]\n")?;
    let scenario = async {
        server.initialize().await?;
        for (index, (arguments, code)) in [
            (json!({"host":"denied","path":""}), "invalid_argument"),
            (json!({"host":"denied","path":"a\0b"}), "invalid_argument"),
            (
                json!({"host":"denied","path":"dir","max_entries":0}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"dir","max_entries":1001}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"dir","max_entries":18446744073709551615u64}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"dir","timeout_secs":0}),
                "invalid_argument",
            ),
            (
                json!({"host":"denied","path":"literal~$*' \n"}),
                "policy_denied",
            ),
            (
                json!({"host":"denied","path":"dir","max_entries":1}),
                "policy_denied",
            ),
            (
                json!({"host":"denied","path":"dir","max_entries":1000}),
                "policy_denied",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 100 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"inspect_directory","arguments":arguments}}))
                .await?;
            let called = server.response(id).await?;
            let result = &called["result"];
            ensure!(result["isError"] == true);
            ensure!(result["structuredContent"]["data"].is_null());
            ensure!(result["structuredContent"]["error"]["code"] == code);
            ensure!(result["structuredContent"]["error"]["remote_state_unknown"] == false);
        }
        for (index, arguments) in [
            json!({"host":"denied","path":"dir","max_entries":-1}),
            json!({"host":"denied","path":"dir","max_entries":"1"}),
            json!({"host":"denied","path":"dir","recursive":true}),
            json!({"host":"denied","path":"dir","sudo":true}),
            json!({"host":"denied","path":"dir","continuation":"PRIVATE_BAD_TOKEN"}),
            json!({"host":"denied","path":"dir","expires_in_secs":1}),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 200 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"inspect_directory","arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(record["tool"] != "inspect_directory" || record["event"] == "reject");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_validation_and_policy_precede_any_ssh_dispatch() -> Result<()> {
    let (mut server, directory) = server_with_config(indoc::indoc! {"
        capabilities = { file_read = true, file_write = true }
        [limits]
        max_file_bytes = 4
        [targets]
    "})?;
    let scenario = async {
        server.initialize().await?;
        for (index, (arguments, code)) in [
            (json!({"host":"denied","path":"","content":""}), "invalid_argument"),
            (json!({"host":"denied","path":"a\0b","content":""}), "invalid_argument"),
            (json!({"host":"denied","path":"file","content":"","timeout_secs":0}), "invalid_argument"),
            (json!({"host":"denied","path":"file","content":"12345"}), "invalid_argument"),
            // Byte length, not scalar count, enforces the file cap.
            (json!({"host":"denied","path":"file","content":"雪é"}), "invalid_argument"),
            (json!({"host":"denied","path":"file","content":"AAECAwQ=","encoding":"base64"}), "invalid_argument"),
            // Standard padded base64 only: no URL-safe alphabet, whitespace,
            // missing/excess padding, or nonzero discarded trailing bits.
            (json!({"host":"denied","path":"file","content":"_w==","encoding":"base64"}), "invalid_encoding"),
            (json!({"host":"denied","path":"file","content":"YQ","encoding":"base64"}), "invalid_encoding"),
            (json!({"host":"denied","path":"file","content":"YQ===","encoding":"base64"}), "invalid_encoding"),
            (json!({"host":"denied","path":"file","content":"YQ==\n","encoding":"base64"}), "invalid_encoding"),
            (json!({"host":"denied","path":"file","content":"YR==","encoding":"base64"}), "invalid_encoding"),
            (json!({"host":"denied","path":"literal~$*' \n","content":""}), "policy_denied"),
            (json!({"host":"denied","path":"file","content":"é\0x"}), "policy_denied"),
            (json!({"host":"denied","path":"file","content":"AP+AQQ==","encoding":"base64","overwrite":true}), "policy_denied"),
        ].into_iter().enumerate() {
            let id = 100 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"change_file_write","arguments":arguments}})).await?;
            let called = server.response(id).await?;
            let result = &called["result"];
            let reply = &result["structuredContent"];
            ensure!(result["isError"] == true);
            ensure!(reply["data"].is_null() && reply["error"]["code"] == code,
                "write rejection {index}: {called}");
            ensure!(reply["error"]["remote_state_unknown"] == false);
            let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().context("text compatibility result")?)?;
            ensure!(text == *reply);
        }
        for (index, arguments) in [
            json!({"host":"denied","path":"file"}),
            json!({"host":"denied","path":"file","content":null}),
            json!({"host":"denied","path":42,"content":"x"}),
            json!({"host":"denied","path":"file","content":["x"]}),
            json!({"host":"denied","path":"file","content":"x","encoding":"hex"}),
            json!({"host":"denied","path":"file","content":"x","overwrite":"true"}),
            json!({"host":"denied","path":"file","content":"x","timeout_secs":-1}),
            json!({"host":"denied","path":"file","content":"x","sudo":true}),
            json!({"host":"denied","path":"file","content":"x","append":true}),
            json!({"host":"denied","path":"file","content":"x","retry_on_connection_loss":true}),
        ].into_iter().enumerate() {
            let id = 200 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"change_file_write","arguments":arguments}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602,
                "wrong-shaped write {index} reached the handler");
        }
        server.send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}})).await?;
        let healthy = server.response(300).await?;
        ensure!(discovery_data(&healthy["result"], "configured")?["targets"] == json!([]));
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    let removed = directory.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["tool"] != "change_file_write" || record["event"] == "reject",
            "invalid write was admitted before validation"
        );
        for field in ["path", "content", "payload"] {
            ensure!(
                record.get(field).is_none(),
                "write rejection audit disclosed {field}"
            );
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mkdir_validation_and_private_inputs_reject_before_ssh_dispatch() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    let probe = directory.path().join("mkdir-must-not-probe");
    std::fs::write(
        directory.path().join("replacement.conf"),
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    std::fs::write(
        &path,
        indoc::indoc! {"
            capabilities = { file_read = true, file_write = true }
            [ssh]
            config_file = 'replacement.conf'
            [limits]
            connect_timeout_secs = 1
            operation_timeout_secs = 2
            max_timeout_secs = 3
            [targets.allowed]
            ssh_host = 'mkdir-private-backend.invalid'
        "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        for (index, (label, arguments, code)) in [
            (
                "empty path",
                json!({"host":"allowed","path":""}),
                "invalid_argument",
            ),
            (
                "NUL path",
                json!({"host":"allowed","path":"MKDIR_PRIVATE_PATH\0tail"}),
                "invalid_argument",
            ),
            (
                "zero timeout",
                json!({"host":"allowed","path":"MKDIR_PRIVATE_PATH","timeout_secs":0}),
                "invalid_argument",
            ),
            (
                "configured timeout ceiling",
                json!({"host":"allowed","path":"MKDIR_PRIVATE_PATH","timeout_secs":4}),
                "invalid_argument",
            ),
            (
                "literal path reaches policy",
                json!({"host":"denied","path":"MKDIR_PRIVATE_PATH 雪 ~/$*'\"\n"}),
                "policy_denied",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 100 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"change_mkdir","arguments":arguments}}))
                .await?;
            let called = server.response(id).await?;
            ensure!(
                called.get("error").is_none(),
                "{label}: route rejected valid shape"
            );
            let result = &called["result"];
            let reply = &result["structuredContent"];
            ensure!(result["isError"] == true, "{label}: expected tool error");
            ensure!(
                reply["data"].is_null() && reply["error"]["code"] == code,
                "{label}: wrong rejection"
            );
            ensure!(
                reply["error"]["remote_state_unknown"] == false,
                "{label}: mutation uncertainty"
            );
            let text: Value = serde_json::from_str(
                result["content"][0]["text"]
                    .as_str()
                    .context("mkdir error text")?,
            )?;
            ensure!(text == *reply, "{label}: text/structured mismatch");
            let encoded = serde_json::to_string(&called)?;
            ensure!(
                !encoded.contains("MKDIR_PRIVATE_PATH")
                    && !encoded.contains("mkdir-private-backend"),
                "{label}: rejection disclosed private input"
            );
        }
        for (index, (control, value)) in [
            ("recursive", json!(true)),
            ("mode", json!(448)),
            ("permissions", json!(448)),
            ("sudo", json!(true)),
            ("exist_ok", json!(true)),
            ("timeout_secs", json!(-1)),
        ]
        .into_iter()
        .enumerate()
        {
            let id = 200 + index as u64;
            let mut arguments = json!({"host":"allowed","path":"MKDIR_PRIVATE_PATH"});
            arguments[control] = value;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"change_mkdir","arguments":arguments}}))
                .await?;
            let rejected = server.response(id).await?;
            ensure!(
                rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                "{control}: malformed mkdir control reached handler"
            );
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"observe_targets","arguments":{}}}))
            .await?;
        let healthy = server.response(300).await?;
        ensure!(
            discovery_data(&healthy["result"], "configured")?["targets"][0]["name"] == "allowed"
        );
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
        "mkdir rejection evaluated SSH configuration"
    );
    let audit = std::str::from_utf8(&stderr)?;
    ensure!(
        !audit.contains("MKDIR_PRIVATE_PATH") && !audit.contains("mkdir-private-backend"),
        "mkdir rejection audit disclosed private input"
    );
    for line in audit.lines() {
        let record: Value = serde_json::from_str(line)?;
        ensure!(
            record["tool"] != "change_mkdir" || record["event"] == "reject",
            "mkdir admitted before prevalidation"
        );
        for field in ["path", "content", "payload"] {
            ensure!(record.get(field).is_none(), "mkdir audit disclosed {field}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_rename_validation_schema_and_private_inputs_reject_before_ssh_dispatch() -> Result<()>
{
    for modern in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator.toml");
        let probe = directory.path().join("rename-must-not-probe");
        std::fs::write(
            directory.path().join("replacement.conf"),
            format!(
                "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                probe.display()
            ),
        )?;
        std::fs::write(
            &path,
            indoc::indoc! {"
            capabilities = { file_read = true, file_write = true }
            [ssh]
            config_file = 'replacement.conf'
            [limits]
            connect_timeout_secs = 1
            operation_timeout_secs = 2
            max_timeout_secs = 3
            [targets.allowed]
            ssh_host = 'rename-private-backend.invalid'
        "},
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
            let rename = listed["result"]["tools"]
                .as_array()
                .context("tool catalog")?
                .iter()
                .find(|tool| tool["name"] == "change_rename")
                .context("rename route")?;
            ensure!(rename["annotations"]["readOnlyHint"] == false);
            ensure!(rename["annotations"]["destructiveHint"] == true);
            ensure!(rename["annotations"]["idempotentHint"] == false);
            let input = &rename["inputSchema"];
            ensure!(input["type"] == "object" && input["additionalProperties"] == false);
            let mut fields: Vec<&str> = input["properties"]
                .as_object()
                .context("rename input fields")?
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            ensure!(fields == ["destination", "host", "overwrite", "source", "timeout_secs"]);
            let mut required: Vec<&str> = input["required"]
                .as_array()
                .context("rename required fields")?
                .iter()
                .map(|field| field.as_str().context("required field"))
                .collect::<Result<_>>()?;
            required.sort_unstable();
            ensure!(required == ["destination", "host", "overwrite", "source"]);
            ensure!(input["properties"]["overwrite"]["type"] == "boolean");
            ensure!(input["properties"]["overwrite"]["const"] == true);
            for field in ["source", "destination"] {
                ensure!(input["properties"][field]["type"] == "string");
                ensure!(
                    !schema_has_property(&rename["outputSchema"], field),
                    "rename output schema publishes private {field}"
                );
            }
            ensure!(schema_has_property(&rename["outputSchema"], "renamed"));
            ensure!(schema_has_property(
                &rename["outputSchema"],
                "remote_state_unknown"
            ));
            let valid = json!({
                "host":"allowed", "source":"RENAME_PRIVATE_SOURCE 雪 ~/$*'\"\n",
                "destination":"RENAME_PRIVATE_DESTINATION {{literal}}\n", "overwrite":true
            });
            for (index, (label, field, value, code)) in [
                ("empty source", "source", json!(""), "invalid_argument"),
                (
                    "NUL source",
                    "source",
                    json!("RENAME_PRIVATE_SOURCE\0tail"),
                    "invalid_argument",
                ),
                (
                    "empty destination",
                    "destination",
                    json!(""),
                    "invalid_argument",
                ),
                (
                    "NUL destination",
                    "destination",
                    json!("RENAME_PRIVATE_DESTINATION\0tail"),
                    "invalid_argument",
                ),
                ("zero timeout", "timeout_secs", json!(0), "invalid_argument"),
                (
                    "configured timeout ceiling",
                    "timeout_secs",
                    json!(4),
                    "invalid_argument",
                ),
                (
                    "literal paths reach policy",
                    "host",
                    json!("denied"),
                    "policy_denied",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 100 + index as u64;
                let mut arguments = valid.clone();
                arguments[field] = value;
                let params = json!({"name":"change_rename","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let called = server.response(id).await?;
                ensure!(
                    called.get("error").is_none(),
                    "{label}: valid shape rejected"
                );
                let result = &called["result"];
                let reply = &result["structuredContent"];
                ensure!(
                    result["isError"] == true && reply["data"].is_null(),
                    "{label}"
                );
                ensure!(reply["error"]["code"] == code, "{label}: wrong rejection");
                ensure!(
                    reply["error"]["remote_state_unknown"] == false,
                    "{label}: mutation uncertainty"
                );
                let text: Value = serde_json::from_str(
                    result["content"][0]["text"]
                        .as_str()
                        .context("rename error text")?,
                )?;
                ensure!(text == *reply, "{label}: text/structured mismatch");
                let encoded = serde_json::to_string(&called)?;
                for secret in [
                    "RENAME_PRIVATE_SOURCE",
                    "RENAME_PRIVATE_DESTINATION",
                    "rename-private-backend",
                ] {
                    ensure!(
                        !encoded.contains(secret),
                        "{label}: private input disclosed"
                    );
                }
            }
            for (index, (control, value)) in [
                ("recursive", json!(true)),
                ("mode", json!(448)),
                ("permissions", json!(448)),
                ("sudo", json!(true)),
                ("path", json!("RENAME_PRIVATE_SOURCE")),
                ("overwrite", json!("true")),
                ("overwrite", json!(1)),
                ("overwrite", Value::Null),
                ("timeout_secs", json!(-1)),
                ("source", json!(false)),
                ("destination", json!(42)),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 200 + index as u64;
                let mut arguments = valid.clone();
                arguments[control] = value;
                let params = json!({"name":"change_rename","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                ensure!(
                    rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                    "{control}: malformed rename control reached handler"
                );
                ensure!(
                    !serde_json::to_string(&rejected)?.contains("RENAME_PRIVATE_"),
                    "shape error disclosed paths"
                );
            }
            let params = json!({"name":"observe_targets","arguments":{}});
            let request = if modern {
                modern_request(json!(300), "tools/call", params, MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":300,"method":"tools/call","params":params})
            };
            server.send(request).await?;
            let healthy = server.response(300).await?;
            ensure!(
                discovery_data(&healthy["result"], "configured")?["targets"][0]["name"]
                    == "allowed"
            );
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
            "rename rejection evaluated SSH configuration"
        );
        let audit = std::str::from_utf8(&stderr)?;
        for secret in [
            "RENAME_PRIVATE_SOURCE",
            "RENAME_PRIVATE_DESTINATION",
            "rename-private-backend",
        ] {
            ensure!(
                !audit.contains(secret),
                "rename rejection audit disclosed private input"
            );
        }
        for line in audit.lines() {
            let record: Value = serde_json::from_str(line)?;
            ensure!(
                record["tool"] != "change_rename" || record["event"] == "reject",
                "rename admitted before prevalidation"
            );
            for field in ["source", "destination", "path", "content", "payload"] {
                ensure!(
                    record.get(field).is_none(),
                    "rename audit disclosed {field}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_remove_file_validation_schema_and_private_inputs_reject_before_ssh_dispatch()
-> Result<()> {
    remove_validation_schema_and_private_inputs_reject_before_ssh_dispatch("change_file_remove")
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_remove_directory_validation_schema_and_private_inputs_reject_before_ssh_dispatch()
-> Result<()> {
    remove_validation_schema_and_private_inputs_reject_before_ssh_dispatch(
        "change_directory_remove",
    )
    .await
}

async fn remove_validation_schema_and_private_inputs_reject_before_ssh_dispatch(
    tool: &str,
) -> Result<()> {
    for modern in [false, true] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("operator.toml");
        let probe = directory.path().join("remove-file-must-not-probe");
        std::fs::write(
            directory.path().join("replacement.conf"),
            format!(
                "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                probe.display()
            ),
        )?;
        std::fs::write(
            &path,
            indoc::indoc! {"
            capabilities = { file_read = true, file_write = true }
            [ssh]
            config_file = 'replacement.conf'
            [limits]
            connect_timeout_secs = 1
            operation_timeout_secs = 2
            max_timeout_secs = 3
            [targets.allowed]
            ssh_host = 'remove-file-private-backend.invalid'
        "},
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
            let remove = listed["result"]["tools"]
                .as_array()
                .context("tool catalog")?
                .iter()
                .find(|entry| entry["name"] == tool)
                .context("remove file route")?;
            ensure!(remove["annotations"]["readOnlyHint"] == false);
            ensure!(remove["annotations"]["destructiveHint"] == true);
            ensure!(remove["annotations"]["idempotentHint"] == false);
            let input = &remove["inputSchema"];
            ensure!(input["type"] == "object" && input["additionalProperties"] == false);
            let mut fields: Vec<&str> = input["properties"]
                .as_object()
                .context("remove file input fields")?
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            ensure!(fields == ["host", "path", "timeout_secs"]);
            let mut required: Vec<&str> = input["required"]
                .as_array()
                .context("remove file required fields")?
                .iter()
                .map(|field| field.as_str().context("required field"))
                .collect::<Result<_>>()?;
            required.sort_unstable();
            ensure!(required == ["host", "path"]);
            ensure!(input["properties"]["host"]["type"] == "string");
            ensure!(input["properties"]["path"]["type"] == "string");
            ensure!(schema_has_property(&remove["outputSchema"], "removed"));
            ensure!(schema_has_property(
                &remove["outputSchema"],
                "remote_state_unknown"
            ));
            for field in ["path", "source", "destination", "content", "payload"] {
                ensure!(
                    !schema_has_property(&remove["outputSchema"], field),
                    "remove file output schema publishes private {field}"
                );
            }
            let valid = json!({
                "host":"allowed", "path":"REMOVE_FILE_PRIVATE_PATH 雪 ~/$*'\"\n"
            });
            for (index, (label, field, value, code)) in [
                ("empty path", "path", json!(""), "invalid_argument"),
                (
                    "NUL path",
                    "path",
                    json!("REMOVE_FILE_PRIVATE_PATH\0tail"),
                    "invalid_argument",
                ),
                ("zero timeout", "timeout_secs", json!(0), "invalid_argument"),
                (
                    "configured timeout ceiling",
                    "timeout_secs",
                    json!(4),
                    "invalid_argument",
                ),
                (
                    "literal path reaches policy",
                    "host",
                    json!("denied"),
                    "policy_denied",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 100 + index as u64;
                let mut arguments = valid.clone();
                arguments[field] = value;
                let params = json!({"name":tool,"arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let called = server.response(id).await?;
                ensure!(
                    called.get("error").is_none(),
                    "{label}: valid shape rejected"
                );
                let result = &called["result"];
                let reply = &result["structuredContent"];
                ensure!(
                    result["isError"] == true && reply["data"].is_null(),
                    "{label}"
                );
                ensure!(reply["error"]["code"] == code, "{label}: wrong rejection");
                ensure!(
                    reply["error"]["remote_state_unknown"] == false,
                    "{label}: mutation uncertainty"
                );
                let text: Value = serde_json::from_str(
                    result["content"][0]["text"]
                        .as_str()
                        .context("remove file error text")?,
                )?;
                ensure!(text == *reply, "{label}: text/structured mismatch");
                let encoded = serde_json::to_string(&called)?;
                for secret in ["REMOVE_FILE_PRIVATE_PATH", "remove-file-private-backend"] {
                    ensure!(
                        !encoded.contains(secret),
                        "{label}: private input disclosed"
                    );
                }
            }
            // Inclusive timeout boundaries and the optional default must reach
            // target policy, not be mistaken for malformed destructive calls.
            for (index, requested_timeout) in
                [json!(1), json!(3), Value::Null].into_iter().enumerate()
            {
                let id = 150 + index as u64;
                let mut arguments = valid.clone();
                arguments["host"] = json!("denied");
                arguments["timeout_secs"] = requested_timeout;
                let params = json!({"name":tool,"arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                profile_policy_denied(&rejected)?;
                ensure!(
                    !serde_json::to_string(&rejected)?.contains("REMOVE_FILE_PRIVATE_"),
                    "{tool}: timeout-boundary policy rejection disclosed private input"
                );
            }
            for (index, (control, value)) in [
                ("recursion", json!(true)),
                ("recursive", json!(true)),
                ("overwrite", json!(true)),
                ("sudo", json!(true)),
                ("missing_ok", json!(true)),
                ("follow_symlinks", json!(true)),
                ("mode", json!(448)),
                ("permissions", json!(448)),
                ("command", json!("REMOVE_FILE_PRIVATE_COMMAND")),
                ("argv", json!(["REMOVE_FILE_PRIVATE_ARGV"])),
                ("source", json!("REMOVE_FILE_PRIVATE_SOURCE")),
                ("destination", json!("REMOVE_FILE_PRIVATE_DESTINATION")),
                ("force", json!(true)),
                ("parents", json!(true)),
                ("dry_run", json!(true)),
                ("empty_only", json!(false)),
                ("no_follow", json!(true)),
                ("ssh_host", json!("REMOVE_FILE_PRIVATE_HOST")),
                ("config_file", json!("REMOVE_FILE_PRIVATE_CONFIG")),
                ("content", json!("REMOVE_FILE_PRIVATE_CONTENT")),
                ("timeout_secs", json!(-1)),
                ("timeout_secs", json!(1.5)),
                ("timeout_secs", json!("1")),
                ("path", json!(false)),
                ("path", Value::Null),
                ("host", json!(42)),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 200 + index as u64;
                let mut arguments = valid.clone();
                arguments[control] = value;
                let params = json!({"name":tool,"arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                ensure!(
                    rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                    "{control}: malformed remove file control reached handler"
                );
                ensure!(
                    !serde_json::to_string(&rejected)?.contains("REMOVE_FILE_PRIVATE_"),
                    "shape error disclosed private input"
                );
            }
            for (index, field) in ["host", "path"].into_iter().enumerate() {
                let id = 250 + index as u64;
                let mut arguments = valid.clone();
                arguments
                    .as_object_mut()
                    .context("remove file arguments")?
                    .remove(field);
                let params = json!({"name":tool,"arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                ensure!(
                    rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                    "missing {field}: malformed remove file request reached handler"
                );
                ensure!(!serde_json::to_string(&rejected)?.contains("REMOVE_FILE_PRIVATE_"));
            }
            let params = json!({"name":"observe_targets","arguments":{}});
            let request = if modern {
                modern_request(json!(300), "tools/call", params, MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":300,"method":"tools/call","params":params})
            };
            server.send(request).await?;
            let healthy = server.response(300).await?;
            ensure!(
                discovery_data(&healthy["result"], "configured")?["targets"][0]["name"]
                    == "allowed"
            );
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
            "remove file rejection evaluated SSH configuration"
        );
        let audit = std::str::from_utf8(&stderr)?;
        for secret in ["REMOVE_FILE_PRIVATE_", "remove-file-private-backend"] {
            ensure!(
                !audit.contains(secret),
                "remove file audit disclosed private input"
            );
        }
        for line in audit.lines() {
            let record: Value = serde_json::from_str(line)?;
            ensure!(
                record["tool"] != tool || record["event"] == "reject",
                "remove file admitted before prevalidation"
            );
            for field in ["source", "destination", "path", "content", "payload"] {
                ensure!(
                    record.get(field).is_none(),
                    "remove file audit disclosed {field}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_replace_file_validation_schema_and_privacy_precede_ssh() -> Result<()> {
    for modern in [false, true] {
        let directory = tempfile::tempdir()?;
        let config = directory.path().join("operator.toml");
        let probe = directory.path().join("replace-must-not-probe");
        std::fs::write(
            directory.path().join("replacement.conf"),
            format!(
                "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
                probe.display()
            ),
        )?;
        std::fs::write(
            &config,
            indoc::indoc! {"
                capabilities = { file_read = true, file_write = true }
                [ssh]
                config_file = 'replacement.conf'
                [limits]
                max_file_bytes = 4
                connect_timeout_secs = 1
                operation_timeout_secs = 2
                max_timeout_secs = 3
                [targets.allowed]
                ssh_host = 'replace-private-backend.invalid'
            "},
        )?;
        let mut server = Server::start(&["--config", config.to_str().context("config path")?])?;
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
            let replace = listed["result"]["tools"]
                .as_array()
                .context("tool catalog")?
                .iter()
                .find(|tool| tool["name"] == "change_file_replace")
                .context("replace route")?;
            ensure!(replace["annotations"]["readOnlyHint"] == false);
            ensure!(replace["annotations"]["destructiveHint"] == true);
            ensure!(replace["annotations"]["idempotentHint"] == false);
            let input = &replace["inputSchema"];
            ensure!(input["type"] == "object" && input["additionalProperties"] == false);
            let mut fields: Vec<&str> = input["properties"]
                .as_object()
                .context("replace input fields")?
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            ensure!(
                fields
                    == [
                        "content",
                        "encoding",
                        "host",
                        "overwrite",
                        "path",
                        "timeout_secs"
                    ]
            );
            let mut required: Vec<&str> = input["required"]
                .as_array()
                .context("replace required fields")?
                .iter()
                .map(|field| field.as_str().context("required field"))
                .collect::<Result<_>>()?;
            required.sort_unstable();
            ensure!(required == ["content", "host", "overwrite", "path"]);
            ensure!(input["properties"]["overwrite"]["type"] == "boolean");
            for field in ["host", "path", "content"] {
                ensure!(input["properties"][field]["type"] == "string");
            }
            ensure!(schema_has_property(
                &replace["outputSchema"],
                "bytes_written"
            ));
            ensure!(schema_has_property(
                &replace["outputSchema"],
                "remote_state_unknown"
            ));
            for field in [
                "path",
                "content",
                "payload",
                "source",
                "destination",
                "staging_path",
            ] {
                ensure!(
                    !schema_has_property(&replace["outputSchema"], field),
                    "replace output schema disclosed {field}"
                );
            }
            let valid = json!({
                "host":"allowed", "path":"REPLACE_PRIVATE_PATH 雪 ~/$*'\"\n{{literal}}",
                "content":"x", "overwrite":true
            });
            for (index, (label, field, value, code)) in [
                (
                    "explicit refusal",
                    "overwrite",
                    json!(false),
                    "invalid_argument",
                ),
                ("empty path", "path", json!(""), "invalid_argument"),
                (
                    "NUL path",
                    "path",
                    json!("REPLACE_PRIVATE_PATH\0tail"),
                    "invalid_argument",
                ),
                ("root", "path", json!("/"), "invalid_argument"),
                ("repeated root", "path", json!("///"), "invalid_argument"),
                (
                    "trailing slash",
                    "path",
                    json!("REPLACE_PRIVATE_PATH/"),
                    "invalid_argument",
                ),
                (
                    "repeated trailing slash",
                    "path",
                    json!("a//"),
                    "invalid_argument",
                ),
                ("dot", "path", json!("."), "invalid_argument"),
                ("dotdot", "path", json!(".."), "invalid_argument"),
                ("final dot", "path", json!("a//."), "invalid_argument"),
                ("final dotdot", "path", json!("/a/.."), "invalid_argument"),
                ("zero timeout", "timeout_secs", json!(0), "invalid_argument"),
                (
                    "timeout ceiling",
                    "timeout_secs",
                    json!(4),
                    "invalid_argument",
                ),
                ("ASCII cap", "content", json!("12345"), "invalid_argument"),
                ("UTF8 byte cap", "content", json!("雪é"), "invalid_argument"),
                (
                    "private payload cap",
                    "content",
                    json!("REPLACE_PRIVATE_CONTENT"),
                    "invalid_argument",
                ),
                ("literal path", "host", json!("denied"), "policy_denied"),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 100 + index as u64;
                let mut arguments = valid.clone();
                arguments[field] = value;
                let params = json!({"name":"change_file_replace","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let called = server.response(id).await?;
                let result = &called["result"];
                let reply = &result["structuredContent"];
                ensure!(called.get("error").is_none(), "{label}: shape rejected");
                ensure!(
                    result["isError"] == true && reply["data"].is_null(),
                    "{label}"
                );
                ensure!(reply["error"]["code"] == code, "{label}: {called}");
                ensure!(reply["error"]["remote_state_unknown"] == false, "{label}");
                let text: Value = serde_json::from_str(
                    result["content"][0]["text"]
                        .as_str()
                        .context("replace error text")?,
                )?;
                ensure!(text == *reply, "{label}: text/structured mismatch");
                ensure!(!serde_json::to_string(&called)?.contains("REPLACE_PRIVATE_"));
            }
            // Valid boundary payloads must reach policy, while malformed or
            // oversized encodings must fail even for an allowed target.
            for (index, (host, path, content, encoding, requested_timeout, code)) in [
                (
                    "allowed",
                    "file",
                    "AAECAwQ=",
                    "base64",
                    json!(1),
                    "invalid_argument",
                ),
                (
                    "allowed",
                    "file",
                    "_w==",
                    "base64",
                    json!(1),
                    "invalid_encoding",
                ),
                (
                    "allowed",
                    "file",
                    "YQ",
                    "base64",
                    json!(1),
                    "invalid_encoding",
                ),
                (
                    "allowed",
                    "file",
                    "YQ===",
                    "base64",
                    json!(1),
                    "invalid_encoding",
                ),
                (
                    "allowed",
                    "file",
                    "YQ==\n",
                    "base64",
                    json!(1),
                    "invalid_encoding",
                ),
                (
                    "allowed",
                    "file",
                    "YR==",
                    "base64",
                    json!(1),
                    "invalid_encoding",
                ),
                ("denied", "file", "", "utf8", Value::Null, "policy_denied"),
                ("denied", "file", "é\0x", "utf8", json!(1), "policy_denied"),
                ("denied", "file", "1234", "utf8", json!(3), "policy_denied"),
                (
                    "denied",
                    "file",
                    "AP+AQQ==",
                    "base64",
                    json!(3),
                    "policy_denied",
                ),
                ("denied", "file", "", "base64", Value::Null, "policy_denied"),
                (
                    "denied",
                    "/a//.././REPLACE_PRIVATE_PATH",
                    "x",
                    "utf8",
                    json!(1),
                    "policy_denied",
                ),
                (
                    "denied",
                    "a/..hidden",
                    "x",
                    "utf8",
                    json!(1),
                    "policy_denied",
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 150 + index as u64;
                let arguments = json!({
                    "host":host,"path":path,"content":content,"encoding":encoding,
                    "overwrite":true,"timeout_secs":requested_timeout
                });
                let params = json!({"name":"change_file_replace","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let called = server.response(id).await?;
                let result = &called["result"];
                let reply = &result["structuredContent"];
                ensure!(called.get("error").is_none(), "encoding case {index}");
                ensure!(result["isError"] == true && reply["data"].is_null());
                ensure!(
                    reply["error"]["code"] == code,
                    "encoding case {index}: {called}"
                );
                ensure!(reply["error"]["remote_state_unknown"] == false);
                let text: Value = serde_json::from_str(
                    result["content"][0]["text"]
                        .as_str()
                        .context("replace error text")?,
                )?;
                ensure!(text == *reply);
                ensure!(!serde_json::to_string(&called)?.contains("REPLACE_PRIVATE_"));
            }
            for (index, (field, value)) in [
                ("overwrite", Value::Null),
                ("overwrite", json!("true")),
                ("overwrite", json!(1)),
                ("host", json!(42)),
                ("path", Value::Null),
                ("content", Value::Null),
                ("content", json!(["x"])),
                ("encoding", json!("hex")),
                ("timeout_secs", json!(-1)),
                ("timeout_secs", json!(1.5)),
                ("timeout_secs", json!("1")),
                ("sudo", json!(true)),
                ("append", json!(true)),
                ("mode", json!(384)),
                ("permissions", json!(384)),
                ("recursive", json!(true)),
                ("follow_symlinks", json!(false)),
                ("parents", json!(true)),
                ("retry_on_connection_loss", json!(true)),
                ("fsync", json!(true)),
                ("command", json!("REPLACE_PRIVATE_COMMAND")),
                ("argv", json!(["REPLACE_PRIVATE_ARGV"])),
                ("ssh_host", json!("REPLACE_PRIVATE_HOST")),
                ("config_file", json!("REPLACE_PRIVATE_CONFIG")),
                ("source", json!("REPLACE_PRIVATE_SOURCE")),
                ("destination", json!("REPLACE_PRIVATE_DESTINATION")),
            ]
            .into_iter()
            .enumerate()
            {
                let id = 200 + index as u64;
                let mut arguments = valid.clone();
                arguments[field] = value;
                let params = json!({"name":"change_file_replace","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                ensure!(
                    rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                    "{field}: malformed replace reached handler"
                );
                ensure!(!serde_json::to_string(&rejected)?.contains("REPLACE_PRIVATE_"));
            }
            for (index, field) in ["host", "path", "content", "overwrite"]
                .into_iter()
                .enumerate()
            {
                let id = 250 + index as u64;
                let mut arguments = valid.clone();
                arguments
                    .as_object_mut()
                    .context("replace arguments")?
                    .remove(field);
                let params = json!({"name":"change_file_replace","arguments":arguments});
                let request = if modern {
                    modern_request(json!(id), "tools/call", params, MODERN_VERSION)
                } else {
                    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params})
                };
                server.send(request).await?;
                let rejected = server.response(id).await?;
                ensure!(
                    rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                    "missing {field}: replace reached handler"
                );
                ensure!(!serde_json::to_string(&rejected)?.contains("REPLACE_PRIVATE_"));
            }
            let params = json!({"name":"observe_targets","arguments":{}});
            let request = if modern {
                modern_request(json!(300), "tools/call", params, MODERN_VERSION)
            } else {
                json!({"jsonrpc":"2.0","id":300,"method":"tools/call","params":params})
            };
            server.send(request).await?;
            let healthy = server.response(300).await?;
            ensure!(
                discovery_data(&healthy["result"], "configured")?["targets"][0]["name"]
                    == "allowed"
            );
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
            "replace rejection evaluated SSH configuration"
        );
        let audit = std::str::from_utf8(&stderr)?;
        for secret in ["REPLACE_PRIVATE_", "replace-private-backend"] {
            ensure!(
                !audit.contains(secret),
                "replace audit disclosed private input"
            );
        }
        for line in audit.lines() {
            let record: Value = serde_json::from_str(line)?;
            ensure!(record["tool"] != "change_file_replace" || record["event"] == "reject");
            for field in [
                "path",
                "content",
                "payload",
                "source",
                "destination",
                "staging_path",
            ] {
                ensure!(
                    record.get(field).is_none(),
                    "replace audit disclosed {field}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_replace_file_modern_actual_id_budget_rejects_before_ssh() -> Result<()> {
    const MESSAGE_LIMIT: usize = 16_777_216;
    let (mut server, _directory) =
        server_with_config("capabilities = { file_read = true, file_write = true }\n[targets]\n")?;
    let scenario = timeout(Duration::from_secs(20), async {
        server
            .send(modern_request(
                json!(3),
                "tools/list",
                json!({}),
                MODERN_VERSION,
            ))
            .await?;
        let listed = server.response(3).await?;
        ensure!(
            listed["result"]["tools"]
                .as_array()
                .context("replace budget tool catalog")?
                .iter()
                .any(|tool| tool["name"] == "change_file_replace")
        );
        let mut request = modern_request(
            json!(""),
            "tools/call",
            json!({"name":"change_file_replace","arguments":{
                "host":"127.0.0.1","path":"REPLACE_PRIVATE_PATH",
                "content":"REPLACE_PRIVATE_CONTENT","overwrite":true
            }}),
            MODERN_VERSION,
        );
        let overhead = serde_json::to_vec(&request)?.len() + 1;
        let id = json!("i".repeat(MESSAGE_LIMIT - overhead - 1));
        request["id"] = id.clone();
        ensure!(serde_json::to_vec(&request)?.len() + 1 < MESSAGE_LIMIT);
        server.send(request).await?;
        let (rejected, bytes) = server.response_with_id(&id).await?;
        ensure!(rejected["id"] == id);
        ensure!(rejected["error"]["code"] == -32602 && rejected.get("result").is_none());
        ensure!(
            bytes <= MESSAGE_LIMIT,
            "actual-ID budget exceeded wire limit"
        );
        ensure!(!serde_json::to_string(&rejected)?.contains("REPLACE_PRIVATE_"));
        server
            .send(modern_request(
                json!(2),
                "tools/call",
                json!({"name":"observe_targets","arguments":{}}),
                MODERN_VERSION,
            ))
            .await?;
        let healthy = server.response(2).await?;
        ensure!(discovery_data(&healthy["result"], "configured")?["targets"] == json!([]));
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("replace actual-ID budget scenario timed out")
    .and_then(|result| result);
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    ensure!(!std::str::from_utf8(&stderr)?.contains("REPLACE_PRIVATE_"));
    Ok(())
}
