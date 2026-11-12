use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::timeout,
};

fn command(args: &[&str]) -> Command {
    let binary = std::env::var_os("SSH_MCP_TEST_BINARY").unwrap_or_else(|| {
        option_env!("SSH_MCP_TEST_BINARY")
            .unwrap_or(env!("CARGO_BIN_EXE_ssh-mcp"))
            .into()
    });
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SSH_MCP_") {
            command.env_remove(name);
        }
    }
    command.args(args).kill_on_drop(true);
    command
}

struct Server {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Server {
    fn start(args: &[&str]) -> Result<Self> {
        Self::from_command(command(args))
    }

    fn from_command(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("child stdin")?;
        let output = child.stdout.take().context("child stdout")?;
        let mut error = child.stderr.take().context("child stderr")?;
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new();
            error.read_to_end(&mut bytes).await?;
            Ok(bytes)
        });
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            stderr: Some(stderr),
        })
    }

    async fn send(&mut self, value: Value) -> Result<()> {
        let input = self.input.as_mut().context("stdin already closed")?;
        input.write_all(&serde_json::to_vec(&value)?).await?;
        input.write_all(b"\n").await?;
        input.flush().await?;
        Ok(())
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let input = self.input.as_mut().context("stdin already closed")?;
        input.write_all(bytes).await?;
        input.flush().await?;
        Ok(())
    }

    async fn frame(&mut self) -> Result<Option<(Value, usize)>> {
        let mut line = Vec::new();
        let size = timeout(Duration::from_secs(5), async {
            (&mut self.output)
                .take(16_777_217)
                .read_until(b'\n', &mut line)
                .await
        })
        .await??;
        if size == 0 {
            return Ok(None);
        }
        ensure!(size <= 16_777_216, "response exceeds 16 MiB: {size} bytes");
        ensure!(line.last() == Some(&b'\n'), "unterminated response");
        let value: Value = serde_json::from_slice(&line).context("non-JSON stdout")?;
        ensure!(value["jsonrpc"] == "2.0", "non-JSON-RPC stdout");
        Ok(Some((value, size)))
    }

    async fn response(&mut self, id: u64) -> Result<Value> {
        Ok(self.response_with_id(&json!(id)).await?.0)
    }

    async fn response_with_id(&mut self, id: &Value) -> Result<(Value, usize)> {
        loop {
            let (value, size) = self
                .frame()
                .await?
                .context("server closed stdout before response")?;
            if value.get("id") == Some(id) {
                ensure!(
                    value.get("result").is_some() ^ value.get("error").is_some(),
                    "correlated frame is not a JSON-RPC response"
                );
                return Ok((value, size));
            }
            ensure!(
                value.get("id").is_none() && value["method"].is_string(),
                "unexpected response ID or non-notification frame"
            );
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        self.send(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "stdio-acceptance", "version": "1"}
            }
        }))
        .await?;
        let initialized = self.response(1).await?;
        ensure!(initialized["result"]["protocolVersion"] == "2025-11-25");
        ensure!(initialized["result"]["capabilities"]["tools"].is_object());
        for unsupported in ["prompts", "resources", "tasks", "logging"] {
            ensure!(
                initialized["result"]["capabilities"]
                    .get(unsupported)
                    .is_none()
            );
        }
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
    }

    async fn close_stderr(&mut self) -> Result<()> {
        if let Some(stderr) = self.stderr.take() {
            stderr.abort();
            match stderr.await {
                Err(error) if error.is_cancelled() => {}
                Ok(result) => {
                    result?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    async fn sigterm(&mut self) -> Result<()> {
        kill(
            Pid::from_raw(i32::try_from(self.child.id().context("live server PID")?)?),
            Signal::SIGTERM,
        )?;
        // Keep stdin open: EOF must not mask the signal lifecycle.
        let status = timeout(Duration::from_secs(5), self.child.wait())
            .await
            .context("SIGTERM did not stop the server")??;
        ensure!(status.success(), "SIGTERM exit status: {status}");
        Ok(())
    }

    async fn finish(mut self) -> Result<(std::process::ExitStatus, Vec<u8>)> {
        drop(self.input.take());
        let status = match timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                bail!("server failed to exit after EOF");
            }
        };
        while let Some((frame, _)) = self.frame().await? {
            ensure!(
                frame.get("id").is_none() && frame["method"].is_string(),
                "uncorrelated response remained at EOF"
            );
        }
        let stderr = match self.stderr {
            Some(mut stderr) => match timeout(Duration::from_secs(5), &mut stderr).await {
                Ok(result) => result??,
                Err(_) => {
                    stderr.abort();
                    let _ = stderr.await;
                    bail!("stderr did not reach EOF after server exit");
                }
            },
            None => Vec::new(),
        };
        Ok((status, stderr))
    }
}

// Assert the public discovery envelope, not incidental default policy values.
fn discovery_data<'a>(result: &'a Value, mode: &str) -> Result<&'a Value> {
    ensure!(result["isError"] != true, "discovery returned a tool error");
    let structured = &result["structuredContent"];
    ensure!(structured.get("error") == Some(&Value::Null));
    let data = &structured["data"];
    ensure!(data["mode"] == mode);
    ensure!(data["targets"].is_array());
    let limits = &data["limits"];
    for field in [
        "connect_timeout_secs",
        "operation_timeout_secs",
        "max_timeout_secs",
        "max_output_bytes",
        "max_file_bytes",
        "max_stdin_bytes",
        "max_command_bytes",
        "max_encoded_command_bytes",
        "max_response_bytes",
    ] {
        ensure!(
            limits[field].as_u64().is_some(),
            "missing numeric limit {field}"
        );
    }
    ensure!(limits["max_stdin_bytes"] == limits["max_file_bytes"]);
    ensure!(limits["max_command_bytes"] == 65_536);
    ensure!(limits["max_encoded_command_bytes"] == 65_536);
    ensure!(limits["max_response_bytes"] == 16_777_216);
    let content = result["content"]
        .as_array()
        .context("discovery text content")?;
    ensure!(content.len() == 1);
    ensure!(content[0]["type"] == "text");
    let text: Value = serde_json::from_str(content[0]["text"].as_str().context("discovery text")?)?;
    ensure!(text == *structured, "discovery text/structured mismatch");
    Ok(data)
}

#[tokio::test]
async fn lifecycle_discovery_and_eof_keep_stdout_protocol_only() -> Result<()> {
    let mut server = Server::start(&[])?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools list")?;
        ensure!(tools.iter().any(|tool| tool["name"] == "ssh_targets"));
        ensure!(!tools.iter().any(|tool| tool["name"] == "ssh_sudo"));
        let run = tools.iter().find(|tool| tool["name"] == "ssh_run")
            .context("run absent from legacy discovery")?;
        ensure!(run["annotations"]["readOnlyHint"] == false);
        ensure!(run["annotations"]["destructiveHint"] == true);
        ensure!(run["annotations"]["idempotentHint"] == false);
        let write = tools.iter().find(|tool| tool["name"] == "ssh_write_file")
            .context("write absent from legacy discovery")?;
        ensure!(write["annotations"]["readOnlyHint"] == false);
        ensure!(write["annotations"]["destructiveHint"] == true);
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        let called = server.response(3).await?;
        let result = &called["result"];
        ensure!(discovery_data(result, "open")?["targets"] == json!([]));
        ensure!(result["isError"] != true);
        let content = result["content"].as_array().context("text compatibility content")?;
        ensure!(content.len() == 1);
        let text: Value = serde_json::from_str(content[0]["text"].as_str().context("text")?)?;
        ensure!(text == result["structuredContent"]);
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_targets","arguments":{"extra":true}}})).await?;
        ensure!(server.response(4).await?["error"]["code"] == -32602);
        server.send(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ssh_sudo","arguments":{}}})).await?;
        ensure!(server.response(5).await?.get("error").is_some());
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, _) = finished?;
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
                ("SSH_MCP_CONNECT_TIMEOUT_SECS", "11"),
                ("SSH_MCP_OPERATION_TIMEOUT_SECS", "13"),
                ("SSH_MCP_MAX_TIMEOUT_SECS", "17"),
                ("SSH_MCP_MAX_OUTPUT_BYTES", "33554432"),
                ("SSH_MCP_MAX_FILE_BYTES", "33554433"),
            ]);
        }
        let mut server = Server::from_command(child)?;
        let scenario = async {
            if !override_limits {
                server.initialize().await?;
            }
            let id = 2;
            let modern = override_limits;
            let params = json!({"name":"ssh_targets","arguments":{}});
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
                        "ssh_exec",
                        "ssh_list_directory",
                        "ssh_read_file",
                        "ssh_run",
                        "ssh_stat",
                        "ssh_sudo",
                        "ssh_write_file"
                    ])
                } else {
                    json!([
                        "ssh_exec",
                        "ssh_list_directory",
                        "ssh_read_file",
                        "ssh_run",
                        "ssh_stat",
                        "ssh_write_file"
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
            "params":{"name":"ssh_targets","arguments":{}}}))
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
            "params":{"name":"ssh_targets","arguments":{}}});
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
            "params":{"name":"ssh_targets","arguments":{}}}))
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
    let path = dir.path().join("operator.toml");
    for text in [
        "[ssh]\nsecret_marker='secret_marker'",
        "[limits]\noperation_timeout_secs='secret_marker'",
        "[targets.secret_marker]\nssh_host='ordinary'\n[targets.secret_marker.sudo]\nmode='secret_marker'",
        "secret_marker = [broken",
    ] {
        std::fs::write(&path, text)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(!output.status.success());
        ensure!(
            output.stdout.is_empty(),
            "invalid configuration started a protocol session"
        );
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("secret_marker"));
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(diagnostic["code"] == "invalid_config", "{diagnostic}");
    }
    Ok(())
}

#[tokio::test]
async fn command_input_and_policy_failures_never_launch_ssh() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            [limits]
            max_file_bytes = 64
            [targets.allowed]
            ssh_host = 'ordinary.invalid'
            [targets.allowed.sudo]
            mode = 'separate-identity'
            ssh_host = 'privileged.invalid'
            programs = ['/usr/bin/id']
            [targets.disabled]
            ssh_host = 'disabled.invalid'
        "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools")?;
        ensure!(tools.iter().any(|tool| tool["name"] == "ssh_sudo"));
        for (index, (tool, args)) in [
            ("ssh_exec", json!({"host":"allowed","command":["DO_NOT_LOG_PAYLOAD"]})),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","shell":"interactive"})),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","sudo":true})),
            ("ssh_run", json!({"host":"allowed","argv":"DO_NOT_LOG_PAYLOAD"})),
            ("ssh_run", json!({"host":"allowed","argv":["true",17]})),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"env":{"SECRET":"DO_NOT_LOG_PAYLOAD"}})),
        ].into_iter().enumerate() {
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        for (index, (tool, args, code)) in [
            ("ssh_exec", json!({"host":"ordinary.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("ssh_exec", json!({"host":"privileged.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","timeout_secs":601}), "invalid_argument"),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","cwd":"relative"}), "invalid_argument"),
            ("ssh_exec", json!({"host":"allowed","command":"bad\u{0}DO_NOT_LOG_PAYLOAD"}), "invalid_argument"),
            ("ssh_run", json!({"host":"ordinary.invalid","argv":["DO_NOT_LOG_PAYLOAD"]}), "policy_denied"),
            ("ssh_run", json!({"host":"allowed","argv":[]}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":[""]}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["bad\u{0}DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["true","bad\u{0}DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"cwd":"relative"}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"timeout_secs":0}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"timeout_secs":601}), "invalid_argument"),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"stdin":"λ".repeat(33)}), "invalid_argument"),
            ("ssh_sudo", json!({"host":"disabled","argv":["/usr/bin/id"]}), "policy_denied"),
            ("ssh_sudo", json!({"host":"allowed","user":"service","argv":["/usr/bin/id"]}), "policy_denied"),
            ("ssh_sudo", json!({"host":"allowed","argv":["/bin/id"]}), "policy_denied"),
            ("ssh_sudo", json!({"host":"allowed","argv":["relative"]}), "invalid_argument"),
        ].into_iter().enumerate() {
            let id = 20 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})).await?;
            let response = server.response(id).await?;
            ensure!(response["result"]["isError"] == true, "{response}");
            ensure!(response["result"]["structuredContent"]["data"].is_null());
            ensure!(response["result"]["structuredContent"]["error"]["code"] == code, "{response}");
            ensure!(response["result"]["structuredContent"]["error"]["remote_state_unknown"] == false);
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    let stderr = String::from_utf8(stderr)?;
    ensure!(!stderr.contains("DO_NOT_LOG_PAYLOAD"));
    for line in stderr.lines() {
        let record: Value = serde_json::from_str(line)?;
        ensure!(
            record["event"] != "master_start",
            "rejected request launched SSH"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_command_rejections_precede_ssh_and_keep_session_usable() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            [targets.allowed]
            ssh_host = 'encoded-command.invalid'
            [targets.allowed.sudo]
            mode = 'same-account'
            users = ['root']
            programs = ['/usr/bin/true']
        "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = timeout(Duration::from_secs(20), async {
        server.initialize().await?;
        let mut argv = vec![""; 100_001];
        argv[0] = "/usr/bin/true";
        let cases = [
            (
                "apostrophe expansion",
                "ssh_exec",
                json!({"host":"allowed","command":format!("#{}", "'".repeat(65_535))}),
            ),
            (
                "bang expansion",
                "ssh_exec",
                json!({"host":"allowed","command":"!".repeat(65_000)}),
            ),
            (
                "nested cwd escaping",
                "ssh_exec",
                // Both the raw cwd and inner script fit; outer shell escaping does not.
                json!({"host":"allowed","command":"true","cwd":format!("/{}", "'".repeat(8_000))}),
            ),
            (
                "ordinary argv quote expansion",
                "ssh_run",
                json!({"host":"allowed","argv":["true","'".repeat(20_000)]}),
            ),
            (
                "ordinary cwd quote expansion",
                "ssh_run",
                json!({"host":"allowed","argv":["true"],"cwd":format!("/{}", "'".repeat(20_000))}),
            ),
            (
                "empty ordinary arguments",
                "ssh_run",
                json!({"host":"allowed","argv":&argv}),
            ),
            (
                "empty sudo arguments",
                "ssh_sudo",
                json!({"host":"allowed","user":"root","argv":argv}),
            ),
        ];
        for (index, (label, tool, arguments)) in cases.into_iter().enumerate() {
            let id = 10 + index as u64;
            server
                .send(json!({
                    "jsonrpc":"2.0", "id":id, "method":"tools/call",
                    "params":{"name":tool,"arguments":arguments}
                }))
                .await?;
            let response = server.response(id).await?;
            let result = &response["result"];
            ensure!(result["isError"] == true, "{label}: expected tool error");
            let content = &result["structuredContent"];
            ensure!(
                content.get("data") == Some(&Value::Null),
                "{label}: expected null data"
            );
            ensure!(
                content["error"]["code"] == "invalid_argument",
                "{label}: expected invalid_argument"
            );
            ensure!(
                content["error"]["remote_state_unknown"] == false,
                "{label}: remote state must remain known"
            );
        }
        server
            .send(json!({
                "jsonrpc":"2.0", "id":20, "method":"tools/call",
                "params":{"name":"ssh_targets","arguments":{}}
            }))
            .await?;
        let discovery = server.response(20).await?;
        ensure!(discovery["result"]["isError"] != true);
        let data = discovery_data(&discovery["result"], "configured")?;
        let rows = data["targets"].as_array().context("recovery targets")?;
        ensure!(
            rows.len() == 1,
            "discovery failed after encoded-command rejections"
        );
        ensure!(rows[0]["name"] == "allowed");
        ensure!(rows[0]["sudo_mode"] == "same-account");
        ensure!(rows[0].get("description") == Some(&Value::Null));
        ensure!(rows[0]["labels"] == json!({}));
        ensure!(rows[0]["observed_capabilities"] == "unknown");
        ensure!(
            rows[0]["permitted_operations"]
                == json!([
                    "ssh_exec",
                    "ssh_list_directory",
                    "ssh_read_file",
                    "ssh_run",
                    "ssh_stat",
                    "ssh_sudo",
                    "ssh_write_file"
                ])
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("encoded-command scenario timed out")
    .and_then(|result| result);
    let finished = server.finish().await;
    let removed = dir.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success(), "server exit status: {status}");
    let mut rejected = [false; 4];
    for line in std::str::from_utf8(&stderr)?.lines() {
        let record: Value = serde_json::from_str(line).context("non-JSON audit record")?;
        ensure!(
            record["event"] != "master_start",
            "encoded-command rejection launched SSH"
        );
        for (index, seen) in rejected.iter_mut().enumerate() {
            if record["event"] == "reject" && record["request_id"] == 10 + index as u64 {
                ensure!(record["error_code"] == "invalid_argument");
                ensure!(record["remote_state_unknown"] == false);
                *seen = true;
            }
        }
    }
    ensure!(
        rejected.into_iter().all(|seen| seen),
        "missing encoded-command rejection audit records"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insufficient_reply_budget_rejects_before_ssh_and_keeps_session_usable() -> Result<()> {
    const MESSAGE_LIMIT: usize = 16_777_216;
    let mut server = Server::start(&[])?;
    let scenario = timeout(Duration::from_secs(20), async {
        server.initialize().await?;
        let id = Value::String("i".repeat(MESSAGE_LIMIT - 256));
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "ssh_exec",
                "arguments": {"host": "127.0.0.1", "command": "printf budget"}
            }
        });
        let request_bytes = serde_json::to_vec(&request)?.len() + 1;
        ensure!(
            request_bytes < MESSAGE_LIMIT,
            "request must fit incoming limit: {request_bytes} bytes"
        );
        server.send(request).await?;
        let (response, response_bytes) = server.response_with_id(&id).await?;
        ensure!(response["id"] == id, "response did not preserve request ID");
        ensure!(
            response["error"]["code"] == -32602,
            "insufficient reply budget must be a protocol invalid-params error"
        );
        ensure!(
            response.get("result").is_none(),
            "rejected request returned a tool result"
        );
        ensure!(
            response_bytes <= MESSAGE_LIMIT,
            "response exceeds limit including newline: {response_bytes} bytes"
        );
        drop(response);
        drop(id);
        server
            .send(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "ssh_targets", "arguments": {}}
            }))
            .await?;
        let targets = server.response(2).await?;
        ensure!(targets["result"]["isError"] != true);
        ensure!(
            discovery_data(&targets["result"], "open")?["targets"] == json!([]),
            "normal discovery failed after budget rejection"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("reply-budget scenario timed out")
    .and_then(|result| result);
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success(), "server exit status: {status}");
    for line in std::str::from_utf8(&stderr)?.lines() {
        let record: Value = serde_json::from_str(line)?;
        ensure!(
            record["event"] != "master_start",
            "budget-rejected request launched SSH"
        );
    }
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

const MODERN_VERSION: &str = "2026-07-28";

fn modern_request(id: Value, method: &str, mut params: Value, version: &str) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name":"stdio-acceptance","version":"1"},
    });
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

fn local_only_server() -> Result<(Server, tempfile::TempDir)> {
    server_with_config("[targets]\n")
}

fn server_with_config(text: &str) -> Result<(Server, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    // A regression must fail without ever consulting the developer's SSH authority.
    std::fs::write(&path, text)?;
    let server = Server::start(&["--config", path.to_str().context("config path")?])?;
    Ok((server, directory))
}

fn no_remote_dispatch(stderr: &[u8]) -> Result<()> {
    ensure!(
        stderr.is_empty() || stderr.last() == Some(&b'\n'),
        "incomplete final audit"
    );
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["event"] != "master_start",
            "protocol rejection launched SSH"
        );
        ensure!(
            record["tool"] != "ssh_exec",
            "protocol rejection reached remote handler"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modern_discovery_calls_and_version_rejection_need_no_initialize() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
    let scenario = async {
        server.send(modern_request(json!("discover"), "server/discover", json!({}), MODERN_VERSION)).await?;
        let discovered = server.response_with_id(&json!("discover")).await?.0;
        ensure!(discovered["error"].is_null());
        let versions = discovered["result"]["supportedVersions"].as_array().context("supported versions")?;
        ensure!(versions.contains(&json!(MODERN_VERSION)));
        ensure!(versions.contains(&json!("2025-11-25")));
        let capabilities = &discovered["result"]["capabilities"];
        ensure!(capabilities["tools"].is_object());
        for unsupported in ["prompts", "resources", "tasks", "logging"] {
            ensure!(capabilities.get(unsupported).is_none());
        }

        // These hit distinct admission paths: bootstrap and an established inline session.
        server.send(modern_request(json!("rejected-bootstrap"), "tools/call", json!({
            "name":"ssh_exec","arguments":{"host":"must-not-connect.invalid","command":"printf NEVER"}
        }), "2099-01-01")).await?;
        let rejected = server.response_with_id(&json!("rejected-bootstrap")).await?.0;
        ensure!(rejected["error"]["code"] == -32022);
        ensure!(rejected.get("result").is_none());
        ensure!(rejected["error"]["data"]["requested"] == "2099-01-01");

        server.send(modern_request(json!("tools"), "tools/list", json!({}), MODERN_VERSION)).await?;
        let listed = server.response_with_id(&json!("tools")).await?.0;
        let tools = listed["result"]["tools"].as_array().context("modern tool catalog")?;
        for name in ["ssh_targets", "ssh_exec", "ssh_run", "ssh_read_file", "ssh_stat", "ssh_list_directory", "ssh_write_file"] {
            ensure!(tools.iter().any(|tool| tool["name"] == name));
        }
        ensure!(!tools.iter().any(|tool| tool["name"] == "ssh_sudo"));
        let run = tools.iter().find(|tool| tool["name"] == "ssh_run")
            .context("run absent from modern discovery")?;
        ensure!(run["annotations"]["readOnlyHint"] == false);
        ensure!(run["annotations"]["destructiveHint"] == true);
        ensure!(run["annotations"]["idempotentHint"] == false);
        let write = tools.iter().find(|tool| tool["name"] == "ssh_write_file")
            .context("write absent from modern discovery")?;
        ensure!(write["annotations"]["readOnlyHint"] == false);
        ensure!(write["annotations"]["destructiveHint"] == true);

        // Both are outstanding before either response is read; correlate by ID,
        // never assume handler completion order.
        server.send(modern_request(json!("targets"), "tools/call", json!({
            "name":"ssh_targets","arguments":{}
        }), MODERN_VERSION)).await?;
        server.send(modern_request(json!(17), "tools/call", json!({
            "name":"ssh_targets","arguments":{"extra":true}
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
            "name":"ssh_exec","arguments":{"host":"must-not-connect.invalid","command":"printf NEVER"}
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
                    "name":"ssh_targets","arguments":{}
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
            "params":{"name":"ssh_targets","arguments":{},"_meta":{
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
            "params":{"name":"ssh_targets","arguments":{}}})).await?;
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
async fn eof_discards_unterminated_requests_without_dispatch_or_response() -> Result<()> {
    for incomplete_json in [false, true] {
        let (mut server, directory) = local_only_server()?;
        let scenario = async {
            server.initialize().await?;
            let mut frame = serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":"truncated","method":"tools/call",
                "params":{"name":"ssh_exec","arguments":{
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_validation_precedes_ssh_and_cannot_raise_the_wire_ceiling() -> Result<()> {
    let (mut server, directory) =
        server_with_config("[limits]\nmax_file_bytes=33554432\n[targets]\n")?;
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
                "params":{"name":"ssh_read_file","arguments":arguments}}))
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
                "params":{"name":"ssh_read_file","arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}}))
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
            record["tool"] != "ssh_read_file" || record["event"] == "reject",
            "invalid read was accepted before validation"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stat_validation_and_policy_precede_any_ssh_dispatch() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
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
                "params":{"name":"ssh_stat","arguments":arguments}}))
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
                "params":{"name":"ssh_stat","arguments":arguments}}))
                .await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}}))
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
            record["tool"] != "ssh_stat" || record["event"] == "reject",
            "invalid stat was accepted before validation"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_limits_and_policy_reject_before_ssh_dispatch() -> Result<()> {
    let (mut server, directory) = local_only_server()?;
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
                "params":{"name":"ssh_list_directory","arguments":arguments}}))
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
        ]
        .into_iter()
        .enumerate()
        {
            let id = 200 + index as u64;
            server
                .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"ssh_list_directory","arguments":arguments}}))
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
        ensure!(record["tool"] != "ssh_list_directory" || record["event"] == "reject");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_validation_and_policy_precede_any_ssh_dispatch() -> Result<()> {
    let (mut server, directory) = server_with_config(indoc::indoc! {"
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
                "params":{"name":"ssh_write_file","arguments":arguments}})).await?;
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
                "params":{"name":"ssh_write_file","arguments":arguments}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602,
                "wrong-shaped write {index} reached the handler");
        }
        server.send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}})).await?;
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
            record["tool"] != "ssh_write_file" || record["event"] == "reject",
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

#[tokio::test]
async fn empty_sudo_program_policy_keeps_route_but_denies_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
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
                .any(|tool| tool["name"] == "ssh_sudo")
        );
        server
            .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}}))
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
                .any(|operation| operation == "ssh_sudo")
        );
        server
            .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{"name":"ssh_sudo","arguments":{"host":"one","argv":["/usr/bin/id"]}}}))
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
