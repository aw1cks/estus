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
    let binary = std::env::var_os("ESTUS_TEST_BINARY").unwrap_or_else(|| {
        option_env!("ESTUS_TEST_BINARY")
            .unwrap_or(env!("CARGO_BIN_EXE_estus"))
            .into()
    });
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ESTUS_") {
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
        "max_directory_cursors",
        "max_directory_cursors_per_target",
        "directory_cursor_idle_timeout_secs",
        "max_directory_page_bytes",
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
    ensure!(limits["max_directory_cursors_per_target"] == 2);
    ensure!(limits["max_directory_page_bytes"] == 1_048_576);
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
        let mut names: Vec<&str> = tools.iter()
            .map(|tool| tool["name"].as_str().context("default tool name"))
            .collect::<Result<_>>()?;
        names.sort_unstable();
        ensure!(names == ["ssh_read_output", "ssh_targets"], "omitted profile exposed native routes");
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        let called = server.response(3).await?;
        let result = &called["result"];
        ensure!(discovery_data(result, "configured")?["targets"] == json!([]));
        ensure!(result["isError"] != true);
        let content = result["content"].as_array().context("text compatibility content")?;
        ensure!(content.len() == 1);
        let text: Value = serde_json::from_str(content[0]["text"].as_str().context("text")?)?;
        ensure!(text == result["structuredContent"]);
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_targets","arguments":{"extra":true}}})).await?;
        ensure!(server.response(4).await?["error"]["code"] == -32602);
        for (index, tool) in [
            "ssh_exec", "ssh_run", "ssh_sudo", "ssh_read_file", "ssh_stat",
            "ssh_list_directory", "ssh_write_file", "ssh_mkdir", "ssh_rename",
            "ssh_replace_file", "ssh_remove_file", "ssh_remove_directory",
        ].into_iter().enumerate() {
            let id = 5 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":tool,"arguments":profile_call_arguments(tool, "DO_NOT_CONNECT.invalid")}})).await?;
            let denied = server.response(id).await?;
            ensure!(denied["error"]["code"] == -32602, "{tool}: {denied}");
            ensure!(denied.get("result").is_none());
        }
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
            profile = 'baseline'
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
                        "ssh_mkdir",
                        "ssh_read_file",
                        "ssh_remove_directory",
                        "ssh_remove_file",
                        "ssh_rename",
                        "ssh_replace_file",
                        "ssh_run",
                        "ssh_stat",
                        "ssh_sudo",
                        "ssh_write_file"
                    ])
                } else {
                    json!([
                        "ssh_exec",
                        "ssh_list_directory",
                        "ssh_mkdir",
                        "ssh_read_file",
                        "ssh_remove_directory",
                        "ssh_remove_file",
                        "ssh_rename",
                        "ssh_replace_file",
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
            ensure!(diagnostic["phase"] == "config_validation");
            if text.starts_with("[ssh]") {
                ensure!(
                    diagnostic["schema_path"] == "ssh",
                    "unknown key lost its containing schema path: {diagnostic}"
                );
            }
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

#[tokio::test]
async fn command_input_and_policy_failures_never_launch_ssh() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            profile = 'baseline'
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
        for name in ["ssh_exec", "ssh_run", "ssh_sudo"] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("command tool")?;
            output_control_schema(&tool["inputSchema"])?;
        }
        for (index, (tool, args)) in [
            ("ssh_exec", json!({"host":"allowed","command":["DO_NOT_LOG_PAYLOAD"]})),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","shell":"interactive"})),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","sudo":true})),
            ("ssh_run", json!({"host":"allowed","argv":"DO_NOT_LOG_PAYLOAD"})),
            ("ssh_run", json!({"host":"allowed","argv":["true",17]})),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"env":{"SECRET":"DO_NOT_LOG_PAYLOAD"}})),
            ("ssh_exec", json!({"host":"allowed","command":"true","retain_output":"DO_NOT_LOG_PAYLOAD"})),
            ("ssh_run", json!({"host":"allowed","argv":["true"],"retain_output":1})),
            ("ssh_sudo", json!({"host":"allowed","argv":["/usr/bin/id"],"retain_output":null})),
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
            ("ssh_sudo", json!({"host":"allowed","user":"bad DO_NOT_LOG_PAYLOAD","argv":["/usr/bin/id"]}), "invalid_argument"),
            ("ssh_sudo", json!({"host":"allowed","user":"DO_NOT_LOG_PAYLOAD","argv":["/usr/bin/id"]}), "policy_denied"),
            ("ssh_sudo", json!({"host":"allowed","argv":["DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("ssh_sudo", json!({"host":"allowed","argv":["/DO_NOT_LOG_PAYLOAD"]}), "policy_denied"),
        ].into_iter().enumerate() {
            let id = 20 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})).await?;
            let response = server.response(id).await?;
            ensure!(!response.to_string().contains("DO_NOT_LOG_PAYLOAD"), "rejection reflected input");
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
        if record["tool"] == "ssh_sudo" {
            ensure!(record["event"] == "reject");
            ensure!(
                record.get("user").is_none() && record.get("program").is_none(),
                "sudo rejection retained caller identity fields: {record}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn accepted_sudo_keeps_validated_identifiers_on_transport_failure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            profile = 'baseline'
            [targets.allowed]
            ssh_host = 'never-connected.invalid'
            [targets.allowed.sudo]
            mode = 'separate-identity'
            ssh_host = 'never-connected-elevated.invalid'
            users = ['root']
            programs = ['/usr/bin/id']
        "},
    )?;
    // A real, immediately failing local executable guarantees no network/SSH
    // configuration evaluation while exercising accepted-operation auditing.
    let false_binary = std::env::split_paths(&std::env::var_os("PATH").context("PATH")?)
        .map(|directory| directory.join("false"))
        .find(|path| path.is_file())
        .context("false executable prerequisite")?;
    let mut server = Server::start(&[
        "--config",
        path.to_str().context("config path")?,
        "--ssh",
        false_binary.to_str().context("false path")?,
    ])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"ssh_sudo","arguments":{
                    "host":"allowed","user":"root","argv":["/usr/bin/id"]}}}))
            .await?;
        let response = server.response(2).await?;
        let code = response["result"]["structuredContent"]["error"]["code"]
            .as_str()
            .context("transport error")?;
        ensure!(
            code != "policy_denied" && code != "invalid_argument",
            "{response}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    let mut events = Vec::new();
    for line in stderr.split_inclusive(|byte| *byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        if record["tool"] == "ssh_sudo" && record["request_id"] == 2 {
            ensure!(record["user"] == "root" && record["program"] == "/usr/bin/id");
            ensure!(record["identity_role"] == "elevated");
            events.push(record["event"].as_str().context("audit event")?.to_owned());
        }
    }
    ensure!(
        events == ["start", "finish"],
        "accepted sudo audit: {events:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_command_rejections_precede_ssh_and_keep_session_usable() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            profile = 'baseline'
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
                    "ssh_mkdir",
                    "ssh_read_file",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
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
    let (mut server, _directory) = server_with_config("profile = 'baseline'\n[targets]\n")?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})).await?;
        let listed = server.response(3).await?;
        let tools = listed["result"]["tools"].as_array().context("budget tool catalog")?;
        for (name, arguments) in [
            (
                "ssh_exec",
                json!({"host":"127.0.0.1","command":"printf budget"}),
            ),
            (
                "ssh_exec",
                json!({"host":"127.0.0.1","command":"printf budget","retain_output":true}),
            ),
            (
                "ssh_run",
                json!({"host":"127.0.0.1","argv":["/usr/bin/true"],"retain_output":true}),
            ),
            (
                "ssh_mkdir",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
            (
                "ssh_rename",
                json!({"host":"127.0.0.1","source":"budget-private-source","destination":"budget-private-destination","overwrite":true}),
            ),
            (
                "ssh_replace_file",
                json!({"host":"127.0.0.1","path":"budget-private-path","content":"x","overwrite":true}),
            ),
            (
                "ssh_remove_file",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
            (
                "ssh_remove_directory",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
        ] {
            ensure!(tools.iter().any(|tool| tool["name"] == name), "{name}: budget route absent");
            // Each full-size wire boundary has its own bounded deadline; adding
            // independent cases must not turn this into a suite-speed assertion.
            timeout(Duration::from_secs(20), async {
            let id = Value::String("i".repeat(MESSAGE_LIMIT - 256));
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name":name,"arguments":arguments}
            });
            let request_bytes = serde_json::to_vec(&request)?.len() + 1;
            ensure!(
                request_bytes < MESSAGE_LIMIT,
                "{name}: request must fit incoming limit: {request_bytes} bytes"
            );
            server.send(request).await?;
            let (response, response_bytes) = server.response_with_id(&id).await?;
            ensure!(response["id"] == id, "response did not preserve request ID");
            ensure!(
                response["error"]["code"] == -32602,
                "{name}: insufficient reply budget must be a protocol invalid-params error"
            );
            ensure!(
                response.get("result").is_none(),
                "{name}: rejected request returned a tool result"
            );
            ensure!(
                response_bytes <= MESSAGE_LIMIT,
                "response exceeds limit including newline: {response_bytes} bytes"
            );
            ensure!(
                !serde_json::to_string(&response)?.contains("budget-private-"),
                "{name}: reply-budget rejection disclosed private paths"
            );
                Ok::<_, anyhow::Error>(())
            }).await.with_context(|| format!("{name}: reply-budget case timed out"))??;
        }
        server
            .send(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "ssh_targets", "arguments": {}}
            }))
            .await?;
        let targets = server.response(2).await?;
        ensure!(targets["result"]["isError"] != true);
        ensure!(
            discovery_data(&targets["result"], "configured")?["targets"] == json!([]),
            "normal discovery failed after budget rejection"
        );
        Ok::<_, anyhow::Error>(())
    }.await;
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
    let (mut server, directory) = server_with_config("profile = 'baseline'\n[targets]\n")?;
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
        for name in ["ssh_targets", "ssh_exec", "ssh_run", "ssh_read_file", "ssh_read_output", "ssh_stat", "ssh_list_directory", "ssh_mkdir", "ssh_remove_directory", "ssh_remove_file", "ssh_rename", "ssh_replace_file", "ssh_write_file"] {
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
async fn malformed_tool_arguments_expose_only_fixed_diagnostics_and_rejection_audit() -> Result<()>
{
    let (mut server, directory) = server_with_config(
        "profile = 'baseline'\n[output]\nenabled = true\n[targets.fixture]\nssh_host = 'never-connected.invalid'\n[targets.fixture.sudo]\nmode = 'same-account'\nusers = ['root']\nprograms = ['/usr/bin/true']\n",
    )?;
    let cases = [
        (
            "ssh_targets",
            json!({"A12_PRIVATE_UNKNOWN_KEY":"/private/A12_PRIVATE_VALUE"}),
        ),
        (
            "ssh_exec",
            json!({"host":"A12_PRIVATE_HOST","command":["A12_PRIVATE_VALUE"]}),
        ),
        ("ssh_exec", json!({"host":"A12_PRIVATE_HOST"})),
        (
            "ssh_sudo",
            json!({
                "host":"A12_PRIVATE_HOST","user":"A12_PRIVATE_USER",
                "argv":["/private/A12_PRIVATE_PROGRAM",{"A12_PRIVATE_UNKNOWN_KEY":"A12_PRIVATE_VALUE"}]
            }),
        ),
        (
            "ssh_read_output",
            json!({
                "handle":"A12_PRIVATE_HANDLE","stream":"A12_PRIVATE_STREAM"
            }),
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
        for (index, (name, arguments)) in cases.iter().enumerate() {
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
                            "schema_path":"arguments"
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
            .find(|tool| tool["name"] == "ssh_targets")
            .context("targets tool")?;
        ensure!(jsonschema::validator_for(&targets["inputSchema"])?.is_valid(&json!({})));
        server
            .send(json!({
                "jsonrpc":"2.0","id":30,"method":"tools/call",
                "params":{"name":"ssh_targets","arguments":{}}
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
        for (index, (name, _)) in cases.iter().enumerate() {
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
                        == if *name == "ssh_sudo" {
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
        let (mut server, directory) = server_with_config("profile = 'baseline'\n[targets]\n")?;
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
                "profile='baseline'\n[ssh]\nconfig_file='replacement.conf'\n{limits}\
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
                "ssh_exec", "ssh_list_directory", "ssh_mkdir", "ssh_read_file",
                "ssh_read_output", "ssh_remove_directory", "ssh_remove_file",
                "ssh_rename", "ssh_replace_file", "ssh_run", "ssh_stat",
                "ssh_sudo", "ssh_targets", "ssh_write_file",
            ]);
            let mut id = 10;
            for tool in tools {
                let name = tool["name"].as_str().context("builtin name")?;
                // Compile the actual consumer-visible schema, including its local
                // references. Cargo disables both HTTP and file retrieval.
                let validator = jsonschema::validator_for(&tool["inputSchema"])
                    .with_context(|| format!("invalid published inputSchema for {name}"))?;
                if name == "ssh_targets" {
                    ensure!(validator.is_valid(&json!({})));
                    ensure!(!validator.is_valid(&json!({"extra":true})));
                    continue;
                }
                let mut base = if name == "ssh_read_output" {
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
                if name == "ssh_exec" {
                    base["command"] = json!("SCHEMA_INPUT_SECRET");
                }
                let expected = if name == "ssh_read_output" { "not_found" } else { "policy_denied" };
                let mut cases = vec![(base.clone(), true, expected)];
                if name != "ssh_read_output" {
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
                if matches!(name, "ssh_run" | "ssh_sudo") {
                    for invalid in [json!([]), json!([""]), json!(["/SCHEMA_INPUT_SECRET", "bad\0argument"])] {
                        let mut arguments = base.clone();
                        arguments["argv"] = invalid;
                        cases.push((arguments, false, "invalid_argument"));
                    }
                }
                if name == "ssh_list_directory" {
                    ensure!(tool["annotations"]["readOnlyHint"] == true);
                    ensure!(tool["annotations"]["idempotentHint"] == false);
                    for (token, valid) in [
                        (handle.to_owned(), true), (String::new(), false),
                        ("a".repeat(31), false), ("a".repeat(33), false),
                        ("A".repeat(32), false), ("g".repeat(32), false),
                    ] {
                        let mut arguments = base.clone();
                        arguments["continuation"] = json!(token);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                    for (entries, valid) in [(0, false), (1, true), (1000, true), (1001, false)] {
                        let mut arguments = base.clone();
                        arguments["max_entries"] = json!(entries);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                }
                if matches!(name, "ssh_read_file" | "ssh_read_output") {
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
                if name == "ssh_read_file" {
                    for (digest, valid) in [
                        (hash.clone(), true), (String::new(), false),
                        ("a".repeat(63), false), ("a".repeat(65), false), ("g".repeat(64), false),
                    ] {
                        let mut arguments = base.clone();
                        arguments["expected_content_sha256"] = json!(digest);
                        cases.push((arguments, valid, if valid { expected } else { "invalid_argument" }));
                    }
                }
                if name == "ssh_read_output" {
                    for invalid in ["".to_owned(), "a".repeat(31), "a".repeat(33), "F".repeat(32), "g".repeat(32)] {
                        let mut arguments = base.clone();
                        arguments["handle"] = json!(invalid);
                        cases.push((arguments, false, "invalid_argument"));
                    }
                }
                if name == "ssh_replace_file" {
                    let mut arguments = base.clone();
                    arguments["overwrite"] = json!(false);
                    cases.push((arguments, false, "invalid_argument"));
                    let mut arguments = base.clone();
                    arguments.as_object_mut().context("replace arguments")?.remove("overwrite");
                    cases.push((arguments, false, "invalid_params"));
                }
                if configured_limits && matches!(name, "ssh_run" | "ssh_write_file" | "ssh_replace_file") {
                    let mut arguments = base.clone();
                    let field = if name == "ssh_run" { "stdin" } else { "content" };
                    // JSON Schema string lengths count characters, not UTF-8
                    // bytes. Runtime byte budgets remain authoritative.
                    arguments[field] = json!("λ".repeat(5));
                    cases.push((arguments, true, "invalid_argument"));
                }
                for (index, (mut arguments, schema_valid, code)) in cases.into_iter().enumerate() {
                    // Let invalid inputs reach their validator: an unconfigured
                    // host must not mask a missing limit check with policy denial.
                    if name != "ssh_read_output" && matches!(code, "invalid_argument" | "invalid_params") {
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
            if record["tool"] == "ssh_read_output" {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_validation_precedes_ssh_and_cannot_raise_the_wire_ceiling() -> Result<()> {
    let (mut server, directory) = server_with_config(
        "profile = 'read-only-files'\n[limits]\nmax_file_bytes=33554432\n[targets]\n",
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
    let (mut server, directory) = server_with_config("profile = 'read-only-files'\n[targets]\n")?;
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
    let (mut server, directory) = server_with_config("profile = 'read-only-files'\n[targets]\n")?;
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
            (
                json!({"host":"denied","path":"dir","continuation":"0123456789abcdef0123456789abcdef"}),
                "policy_denied",
            ),
            (
                json!({"host":"denied","path":"dir","continuation":"PRIVATE_BAD_TOKEN"}),
                "invalid_argument",
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
        profile = 'files-only'
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
            profile = 'files-only'
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
                "params":{"name":"ssh_mkdir","arguments":arguments}}))
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
                "params":{"name":"ssh_mkdir","arguments":arguments}}))
                .await?;
            let rejected = server.response(id).await?;
            ensure!(
                rejected["error"]["code"] == -32602 && rejected.get("result").is_none(),
                "{control}: malformed mkdir control reached handler"
            );
        }
        server
            .send(json!({"jsonrpc":"2.0","id":300,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}}))
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
            record["tool"] != "ssh_mkdir" || record["event"] == "reject",
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
            profile = 'files-only'
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
                .find(|tool| tool["name"] == "ssh_rename")
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
            ensure!(required == ["destination", "host", "source"]);
            ensure!(input["properties"]["overwrite"]["type"] == "boolean");
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
                let params = json!({"name":"ssh_rename","arguments":arguments});
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
                let params = json!({"name":"ssh_rename","arguments":arguments});
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
            let params = json!({"name":"ssh_targets","arguments":{}});
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
                record["tool"] != "ssh_rename" || record["event"] == "reject",
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

#[tokio::test]
async fn empty_sudo_program_policy_keeps_route_but_denies_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
        profile = 'baseline'
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

// Every payload is valid for its route: a JSON-RPC rejection therefore proves
// omission, rather than accidentally testing argument deserialization.
fn profile_call_arguments(tool: &str, host: &str) -> Value {
    match tool {
        "ssh_exec" => json!({"host":host,"command":"true"}),
        "ssh_run" => json!({"host":host,"argv":["/usr/bin/true"]}),
        "ssh_sudo" => json!({"host":host,"argv":["/usr/bin/true"]}),
        "ssh_rename" => {
            json!({"host":host,"source":"/private/profile-payload-source","destination":"/private/profile-payload-destination","overwrite":true})
        }
        "ssh_replace_file" => {
            json!({"host":host,"path":"/private/profile-payload","content":"x","overwrite":true})
        }
        "ssh_write_file" => {
            json!({"host":host,"path":"/private/profile-payload","content":"PROFILE_PAYLOAD"})
        }
        "ssh_read_file"
        | "ssh_stat"
        | "ssh_list_directory"
        | "ssh_mkdir"
        | "ssh_remove_directory"
        | "ssh_remove_file" => {
            json!({"host":host,"path":"/private/profile-payload"})
        }
        _ => panic!("unexpected profile test tool"),
    }
}

fn profile_policy_denied(response: &Value) -> Result<()> {
    ensure!(
        response.get("error").is_none(),
        "route was not registered: {response}"
    );
    let result = &response["result"];
    ensure!(result["isError"] == true, "{response}");
    let structured = &result["structuredContent"];
    ensure!(structured["data"].is_null());
    ensure!(structured["error"]["code"] == "policy_denied", "{response}");
    ensure!(structured["error"]["remote_state_unknown"] == false);
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("policy error text")?,
    )?;
    ensure!(text == *structured);
    let encoded = serde_json::to_string(response)?;
    for secret in [
        "profile-payload",
        "PROFILE_PAYLOAD",
        "private-backend",
        "private-identity",
        "read-only-files",
        "files-only",
        "actions-only",
    ] {
        ensure!(
            !encoded.contains(secret),
            "policy error leaked private input"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_profiles_publish_exact_routes_and_matching_discovery() -> Result<()> {
    let ordinary = [
        "ssh_exec",
        "ssh_list_directory",
        "ssh_mkdir",
        "ssh_read_file",
        "ssh_remove_directory",
        "ssh_remove_file",
        "ssh_rename",
        "ssh_replace_file",
        "ssh_run",
        "ssh_stat",
        "ssh_sudo",
        "ssh_write_file",
    ];
    for (profile, expected) in [
        ("baseline", ordinary.as_slice()),
        (
            "read-only-files",
            &["ssh_list_directory", "ssh_read_file", "ssh_stat"][..],
        ),
        (
            "files-only",
            &[
                "ssh_list_directory",
                "ssh_mkdir",
                "ssh_read_file",
                "ssh_remove_directory",
                "ssh_remove_file",
                "ssh_rename",
                "ssh_replace_file",
                "ssh_stat",
                "ssh_write_file",
            ][..],
        ),
        ("actions-only", &[][..]),
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
                        "[targets.one]\nssh_host = 'private-backend.invalid'\nprofile = 'baseline'\n[targets.one.sudo]\nmode = 'same-account'\n"
                    }
                    "ordinary" => "[targets.one]\nssh_host = 'private-backend.invalid'\n",
                    _ => "[targets]\n",
                };
                std::fs::write(
                    &path,
                    format!(
                        "profile = '{profile}'\n[ssh]\nconfig_file = 'replacement.conf'\n{target}"
                    ),
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
                        .filter(|name| *name != "ssh_sudo" || target_kind == "sudo")
                        .collect();
                    expected_operations.sort_unstable();
                    let mut expected_routes = expected_operations.clone();
                    expected_routes.push("ssh_targets");
                    expected_routes.push("ssh_read_output");
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
                        if tool["name"] == "ssh_run" || tool["name"] == "ssh_write_file" {
                            ensure!(tool["annotations"]["readOnlyHint"] == false);
                            ensure!(tool["annotations"]["destructiveHint"] == true);
                            ensure!(tool["annotations"]["idempotentHint"] == false);
                        }
                    }
                    let params = json!({"name":"ssh_targets","arguments":{}});
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
                    let params = json!({"name":"ssh_read_output","arguments":{"handle":"0123456789abcdef0123456789abcdef","stream":"stdout","max_bytes":1}});
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
        profile = 'baseline'
        [ssh]
        config_file = 'replacement.conf'
        [limits]
        connect_timeout_secs = 1
        operation_timeout_secs = 2
        [targets.read]
        ssh_host = 'private-backend-read.invalid'
        profile = 'read-only-files'
        [targets.read.sudo]
        mode = 'separate-identity'
        ssh_host = 'private-identity.invalid'
        [targets.files]
        ssh_host = 'private-backend-files.invalid'
        profile = 'files-only'
        [targets.files.sudo]
        mode = 'same-account'
        [targets.actions]
        ssh_host = 'private-backend-actions.invalid'
        profile = 'actions-only'
        [targets.actions.sudo]
        mode = 'same-account'
        [targets.base]
        ssh_host = 'private-backend-base.invalid'
        profile = 'baseline'
        [targets.empty]
        ssh_host = 'private-backend-empty.invalid'
        profile = 'baseline'
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
        ensure!(listed["result"]["tools"].as_array().context("tools")?.len() == 14);
        server
            .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"ssh_targets","arguments":{}}}))
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
                    "ssh_exec",
                    "ssh_list_directory",
                    "ssh_mkdir",
                    "ssh_read_file",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
                    "ssh_run",
                    "ssh_stat",
                    "ssh_write_file"
                ]),
            ),
            (
                "empty",
                json!([
                    "ssh_exec",
                    "ssh_list_directory",
                    "ssh_mkdir",
                    "ssh_read_file",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
                    "ssh_run",
                    "ssh_stat",
                    "ssh_write_file"
                ]),
            ),
            (
                "files",
                json!([
                    "ssh_list_directory",
                    "ssh_mkdir",
                    "ssh_read_file",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
                    "ssh_stat",
                    "ssh_write_file"
                ]),
            ),
            (
                "read",
                json!(["ssh_list_directory", "ssh_read_file", "ssh_stat"]),
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
                    "ssh_exec",
                    "ssh_run",
                    "ssh_write_file",
                    "ssh_mkdir",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
                    "ssh_sudo",
                ][..],
            ),
            ("files", &["ssh_exec", "ssh_run", "ssh_sudo"][..]),
            (
                "actions",
                &[
                    "ssh_exec",
                    "ssh_run",
                    "ssh_write_file",
                    "ssh_sudo",
                    "ssh_read_file",
                    "ssh_stat",
                    "ssh_list_directory",
                    "ssh_mkdir",
                    "ssh_remove_directory",
                    "ssh_remove_file",
                    "ssh_rename",
                    "ssh_replace_file",
                ][..],
            ),
            ("base", &["ssh_sudo"][..]),
            ("empty", &["ssh_sudo"][..]),
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
    let (mut server, directory) = server_with_config("profile = 'actions-only'\n[targets]\n")?;
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
                "ssh_targets"
            } else {
                "ssh_exec"
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
            "profile = 'baseline'\n[targets]\n",
        )?;
        server
            .send(json!({"jsonrpc":"2.0","id":20,"method":"tools/list","params":{}}))
            .await?;
        let listed = server.response(20).await?;
        let tools = listed["result"]["tools"]
            .as_array()
            .context("immutable tool list")?;
        ensure!(tools.len() == 2);
        for name in ["ssh_read_output", "ssh_targets"] {
            ensure!(tools.iter().any(|tool| tool["name"] == name));
        }
        for (index, tool) in [
            "ssh_exec",
            "ssh_run",
            "ssh_sudo",
            "ssh_read_file",
            "ssh_stat",
            "ssh_list_directory",
            "ssh_write_file",
            "ssh_mkdir",
            "ssh_remove_directory",
            "ssh_remove_file",
            "ssh_rename",
            "ssh_replace_file",
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
    for value in [
        "'private-profile-secret'",
        "['private-profile-secret']",
        "42",
        "true",
        "{ private_profile_secret = 'private-profile-secret' }",
    ] {
        for target in [false, true] {
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
            ensure!(!output.status.success(), "accepted profile {value}");
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
            let field = if target {
                "targets.*.profile"
            } else {
                "profile"
            };
            ensure!(
                diagnostic["schema_path"] == field && diagnostic["phase"] == "config_validation",
                "wrong profile diagnostic context: {diagnostic}"
            );
        }
    }
    Ok(())
}

const NAMED_TOOL_CONFIG: &str = indoc::indoc! {r#"
    profile = "actions-only"
    enabled_tools = ["observe_account", "change_account"]
    [ssh]
    config_file = "replacement.conf"
    [limits]
    connect_timeout_secs = 1
    operation_timeout_secs = 3
    max_timeout_secs = 5
    max_output_bytes = 4096
    [targets.base]
    ssh_host = "private-binding-backend.invalid"
    [targets.base.sudo]
    mode = "separate-identity"
    ssh_host = "private-binding-elevated.invalid"
    [targets.read]
    ssh_host = "private-binding-read.invalid"
    profile = "read-only-files"
    [targets.files]
    ssh_host = "private-binding-files.invalid"
    profile = "files-only"
    [targets.other]
    ssh_host = "private-binding-other.invalid"
    [tools.observe_account]
    description = "Observe an approved account."
    revision = "review-1"
    targets = ["base", "read", "files"]
    authority = "ordinary"
    effects = ["read", "sensitive_read"]
    execution = { kind = "native_argv", program = "/private/binding-program", cwd = "/private/binding-cwd", argv = ["private-binding-fixed", "--", { input = "account" }, { input = "count" }, { input = "verbose" }] }
    input_schema = { type = "object", additionalProperties = false, required = ["account", "count", "verbose"], properties = { account = { type = "string", minLength = 1, maxLength = 16, enum = ["root", "operator"] }, count = { type = "integer", minimum = -2, maximum = 4 }, verbose = { type = "boolean" } } }
    result = { kind = "command" }
    limits = { timeout_secs = 2, max_output_bytes = 1024 }
    [tools.change_account]
    description = "Change an approved account."
    revision = "change-2"
    targets = ["base"]
    authority = "ordinary"
    effects = ["persistent_write"]
    execution = { kind = "native_argv", program = "/private/binding-program", argv = ["private-binding-fixed"] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
    [tools.disabled_account]
    description = "Not enabled."
    revision = "disabled-3"
    targets = ["base"]
    authority = "ordinary"
    effects = ["unknown"]
    execution = { kind = "native_argv", program = "/private/binding-disabled", argv = [] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
"#};

fn named_tools_server(config: &str) -> Result<(Server, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let probe = directory.path().join("binding-must-not-probe");
    std::fs::write(
        directory.path().join("replacement.conf"),
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    let path = directory.path().join("operator.toml");
    std::fs::write(&path, config)?;
    let server = Server::start(&["--config", path.to_str().context("config path")?])?;
    Ok((server, directory))
}

fn binding_public_only(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    for private in [
        "private-binding",
        "/private/binding",
        "BINDING_INPUT_SECRET",
        "replacement.conf",
    ] {
        ensure!(!text.contains(private), "binding private content disclosed");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn named_tools_publish_reviewed_metadata_and_freeze_startup_selection() -> Result<()> {
    let config = NAMED_TOOL_CONFIG.replacen("profile = \"actions-only\"\n", "", 1);
    let (mut server, directory) = named_tools_server(&config)?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        binding_public_only(&serde_json::to_vec(&listed)?)?;
        let tools = listed["result"]["tools"].as_array().context("named tools")?;
        let mut names: Vec<_> = tools.iter().map(|tool| tool["name"].as_str().context("tool name")).collect::<Result<_>>()?;
        names.sort_unstable();
        ensure!(names == ["change_account", "observe_account", "ssh_read_output", "ssh_targets"]);
        for (name, revision, effects, read_only, destructive) in [
            ("observe_account", "review-1", json!(["read", "sensitive_read"]), true, false),
            ("change_account", "change-2", json!(["persistent_write"]), false, true),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("binding metadata")?;
            ensure!(tool["_meta"] == json!({
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
        for name in ["observe_account", "change_account"] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("native binding")?;
            output_control_schema(&tool["inputSchema"])?;
        }
        let observe = tools.iter().find(|tool| tool["name"] == "observe_account").context("observe tool")?;
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
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        let discovered = server.response(3).await?;
        binding_public_only(&serde_json::to_vec(&discovered)?)?;
        let rows = discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("binding target rows")?;
        for (name, expected) in [
            ("base", json!(["change_account", "observe_account"])),
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
                .replace("[\"observe_account\", \"change_account\"]", "[\"disabled_account\"]")
                .replace("review-1", "review-99"),
        )?;
        server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})).await?;
        ensure!(server.response(4).await?["result"] == listed["result"]);
        for (index, tool) in ["disabled_account", "ssh_exec", "ssh_run", "ssh_sudo"].into_iter().enumerate() {
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
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_account","arguments":arguments}})).await?;
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
        server.send(json!({"jsonrpc":"2.0","id":200,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
        if record["tool"] == "observe_account" {
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
    for profile in ["read-only-files", "files-only"] {
        let config = NAMED_TOOL_CONFIG.replace(
            "profile = \"actions-only\"",
            &format!("profile = \"{profile}\""),
        );
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("profile tools")?;
            for name in ["observe_account", "change_account", "disabled_account"] {
                ensure!(!tools.iter().any(|tool| tool["name"] == name));
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_account","arguments":{"host":"base","account":"root","count":0,"verbose":false}}})).await?;
            ensure!(server.response(3).await?["error"]["code"] == -32602);
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
            let response = server.response(4).await?;
            for row in discovery_data(&response["result"], "configured")?["targets"].as_array().context("profile rows")? {
                let operations = row["permitted_operations"].as_array().context("profile operations")?;
                ensure!(!operations.contains(&json!("observe_account")));
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
            "[\"observe_account\", \"change_account\"]",
            "[\"BINDING_CONFIG_SECRET\"]",
        ),
        (
            "[\"observe_account\", \"change_account\"]",
            "[\"observe_account\", \"observe_account\"]",
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
        ("[tools.disabled_account]", "[tools.ssh_exec]"),
        ("[tools.disabled_account]", "[tools.ssh_sudo]"),
        ("[tools.disabled_account]", "[tools.ssh_targets]"),
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
        (NAMED_TOOL_CONFIG, ["observe_account", "change_account"]),
        (FIXED_SUDO_TOOL_CONFIG, ["fixed_id", "fixed_printf"]),
    ] {
        let config = fixture.replace("profile = \"actions-only\"", "profile = \"baseline\"");
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
                .find(|tool| tool["name"] == "ssh_run")
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

const FIXED_SUDO_TOOL_CONFIG: &str = indoc::indoc! {r#"
    profile = "actions-only"
    enabled_tools = ["fixed_id", "fixed_printf"]
    [ssh]
    config_file = "replacement.conf"
    [limits]
    connect_timeout_secs = 1
    operation_timeout_secs = 3
    max_timeout_secs = 5
    max_output_bytes = 4096
    [targets.base]
    ssh_host = "private-binding-backend.invalid"
    [targets.base.sudo]
    mode = "separate-identity"
    ssh_host = "private-binding-elevated.invalid"
    users = ["root"]
    programs = ["/usr/bin/id", "/usr/bin/printf"]
    [targets.same]
    ssh_host = "private-binding-same.invalid"
    profile = "actions-only"
    [targets.same.sudo]
    mode = "same-account"
    users = ["root"]
    programs = ["/usr/bin/id", "/usr/bin/printf"]
    [targets.read]
    ssh_host = "private-binding-read.invalid"
    profile = "read-only-files"
    [targets.read.sudo]
    mode = "same-account"
    [targets.files]
    ssh_host = "private-binding-files.invalid"
    profile = "files-only"
    [targets.files.sudo]
    mode = "same-account"
    [targets.other]
    ssh_host = "private-binding-other.invalid"
    [tools.fixed_id]
    description = "Observe the fixed privileged account."
    revision = "id-1"
    targets = ["base", "same", "read", "files"]
    authority = { sudo = "root" }
    effects = ["read"]
    execution = { kind = "native_argv", program = "/usr/bin/id", argv = ["-u"] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
    [tools.fixed_printf]
    description = "Perform the reviewed privileged operation."
    revision = "printf-1"
    targets = ["base", "same", "read", "files"]
    authority = { sudo = "root" }
    effects = ["persistent_write"]
    execution = { kind = "native_argv", program = "/usr/bin/printf", argv = ["--", "%s", { input = "value" }] }
    input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 64 } } }
    result = { kind = "command" }
"#};

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
        ensure!(names == ["fixed_id", "fixed_printf", "ssh_read_output", "ssh_targets"]);
        for (name, revision, effects, read_only, destructive) in [
            ("fixed_id", "id-1", json!(["read"]), true, false),
            ("fixed_printf", "printf-1", json!(["persistent_write"]), false, true),
        ] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("fixed sudo metadata")?;
            ensure!(tool["_meta"] == json!({
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
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
        for tool in ["ssh_exec", "ssh_run", "ssh_sudo"] {
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
        server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
    for profile in ["read-only-files", "files-only"] {
        let config = FIXED_SUDO_TOOL_CONFIG.replacen(
            "profile = \"actions-only\"",
            &format!("profile = \"{profile}\""),
            1,
        );
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            let tools = listed["result"]["tools"].as_array().context("file profile tools")?;
            for (index, name) in ["fixed_id", "fixed_printf", "ssh_sudo"].into_iter().enumerate() {
                ensure!(!tools.iter().any(|tool| tool["name"] == name));
                let id = 3 + index as u64;
                let arguments = match name {
                    "fixed_printf" => json!({"host":"base","value":"BINDING_INPUT_SECRET"}),
                    "ssh_sudo" => profile_call_arguments(name, "base"),
                    _ => json!({"host":"base"}),
                };
                server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})).await?;
                let response = server.response(id).await?;
                ensure!(response["error"]["code"] == -32602);
                binding_public_only(&serde_json::to_vec(&response)?)?;
            }
            server.send(json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
        unauthorized.replace(
            "enabled_tools = [\"fixed_id\", \"fixed_printf\"]",
            "enabled_tools = []",
        ),
    ));
    cases.push((
        "profile-hidden unauthorized definition",
        unauthorized.replacen("profile = \"actions-only\"", "profile = \"files-only\"", 1),
    ));
    cases.push((
        "disabled malformed definition",
        FIXED_SUDO_TOOL_CONFIG
            .replace(
                "enabled_tools = [\"fixed_id\", \"fixed_printf\"]",
                "enabled_tools = []",
            )
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

const REMOTE_SCRIPT_TOOL_CONFIG: &str = indoc::indoc! {r#"
    profile = "actions-only"
    enabled_tools = ["observe_script"]
    [ssh]
    config_file = "replacement.conf"
    [limits]
    connect_timeout_secs = 1
    operation_timeout_secs = 3
    max_timeout_secs = 5
    max_output_bytes = 4096
    max_file_bytes = 8192
    [targets.base]
    ssh_host = "private-binding-script-backend.invalid"
    [targets.base.sudo]
    mode = "separate-identity"
    ssh_host = "private-binding-script-elevated.invalid"
    users = ["root"]
    programs = ["/private/binding-script-interpreter"]
    [targets.read]
    ssh_host = "private-binding-script-read.invalid"
    profile = "read-only-files"
    [targets.files]
    ssh_host = "private-binding-script-files.invalid"
    profile = "files-only"
    [targets.other]
    ssh_host = "private-binding-script-other.invalid"
    [tools.observe_script]
    description = "Observe a reviewed site script."
    revision = "script-1"
    targets = ["base", "read", "files"]
    authority = "ordinary"
    effects = ["read"]
    execution = { kind = "remote_script", source = { path = "/private/binding-script-source", content_sha256 = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF", max_bytes = 4096 }, interpreter = { program = "/private/binding-script-interpreter", argv = ["private-binding-script-prefix", "-s", "--"] }, argv = ["private-binding-script-fixed", { input = "value" }], cwd = "/private/binding-script-cwd" }
    input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 64 } } }
    result = { kind = "command" }
    limits = { timeout_secs = 2, max_output_bytes = 1024 }
"#};

fn script_public_only(bytes: &[u8]) -> Result<()> {
    binding_public_only(bytes)?;
    let text = std::str::from_utf8(bytes)?;
    for private in [
        "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "SCRIPT_CONFIG_SECRET",
    ] {
        ensure!(!text.contains(private), "script private content disclosed");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_scripts_publish_private_ordinary_command_contracts() -> Result<()> {
    // Neither publication nor discovery may load the nonexistent remote source.
    for default_cap in [false, true] {
        let config = REMOTE_SCRIPT_TOOL_CONFIG.replacen(
            "profile = \"actions-only\"",
            "profile = \"baseline\"",
            1,
        );
        let config = if default_cap {
            config.replace(", max_bytes = 4096", "")
        } else {
            config
        };
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            script_public_only(&serde_json::to_vec(&listed)?)?;
            let tools = listed["result"]["tools"].as_array().context("script tools")?;
            let tool = tools.iter().find(|tool| tool["name"] == "observe_script").context("script route")?;
            ensure!(tool["_meta"] == json!({
                "revision":"script-1", "authority":"ordinary", "effects":["read"],
                "result":"command", "executor":"remote_script",
                "execution_location": "remote", "trusted_controller_code": false,
                "restriction_boundary": {
                    "mcp": "request_policy", "os": "service_account_and_remote_identity",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                },
            }));
            ensure!(tool["annotations"]["readOnlyHint"] == true);
            ensure!(tool["annotations"]["destructiveHint"] == false);
            ensure!(tool["annotations"]["idempotentHint"] == false);
            let schema = &tool["inputSchema"];
            ensure!(schema["additionalProperties"] == false);
            let properties = schema["properties"].as_object().context("script input properties")?;
            ensure!(properties.len() == 4);
            ensure!(properties.contains_key("host") && properties.contains_key("value"));
            let required = schema["required"].as_array().context("script required inputs")?;
            ensure!(required.len() == 2);
            ensure!(required.contains(&json!("host")) && required.contains(&json!("value")));
            ensure!(schema["properties"]["timeout_secs"]["maximum"] == 2);
            output_control_schema(schema)?;
            let command = tools.iter().find(|tool| tool["name"] == "ssh_run").context("native command route")?;
            ensure!(tool["outputSchema"].is_object());
            ensure!(tool["outputSchema"] == command["outputSchema"]);
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
            let discovered = server.response(3).await?;
            script_public_only(&serde_json::to_vec(&discovered)?)?;
            for row in discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("script target rows")? {
                let operations = row["permitted_operations"].as_array().context("script operations")?;
                ensure!(operations.contains(&json!("observe_script")) == (row["name"] == "base"), "{row}");
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success());
        no_remote_dispatch(&stderr)?;
        script_public_only(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_script_source_execution_and_control_overrides_reject_before_ssh() -> Result<()> {
    let (mut server, directory) = named_tools_server(REMOTE_SCRIPT_TOOL_CONFIG)?;
    let scenario = async {
        server.initialize().await?;
        let valid = json!({"host":"base","value":"BINDING_INPUT_SECRET"});
        let mut id = 2;
        for (field, value) in [
            ("source", json!({"path":"/private/binding-override","content_sha256":"BINDING_INPUT_SECRET"})),
            ("path", json!("/private/binding-override")),
            ("content_sha256", json!("BINDING_INPUT_SECRET")),
            ("max_bytes", json!(1)),
            ("interpreter", json!({"program":"/private/binding-override","argv":["--"]})),
            ("program", json!("/private/binding-override")),
            ("argv", json!(["BINDING_INPUT_SECRET"])),
            ("cwd", json!("/private/binding-override")),
            ("stdin", json!("BINDING_INPUT_SECRET")),
            ("execution", json!({"kind":"native_argv"})),
            ("authority", json!({"sudo":"root"})),
            ("user", json!("root")),
            ("role", json!("elevated")),
            ("sudo", json!(true)),
            ("profile", json!("baseline")),
            ("enabled_tools", json!(["observe_script"])),
            ("timeout_secs", json!("BINDING_INPUT_SECRET")),
            ("retain_output", json!("BINDING_INPUT_SECRET")),
            ("value", json!({"input":"BINDING_INPUT_SECRET"})),
            ("extra", json!("BINDING_INPUT_SECRET")),
        ] {
            let mut arguments = valid.clone();
            arguments[field] = value;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_script","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            ensure!(response["error"]["code"] == -32602, "{field}: {response}");
            script_public_only(&serde_json::to_vec(&response)?)?;
            id += 1;
        }
        for missing in ["host", "value"] {
            let mut arguments = valid.clone();
            arguments.as_object_mut().context("script arguments")?.remove(missing);
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_script","arguments":arguments}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602, "missing {missing}");
            id += 1;
        }
        for timeout_secs in [0, 3] {
            let mut arguments = valid.clone();
            arguments["timeout_secs"] = json!(timeout_secs);
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_script","arguments":arguments}})).await?;
            let response = server.response(id).await?;
            ensure!(response["result"]["isError"] == true);
            let structured = &response["result"]["structuredContent"];
            ensure!(structured["data"].is_null());
            ensure!(structured["error"]["code"] == "invalid_argument");
            ensure!(structured["error"]["remote_state_unknown"] == false);
            script_public_only(&serde_json::to_vec(&response)?)?;
            id += 1;
        }
        for host in ["read", "files", "other", "private-binding-script-elevated.invalid", "unconfigured.invalid"] {
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"observe_script","arguments":{"host":host,"value":"BINDING_INPUT_SECRET"}}})).await?;
            let response = server.response(id).await?;
            profile_policy_denied(&response)?;
            script_public_only(&serde_json::to_vec(&response)?)?;
            id += 1;
        }
        server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        discovery_data(&server.response(id).await?["result"], "configured")?;
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    no_remote_dispatch(&stderr)?;
    script_public_only(&stderr)?;
    let mut rejections = 0;
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        if record["tool"] == "observe_script" {
            rejections += 1;
            ensure!(record["event"] == "reject");
            ensure!(record["identity_role"] == "ordinary");
            ensure!(record["binding_revision"] == "script-1");
            ensure!(record["executor"] == "remote_script");
            ensure!(record["remote_state_unknown"] == false);
        }
    }
    ensure!(rejections > 0, "script policy rejections were not audited");
    ensure!(!directory.path().join("binding-must-not-probe").exists());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_scripts_require_enablement_and_cannot_bypass_hidden_profiles() -> Result<()> {
    for (label, config) in [
        (
            "unselected",
            REMOTE_SCRIPT_TOOL_CONFIG
                .replace("enabled_tools = [\"observe_script\"]", "enabled_tools = []"),
        ),
        (
            "no selection",
            REMOTE_SCRIPT_TOOL_CONFIG.replace("enabled_tools = [\"observe_script\"]\n", ""),
        ),
        (
            "read-only",
            REMOTE_SCRIPT_TOOL_CONFIG.replacen(
                "profile = \"actions-only\"",
                "profile = \"read-only-files\"",
                1,
            ),
        ),
        (
            "files-only",
            REMOTE_SCRIPT_TOOL_CONFIG.replacen(
                "profile = \"actions-only\"",
                "profile = \"files-only\"",
                1,
            ),
        ),
    ] {
        let (mut server, directory) = named_tools_server(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            script_public_only(&serde_json::to_vec(&listed)?)?;
            ensure!(!listed["result"]["tools"].as_array().context("hidden script tools")?.iter().any(|tool| tool["name"] == "observe_script"), "{label}");
            // Valid declared arguments prove route hiding, not shape rejection.
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_script","arguments":{"host":"base","value":"BINDING_INPUT_SECRET"}}})).await?;
            let response = server.response(3).await?;
            ensure!(response["error"]["code"] == -32602, "{label}: {response}");
            script_public_only(&serde_json::to_vec(&response)?)?;
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
            let discovered = server.response(4).await?;
            script_public_only(&serde_json::to_vec(&discovered)?)?;
            for row in discovery_data(&discovered["result"], "configured")?["targets"].as_array().context("hidden script targets")? {
                ensure!(!row["permitted_operations"].as_array().context("hidden script operations")?.contains(&json!("observe_script")), "{label}: {row}");
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        let (status, stderr) = finished?;
        ensure!(status.success(), "{label}");
        no_remote_dispatch(&stderr)?;
        script_public_only(&stderr)?;
        ensure!(!directory.path().join("binding-must-not-probe").exists());
    }
    Ok(())
}

#[tokio::test]
async fn invalid_remote_script_definitions_fail_sanitized_startup_before_mcp() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("private-binding-script-config.toml");
    // This prerequisite must be valid, otherwise every compiler case can pass
    // solely because SSH configuration loading failed first.
    std::fs::write(
        directory.path().join("replacement.conf"),
        "Host *\n  ProxyCommand false\n",
    )?;
    let mut cases = Vec::new();
    for (label, from, to) in [
        ("missing source", "source = {", "SCRIPT_CONFIG_SECRET = {"),
        (
            "relative source",
            "path = \"/private/binding-script-source\"",
            "path = \"SCRIPT_CONFIG_SECRET\"",
        ),
        (
            "NUL source",
            "path = \"/private/binding-script-source\"",
            "path = \"/SCRIPT_CONFIG_SECRET\\u0000\"",
        ),
        ("missing pin", "content_sha256 =", "SCRIPT_CONFIG_SECRET ="),
        (
            "short pin",
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
            "SCRIPT_CONFIG_SECRET",
        ),
        (
            "nonhex pin",
            "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF",
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
        ("zero source cap", "max_bytes = 4096", "max_bytes = 0"),
        ("negative source cap", "max_bytes = 4096", "max_bytes = -1"),
        (
            "cap above global file limit",
            "max_bytes = 4096",
            "max_bytes = 8193",
        ),
        (
            "nonscalar source cap",
            "max_bytes = 4096",
            "max_bytes = \"SCRIPT_CONFIG_SECRET\"",
        ),
        (
            "unknown source field",
            "max_bytes = 4096",
            "max_bytes = 4096, owner = \"SCRIPT_CONFIG_SECRET\"",
        ),
        (
            "missing interpreter",
            "interpreter = {",
            "SCRIPT_CONFIG_SECRET = {",
        ),
        (
            "missing interpreter argv",
            "argv = [\"private-binding-script-prefix\", \"-s\", \"--\"]",
            "SCRIPT_CONFIG_SECRET = []",
        ),
        (
            "relative interpreter",
            "program = \"/private/binding-script-interpreter\"",
            "program = \"SCRIPT_CONFIG_SECRET\"",
        ),
        (
            "directory interpreter",
            "program = \"/private/binding-script-interpreter\"",
            "program = \"/private/binding-script-interpreter/\"",
        ),
        (
            "NUL interpreter",
            "program = \"/private/binding-script-interpreter\"",
            "program = \"/SCRIPT_CONFIG_SECRET\\u0000\"",
        ),
        (
            "dynamic interpreter prefix",
            "\"private-binding-script-prefix\", \"-s\", \"--\"",
            "{ input = \"value\" }, \"--\"",
        ),
        (
            "NUL interpreter prefix",
            "\"private-binding-script-prefix\"",
            "\"SCRIPT_CONFIG_SECRET\\u0000\"",
        ),
        (
            "unbounded option input",
            "\"private-binding-script-prefix\", \"-s\", \"--\"",
            "\"-s\"",
        ),
        (
            "unknown interpreter field",
            "interpreter = { program",
            "interpreter = { env = \"SCRIPT_CONFIG_SECRET\", program",
        ),
        (
            "unknown execution field",
            "kind = \"remote_script\", source",
            "kind = \"remote_script\", stdin = \"SCRIPT_CONFIG_SECRET\", source",
        ),
        (
            "unknown mapped input",
            "{ input = \"value\" }",
            "{ input = \"SCRIPT_CONFIG_SECRET\" }",
        ),
        (
            "interpolated input",
            "{ input = \"value\" }",
            "{ template = \"SCRIPT_CONFIG_SECRET\" }",
        ),
        (
            "sudo despite interpreter allowlist",
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        ),
        (
            "unsupported executor",
            "kind = \"remote_script\"",
            "kind = \"SCRIPT_CONFIG_SECRET\"",
        ),
        (
            "missing enabled definition",
            "enabled_tools = [\"observe_script\"]",
            "enabled_tools = [\"SCRIPT_CONFIG_SECRET\"]",
        ),
        (
            "duplicate enablement",
            "enabled_tools = [\"observe_script\"]",
            "enabled_tools = [\"observe_script\", \"observe_script\"]",
        ),
        ("built-in name collision", "observe_script", "ssh_run"),
    ] {
        cases.push((label, REMOTE_SCRIPT_TOOL_CONFIG.replace(from, to)));
    }
    cases.push((
        "sudo on an otherwise fully authorized target",
        REMOTE_SCRIPT_TOOL_CONFIG
            .replace(
                "targets = [\"base\", \"read\", \"files\"]",
                "targets = [\"base\"]",
            )
            .replace(
                "authority = \"ordinary\"",
                "authority = { sudo = \"root\" }",
            ),
    ));
    cases.push((
        "combined interpreter and script slot limit",
        REMOTE_SCRIPT_TOOL_CONFIG.replace(
            "\"private-binding-script-prefix\", \"-s\", \"--\"",
            &format!(
                "{}, \"--\"",
                vec!["\"private-binding-script-prefix\""; 63].join(", ")
            ),
        ),
    ));
    cases.push((
        "source above absolute ceiling",
        REMOTE_SCRIPT_TOOL_CONFIG
            .replace("max_file_bytes = 8192", "max_file_bytes = 2097152")
            .replace("max_bytes = 4096", "max_bytes = 1048577"),
    ));
    for (label, selection) in [
        ("disabled malformed source", "enabled_tools = []"),
        (
            "profile-hidden malformed source",
            "enabled_tools = [\"observe_script\"]",
        ),
    ] {
        cases.push((
            label,
            REMOTE_SCRIPT_TOOL_CONFIG
                .replace("enabled_tools = [\"observe_script\"]", selection)
                .replacen("profile = \"actions-only\"", "profile = \"files-only\"", 1)
                .replace("max_bytes = 4096", "max_bytes = 0"),
        ));
    }
    for (label, config) in cases {
        std::fs::write(&path, config)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&["--config", path.to_str().context("config path")?]).output(),
        )
        .await??;
        ensure!(!output.status.success(), "accepted {label}");
        ensure!(output.stdout.is_empty(), "started MCP for {label}");
        script_public_only(&output.stderr)?;
        let stderr = std::str::from_utf8(&output.stderr)?;
        ensure!(
            !stderr.contains(path.to_str().context("config path")?),
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

// Every local capability prerequisite is real and owned by this fixture. In
// particular, a missing SSH config must never mask a controller compiler error.
struct ControllerProtocolFixture {
    directory: tempfile::TempDir,
    source: std::path::PathBuf,
    interpreter: std::path::PathBuf,
    root: std::path::PathBuf,
    config_path: std::path::PathBuf,
    config: String,
    hash: String,
}

impl ControllerProtocolFixture {
    fn new() -> Result<Self> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let source = directory.path().join("private-controller-source");
        let interpreter = directory.path().join("private-controller-interpreter");
        let root = directory.path().join("private-controller-workspace");
        let config_path = directory.path().join("private-controller-config.toml");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let shell = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join("sh"))
            .chain([std::path::PathBuf::from("/bin/sh")])
            .find(|path| path.is_file())
            .context("a POSIX sh interpreter is required")?;
        let shell = std::fs::canonicalize(shell)?;
        let quoted_shell = format!("'{}'", shell.to_string_lossy().replace('\'', "'\\''"));
        std::fs::write(
            &interpreter,
            format!("#!{}\nexec {quoted_shell} \"$@\"\n", shell.display()),
        )?;
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o700))?;
        // Shell builtins only: no runtime PATH dependencies and no evaluation of
        // the private input, including hostile shell metacharacters.
        let bytes = b"IFS= read -r payload < \"$1\" || :\nprintf '%s' \"$payload\"\n";
        std::fs::write(&source, bytes)?;
        let hash = hex::encode(Sha256::digest(std::fs::read(&source)?));
        std::fs::write(
            directory.path().join("replacement.conf"),
            "Host *\n  ProxyCommand false\n  BatchMode yes\n",
        )?;
        let string = |path: &std::path::Path| -> Result<String> {
            Ok(serde_json::to_string(
                path.to_str().context("fixture UTF-8 path")?,
            )?)
        };
        let config = format!(
            r#"profile = "actions-only"
enabled_tools = ["observe_controller"]
[ssh]
config_file = "replacement.conf"
[limits]
connect_timeout_secs = 1
operation_timeout_secs = 3
max_timeout_secs = 5
max_output_bytes = 4096
max_file_bytes = 8192
[controller]
workspace_root = {}
[targets.base]
ssh_host = "controller-protocol-never-connect.invalid"
profile = "read-only-files"
[tools.observe_controller]
description = "Observe explicit controller authority."
revision = "review-controller-1"
authority = "controller"
effects = ["read"]
execution = {{ kind = "controller_script", source = {{ path = {}, content_sha256 = "{hash}", max_bytes = 4096 }}, interpreter = {{ program = {}, argv = [] }}, environment = {{ MCP_APPLICATION = "CONTROLLER_CONFIG_SECRET" }} }}
input_schema = {{ type = "object", additionalProperties = false, required = ["label", "count", "verbose"], properties = {{ label = {{ type = "string", maxLength = 256 }}, count = {{ type = "integer", minimum = -2, maximum = 4 }}, verbose = {{ type = "boolean" }} }} }}
result = {{ kind = "controller_command" }}
limits = {{ timeout_secs = 2, max_output_bytes = 1024 }}
"#,
            string(&root)?,
            string(&source)?,
            string(&interpreter)?,
        );
        Ok(Self {
            directory,
            source,
            interpreter,
            root,
            config_path,
            config,
            hash,
        })
    }

    fn start(&self, config: &str) -> Result<Server> {
        std::fs::write(&self.config_path, config)?;
        Server::start(&[
            "--config",
            self.config_path.to_str().context("config path")?,
        ])
    }

    fn public_only(&self, bytes: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(bytes)?;
        for secret in [
            self.directory.path().to_str().context("fixture path")?,
            self.hash.as_str(),
            "CONTROLLER_CONFIG_SECRET",
            "CONTROLLER_INPUT_SECRET",
            "controller-protocol-never-connect.invalid",
        ] {
            ensure!(
                !text.contains(secret),
                "controller private content disclosed"
            );
        }
        Ok(())
    }

    async fn rejects_startup(&self, label: &str, config: &str) -> Result<()> {
        std::fs::write(&self.config_path, config)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&[
                "--config",
                self.config_path.to_str().context("config path")?,
            ])
            .output(),
        )
        .await??;
        ensure!(!output.status.success(), "accepted {label}");
        ensure!(output.stdout.is_empty(), "started MCP for {label}");
        self.public_only(&output.stderr)?;
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_config",
            "{label}: {diagnostic}"
        );
        Ok(())
    }
}

fn output_control_schema(schema: &Value) -> Result<()> {
    ensure!(schema["properties"]["retain_output"]["type"] == "boolean");
    ensure!(schema["properties"]["retain_output"]["default"] == false);
    ensure!(
        !schema["required"]
            .as_array()
            .is_some_and(|fields| fields.contains(&json!("retain_output"))),
        "output retention became required"
    );
    Ok(())
}

fn schema_has_property(value: &Value, property: &str) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key(property))
                || object
                    .values()
                    .any(|child| schema_has_property(child, property))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| schema_has_property(child, property)),
        _ => false,
    }
}

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
    for profile in ["baseline", "actions-only"] {
        let fixture = ControllerProtocolFixture::new()?;
        let config = fixture.config.replace(
            "profile = \"actions-only\"",
            &format!("profile = \"{profile}\""),
        );
        let mut server = fixture.start(&config)?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
            let listed = server.response(2).await?;
            fixture.public_only(&serde_json::to_vec(&listed)?)?;
            let tools = listed["result"]["tools"].as_array().context("controller tools")?;
            let tool = tools.iter().find(|tool| tool["name"] == "observe_controller").context("controller route")?;
            ensure!(tool["_meta"] == json!({
                "revision":"review-controller-1", "authority":"controller", "effects":["read"],
                "executor":"controller_script", "result":"controller_command", "execution_location":"controller",
                "trusted_controller_code": true,
                "restriction_boundary": {
                    "mcp": "request_policy", "os": "service_account",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                }
            }));
            let inspected = command(&[
                "catalog", "--root",
                concat!(env!("CARGO_MANIFEST_DIR"), "/catalog"),
                "inspect", "--site",
                fixture.config_path.to_str().context("controller config path")?,
            ]).output().await?;
            ensure!(inspected.status.success(), "controller inspection failed");
            fixture.public_only(&inspected.stdout)?;
            fixture.public_only(&inspected.stderr)?;
            let report: Value = serde_json::from_slice(&inspected.stdout)?;
            ensure!(report["deployment_boundary"] == json!({
                "mcp": "request_policy",
                "same_identity_arbitrary_execution": "outside_restriction",
                "service_account_separation": "operator_managed_not_observed",
                "sandbox": "not_provided_by_estus"
            }));
            let inspected_tool = report["tools"].as_array().context("inspected controller tools")?
                .iter().find(|tool| tool["name"] == "observe_controller")
                .context("inspected controller binding")?;
            for field in ["executor", "authority", "execution_location", "trusted_controller_code", "restriction_boundary"] {
                ensure!(inspected_tool[field] == tool["_meta"][field], "controller inspection changed {field}");
            }
            ensure!(inspected_tool["enabled"] == true);
            ensure!(inspected_tool["catalog_template"] == json!({"qualification":"unqualified"}));
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
                let native = tools.iter().find(|tool| tool["name"] == "ssh_run").context("native command")?;
                ensure!(native["outputSchema"] != *output);
                ensure!(schema_has_property(&native["outputSchema"], "remote_may_still_be_running"));
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
    for (profile, selection) in [
        ("actions-only", Some("enabled_tools = []")),
        ("baseline", None),
        (
            "files-only",
            Some("enabled_tools = [\"observe_controller\"]"),
        ),
        (
            "read-only-files",
            Some("enabled_tools = [\"observe_controller\"]"),
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
            .replace(
                "profile = \"actions-only\"",
                &format!("profile = \"{profile}\""),
            )
            .replace(
                "enabled_tools = [\"observe_controller\"]",
                selection.unwrap_or(""),
            );
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
            ensure!(tools.iter().any(|tool| tool["name"] == "ssh_targets"));
            if profile == "baseline" {
                ensure!(tools.iter().any(|tool| tool["name"] == "ssh_run"), "native route depends on inactive controller");
            }
            server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"observe_controller","arguments":{"label":"CONTROLLER_INPUT_SECRET","count":1,"verbose":true}}})).await?;
            ensure!(server.response(3).await?["error"]["code"] == -32602);
            server.send(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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
        ("built-in collision", "observe_controller", "ssh_run"),
        (
            "duplicate selection",
            "enabled_tools = [\"observe_controller\"]",
            "enabled_tools = [\"observe_controller\", \"observe_controller\"]",
        ),
    ] {
        let config = fixture.config.replace(from, to);
        fixture.rejects_startup(label, &config).await?;
        fixture
            .rejects_startup(
                &format!("inactive {label}"),
                &config.replace("profile = \"actions-only\"", "profile = \"files-only\""),
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
                .replace(
                    "enabled_tools = [\"observe_controller\"]",
                    "enabled_tools = []",
                ),
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
                &config.replace(
                    "enabled_tools = [\"observe_controller\"]",
                    "enabled_tools = []",
                ),
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
    use sha2::{Digest, Sha256};

    let fixture = ControllerProtocolFixture::new()?;
    let marker = fixture.directory.path().join("remote-must-not-run-locally");
    let marker_quoted = format!("'{}'", marker.to_string_lossy().replace('\'', "'\\''"));
    let source = format!("printf forbidden > {marker_quoted}\n");
    std::fs::write(&fixture.source, source.as_bytes())?;
    let pin = hex::encode(Sha256::digest(std::fs::read(&fixture.source)?));
    let config = fixture.config
        .replace(&fixture.hash, &pin)
        .replace("enabled_tools = [\"observe_controller\"]", "enabled_tools = [\"remote_only\"]")
        .replace("[tools.observe_controller]", "[tools.remote_only]")
        .replace("authority = \"controller\"", "targets = [\"base\"]\nauthority = \"ordinary\"")
        .replace("profile = \"read-only-files\"", "profile = \"baseline\"")
        .replace("kind = \"controller_script\"", "kind = \"remote_script\"")
        .replace(
            "argv = [] }, environment = { MCP_APPLICATION = \"CONTROLLER_CONFIG_SECRET\" }",
            "argv = [\"-s\", \"--\"] }, argv = [{ input = \"label\" }, { input = \"count\" }, { input = \"verbose\" }]",
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_remove_file_validation_schema_and_private_inputs_reject_before_ssh_dispatch()
-> Result<()> {
    remove_validation_schema_and_private_inputs_reject_before_ssh_dispatch("ssh_remove_file").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_remove_directory_validation_schema_and_private_inputs_reject_before_ssh_dispatch()
-> Result<()> {
    remove_validation_schema_and_private_inputs_reject_before_ssh_dispatch("ssh_remove_directory")
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
            profile = 'files-only'
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
            let params = json!({"name":"ssh_targets","arguments":{}});
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
                profile = 'files-only'
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
                .find(|tool| tool["name"] == "ssh_replace_file")
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
                let params = json!({"name":"ssh_replace_file","arguments":arguments});
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
                let params = json!({"name":"ssh_replace_file","arguments":arguments});
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
                let params = json!({"name":"ssh_replace_file","arguments":arguments});
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
                let params = json!({"name":"ssh_replace_file","arguments":arguments});
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
            let params = json!({"name":"ssh_targets","arguments":{}});
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
            ensure!(record["tool"] != "ssh_replace_file" || record["event"] == "reject");
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
    let (mut server, _directory) = server_with_config("profile = 'files-only'\n[targets]\n")?;
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
                .any(|tool| tool["name"] == "ssh_replace_file")
        );
        let mut request = modern_request(
            json!(""),
            "tools/call",
            json!({"name":"ssh_replace_file","arguments":{
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
                json!({"name":"ssh_targets","arguments":{}}),
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
            "profile='actions-only'\n[ssh]\nconfig_file='replacement.conf'\n[limits]\nmax_file_bytes=33554432\n[targets]\n",
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
            let tool = tools.iter().find(|tool| tool["name"] == "ssh_read_output").context("read output route")?;
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
                let params = json!({"name":"ssh_read_output","arguments":arguments});
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
            let params = json!({"name":"ssh_read_output","arguments":{"handle":handle,"stream":"stdout","max_bytes":1024,"encoding":"base64"}});
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
            server.send(json!({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"ssh_read_output","arguments":{"handle":handle,"stream":"stdout","max_bytes":1024}}})).await?;
            let read = server.response(30).await?;
            ensure!(read["result"]["isError"] != true, "{read}");
            let read_data = &read["result"]["structuredContent"]["data"];
            ensure!(read_data["content"] == stdout);
            ensure!(read_data["bytes_read"] == stdout.len());
            ensure!(read_data["next_offset"] == stdout.len() && read_data["eof"] == true);
            ensure!(read_data["content_sha256"] == hex::encode(Sha256::digest(stdout.as_bytes())));
            server.send(json!({"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"ssh_read_output","arguments":{"handle":handle,"stream":"stderr","max_bytes":1,"encoding":"base64"}}})).await?;
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
        if record["tool"] == "ssh_read_output" {
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
            "name":"ssh_read_output","arguments":{"handle":"0123456789abcdef0123456789abcdef","stream":"stdout","max_bytes":1}
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
    let builtin = "profile='baseline'\n[ssh]\nconfig_file='replacement.conf'\n[targets.base]\nssh_host='private-binding-backend.invalid'\n[targets.base.sudo]\nmode='same-account'\n";
    for (config, calls) in [
        (
            builtin,
            vec![
                ("ssh_exec", json!({"host":"base","command":"true"})),
                ("ssh_run", json!({"host":"base","argv":["/usr/bin/true"]})),
                ("ssh_sudo", json!({"host":"base","argv":["/usr/bin/true"]})),
            ],
        ),
        (
            NAMED_TOOL_CONFIG,
            vec![
                (
                    "observe_account",
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
        (
            REMOTE_SCRIPT_TOOL_CONFIG,
            vec![(
                "observe_script",
                json!({"host":"base","value":"BINDING_INPUT_SECRET"}),
            )],
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
            server.send(json!({"jsonrpc":"2.0","id":500,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
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

#[tokio::test]
async fn directory_cursor_discovery_and_output_schema_are_consumer_visible() -> Result<()> {
    let (mut server, directory) = server_with_config(
        "profile='read-only-files'\n[directory]\nmax_cursors=1\nidle_timeout_secs=1\n[targets]\n",
    )?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        let response = server.response(2).await?;
        let data = discovery_data(&response["result"], "configured")?;
        ensure!(data["limits"]["max_directory_cursors"] == 1);
        ensure!(data["limits"]["directory_cursor_idle_timeout_secs"] == 1);
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})).await?;
        let response = server.response(3).await?;
        let tool = response["result"]["tools"].as_array().context("tools")?
            .iter().find(|tool| tool["name"] == "ssh_list_directory").context("listing route")?;
        ensure!(tool["annotations"]["readOnlyHint"] == true);
        ensure!(tool["annotations"]["idempotentHint"] == false);
        let input = jsonschema::validator_for(&tool["inputSchema"])?;
        ensure!(input.is_valid(&json!({"host":"allowed","path":"/literal","continuation":"0123456789abcdef0123456789abcdef"})));
        ensure!(!input.is_valid(&json!({"host":"allowed","path":"/literal","continuation":"PRIVATE_BAD_TOKEN"})));
        let output = jsonschema::validator_for(&tool["outputSchema"])?;
        for data in [
            json!({"entries":[],"truncated":false}),
            json!({"entries":[],"truncated":true,"continuation":"0123456789abcdef0123456789abcdef","expires_in_secs":1}),
        ] {
            ensure!(output.is_valid(&json!({"data":data,"error":null})), "published schema rejects directory response metadata");
        }
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
