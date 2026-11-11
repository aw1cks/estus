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
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssh-mcp"));
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
        let mut child = command(args)
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
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
        let called = server.response(3).await?;
        let result = &called["result"];
        ensure!(result["structuredContent"] == json!({"data":{"mode":"open","targets":[]},"error":null}));
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
    for (text, expected) in [
        ("[targets]", json!({"mode":"configured","targets":[]})),
        (
            "[targets.zeta]\nssh_host='ordinary-secret'\n[targets.zeta.sudo]\nmode='separate-identity'\nssh_host='privileged-secret'\n[targets.alpha]\nssh_host='another-secret'",
            json!({"mode":"configured","targets":[
                {"name":"alpha","sudo_mode":"disabled"},
                {"name":"zeta","sudo_mode":"separate-identity"}
            ]}),
        ),
    ] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("operator.toml");
        std::fs::write(&path, text)?;
        let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
        let scenario = async {
            server.initialize().await?;
            server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ssh_targets","arguments":{}}})).await?;
            let response = server.response(2).await?;
            ensure!(response["result"]["structuredContent"] == json!({"data":expected,"error":null}));
            Ok::<_, anyhow::Error>(())
        }.await;
        let finished = server.finish().await;
        scenario?;
        ensure!(finished?.0.success());
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
        "[targets.allowed]\nssh_host='ordinary.invalid'\n[targets.allowed.sudo]\nmode='separate-identity'\nssh_host='privileged.invalid'\nprograms=['/usr/bin/id']\n[targets.disabled]\nssh_host='disabled.invalid'\n",
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools")?;
        ensure!(tools.iter().any(|tool| tool["name"] == "ssh_sudo"));
        for (index, args) in [
            json!({"host":"allowed","command":["DO_NOT_LOG_PAYLOAD"]}),
            json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","shell":"interactive"}),
            json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","sudo":true}),
        ].into_iter().enumerate() {
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"ssh_exec","arguments":args}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        for (index, (tool, args, code)) in [
            ("ssh_exec", json!({"host":"ordinary.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("ssh_exec", json!({"host":"privileged.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","timeout_secs":601}), "invalid_argument"),
            ("ssh_exec", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","cwd":"relative"}), "invalid_argument"),
            ("ssh_exec", json!({"host":"allowed","command":"bad\u{0}DO_NOT_LOG_PAYLOAD"}), "invalid_argument"),
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
        ensure!(
            discovery["result"]["structuredContent"]
                == json!({
                    "data":{"mode":"configured","targets":[
                        {"name":"allowed","sudo_mode":"same-account"}
                    ]},
                    "error":null
                }),
            "discovery failed after encoded-command rejections"
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
            targets["result"]["structuredContent"]
                == json!({"data": {"mode": "open", "targets": []}, "error": null}),
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
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    // A regression must fail without ever consulting the developer's SSH authority.
    std::fs::write(&path, "[targets]\n")?;
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
        for name in ["ssh_targets", "ssh_exec"] {
            ensure!(tools.iter().any(|tool| tool["name"] == name));
        }
        ensure!(!tools.iter().any(|tool| tool["name"] == "ssh_sudo"));

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
        let expected = json!({"data":{"mode":"configured","targets":[]},"error":null});
        ensure!(result["structuredContent"] == expected);
        ensure!(result["isError"] != true);
        let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().context("text result")?)?;
        ensure!(text == expected);
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
        ensure!(
            called["result"]["structuredContent"]
                == json!({"data":{"mode":"configured","targets":[]},"error":null})
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
