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
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
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
            stderr,
        })
    }

    async fn send(&mut self, value: Value) -> Result<()> {
        let input = self.input.as_mut().context("stdin already closed")?;
        input.write_all(&serde_json::to_vec(&value)?).await?;
        input.write_all(b"\n").await?;
        input.flush().await?;
        Ok(())
    }

    async fn response(&mut self, id: u64) -> Result<Value> {
        Ok(self.response_with_id(&json!(id)).await?.0)
    }

    async fn response_with_id(&mut self, id: &Value) -> Result<(Value, usize)> {
        loop {
            let mut line = Vec::new();
            let size = timeout(Duration::from_secs(5), async {
                (&mut self.output)
                    .take(16_777_217)
                    .read_until(b'\n', &mut line)
                    .await
            })
            .await??;
            ensure!(size != 0, "server closed stdout before response");
            ensure!(size <= 16_777_216, "response exceeds 16 MiB: {size} bytes");
            ensure!(line.last() == Some(&b'\n'), "unterminated response");
            let value: Value = serde_json::from_slice(&line).context("non-JSON stdout")?;
            ensure!(value["jsonrpc"] == "2.0", "non-JSON-RPC stdout");
            if &value["id"] == id {
                return Ok((value, size));
            }
            ensure!(value.get("id").is_none(), "unexpected response ID");
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

    async fn finish(mut self) -> Result<(std::process::ExitStatus, Vec<u8>)> {
        drop(self.input.take());
        let status = match timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                bail!("server failed to exit after EOF");
            }
        };
        let mut line = String::new();
        while self.output.read_line(&mut line).await? != 0 {
            let value: Value = serde_json::from_str(&line).context("non-JSON trailing stdout")?;
            ensure!(value["jsonrpc"] == "2.0");
            line.clear();
        }
        Ok((status, self.stderr.await??))
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
        let pid = server.child.id().context("owned child PID")?;
        kill(Pid::from_raw(i32::try_from(pid)?), Signal::SIGTERM)?;
        // Keep stdin open: this must be signal handling rather than EOF handling.
        let status = timeout(Duration::from_secs(5), server.child.wait()).await??;
        ensure!(status.success(), "SIGTERM was not handled: {status}");
        Ok::<_, anyhow::Error>(())
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
