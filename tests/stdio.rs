use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::timeout,
};

struct Server {
    child: Child,
    input: Option<ChildStdin>,
    lines: Lines<BufReader<ChildStdout>>,
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
}

impl Server {
    fn start(args: &[&str]) -> Result<Self> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ssh-mcp"));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SSH_MCP_") {
                command.env_remove(name);
            }
        }
        let mut child = command
            .args(args)
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
            lines: BufReader::new(output).lines(),
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
        loop {
            let line = timeout(Duration::from_secs(5), self.lines.next_line())
                .await??
                .context("server closed stdout before response")?;
            let value: Value = serde_json::from_str(&line).context("non-JSON stdout")?;
            ensure!(value["jsonrpc"] == "2.0", "non-JSON-RPC stdout");
            if value["id"] == id {
                return Ok(value);
            }
            ensure!(value.get("id").is_none(), "unexpected response ID: {value}");
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
        while let Some(line) = self.lines.next_line().await? {
            let value: Value = serde_json::from_str(&line).context("non-JSON trailing stdout")?;
            ensure!(value["jsonrpc"] == "2.0");
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
