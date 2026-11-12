// This CLI-only consumer shares the broader native/MCP fixture module.
#[allow(dead_code)]
mod support;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, Command},
    task::JoinHandle,
    time::timeout,
};

struct Doctor {
    child: Child,
    // Deliberately retained until after wait: doctor must not wait for MCP EOF.
    input: ChildStdin,
    out: JoinHandle<std::io::Result<Vec<u8>>>,
    err: JoinHandle<std::io::Result<Vec<u8>>>,
}

fn drain(
    mut pipe: impl AsyncRead + Unpin + Send + 'static,
) -> JoinHandle<std::io::Result<Vec<u8>>> {
    tokio::spawn(async move {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).await?;
        Ok(bytes)
    })
}

impl Doctor {
    fn start(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        Ok(Self {
            input: child.stdin.take().context("doctor stdin")?,
            out: drain(child.stdout.take().context("doctor stdout")?),
            err: drain(child.stderr.take().context("doctor stderr")?),
            child,
        })
    }

    async fn finish(mut self) -> Result<Output> {
        let status = match timeout(Duration::from_secs(20), self.child.wait()).await {
            Ok(result) => result?,
            Err(error) => {
                self.child.kill().await?;
                self.out.abort();
                self.err.abort();
                return Err(error).context("doctor did not exit with stdin still open");
            }
        };
        drop(self.input);
        Ok(Output {
            status,
            stdout: timeout(support::CLEANUP, self.out).await???,
            stderr: timeout(support::CLEANUP, self.err).await???,
        })
    }
}

fn command(config: &Path, args: &[&str]) -> Result<Command> {
    let mut command = support::server_command(config)?;
    command.arg("doctor").args(args);
    Ok(command)
}

fn report(output: &Output, exit: i32) -> Result<Value> {
    ensure!(
        output.status.code() == Some(exit),
        "unexpected doctor status: {}",
        output.status
    );
    ensure!(output.stdout.len() <= 65_536, "unbounded doctor report");
    ensure!(output.stdout.last() == Some(&b'\n'), "unterminated report");
    ensure!(
        output.stdout.iter().filter(|&&b| b == b'\n').count() == 1,
        "multiple stdout frames"
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let object = value.as_object().context("report object")?;
    ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "ok" | "targets" | "error_code"))
    );
    ensure!(value["ok"] == (exit == 0));
    for target in value["targets"].as_array().context("target array")? {
        let target = target.as_object().context("target object")?;
        ensure!(target.len() == 4);
        ensure!(target.get("target").is_some_and(Value::is_string));
        for name in ["ssh", "sftp", "sudo"] {
            let check = target
                .get(name)
                .and_then(Value::as_object)
                .context("check object")?;
            ensure!(
                check
                    .keys()
                    .all(|key| matches!(key.as_str(), "status" | "error_code"))
            );
            ensure!(matches!(
                check.get("status").and_then(Value::as_str),
                Some("passed" | "failed" | "not_tested")
            ));
            if let Some(code) = check.get("error_code") {
                fixed_code(code)?;
            }
        }
        ensure!(target["sudo"] == json!({"status":"not_tested"}));
    }
    if let Some(code) = value.get("error_code") {
        fixed_code(code)?;
    }
    Ok(value)
}

fn fixed_code(value: &Value) -> Result<()> {
    let code = value.as_str().context("static error code")?;
    ensure!(!code.is_empty() && code.len() <= 64);
    ensure!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    Ok(())
}

fn private(output: &Output, secrets: &[&str]) -> Result<()> {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in secrets {
            ensure!(
                !text.contains(secret),
                "doctor disclosed private fixture data"
            );
        }
        for forbidden in [
            "jsonrpc",
            "tools/list",
            "tools/call",
            "PRIVATE KEY",
            "Permission denied",
            "Host key verification failed",
        ] {
            ensure!(
                !text.contains(forbidden),
                "doctor emitted backend/MCP diagnostics"
            );
        }
    }
    Ok(())
}

fn config_error(output: &Output) -> Result<()> {
    ensure!(output.status.code() == Some(2));
    ensure!(
        output.stdout.is_empty(),
        "invalid config entered doctor/MCP output"
    );
    let error: Value = serde_json::from_slice(&output.stderr)?;
    ensure!(error["event"] == "error" && error["code"] == "invalid_config");
    ensure!(error["message"].is_string());
    Ok(())
}

struct Local {
    root: TempDir,
    config: PathBuf,
    ssh: PathBuf,
    marker: PathBuf,
}

impl Local {
    fn new(body: &str) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("doctor-private-config-")
            .tempdir()?;
        let config = root.path().join("private-service.toml");
        let ssh = root.path().join("private-ssh-config");
        let marker = root.path().join("ssh-must-not-start");
        // A readable real OpenSSH configuration, not an early load-error shortcut.
        // Any accidental dispatch is observed without a listener or network access.
        fs::write(
            &ssh,
            format!(
                "Host *\n HostName 127.0.0.1\n ProxyCommand /bin/sh -c {}\n IdentityAgent none\n BatchMode yes\n",
                support::quote(&format!(
                    "printf forbidden > {}; exit 1",
                    support::quote(&marker.to_string_lossy())
                ))
            ),
        )?;
        fs::write(
            &config,
            format!(
                "[ssh]\nconfig_file = {}\n{body}",
                serde_json::to_string(&ssh.to_string_lossy())?
            ),
        )?;
        Ok(Self {
            root,
            config,
            ssh,
            marker,
        })
    }

    async fn invalid(&self, args: &[&str], code: &str) -> Result<()> {
        let before = (fs::read(&self.config)?, fs::read(&self.ssh)?);
        let mut child = Doctor::start(command(&self.config, args)?)?;
        // These bytes must neither trigger initialize nor become a tool exchange.
        if let Err(error) = child
            .input
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n")
            .await
        {
            ensure!(error.kind() == std::io::ErrorKind::BrokenPipe);
        }
        let output = child.finish().await?;
        if code == "invalid_config" {
            config_error(&output)?;
        } else {
            let value = report(&output, 2)?;
            ensure!(value == json!({"ok":false,"targets":[],"error_code":code}));
        }
        private(
            &output,
            &[
                &self.root.path().to_string_lossy(),
                "PRIVATE_ALIAS_D01",
                "PRIVATE_UNKNOWN_D01",
            ],
        )?;
        ensure!(!self.marker.exists(), "invalid selection started SSH");
        ensure!(before == (fs::read(&self.config)?, fs::read(&self.ssh)?));
        Ok(())
    }
}

#[tokio::test]
async fn doctor_invalid_selections_are_network_free_private_and_not_mcp() -> Result<()> {
    let fixture = Local::new(
        "[targets.allowed]\nssh_host = 'PRIVATE_ALIAS_D01'\n[limits]\nmax_timeout_secs = 15\noperation_timeout_secs = 10\n",
    )?;
    for args in [
        vec!["--target", "PRIVATE_UNKNOWN_D01"],
        vec!["--target", "PRIVATE_ALIAS_D01"],
        vec!["--target", "allowed", "--target", "PRIVATE_UNKNOWN_D01"],
        vec!["--target", "allowed", "--target", "allowed"],
        vec!["--target", "allowed", "--timeout-secs", "0"],
        vec!["--target", "allowed", "--timeout-secs", "16"],
        vec![
            "--target",
            "allowed",
            "--timeout-secs",
            "18446744073709551615",
        ],
    ] {
        let code = if args.contains(&"--timeout-secs") {
            "invalid_timeout"
        } else {
            "invalid_target_selection"
        };
        fixture.invalid(&args, code).await?;
    }
    let open = Local::new("")?;
    open.invalid(
        &["--target", "PRIVATE_ALIAS_D01"],
        "invalid_target_selection",
    )
    .await?;
    let mut body = String::new();
    let names: Vec<_> = (0..33).map(|index| format!("target-{index:02}")).collect();
    for name in &names {
        body.push_str(&format!(
            "[targets.{name}]\nssh_host = 'PRIVATE_ALIAS_D01'\n"
        ));
    }
    let limit = Local::new(&body)?;
    let args: Vec<_> = names
        .iter()
        .flat_map(|name| ["--target", name.as_str()])
        .collect();
    limit.invalid(&args, "invalid_target_selection").await
}

#[tokio::test]
async fn doctor_config_errors_are_private_and_do_not_dispatch() -> Result<()> {
    for body in [
        "PRIVATE_UNKNOWN_D01 = 'PRIVATE_ALIAS_D01'\n",
        "[targets.allowed]\nssh_host = 'PRIVATE_ALIAS_D01'\nPRIVATE_UNKNOWN_D01 = true\n",
        "[targets.allowed]\nssh_host = ['PRIVATE_ALIAS_D01']\n",
        "[targets.allowed\nPRIVATE_UNKNOWN_D01",
    ] {
        Local::new(body)?
            .invalid(&["--target", "allowed"], "invalid_config")
            .await?;
    }
    let fixture = Local::new("[targets.allowed]\nssh_host = 'PRIVATE_ALIAS_D01'\n")?;
    for path in [
        fixture.root.path().join("PRIVATE_UNKNOWN_D01"),
        fixture.root.path().to_path_buf(),
    ] {
        let output = Doctor::start(command(&path, &["--target", "allowed"])?)?
            .finish()
            .await?;
        config_error(&output)?;
        private(&output, &[&path.to_string_lossy(), "PRIVATE_UNKNOWN_D01"])?;
    }
    ensure!(!fixture.marker.exists());
    Ok(())
}

#[tokio::test]
async fn doctor_help_and_argument_surface_are_standalone() -> Result<()> {
    let fixture = Local::new("")?;
    let output = Doctor::start(command(&fixture.config, &["--help"])?)?
        .finish()
        .await?;
    ensure!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for option in ["--target", "--timeout-secs", "--config", "--ssh-config"] {
        ensure!(help.contains(option), "missing doctor option {option}");
    }
    for args in [
        vec![],
        vec!["--all"],
        vec!["--target", "allowed", "--sudo"],
        vec!["--target", "allowed", "--host", "PRIVATE_ALIAS_D01"],
    ] {
        let output = Doctor::start(command(&fixture.config, &args)?)?
            .finish()
            .await?;
        ensure!(output.status.code() == Some(2));
        ensure!(
            output.stdout.is_empty(),
            "argument rejection started report/MCP"
        );
    }
    // Both global positions must reach semantic validation, not clap rejection.
    let inherited = support::server_command(&fixture.config)?;
    let mut after = Command::new(inherited.as_std().get_program());
    for (key, value) in inherited.as_std().get_envs() {
        if let Some(value) = value {
            after.env(key, value);
        } else {
            after.env_remove(key);
        }
    }
    after
        .args(["doctor", "--config"])
        .arg(&fixture.config)
        .arg("--ssh-config")
        .arg(&fixture.ssh)
        .args(["--target", "PRIVATE_UNKNOWN_D01"]);
    let output = Doctor::start(after)?.finish().await?;
    report(&output, 2)?;
    private(&output, &["PRIVATE_UNKNOWN_D01"])?;
    ensure!(!fixture.marker.exists());
    Ok(())
}

#[tokio::test]
async fn doctor_explicit_ssh_config_errors_never_fall_back_to_environment() -> Result<()> {
    let fixture = Local::new("[targets.allowed]\nssh_host = 'PRIVATE_ALIAS_D01'\n")?;
    let before = (fs::read(&fixture.config)?, fs::read(&fixture.ssh)?);
    for path in [
        fixture.root.path().join("PRIVATE_UNKNOWN_D01"),
        fixture.root.path().to_path_buf(),
    ] {
        let mut command = command(&fixture.config, &["--target", "allowed"])?;
        command
            .arg("--ssh-config")
            .arg(&path)
            .env("SSH_MCP_SSH_CONFIG", &fixture.ssh);
        let output = Doctor::start(command)?.finish().await?;
        config_error(&output)?;
        private(
            &output,
            &[
                &fixture.root.path().to_string_lossy(),
                "PRIVATE_ALIAS_D01",
                "PRIVATE_UNKNOWN_D01",
            ],
        )?;
    }
    ensure!(
        !fixture.marker.exists(),
        "invalid SSH configuration fell back or dispatched"
    );
    ensure!(before == (fs::read(&fixture.config)?, fs::read(&fixture.ssh)?));
    Ok(())
}
