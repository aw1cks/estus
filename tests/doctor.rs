// This CLI-only consumer shares the broader native/MCP fixture module.
#[allow(dead_code)]
mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};
use support::{Fixture, Process, assert_masters_gone};
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

fn snapshots(fixture: &Fixture) -> Result<Vec<(PathBuf, Vec<u8>)>> {
    [
        "server.toml",
        "ssh_config",
        "included.conf",
        "known_hosts",
        "client",
        "host0",
        "host1",
        "doctor-source",
    ]
    .into_iter()
    .map(|name| {
        let path = fixture.root.path().join(name);
        let bytes = fs::read(&path)?;
        Ok((path, bytes))
    })
    .collect()
}

fn unchanged(before: &[(PathBuf, Vec<u8>)]) -> Result<()> {
    for (path, bytes) in before {
        ensure!(
            &fs::read(path)? == bytes,
            "doctor changed fixture-owned file"
        );
    }
    Ok(())
}

async fn cleaned(output: &Output) -> Result<usize> {
    let mut owned = Vec::new();
    for line in output
        .stderr
        .split(|&b| b == b'\n')
        .filter(|line| !line.is_empty())
    {
        if let Ok(record) = serde_json::from_slice::<Value>(line)
            && record["event"] == "master_start"
        {
            ensure!(record["role"] == "ordinary");
            owned.push((
                u32::try_from(record["pid"].as_u64().context("master PID")?)?,
                PathBuf::from(record["socket"].as_str().context("master socket")?),
            ));
        }
    }
    if !owned.is_empty() {
        assert_masters_gone(&owned).await?;
    }
    Ok(owned.len())
}

fn native_privacy(output: &Output, fixture: &Fixture) -> Result<()> {
    private(
        output,
        &[
            &fixture.root.path().to_string_lossy(),
            "plain",
            "nosftp",
            "PRIVATE_ELEVATED_D01",
            "PRIVATE_DIAGNOSTIC_D01",
            "PRIVATE_SOURCE_D01",
        ],
    )
}

fn native_config(fixture: &Fixture, body: &str) -> Result<()> {
    fs::write(
        fixture.root.path().join("doctor-source"),
        b"PRIVATE_SOURCE_D01\n",
    )?;
    fs::write(
        &fixture.config,
        format!(
            "[ssh]\nconfig_file = {}\n[limits]\nconnect_timeout_secs = 3\noperation_timeout_secs = 10\nmax_timeout_secs = 15\n{body}",
            serde_json::to_string(&fixture.ssh_config.to_string_lossy())?
        ),
    )?;
    Ok(())
}

fn no_commands(fixture: &Fixture, before: &[String]) -> Result<()> {
    for (listener, before) in fixture.listeners.iter().zip(before) {
        let after = listener.log.text();
        let commands = |text: &str| {
            text.lines()
                .filter(|line| {
                    line.contains("Starting session: command")
                        || line.contains("Starting session: shell")
                })
                .count()
        };
        ensure!(
            commands(&after) == commands(before),
            "doctor executed a remote command or shell"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "native: Nix OpenSSH, non-root POSIX account, private runtime directory, loopback"]
async fn doctor_native_selected_ssh_executable_is_shared_with_native_tools() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let wrapper = fixture.root.path().join("selected ssh");
        let launches = fixture.root.path().join("selected-ssh-launches");
        // This wrapper still runs real OpenSSH and preserves its PID/ownership.
        // Its marker distinguishes selecting it from merely connecting successfully.
        fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nprintf 'selected\\n' >> {}\nexec {} \"$@\"\n",
                support::quote(&launches.to_string_lossy()),
                support::quote(&fixture.ssh.to_string_lossy()),
            ),
        )?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))?;
        native_config(&fixture, "[targets.selected]\nssh_host = 'plain'\n")?;
        let config = fs::read_to_string(&fixture.config)?;
        fs::write(
            &fixture.config,
            config.replacen("[ssh]\n", "[ssh]\nexecutable = 'selected ssh'\n", 1),
        )?;
        let empty_path = fixture.root.path().join("empty-path");
        fs::create_dir(&empty_path)?;
        let auth = fixture.authentications();
        let mut diagnostic = command(&fixture.config, &["--target", "selected"])?;
        // Neither the selected wrapper nor the native master may look up ssh again.
        diagnostic.env("PATH", &empty_path);
        let output = Doctor::start(diagnostic)?.finish().await?;
        let value = report(&output, 0)?;
        ensure!(value["targets"][0]["ssh"] == json!({"status":"passed"}));
        ensure!(value["targets"][0]["sftp"] == json!({"status":"passed"}));
        ensure!(fs::read_to_string(&launches)? == "selected\n");
        ensure!(cleaned(&output).await? == 1);
        native_privacy(&output, &fixture)?;

        let mut native = support::server_command(&fixture.config)?;
        native.env("PATH", &empty_path);
        let mut server = support::WireServer::start_command(native)?;
        let connected = async {
            server.initialize().await?;
            let reply = server
                .request(
                    2,
                    "tools/call",
                    json!({"name":"ssh_exec","arguments":{
                        "host":"selected","command":"printf selected-native"
                    }}),
                )
                .await?;
            let result = &reply["result"]["structuredContent"];
            ensure!(
                result["error"].is_null() && result["data"]["exit_code"] == 0,
                "native exec failed: {reply}"
            );
            ensure!(result["data"]["stdout"] == "selected-native");
            ensure!(fs::read_to_string(&launches)? == "selected\nselected\n");
            fixture.await_authentications(auth + 2).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let stopped = server.stop(None).await;
        connected?;
        let log = stopped?;
        let owned = support::masters(&log)?;
        ensure!(owned.len() == 1);
        assert_masters_gone(&owned).await
    }
    .await;
    let stopped = fixture.stop().await;
    scenario?;
    stopped
}

#[tokio::test]
#[ignore = "native: Nix OpenSSH, non-root POSIX account, private runtime directory, loopback"]
async fn doctor_native_restrictive_profiles_are_ordinary_read_only_and_do_not_load_keys()
-> Result<()> {
    // Deny every file operation; protocol INIT/VERSION and close must still work.
    let server = Fixture::sftp_server()?;
    let subsystem = format!(
        "{} -P open,close,read,write,lstat,fstat,setstat,fsetstat,opendir,readdir,remove,mkdir,rmdir,realpath,stat,rename,readlink,symlink,hardlink,fsync,statvfs,fstatvfs",
        server.display()
    );
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        // Unix-domain socket limits are shorter than the trusted native fixture ancestry.
        let agent_directory = tempfile::Builder::new().prefix("da-").tempdir_in("/tmp")?;
        let agent_path = agent_directory.path().join("a");
        let mut agent = Command::new(support::find_program("ssh-agent")?);
        agent.args(["-D", "-a"]).arg(&agent_path);
        let agent = Process::start(&mut agent)?;
        let scenario = async {
            Fixture::await_file(&agent_path).await?;
            let ssh_add = support::find_program("ssh-add")?;
            let empty = support::run(Command::new(&ssh_add).arg("-l").env("SSH_AUTH_SOCK", &agent_path)).await?;
            ensure!(empty.status.code() == Some(1), "owned agent is not empty");
            let ssh = format!(
                "Host *\n    IdentityAgent {}\n    AddKeysToAgent yes\n    UpdateHostKeys yes\n{}",
                agent_path.display(), fs::read_to_string(&fixture.ssh_config)?,
            );
            fs::write(&fixture.ssh_config, ssh)?;
            let mut body = String::new();
            for (name, profile) in [("alpha", "actions-only"), ("beta", "files-only"), ("gamma", "read-only-files")] {
                body.push_str(&format!("[targets.{name}]\nssh_host = 'plain'\nprofile = '{profile}'\n[targets.{name}.sudo]\nmode = 'separate-identity'\nssh_host = 'PRIVATE_ELEVATED_D01'\n"));
            }
            native_config(&fixture, &body)?;
            let config = fs::read_to_string(&fixture.config)?;
            fs::write(&fixture.config, format!("profile = 'actions-only'\n{config}"))?;
            let before = snapshots(&fixture)?;
            let logs: Vec<_> = fixture.listeners.iter().map(|listener| listener.log.text()).collect();
            let auth = fixture.authentications();
            let output = Doctor::start(command(&fixture.config, &["--target", "gamma", "--target", "alpha", "--target", "beta"])?)?.finish().await?;
            let value = report(&output, 0)?;
            let targets: Vec<_> = ["alpha", "beta", "gamma"].into_iter().map(|target| json!({"target":target,"ssh":{"status":"passed"},"sftp":{"status":"passed"},"sudo":{"status":"not_tested"}})).collect();
            ensure!(value == json!({"ok":true,"targets":targets}));
            ensure!(cleaned(&output).await? == 3);
            fixture.await_authentications(auth + 3).await?;
            no_commands(&fixture, &logs)?;
            native_privacy(&output, &fixture)?;
            unchanged(&before)?;
            let still_empty = support::run(Command::new(&ssh_add).arg("-l").env("SSH_AUTH_SOCK", &agent_path)).await?;
            ensure!(still_empty.status.code() == Some(1), "doctor enrolled a key in the owned agent");
            Ok::<_, anyhow::Error>(())
        }.await;
        let stopped = agent.stop().await;
        scenario?;
        stopped
    }.await;
    let stopped = fixture.stop().await;
    scenario?;
    stopped
}

#[tokio::test]
#[ignore = "native: Nix OpenSSH, non-root POSIX account, private runtime directory, loopback"]
async fn doctor_native_sftp_failure_is_not_an_ssh_or_sudo_diagnosis() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        native_config(&fixture, "[targets.selected]\nssh_host = 'nosftp'\n[targets.unselected]\nssh_host = 'PRIVATE_ELEVATED_D01'\n")?;
        let before = snapshots(&fixture)?;
        let logs: Vec<_> = fixture.listeners.iter().map(|listener| listener.log.text()).collect();
        let auth = fixture.authentications();
        let output = Doctor::start(command(&fixture.config, &["--target", "selected"])?)?.finish().await?;
        let value = report(&output, 1)?;
        ensure!(value["targets"].as_array().context("targets")?.len() == 1);
        let target = &value["targets"][0];
        ensure!(target["target"] == "selected");
        ensure!(target["ssh"] == json!({"status":"passed"}));
        ensure!(target["sftp"]["status"] == "failed");
        ensure!(matches!(target["sftp"]["error_code"].as_str(), Some("unsupported" | "io_error" | "connection_lost")));
        ensure!(cleaned(&output).await? == 1);
        fixture.await_authentications(auth + 1).await?;
        no_commands(&fixture, &logs)?;
        native_privacy(&output, &fixture)?;
        unchanged(&before)
    }.await;
    let stopped = fixture.stop().await;
    scenario?;
    stopped
}

#[tokio::test]
#[ignore = "native: Nix OpenSSH, non-root POSIX account, private runtime directory, loopback"]
async fn doctor_native_unknown_host_key_is_not_enrolled_or_repaired() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        native_config(&fixture, "[targets.selected]\nssh_host = 'plain'\n")?;
        fs::write(fixture.root.path().join("known_hosts"), b"")?;
        let ssh = fs::read_to_string(&fixture.ssh_config)?.replace(
            "StrictHostKeyChecking yes",
            "StrictHostKeyChecking accept-new\n    UpdateHostKeys yes\n    AddKeysToAgent yes",
        );
        fs::write(&fixture.ssh_config, ssh)?;
        let before = snapshots(&fixture)?;
        let auth = fixture.authentications();
        let output = Doctor::start(command(&fixture.config, &["--target", "selected"])?)?
            .finish()
            .await?;
        let value = report(&output, 1)?;
        ensure!(
            value["targets"][0]["ssh"]
                == json!({"status":"failed","error_code":"ssh_connect_failed"})
        );
        ensure!(value["targets"][0]["sftp"]["status"] == "not_tested");
        cleaned(&output).await?;
        ensure!(fixture.authentications() == auth);
        native_privacy(&output, &fixture)?;
        unchanged(&before)
    }
    .await;
    let stopped = fixture.stop().await;
    scenario?;
    stopped
}

#[tokio::test]
#[ignore = "native: Nix OpenSSH, non-root POSIX account, private runtime directory, loopback"]
async fn doctor_native_shared_deadline_and_signals_finalize_owned_masters() -> Result<()> {
    for signal in [None, Some(Signal::SIGINT), Some(Signal::SIGTERM)] {
        // SFTP protocol startup stalls while SSH has already authenticated. This
        // catches dropping the operation future instead of cancelling/finalizing it.
        let fixture = Fixture::start_with_sftp_subsystem(
            "",
            "/bin/sh -c 'sleep 4; printf PRIVATE_DIAGNOSTIC_D01 >&2; exit 1'",
        )
        .await?;
        let scenario = async {
            native_config(&fixture, "[targets.alpha]\nssh_host = 'plain'\n[targets.beta]\nssh_host = 'plain'\n")?;
            let before = snapshots(&fixture)?;
            let logs: Vec<_> = fixture.listeners.iter().map(|listener| listener.log.text()).collect();
            let auth = fixture.authentications();
            let budget = if signal.is_some() { "10" } else { "1" };
            let child = Doctor::start(command(&fixture.config, &["--target", "beta", "--target", "alpha", "--timeout-secs", budget])?)?;
            if let Some(signal) = signal {
                fixture.await_authentications(auth + 1).await?;
                timeout(Duration::from_secs(5), async {
                    loop {
                        if fixture.listeners[0].log.text().contains("subsystem 'sftp'") {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }).await.context("SFTP negotiation did not start")?;
                kill(Pid::from_raw(i32::try_from(child.child.id().context("doctor PID")?)?), signal)?;
            }
            let output = child.finish().await?;
            let value = report(&output, 1)?;
            let cause = if signal.is_some() { "cancelled" } else { "timeout" };
            ensure!(value["targets"].as_array().context("targets")?.len() == 2);
            ensure!(value["targets"][0]["target"] == "alpha");
            ensure!(value["targets"][0]["ssh"] == json!({"status":"passed"}));
            ensure!(value["targets"][0]["sftp"]["error_code"] == cause);
            ensure!(value["targets"][1] == json!({"target":"beta","ssh":{"status":"not_tested","error_code":cause},"sftp":{"status":"not_tested","error_code":cause},"sudo":{"status":"not_tested"}}));
            ensure!(cleaned(&output).await? == 1);
            fixture.await_authentications(auth + 1).await?;
            no_commands(&fixture, &logs)?;
            native_privacy(&output, &fixture)?;
            unchanged(&before)
        }.await;
        let stopped = fixture.stop().await;
        scenario?;
        stopped?;
    }
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
            .env("ESTUS_SSH_CONFIG", &fixture.ssh);
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
