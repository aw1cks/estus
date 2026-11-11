use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use indoc::{formatdoc, indoc};
use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, Uid, User},
};
use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

pub const CLEANUP: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<u8>>>);

impl Log {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log lock poisoned")).into_owned()
    }

    pub fn records(&self) -> Result<Vec<Value>> {
        // A live pipe read can end halfway through a JSON record.
        self.text()
            .split_inclusive('\n')
            .filter(|line| line.ends_with('\n'))
            .map(|line| serde_json::from_str(line).context("non-JSON audit stderr"))
            .collect()
    }

    fn drain(
        &self,
        mut reader: impl AsyncRead + Unpin + Send + 'static,
    ) -> JoinHandle<std::io::Result<()>> {
        let bytes = self.0.clone();
        tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    return Ok(());
                }
                bytes
                    .lock()
                    .expect("log lock poisoned")
                    .extend_from_slice(&buffer[..n]);
            }
        })
    }
}

pub struct Process {
    pub child: Child,
    pub log: Log,
    drain: JoinHandle<std::io::Result<()>>,
}

impl Process {
    pub fn start(command: &mut Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let log = Log::default();
        let drain = log.drain(child.stderr.take().context("owned process stderr")?);
        Ok(Self { child, log, drain })
    }

    pub async fn stop(mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.start_kill()?;
        }
        timeout(CLEANUP, self.child.wait())
            .await
            .context("owned process did not reap")??;
        // sshd session descendants may temporarily inherit stderr; all fixture commands are finite.
        match timeout(CLEANUP, &mut self.drain).await {
            Ok(result) => result??,
            Err(_) => {
                self.drain.abort();
                bail!("owned process stderr remained open after teardown");
            }
        }
        Ok(())
    }
}

pub fn executable(path: &Path) -> Result<PathBuf> {
    let path =
        fs::canonicalize(path).with_context(|| format!("missing executable {}", path.display()))?;
    let metadata = fs::metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "not an executable: {}",
        path.display()
    );
    Ok(path)
}

pub fn find_program(name: &str) -> Result<PathBuf> {
    for directory in std::env::split_paths(&std::env::var_os("PATH").context("PATH prerequisite")?)
    {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return executable(&candidate);
        }
    }
    bail!("native prerequisite missing from PATH: {name}")
}

pub fn server_command(config: &Path) -> Result<Command> {
    let binary = match std::env::var_os("SSH_MCP_TEST_BINARY") {
        Some(path) => executable(Path::new(&path))?,
        None => executable(Path::new(env!("CARGO_BIN_EXE_ssh-mcp")))?,
    };
    let mut command = Command::new(binary);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SSH_MCP_") {
            command.env_remove(name);
        }
    }
    command.arg("--config").arg(config).kill_on_drop(true);
    Ok(command)
}

pub struct Client {
    pub service: RunningService<RoleClient, ()>,
    pub log: Log,
    drain: JoinHandle<std::io::Result<()>>,
}

impl Client {
    pub async fn start(config: &Path) -> Result<Self> {
        let command = server_command(config)?;
        let (transport, stderr) = TokioChildProcess::builder(command)
            .stderr(Stdio::piped())
            .spawn()?;
        let log = Log::default();
        let drain = log.drain(stderr.context("SDK child stderr")?);
        match timeout(Duration::from_secs(10), ().serve(transport)).await {
            Ok(Ok(service)) => Ok(Self {
                service,
                log,
                drain,
            }),
            result => {
                timeout(CLEANUP, drain)
                    .await
                    .context("failed SDK startup cleanup")???;
                bail!("MCP initialize failed: {result:?}")
            }
        }
    }

    pub async fn call(&self, name: &str, args: Value) -> Result<Value> {
        let seconds = args
            .get("timeout_secs")
            .and_then(Value::as_u64)
            .unwrap_or(10);
        let result = timeout(
            Duration::from_secs(seconds + 5),
            self.service.call_tool(params(name, args)),
        )
        .await
        .context("MCP tool request exceeded timeout plus five seconds")??;
        envelope(result)
    }

    pub async fn stop(mut self) -> Result<Log> {
        let closed = timeout(CLEANUP, self.service.close())
            .await
            .context("SDK server cleanup deadline");
        let drained = timeout(CLEANUP, &mut self.drain)
            .await
            .context("SDK stderr cleanup deadline");
        if drained.is_err() {
            self.drain.abort();
        }
        closed??;
        drained???;
        Ok(self.log)
    }
}

pub fn params(name: &str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_owned())
        .with_arguments(args.as_object().expect("object arguments").clone())
}

pub fn envelope(result: CallToolResult) -> Result<Value> {
    let value = result
        .structured_content
        .context("missing structuredContent")?;
    ensure!(
        value.get("data").is_some() && value.get("error").is_some(),
        "missing tool envelope: {value}"
    );
    ensure!(
        result.is_error.unwrap_or(false) == !value["error"].is_null(),
        "isError disagrees with envelope"
    );
    let wire = serde_json::to_value(result.content)?;
    ensure!(
        wire.as_array().context("content array")?.len() == 1,
        "expected one compatibility text block"
    );
    let text: Value =
        serde_json::from_str(wire[0]["text"].as_str().context("compatibility text")?)?;
    ensure!(text == value, "text and structuredContent disagree");
    Ok(value)
}

pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub async fn run(command: &mut Command) -> Result<std::process::Output> {
    // Only short credential/readiness helpers use output(), never the server command path.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("helper stdout")?;
    let mut stderr = child.stderr.take().context("helper stderr")?;
    let out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match timeout(Duration::from_secs(10), child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            child.kill().await?;
            out.abort();
            err.abort();
            bail!("native helper timed out and was killed/reaped");
        }
    };
    Ok(std::process::Output {
        status,
        stdout: timeout(CLEANUP, out).await???,
        stderr: timeout(CLEANUP, err).await???,
    })
}

pub struct Fixture {
    pub root: TempDir,
    pub ssh: PathBuf,
    pub ssh_config: PathBuf,
    pub config: PathBuf,
    pub listeners: Vec<Process>,
    pub ports: Vec<u16>,
    pub eventual_markers: Vec<PathBuf>,
}

impl Fixture {
    pub async fn start() -> Result<Self> {
        Self::start_with_sshd_config("").await
    }

    pub async fn start_with_sshd_config(extra_sshd_config: &str) -> Result<Self> {
        let uid = Uid::current();
        ensure!(
            !uid.is_root(),
            "native prerequisite: invoke as a non-root local account"
        );
        let user =
            User::from_uid(uid)?.context("native prerequisite: current UID has no OS account")?;
        executable(&user.shell).context("native prerequisite: executable login shell")?;
        let shell = user
            .shell
            .file_name()
            .and_then(|name| name.to_str())
            .context("account shell name")?;
        ensure!(
            ["sh", "bash", "dash", "zsh", "ksh"].contains(&shell),
            "native prerequisite: POSIX-compatible account login shell required"
        );
        let sshd = find_program("sshd")?;
        ensure!(
            sshd.starts_with("/nix/store"),
            "native prerequisite: sshd must be Nix-provided, got {}",
            sshd.display()
        );
        let ssh = find_program("ssh")?;
        let keygen = find_program("ssh-keygen")?;
        let temporary_parent = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        // StrictModes checks every authorized_keys ancestor, including sticky
        // /tmp. Never weaken it or chmod a host directory to make the fixture work.
        let temporary_parent = fs::canonicalize(&temporary_parent)
            .context("native prerequisite: existing private temporary parent")?;
        for ancestor in temporary_parent.ancestors() {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(ancestor)?;
            ensure!(
                metadata.is_dir()
                    && [0, uid.as_raw()].contains(&metadata.uid())
                    && metadata.mode() & 0o022 == 0,
                "native prerequisite: authorized_keys requires trusted temporary ancestry; {} is writable by other users or has an unexpected owner (use a private runtime directory via TMPDIR/XDG_RUNTIME_DIR)",
                ancestor.display()
            );
        }
        let root = tempfile::Builder::new()
            .prefix("ssh-mcp-native-")
            .tempdir_in(temporary_parent)?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let mut fixture = Self {
            ssh,
            ssh_config: root.path().join("ssh_config"),
            config: root.path().join("server.toml"),
            root,
            listeners: Vec::new(),
            ports: Vec::new(),
            eventual_markers: Vec::new(),
        };
        let setup = fixture
            .configure(&sshd, &keygen, &user.name, extra_sshd_config)
            .await;
        if let Err(error) = setup {
            let cleanup = fixture.stop().await;
            cleanup.context("cleanup after native fixture startup failure")?;
            return Err(error);
        }
        Ok(fixture)
    }

    async fn configure(
        &mut self,
        sshd: &Path,
        keygen: &Path,
        user: &str,
        extra_sshd_config: &str,
    ) -> Result<()> {
        for name in ["client", "host0", "host1", "wrong"] {
            let path = self.root.path().join(name);
            let output = run(Command::new(keygen)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path))
            .await?;
            ensure!(output.status.success(), "ssh-keygen prerequisite failed");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        fs::write(
            self.root.path().join("authorized_keys"),
            fs::read(self.root.path().join("client.pub"))?,
        )?;
        fs::set_permissions(
            self.root.path().join("authorized_keys"),
            fs::Permissions::from_mode(0o600),
        )?;
        for index in 0..2 {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut ready = false;
            for attempt in 0..8 {
                ensure!(
                    Instant::now() < deadline,
                    "native listener startup exceeded 60 seconds"
                );
                let reservation = TcpListener::bind(("127.0.0.1", 0))
                    .context("native prerequisite: loopback high port")?;
                let port = reservation.local_addr()?.port();
                ensure!(port > 1024, "ephemeral port was not unprivileged");
                let config = self.root.path().join(format!("sshd{index}.conf"));
                let base = self.root.path().display();
                let subsystem = if index == 0 {
                    "Subsystem sftp internal-sftp\n"
                } else {
                    ""
                };
                let contents = formatdoc! {"
                    ListenAddress 127.0.0.1
                    Port {port}
                    HostKey {base}/host{index}
                    AuthorizedKeysFile {base}/authorized_keys
                    PidFile {base}/sshd{index}.pid
                    AllowUsers {user}
                    AuthenticationMethods publickey
                    PubkeyAuthentication yes
                    PasswordAuthentication no
                    KbdInteractiveAuthentication no
                    PermitRootLogin no
                    StrictModes yes
                    PermitUserRC no
                    LogLevel VERBOSE
                    AllowTcpForwarding yes
                    {subsystem}{extra_sshd_config}
                "};
                fs::write(&config, &contents)?;
                // Probe the selected build rather than assuming PAM exists on Darwin.
                let pam = run(Command::new(sshd)
                    .arg("-T")
                    .arg("-f")
                    .arg(&config)
                    .args(["-o", "UsePAM=no"]))
                .await?;
                let diagnostic = String::from_utf8_lossy(&pam.stderr);
                if !diagnostic.contains("Unsupported option UsePAM") {
                    ensure!(
                        pam.status.success(),
                        "sshd configuration prerequisite failed: {diagnostic}"
                    );
                    fs::write(&config, format!("{contents}UsePAM no\n"))?;
                }
                drop(reservation);
                self.listeners.push(Process::start(
                    Command::new(sshd).args(["-D", "-e", "-f"]).arg(&config),
                )?);
                self.ports.push(port);
                self.write_ssh_config(user)?;
                loop {
                    let output = self
                        .direct(
                            if index == 0 { "plain" } else { "nosftp" },
                            "printf NATIVE_READY",
                        )
                        .await?;
                    if output.status.success() && output.stdout == b"NATIVE_READY" {
                        ready = true;
                        break;
                    }
                    if self
                        .listeners
                        .last_mut()
                        .context("listener")?
                        .child
                        .try_wait()?
                        .is_some()
                    {
                        break;
                    }
                    ensure!(
                        Instant::now() < deadline,
                        "authenticated sshd readiness failed: {}",
                        self.listeners.last().context("listener")?.log.text()
                    );
                    sleep(Duration::from_millis(40)).await;
                }
                if ready {
                    break;
                }
                self.ports.pop();
                self.listeners
                    .pop()
                    .context("failed listener")?
                    .stop()
                    .await?;
                ensure!(
                    attempt < 7,
                    "native listener bind/startup failed after bounded retries"
                );
            }
            ensure!(ready, "native listener did not authenticate");
        }
        self.write_server_config(&self.config, &self.ssh_config)?;
        Ok(())
    }

    fn write_ssh_config(&self, user: &str) -> Result<()> {
        let root = self.root.path().display();
        let mut known = String::new();
        let mut hosts = String::new();
        for (index, port) in self.ports.iter().enumerate() {
            let public = fs::read_to_string(self.root.path().join(format!("host{index}.pub")))?;
            let mut fields = public.split_whitespace();
            known.push_str(&format!(
                "[127.0.0.1]:{port} {} {}\n",
                fields.next().context("key type")?,
                fields.next().context("key bytes")?
            ));
            let alias = if index == 0 {
                "plain jump viajump"
            } else {
                "nosftp"
            };
            hosts.push_str(&formatdoc! {"
                Host {alias}
                    HostName 127.0.0.1
                    Port {port}
                    User {user}
            "});
        }
        fs::write(self.root.path().join("known_hosts"), known)?;
        hosts.push_str(indoc! {"
            Host viajump
                ProxyJump jump
        "});
        let port = self.ports.first().context("primary listener port")?;
        // ssh_config directives cannot contain literal newlines, even when quoted.
        let proxy_script = format!(
            concat!(
                "printf ready > {started}; ",
                "sleep 2; ",
                "exec {ssh} -F {config} -W 127.0.0.1:{port} jump",
            ),
            started = quote(&self.root.path().join("delayed-started").to_string_lossy()),
            ssh = quote(&self.ssh.to_string_lossy()),
            config = quote(&self.ssh_config.to_string_lossy()),
            port = port,
        );
        hosts.push_str(&formatdoc! {"
            Host delayed
                HostName 127.0.0.1
                Port {port}
                User {user}
                ConnectTimeout 5
                ProxyCommand /bin/sh -c {proxy_script}
            Match originalhost plain,nosftp,jump,viajump,delayed
                IdentitiesOnly yes
            ",
            proxy_script = quote(&proxy_script),
        });
        fs::write(self.root.path().join("included.conf"), hosts)?;
        fs::write(
            &self.ssh_config,
            formatdoc! {"
                Include {root}/included.conf
                Host *
                    IdentityAgent none
                    IdentityFile {root}/client
                    UserKnownHostsFile {root}/known_hosts
                    GlobalKnownHostsFile /dev/null
                    StrictHostKeyChecking yes
                    BatchMode yes
                    ConnectTimeout 2
                    ControlMaster no
                    ControlPath none
            "},
        )?;
        Ok(())
    }

    pub fn write_server_config(&self, path: &Path, ssh_config: &Path) -> Result<()> {
        let ssh_path = serde_json::to_string(&ssh_config.to_string_lossy())?;
        let mut config = formatdoc! {"
            [ssh]
            config_file = {ssh_path}

            [limits]
            connect_timeout_secs = 3
            operation_timeout_secs = 10
            max_timeout_secs = 15
            max_output_bytes = 1024

            [targets.plain]
            ssh_host = 'plain'
            [targets.nosftp]
            ssh_host = 'nosftp'
            [targets.viajump]
            ssh_host = 'viajump'
            [targets.resource]
            ssh_host = 'plain'
            [targets.delayed]
            ssh_host = 'delayed'

            [targets.restricted]
            ssh_host = 'must-never-connect'
            [targets.restricted.sudo]
            mode = 'same-account'
            users = ['root']
            programs = ['/usr/bin/true']
        "};
        for index in 0..4 {
            config.push_str(&formatdoc! {"
                [targets.slots-{index}]
                ssh_host = 'plain'
            "});
        }
        fs::write(path, config)?;
        Ok(())
    }

    pub async fn direct(&self, alias: &str, command: &str) -> Result<std::process::Output> {
        run(Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.ssh_config)
            .args(["-T", alias, command]))
        .await
    }

    pub fn authentications(&self) -> usize {
        self.listeners
            .iter()
            .map(|listener| {
                listener
                    .log
                    .text()
                    .lines()
                    .filter(|line| line.contains("Accepted publickey"))
                    .count()
            })
            .sum()
    }

    pub async fn await_file(path: &Path) -> Result<()> {
        timeout(Duration::from_secs(10), async {
            while !path.exists() {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .with_context(|| format!("finite remote command did not complete: {}", path.display()))
    }

    pub async fn stop(mut self) -> Result<()> {
        let mut failures = Vec::new();
        for marker in &self.eventual_markers {
            if let Err(error) = Self::await_file(marker).await {
                failures.push(error.to_string());
            }
        }
        for process in self.listeners.drain(..) {
            if let Err(error) = process.stop().await {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            self.root.close()?;
            Ok(())
        } else {
            bail!("native fixture cleanup failed: {}", failures.join("; "))
        }
    }
}

pub struct WireServer {
    child: Child,
    input: Option<ChildStdin>,
    lines: Lines<BufReader<ChildStdout>>,
    pub log: Log,
    drain: JoinHandle<std::io::Result<()>>,
}

impl WireServer {
    pub fn start(config: &Path) -> Result<Self> {
        let mut child = server_command(config)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let input = Some(child.stdin.take().context("wire stdin")?);
        let lines = BufReader::new(child.stdout.take().context("wire stdout")?).lines();
        let log = Log::default();
        let drain = log.drain(child.stderr.take().context("wire stderr")?);
        Ok(Self {
            child,
            input,
            lines,
            log,
            drain,
        })
    }

    pub async fn request(&mut self, id: u64, method: &str, params: Value) -> Result<Value> {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        loop {
            let line = timeout(Duration::from_secs(15), self.lines.next_line())
                .await??
                .context("wire server closed stdout")?;
            let value: Value = serde_json::from_str(&line).context("non-JSON server stdout")?;
            ensure!(value["jsonrpc"] == "2.0", "non-protocol stdout");
            if value["id"] == id {
                return Ok(value);
            }
            ensure!(value.get("id").is_none(), "unexpected response: {value}");
        }
    }

    pub async fn send(&mut self, value: Value) -> Result<()> {
        let input = self.input.as_mut().context("closed wire stdin")?;
        input.write_all(&serde_json::to_vec(&value)?).await?;
        input.write_all(b"\n").await?;
        input.flush().await?;
        Ok(())
    }

    pub async fn initialize(&mut self) -> Result<()> {
        let result = self.request(1, "initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"native-shutdown","version":"1"}})).await?;
        ensure!(
            result["result"]["capabilities"]["tools"].is_object(),
            "initialize failed: {result}"
        );
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await
    }

    pub async fn stop(mut self, sigterm: bool) -> Result<Log> {
        if sigterm && self.child.try_wait()?.is_none() {
            kill(
                Pid::from_raw(i32::try_from(self.child.id().context("owned server PID")?)?),
                Signal::SIGTERM,
            )?;
        } else {
            drop(self.input.take());
        }
        let status = match timeout(CLEANUP, self.child.wait()).await {
            Ok(result) => result?,
            Err(_) => {
                self.child.kill().await?;
                self.drain.abort();
                bail!("server shutdown exceeded ten seconds");
            }
        };
        drop(self.input.take());
        while let Some(line) = timeout(CLEANUP, self.lines.next_line()).await?? {
            ensure!(
                serde_json::from_str::<Value>(&line)?["jsonrpc"] == "2.0",
                "non-protocol trailing stdout"
            );
        }
        timeout(CLEANUP, self.drain).await???;
        ensure!(status.success(), "server shutdown status: {status}");
        Ok(self.log)
    }
}

pub fn masters(log: &Log) -> Result<Vec<(u32, PathBuf)>> {
    log.records()?
        .iter()
        .filter(|record| record["event"] == "master_start")
        .map(|record| {
            Ok((
                u32::try_from(record["pid"].as_u64().context("master PID")?)?,
                PathBuf::from(record["socket"].as_str().context("master socket")?),
            ))
        })
        .collect()
}

pub async fn assert_masters_gone(owned: &[(u32, PathBuf)]) -> Result<()> {
    ensure!(!owned.is_empty(), "no master lifecycle evidence");
    timeout(CLEANUP, async {
        loop {
            let gone = owned.iter().all(|(pid, socket)| {
                !socket.exists()
                    && matches!(
                        kill(Pid::from_raw(*pid as i32), None),
                        Err(nix::errno::Errno::ESRCH)
                    )
            });
            if gone {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("owned master PID/socket survived shutdown")
}
