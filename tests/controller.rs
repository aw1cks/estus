//! Network-free acceptance tests against the real stdio server and real POSIX children.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod support;

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(15);
const AMBIENT_SECRET: &str = "CONTROLLER_AMBIENT_SECRET_8ff9";
const CONFIG_SECRET: &str = "CONTROLLER_CONFIG_SECRET_37ad";

struct Server {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    stderr: Option<JoinHandle<std::io::Result<()>>>,
    error: Option<ChildStderr>,
    audit: Arc<Mutex<Vec<u8>>>,
    responses: BTreeMap<u64, Value>,
}

impl Server {
    async fn start(fixture: &Fixture) -> Result<Self> {
        Self::start_with_stderr(fixture, true).await
    }

    async fn start_with_stderr(fixture: &Fixture, drain: bool) -> Result<Self> {
        let mut command = support::server_command(&fixture.config)?;
        command
            .env("UNREVIEWED_CONTROLLER_SECRET", AMBIENT_SECRET)
            .env("MCP_AMBIENT_ONLY", AMBIENT_SECRET)
            .env("HOME", fixture.temp.path().join("ambient-home"))
            .env("TMPDIR", fixture.temp.path().join("ambient-tmp"))
            // Any accidental SSH dispatch is a local, observable failure, never a network attempt.
            .env("PATH", &fixture.commands);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("server stdin")?;
        let output = BufReader::new(child.stdout.take().context("server stdout")?);
        let error = child.stderr.take().context("server stderr")?;
        let audit = Arc::new(Mutex::new(Vec::new()));
        let mut server = Self {
            child,
            input: Some(input),
            output,
            stderr: None,
            error: Some(error),
            audit,
            responses: BTreeMap::new(),
        };
        if drain {
            server.drain_stderr();
        }
        server
            .send(
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"controller-process-acceptance","version":"1"}
                }}),
            )
            .await?;
        let initialized = server.response(1).await?;
        ensure!(
            initialized["result"]["capabilities"]["tools"].is_object(),
            "initialize: {initialized}"
        );
        server
            .send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        Ok(server)
    }

    fn drain_stderr(&mut self) {
        let Some(mut error) = self.error.take() else {
            return;
        };
        let captured = Arc::clone(&self.audit);
        self.stderr = Some(tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let count = error.read(&mut buffer).await?;
                if count == 0 {
                    return Ok(());
                }
                captured
                    .lock()
                    .expect("audit lock")
                    .extend_from_slice(&buffer[..count]);
            }
        }));
    }

    async fn send(&mut self, frame: Value) -> Result<()> {
        let input = self.input.as_mut().context("closed server input")?;
        input.write_all(&serde_json::to_vec(&frame)?).await?;
        input.write_all(b"\n").await?;
        input.flush().await?;
        Ok(())
    }

    async fn call(&mut self, id: u64, arguments: Value) -> Result<()> {
        self.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
            "params":{"name":"observe_controller","arguments":arguments}}))
            .await
    }

    async fn response(&mut self, id: u64) -> Result<Value> {
        if let Some(frame) = self.responses.remove(&id) {
            return Ok(frame);
        }
        timeout(WAIT, async {
            loop {
                let mut line = Vec::new();
                let count = (&mut self.output)
                    .take(16_777_217)
                    .read_until(b'\n', &mut line)
                    .await?;
                ensure!(
                    count > 0 && count <= 16_777_216 && line.last() == Some(&b'\n'),
                    "invalid server frame length"
                );
                let frame: Value = serde_json::from_slice(&line)?;
                ensure!(frame["jsonrpc"] == "2.0", "non-protocol server output");
                if let Some(received) = frame["id"].as_u64() {
                    if received == id {
                        return Ok(frame);
                    }
                    ensure!(
                        self.responses.insert(received, frame).is_none(),
                        "duplicate response ID"
                    );
                } else {
                    ensure!(frame["method"].is_string(), "unexpected frame: {frame}");
                }
            }
        })
        .await
        .context("controller response deadline")?
    }

    async fn cancel(&mut self, id: u64) -> Result<()> {
        self.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":id,"reason":"acceptance cancellation"}}))
            .await
    }

    async fn finished(&self, id: u64, error: &str) -> Result<Value> {
        // RMCP deliberately suppresses a cancelled request's wire response.
        // Its correlated audit is the observable completion/cleanup boundary.
        timeout(WAIT, async {
            loop {
                {
                    let audit = self.audit.lock().expect("audit lock");
                    for line in audit.split_inclusive(|byte| *byte == b'\n') {
                        if line.last() != Some(&b'\n') {
                            continue;
                        }
                        let event: Value = serde_json::from_slice(line)?;
                        if event["event"] == "finish" && event["request_id"] == id {
                            ensure!(
                                event["error_code"] == error,
                                "unexpected controller completion: {event}"
                            );
                            ensure!(
                                event["owned_group_cleanup"] == "signalled_and_reaped",
                                "cancel cleanup: {event}"
                            );
                            return Ok(event);
                        }
                    }
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("controller finish audit deadline")?
    }

    async fn stop(mut self, sigterm: bool) -> Result<Vec<u8>> {
        if sigterm && self.child.try_wait()?.is_none() {
            // This is our still-owned, unreaped direct child, not a remembered descendant PID.
            kill(
                Pid::from_raw(i32::try_from(self.child.id().context("owned server PID")?)?),
                Signal::SIGTERM,
            )?;
        } else {
            drop(self.input.take());
        }
        let mut trailing = Vec::new();
        let (status, output) = timeout(WAIT, async {
            tokio::join!(self.child.wait(), self.output.read_to_end(&mut trailing))
        })
        .await
        .context("controller server shutdown deadline")?;
        ensure!(status?.success(), "controller server shutdown failed");
        output?;
        for line in trailing
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            ensure!(
                serde_json::from_slice::<Value>(line)?["jsonrpc"] == "2.0",
                "non-protocol shutdown output"
            );
        }
        // Deliberately held pipes stay undrained until the process has exited.
        self.drain_stderr();
        if let Some(stderr) = self.stderr.take() {
            timeout(WAIT, stderr).await???;
        }
        let stderr = self.audit.lock().expect("audit lock").clone();
        for line in stderr
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: Value = serde_json::from_slice(line).context("non-JSON controller audit")?;
            ensure!(
                event["identity_role"] != "controller"
                    || event.get("remote_state_unknown").is_none(),
                "local audit claimed remote state"
            );
        }
        Ok(stderr)
    }
}

struct Fixture {
    temp: TempDir,
    root: PathBuf,
    observations: PathBuf,
    commands: PathBuf,
    source: PathBuf,
    config: PathBuf,
    sh: PathBuf,
    ps: PathBuf,
}

impl Fixture {
    fn new(body: &str, output_limit: u64, timeout_secs: u64) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let root = temp.path().join("explicit-private-root");
        let observations = temp.path().join("observations");
        let commands = temp.path().join("commands");
        for directory in [&root, &observations, &commands] {
            fs::create_dir(directory)?;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        // This unrelated entry must survive operation cleanup; cleanup is not a root sweep.
        fs::write(root.join("operator-owned-sentinel"), b"retain me")?;
        let sh = support::find_program("sh")?;
        // Match the running Darwin kernel's process-state ABI; the older pinned
        // adv_cmds ps omits its state letter on current macOS.
        #[cfg(target_os = "macos")]
        let ps = support::executable(Path::new("/bin/ps"))?;
        #[cfg(not(target_os = "macos"))]
        let ps = support::find_program("ps")?;
        let source = temp.path().join("reviewed-source.sh");
        let config = temp.path().join("controller.toml");
        let mut script = body
            .replace(
                "@OBS@",
                &support::quote(observations.to_str().context("UTF-8 fixture")?),
            )
            .replace(
                "@SH@",
                &support::quote(sh.to_str().context("UTF-8 interpreter")?),
            );
        for (token, program) in [
            ("@CAT@", "cat"),
            ("@ENV@", "env"),
            ("@SLEEP@", "sleep"),
            ("@MKDIR@", "mkdir"),
        ] {
            script = script.replace(
                token,
                &support::quote(
                    support::find_program(program)?
                        .to_str()
                        .context("UTF-8 program")?,
                ),
            );
        }
        fs::write(&source, &script)?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
        for name in ["ssh", "scp", "sftp"] {
            let path = commands.join(name);
            fs::write(
                &path,
                format!(
                    "#!{}\nprintf invoked > {}\nexit 99\n",
                    sh.display(),
                    support::quote(temp.path().join("remote-dispatch").to_str().unwrap())
                ),
            )?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let digest = hex::encode(Sha256::digest(script.as_bytes()));
        let string = |text: &str| toml::Value::String(text.to_owned()).to_string();
        fs::write(
            &config,
            format!(
                r#"
profile = "actions-only"
enabled_tools = ["observe_controller"]
[controller]
workspace_root = {root}
[limits]
operation_timeout_secs = 15
max_timeout_secs = 15
max_output_bytes = 8192
[tools.observe_controller]
description = "Observe explicit controller execution."
revision = "process-1"
authority = "controller"
effects = ["read"]
execution = {{ kind = "controller_script", source = {{ path = {source}, content_sha256 = "{digest}", max_bytes = 65536 }}, interpreter = {{ program = {sh}, argv = [] }}, environment = {{ MCP_ALLOWED = "{CONFIG_SECRET}" }} }}
input_schema = {{ type = "object", additionalProperties = false, required = ["label", "count", "flag"], properties = {{ label = {{ type = "string", maxLength = 4096 }}, count = {{ type = "integer", minimum = -10, maximum = 10 }}, flag = {{ type = "boolean" }} }} }}
result = {{ kind = "controller_command" }}
limits = {{ timeout_secs = {timeout_secs}, max_output_bytes = {output_limit} }}
"#,
                root = string(root.to_str().unwrap()),
                source = string(source.to_str().unwrap()),
                sh = string(sh.to_str().unwrap())
            ),
        )?;
        Ok(Self {
            temp,
            root,
            observations,
            commands,
            source,
            config,
            sh,
            ps,
        })
    }

    fn records(&self) -> Result<Vec<PathBuf>> {
        let mut paths = fs::read_dir(&self.observations)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        Ok(paths)
    }

    async fn ready(
        &self,
        count: usize,
        server: &mut Server,
        request_id: u64,
    ) -> Result<Vec<PathBuf>> {
        let readiness = timeout(WAIT, async {
            loop {
                let records = self.records()?;
                if records.len() == count
                    && records.iter().all(|record| {
                        record.join("ready").exists() && record.join("worker-ready").exists()
                    })
                {
                    return Ok(records);
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        match readiness {
            Ok(result) => result,
            Err(error) => {
                let completion = timeout(Duration::from_secs(1), server.response(request_id)).await;
                anyhow::bail!(
                    "script readiness barrier: {error}; controller completion: {completion:?}"
                );
            }
        }
    }

    fn release_all(&self) -> Result<()> {
        for record in self.records()? {
            fs::write(record.join("release-leader"), b"release")?;
            fs::write(record.join("release-worker"), b"release")?;
        }
        Ok(())
    }

    fn operation_directories(&self) -> Result<Vec<PathBuf>> {
        Ok(fs::read_dir(&self.root)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.file_name() == "operator-owned-sentinel" => None,
                other => Some(other.map(|entry| entry.path())),
            })
            .collect::<std::io::Result<Vec<_>>>()?)
    }

    async fn clean(&self) -> Result<()> {
        timeout(WAIT, async {
            loop {
                if self.operation_directories()?.is_empty() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
            ensure!(
                fs::read(self.root.join("operator-owned-sentinel"))? == b"retain me",
                "cleanup touched an unowned root entry"
            );
            ensure!(
                !self.temp.path().join("remote-dispatch").exists(),
                "controller execution dispatched SSH"
            );
            Ok(())
        })
        .await
        .context("owned workspace cleanup deadline")?
    }

    // Observation only: never signal a remembered numeric PID or PGID. Grandchild zombies
    // are not executable work, and are not ours to reap on Linux without a subreaper.
    async fn process(&self, pid: i32) -> Result<Option<(i32, String)>> {
        ensure!(pid > 0, "invalid recorded PID");
        let output = Command::new(&self.ps)
            .args(["-o", "pgid=,stat=", "-p", &pid.to_string()])
            .env("LC_ALL", "C")
            .output()
            .await?;
        ensure!(
            output.status.success() || output.status.code() == Some(1),
            "ps failed: {:?}",
            output.status
        );
        let text = std::str::from_utf8(&output.stdout)?.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let mut words = text.split_whitespace();
        let group = words.next().context("ps group")?.parse()?;
        let state = words.next().context("ps process state")?.to_owned();
        Ok(Some((group, state)))
    }

    async fn gone(&self, pids: &[i32]) -> Result<()> {
        timeout(WAIT, async {
            loop {
                let mut live = Vec::new();
                for &pid in pids {
                    if let Some((_, state)) = self.process(pid).await?
                        && !state.starts_with('Z')
                    {
                        live.push((pid, state));
                    }
                }
                if live.is_empty() {
                    return Ok(());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("recorded descendant executable work survived cleanup")?
    }
}

fn arguments() -> Value {
    json!({"label":"ordinary","count":-7,"flag":true})
}

fn envelope(frame: &Value) -> Result<&Value> {
    ensure!(
        frame.get("error").is_none(),
        "JSON-RPC error instead of controller result: {frame}"
    );
    let result = &frame["result"];
    let envelope = &result["structuredContent"];
    ensure!(
        envelope.get("data").is_some() && envelope.get("error").is_some(),
        "missing controller envelope: {frame}"
    );
    ensure!(
        result["isError"].as_bool().unwrap_or(false) == !envelope["error"].is_null(),
        "inconsistent error flag"
    );
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("compatibility text")?,
    )?;
    ensure!(
        text == *envelope,
        "structured and text controller results differ"
    );
    ensure!(
        envelope["data"]
            .get("remote_may_still_be_running")
            .is_none()
    );
    ensure!(envelope["error"].get("remote_state_unknown").is_none());
    Ok(envelope)
}

fn cleaned(data: &Value) -> Result<()> {
    ensure!(
        data["owned_group_cleanup"] == "signalled_and_reaped",
        "cleanup evidence: {data}"
    );
    Ok(())
}

fn pid(record: &Path, name: &str) -> Result<i32> {
    Ok(fs::read_to_string(record.join(name))?.trim().parse()?)
}

// Gates are explicit observable barriers. The short polling interval is not an
// assumption that work has finished: every wait is bounded and checks its predicate.
const GROUP_SCRIPT: &str = r#"
set -eu
record=@OBS@/${PWD##*/}
wait_gate() {
    attempts=0
    while [ ! -f "$1" ]; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 3000 ] || exit 90
        @SLEEP@ 0.01
    done
}
if [ "${2-}" = worker ]; then
    printf ready > "$record/worker-ready"
    wait_gate "$record/release-worker"
    exit 0
fi
@MKDIR@ "$record"
printf '%s\n' "$$" > "$record/leader"
printf '%s\n' "$0" > "$record/source"
printf '%s\n' "$1" > "$record/input"
@SH@ "$0" "$1" worker &
printf '%s\n' "$!" > "$record/worker"
printf ready > "$record/ready"
wait_gate "$record/release-leader"
printf 'leader completed\n'
exit 0
"#;

async fn flood_audit(server: &mut Server) -> Result<()> {
    // More than a MiB of diagnostics exceeds the supported hosts' pipe buffers
    // and the bounded delivery queue. Requests remain sequential and bounded.
    for id in 100..4196 {
        server
            .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":"ssh_targets","arguments":{}}}))
            .await?;
        let response = server.response(id).await?;
        ensure!(
            response["result"]["isError"] != true && response.get("error").is_none(),
            "discovery stalled or failed under audit backpressure: {response}"
        );
    }
    Ok(())
}

#[cfg_attr(
    target_os = "macos",
    ignore = "requires native process observation outside the Darwin build sandbox"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_backpressure_does_not_hold_cleanup_and_recovers_ordered_records() -> Result<()> {
    let fixture = Fixture::new(GROUP_SCRIPT, 8192, 15)?;
    let mut server = Server::start_with_stderr(&fixture, false).await?;
    let scenario = async {
        flood_audit(&mut server).await?;
        server.call(2, arguments()).await?;
        let records = fixture.ready(1, &mut server, 2).await?;
        let leader = pid(&records[0], "leader")?;
        let worker = pid(&records[0], "worker")?;
        fs::write(records[0].join("release-leader"), b"release")?;
        let frame = server.response(2).await?;
        let result = envelope(&frame)?;
        ensure!(result["error"].is_null(), "{result}");
        cleaned(&result["data"])?;
        fixture.gone(&[leader, worker]).await?;
        ensure!(
            fixture.process(leader).await?.is_none(),
            "leader not reaped"
        );
        fixture.clean().await?;

        server.drain_stderr();
        timeout(WAIT, async {
            loop {
                {
                    let audit = server.audit.lock().expect("audit lock");
                    for line in audit.split_inclusive(|byte| *byte == b'\n') {
                        if line.last() == Some(&b'\n') {
                            let event: Value = serde_json::from_slice(line)?;
                            if event["event"] == "diagnostic_loss" {
                                ensure!(event["dropped_records"].as_u64().unwrap_or(0) > 0);
                                return Ok::<_, anyhow::Error>(());
                            }
                        }
                    }
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("audit loss not reported after draining")??;
        // A later operation proves delivery recovers, not merely buffered bytes.
        server
            .send(json!({"jsonrpc":"2.0","id":5000,"method":"tools/call",
                "params":{"name":"ssh_targets","arguments":{}}}))
            .await?;
        server.response(5000).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if scenario.is_err() {
        fixture.release_all()?;
    }
    let stopped = server.stop(false).await;
    scenario?;
    let audit = stopped?;
    ensure!(
        audit.last() == Some(&b'\n'),
        "incomplete recovered diagnostic"
    );
    let mut last = 0;
    let mut recovered = false;
    for line in audit.split_inclusive(|byte| *byte == b'\n') {
        let event: Value = serde_json::from_slice(line)?;
        if event["tool"] == "ssh_targets" {
            let id = event["request_id"].as_u64().context("discovery audit ID")?;
            // Each request emits start then finish; both retain enqueue order.
            ensure!(id >= last, "accepted diagnostics reordered");
            last = id;
            recovered |= id == 5000 && event["event"] == "finish";
        }
    }
    ensure!(recovered, "diagnostics did not recover after draining");
    Ok(())
}

#[cfg_attr(
    target_os = "macos",
    ignore = "requires native process observation outside the Darwin build sandbox"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_blocked_and_closed_pipes_do_not_hold_shutdown_cleanup() -> Result<()> {
    for closed in [false, true] {
        let fixture = Fixture::new(GROUP_SCRIPT, 8192, 15)?;
        let mut server = Server::start_with_stderr(&fixture, false).await?;
        if closed {
            drop(server.error.take());
        }
        let mut observed = Vec::new();
        let scenario = async {
            flood_audit(&mut server).await?;
            server.call(2, arguments()).await?;
            let records = fixture.ready(1, &mut server, 2).await?;
            let leader = pid(&records[0], "leader")?;
            let worker = pid(&records[0], "worker")?;
            let (group, _) = fixture.process(leader).await?.context("live leader")?;
            observed.extend([leader, worker, group]);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if scenario.is_err() {
            fixture.release_all()?;
        }
        // No stderr reader exists until after stop observes process exit.
        let stopped = timeout(Duration::from_secs(5), server.stop(false)).await;
        scenario?;
        stopped.context("audit sink exceeded bounded server shutdown")??;
        fixture.gone(&observed).await?;
        ensure!(
            fixture.process(observed[0]).await?.is_none()
                && fixture.process(observed[2]).await?.is_none(),
            "shutdown left unreaped direct children"
        );
        fixture.clean().await?;
    }
    Ok(())
}

#[cfg_attr(
    target_os = "macos",
    ignore = "requires native process observation outside the Darwin build sandbox"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_typed_input_sanitized_environment_and_pinned_startup_image() -> Result<()> {
    let script = r#"
set -eu
[ "$#" -eq 1 ] || exit 81
record=@OBS@/private
@MKDIR@ "$record"
printf '%s\n' "$$" > "$record/leader"
printf '%s\n' "$0" > "$record/source"
printf '%s\n' "$1" > "$record/input"
printf '%s\n' "$PWD" > "$record/cwd"
@CAT@ "$1" > "$record/payload"
@ENV@ > "$record/environment"
printf ready > "$record/worker-ready"
printf ready > "$record/ready"
attempts=0
while [ ! -f "$record/release-leader" ]; do
    attempts=$((attempts + 1))
    [ "$attempts" -lt 3000 ] || exit 90
    @SLEEP@ 0.01
done
printf 'PINNED SOURCE\n'
"#;
    let fixture = Fixture::new(script, 8192, 15)?;
    let mut server = Server::start(&fixture).await?;
    let scenario = async {
        // Activation happened before initialize completed. Replace the reviewed pathname,
        // rather than merely modifying it before the source is first opened.
        let replacement = fixture.temp.path().join("replacement.sh");
        fs::write(
            &replacement,
            format!(
                "printf replaced > {}\n",
                support::quote(
                    fixture
                        .temp
                        .path()
                        .join("replacement-ran")
                        .to_str()
                        .unwrap()
                )
            ),
        )?;
        fs::rename(replacement, &fixture.source)?;
        let hostile = format!(
            "PRIVATE_PAYLOAD_雪\n'\"; $(printf pwned > {}); `false` \\ \t",
            fixture.temp.path().join("injected").display()
        );
        let input = json!({"label":hostile,"count":-7,"flag":true,"timeout_secs":15});
        server.call(2, input).await?;
        let records = fixture.ready(1, &mut server, 2).await?;
        let record = &records[0];
        let payload: Value = serde_json::from_slice(&fs::read(record.join("payload"))?)?;
        ensure!(
            payload == json!({"label":hostile,"count":-7,"flag":true}),
            "input lost JSON types or included controls: {payload}"
        );
        let source = PathBuf::from(fs::read_to_string(record.join("source"))?.trim());
        let input = PathBuf::from(fs::read_to_string(record.join("input"))?.trim());
        let cwd = PathBuf::from(fs::read_to_string(record.join("cwd"))?.trim());
        ensure!(
            source != fixture.source && source.parent() == input.parent(),
            "source/input are not private sibling snapshots"
        );
        ensure!(
            cwd.starts_with(fs::canonicalize(&fixture.root)?)
                && source.parent() == Some(cwd.as_path()),
            "default cwd is not the operation workspace"
        );
        for (path, mode) in [
            (&fixture.root, 0o700),
            (&cwd, 0o700),
            (&source, 0o600),
            (&input, 0o600),
        ] {
            ensure!(
                fs::metadata(path)?.permissions().mode() & 0o777 == mode,
                "wrong private mode for {path:?}"
            );
        }
        ensure!(
            fs::read_to_string(&source)?.contains("PINNED SOURCE"),
            "snapshot did not preserve reviewed bytes"
        );
        let environment = fs::read_to_string(record.join("environment"))?;
        let environment = environment
            .lines()
            .map(|line| line.split_once('=').context("environment assignment"))
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(
            !environment
                .values()
                .any(|value| value.contains(AMBIENT_SECRET)),
            "ambient secret inherited"
        );
        ensure!(
            !environment.contains_key("UNREVIEWED_CONTROLLER_SECRET")
                && !environment.contains_key("MCP_AMBIENT_ONLY")
        );
        ensure!(environment.get("MCP_ALLOWED") == Some(&CONFIG_SECRET));
        for key in [
            "HOME",
            "TMPDIR",
            "TMP",
            "TEMP",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
        ] {
            let managed = Path::new(environment.get(key).context("managed environment value")?);
            ensure!(managed.starts_with(&cwd), "{key} escaped owned workspace");
            ensure!(managed.is_dir(), "managed {key} is unavailable");
        }
        for (key, value) in [
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("TZ", "UTC"),
        ] {
            ensure!(environment.get(key) == Some(&value), "wrong default {key}");
        }
        let process = Command::new(&fixture.ps)
            .args([
                "-ww",
                "-o",
                "command=",
                "-p",
                &pid(record, "leader")?.to_string(),
            ])
            .output()
            .await?;
        ensure!(
            process.status.success(),
            "cannot inspect actual interpreter argv"
        );
        let argv = std::str::from_utf8(&process.stdout)?;
        let expected_argv = format!(
            "{} {} {}",
            fixture.sh.display(),
            source.display(),
            input.display()
        );
        ensure!(
            argv.trim() == expected_argv,
            "actual interpreter argv differs from fixed program plus two private paths: {argv}"
        );
        ensure!(
            !argv.contains("PRIVATE_PAYLOAD_")
                && !argv.contains(CONFIG_SECRET)
                && !argv.contains(AMBIENT_SECRET),
            "private values entered OS argv"
        );
        fixture.release_all()?;
        let frame = server.response(2).await?;
        let result = envelope(&frame)?;
        ensure!(result["error"].is_null(), "controller failed: {result}");
        ensure!(result["data"]["stdout"] == "PINNED SOURCE\n");
        cleaned(&result["data"])?;
        ensure!(
            !fixture.temp.path().join("replacement-ran").exists()
                && !fixture.temp.path().join("injected").exists(),
            "source replacement or hostile input executed"
        );
        fixture.clean().await?;
        ensure!(
            !source.exists() && !input.exists(),
            "private files retained after completion"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    fixture.release_all()?;
    let stopped = server.stop(false).await;
    scenario?;
    let audit = String::from_utf8(stopped?)?;
    for private in [
        "PRIVATE_PAYLOAD_",
        AMBIENT_SECRET,
        CONFIG_SECRET,
        fixture.temp.path().to_str().unwrap(),
    ] {
        ensure!(
            !audit.contains(private),
            "private data leaked through audit"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_stream_capture_nonzero_and_signal_are_distinct() -> Result<()> {
    for (name, script, limit) in [
        (
            "streams",
            "out=o; err=e; i=0; while [ \"$i\" -lt 10 ]; do out=$out$out; err=$err$err; i=$((i + 1)); done; i=0; while [ \"$i\" -lt 2048 ]; do printf '%s' \"$out\"; printf '%s' \"$err\" >&2; i=$((i + 1)); done; printf '\\377'; printf '\\377' >&2\n",
            128,
        ),
        ("lossy", "printf '\\377'; printf '\\376' >&2\n", 8192),
        (
            "nonzero",
            "printf x >> @OBS@/attempts; printf 'before failure\\n'; printf 'private diagnostic\\n' >&2; exit 23\n",
            8192,
        ),
        (
            "signal",
            "printf 'before signal\\n'; kill -TERM \"$$\"\n",
            8192,
        ),
    ] {
        let fixture = Fixture::new(script, limit, 15)?;
        let mut server = Server::start(&fixture).await?;
        let scenario = async {
            server.call(2, arguments()).await?;
            let frame = server.response(2).await?;
            let result = envelope(&frame)?;
            let data = &result["data"];
            cleaned(data)?;
            match name {
                "streams" => {
                    ensure!(result["error"].is_null(), "capture failed: {result}");
                    let stdout = data["stdout"].as_str().context("captured stdout")?;
                    let stderr = data["stderr"].as_str().context("captured stderr")?;
                    ensure!(
                        stdout == "o".repeat(limit as usize)
                            && stderr == "e".repeat(limit as usize),
                        "capture lost bounded stream prefixes"
                    );
                    ensure!(
                        data["stdout_truncated"] == true && data["stderr_truncated"] == true,
                        "streams were not drained/truncated: {data}"
                    );
                    ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
                }
                "lossy" => {
                    ensure!(result["error"].is_null(), "lossy capture failed: {result}");
                    ensure!(data["stdout"] == "\u{fffd}" && data["stderr"] == "\u{fffd}");
                    ensure!(data["stdout_lossy"] == true && data["stderr_lossy"] == true);
                    ensure!(data["stdout_truncated"] == false && data["stderr_truncated"] == false);
                }
                "nonzero" => {
                    ensure!(
                        result["error"]["code"] == "command_failed",
                        "nonzero error category: {result}"
                    );
                    ensure!(
                        data["stdout"] == "before failure\n"
                            && data["stderr"] == "private diagnostic\n"
                    );
                    ensure!(
                        data["exit_code"] == 23
                            && data["signal"].is_null()
                            && data["termination"] == "exited"
                    );
                    ensure!(
                        fs::read(fixture.observations.join("attempts"))? == b"x",
                        "failed local command was replayed"
                    );
                }
                "signal" => {
                    ensure!(!result["error"].is_null(), "signal was reported as success");
                    ensure!(data["stdout"] == "before signal\n" && data["exit_code"].is_null());
                    ensure!(
                        data["signal"] == 15 && data["termination"] == "signalled",
                        "signal status was lost: {data}"
                    );
                }
                _ => unreachable!(),
            }
            fixture.clean().await
        }
        .await;
        let stopped = server.stop(false).await;
        scenario.with_context(|| name)?;
        stopped?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interpreter_disappearing_after_activation_is_local_spawn_failure_without_fallback()
-> Result<()> {
    let fixture = Fixture::new("printf unexpected > @OBS@/executed\n", 8192, 15)?;
    let interpreter = fixture.temp.path().join("declared-interpreter");
    std::os::unix::fs::symlink(&fixture.sh, &interpreter)?;
    let mut config: toml::Value = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
    config["tools"]["observe_controller"]["execution"]["interpreter"]["program"] =
        toml::Value::String(
            interpreter
                .to_str()
                .context("UTF-8 interpreter")?
                .to_owned(),
        );
    fs::write(&fixture.config, toml::to_string(&config)?)?;
    let mut server = Server::start(&fixture).await?;
    let scenario = async {
        fs::remove_file(&interpreter)?;
        server.call(2, arguments()).await?;
        let frame = server.response(2).await?;
        let result = envelope(&frame)?;
        ensure!(
            result["error"]["code"] == "spawn_failed",
            "local spawn failure lost its category: {result}"
        );
        ensure!(
            result["data"]["termination"] == "io_error" && result["data"]["exit_code"].is_null()
        );
        ensure!(result["data"]["stdout"] == "" && result["data"]["stderr"] == "");
        cleaned(&result["data"])?;
        ensure!(
            fixture.records()?.is_empty(),
            "failed dispatch executed source"
        );
        ensure!(
            !serde_json::to_string(result)?.contains(fixture.temp.path().to_str().unwrap()),
            "spawn diagnostic leaked a private path"
        );
        fixture.clean().await
    }
    .await;
    let stopped = server.stop(false).await;
    scenario?;
    stopped?;
    Ok(())
}

#[cfg_attr(
    target_os = "macos",
    ignore = "requires native process observation outside the Darwin build sandbox"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_exit_timeout_cancel_eof_and_sigterm_clean_actual_group_children() -> Result<()> {
    for trigger in ["normal", "timeout", "cancel", "eof", "sigterm"] {
        let fixture = Fixture::new(
            GROUP_SCRIPT,
            8192,
            if trigger == "timeout" { 5 } else { 15 },
        )?;
        let mut server = Server::start(&fixture).await?;
        let mut observed = Vec::new();
        let scenario = async {
            server.call(2, arguments()).await?;
            let records = fixture.ready(1, &mut server, 2).await?;
            let record = &records[0];
            let leader = pid(record, "leader")?;
            let worker = pid(record, "worker")?;
            let (group, leader_state) = fixture
                .process(leader)
                .await?
                .context("live script leader")?;
            let (worker_group, worker_state) = fixture
                .process(worker)
                .await?
                .context("live background pipe holder")?;
            ensure!(!leader_state.starts_with('Z') && !worker_state.starts_with('Z'));
            ensure!(
                group == worker_group && group != leader,
                "script was not joined to a separately retained anchor group"
            );
            ensure!(
                fixture.process(group).await?.is_some(),
                "anchor was reaped while command was live"
            );
            observed.extend([leader, worker, group]);
            ensure!(
                fixture.operation_directories()?.len() == 1,
                "live operation lost workspace ownership"
            );
            match trigger {
                "normal" => fs::write(record.join("release-leader"), b"release")?,
                "cancel" => server.cancel(2).await?,
                "timeout" | "eof" | "sigterm" => {}
                _ => unreachable!(),
            }
            if !matches!(trigger, "eof" | "sigterm") {
                if trigger == "cancel" {
                    server.finished(2, "cancelled").await?;
                } else {
                    let frame = server.response(2).await?;
                    let result = envelope(&frame)?;
                    let expected = if trigger == "normal" {
                        "exited"
                    } else {
                        "timeout"
                    };
                    ensure!(
                        result["data"]["termination"] == expected,
                        "{trigger}: {result}"
                    );
                    cleaned(&result["data"])?;
                    if trigger == "normal" {
                        ensure!(result["error"].is_null() && result["data"]["exit_code"] == 0);
                        ensure!(
                            result["data"]["stdout"] == "leader completed\n",
                            "leader status/output lost behind inherited pipes"
                        );
                    } else {
                        ensure!(
                            !result["error"].is_null(),
                            "interruption reported as success"
                        );
                    }
                }
                fixture.gone(&observed).await?;
                // Direct children must actually be reaped, not merely zombies.
                ensure!(
                    fixture.process(leader).await?.is_none()
                        && fixture.process(group).await?.is_none(),
                    "direct child not reaped"
                );
                fixture.clean().await?;
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // On failure unblock our fixture before asking the server to stop. On success,
        // keep workers blocked until EOF/SIGTERM proves that shutdown itself kills them.
        if scenario.is_err() {
            fixture.release_all()?;
        }
        let stopped = server.stop(trigger == "sigterm").await;
        let completed = async {
            scenario.with_context(|| trigger)?;
            let audit = stopped.with_context(|| trigger)?;
            if matches!(trigger, "eof" | "sigterm") {
                let records = audit
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .map(serde_json::from_slice::<Value>)
                    .collect::<serde_json::Result<Vec<_>>>()?;
                let finish = records
                    .iter()
                    .find(|event| event["event"] == "finish" && event["request_id"] == 2)
                    .context("shutdown did not finish the controller owner")?;
                ensure!(
                    finish["error_code"] == "cancelled"
                        && finish["owned_group_cleanup"] == "signalled_and_reaped",
                    "shutdown cleanup: {finish}"
                );
            }
            // Do not release fixture gates until these observations: otherwise a
            // broken shutdown could pass merely because the test let workers exit.
            fixture.gone(&observed).await.with_context(|| trigger)?;
            ensure!(
                fixture.process(observed[0]).await?.is_none()
                    && fixture.process(observed[2]).await?.is_none(),
                "shutdown left an unreaped direct child"
            );
            fixture.clean().await.with_context(|| trigger)
        }
        .await;
        fixture.release_all()?;
        if completed.is_err() {
            fixture.gone(&observed).await?;
        }
        completed?;
    }
    Ok(())
}

#[cfg_attr(
    target_os = "macos",
    ignore = "requires native process observation outside the Darwin build sandbox"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_admission_is_held_by_live_controller_owners_and_recovers_after_cleanup()
-> Result<()> {
    let fixture = Fixture::new(GROUP_SCRIPT, 8192, 15)?;
    let mut server = Server::start(&fixture).await?;
    let mut observed = Vec::new();
    let scenario = async {
        for id in 10..18 {
            server.call(id, arguments()).await?;
        }
        let records = fixture.ready(8, &mut server, 10).await?;
        ensure!(
            fixture.operation_directories()?.len() == 8,
            "admitted operations do not own distinct workspaces"
        );
        for record in &records {
            observed.extend([pid(record, "leader")?, pid(record, "worker")?]);
        }
        server.call(100, arguments()).await?;
        let rejected = server.response(100).await?;
        let result = envelope(&rejected)?;
        ensure!(
            result["error"]["code"] == "resource_limit" && result["data"].is_null(),
            "admission overflow: {result}"
        );
        ensure!(
            fixture.records()?.len() == 8 && fixture.operation_directories()?.len() == 8,
            "rejected call performed local work"
        );
        // Cancellation keeps the actual operation owner responsible for cleanup.
        for id in 10..18 {
            server.cancel(id).await?;
        }
        for id in 10..18 {
            server.finished(id, "cancelled").await?;
        }
        fixture.gone(&observed).await?;
        fixture.clean().await?;
        server.call(101, arguments()).await?;
        let all_records = fixture.ready(9, &mut server, 101).await?;
        let next = all_records
            .iter()
            .find(|path| !records.contains(path))
            .context("newly admitted controller")?;
        observed.extend([pid(next, "leader")?, pid(next, "worker")?]);
        fs::write(next.join("release-leader"), b"release")?;
        let frame = server.response(101).await?;
        let result = envelope(&frame)?;
        ensure!(
            result["error"].is_null(),
            "admission did not recover: {result}"
        );
        cleaned(&result["data"])?;
        fixture.gone(&observed).await?;
        fixture.clean().await
    }
    .await;
    fixture.release_all()?;
    let stopped = server.stop(false).await;
    scenario?;
    stopped?;
    fixture.gone(&observed).await?;
    Ok(())
}

async fn controller_output_read(server: &mut Server, id: u64, arguments: Value) -> Result<Value> {
    server
        .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"ssh_read_output","arguments":arguments}}))
        .await?;
    let frame = server.response(id).await?;
    let result = &frame["result"];
    let reply = &result["structuredContent"];
    ensure!(reply.is_object(), "missing local output envelope: {frame}");
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("output compatibility text")?,
    )?;
    ensure!(text == *reply);
    ensure!(result["isError"].as_bool().unwrap_or(false) == !reply["error"].is_null());
    Ok(reply.clone())
}

fn controller_output_entries(path: &Path) -> Result<Vec<PathBuf>> {
    Ok(fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_output_exact_raw_ranges_default_permissions_and_shutdown() -> Result<()> {
    let fixture = Fixture::new(
        "printf 'abc\\000\\303\\251\\377Z'; printf 'err\\000\\376' >&2\n",
        4,
        15,
    )?;
    let temporary = fixture.temp.path().join("ambient-tmp");
    fs::create_dir(&temporary)?;
    let mut config = fs::read_to_string(&fixture.config)?;
    config.push_str("\n[output]\nper_stream_bytes = 64\ntotal_bytes = 256\nmax_handles = 2\n");
    fs::write(&fixture.config, config)?;
    let mut server = Server::start(&fixture).await?;
    let scenario = async {
        server.call(2, arguments()).await?;
        let frame = server.response(2).await?;
        let result = envelope(&frame)?;
        ensure!(result["error"].is_null());
        ensure!(result["data"].get("output").is_none());
        ensure!(controller_output_entries(&temporary)?.is_empty(), "default created artifacts");
        let mut request = arguments();
        request["retain_output"] = json!(true);
        server.call(3, request).await?;
        let frame = server.response(3).await?;
        let result = envelope(&frame)?;
        let data = &result["data"];
        ensure!(result["error"].is_null());
        cleaned(data)?;
        ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
        ensure!(data["stdout"] == "abc\0" && data["stderr"] == "err\0");
        ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
        let receipt = &data["output"];
        ensure!(receipt["status"] == "ready", "output receipt: {receipt}");
        let handle = receipt["handle"].as_str().context("retained controller handle")?.to_owned();
        ensure!(handle.len() == 32 && handle.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        for (stream, size) in [("stdout", 8), ("stderr", 5)] {
            ensure!(receipt[stream] == json!({"bytes_retained":size,"total_bytes":size,"truncated":false}));
        }
        let directories = controller_output_entries(&temporary)?;
        ensure!(directories.len() == 1);
        ensure!(fs::metadata(&directories[0])?.permissions().mode() & 0o777 == 0o700);
        let files = controller_output_entries(&directories[0])?;
        ensure!(files.len() == 2);
        let mut contents = Vec::new();
        for file in files {
            ensure!(fs::metadata(&file)?.permissions().mode() & 0o777 == 0o600);
            contents.push(fs::read(file)?);
        }
        ensure!(contents.contains(&b"abc\0\xc3\xa9\xffZ".to_vec()));
        ensure!(contents.contains(&b"err\0\xfe".to_vec()));
        for (index, (stream, offset, limit, bytes, eof, encoding)) in [
            ("stdout", 0, 8, &b"abc\0\xc3\xa9\xffZ"[..], true, "base64"),
            ("stderr", 0, 5, &b"err\0\xfe"[..], true, "base64"),
            ("stdout", 0, 3, &b"abc"[..], false, "utf8"),
            ("stdout", 3, 1, &b"\0"[..], false, "utf8"),
            ("stdout", 4, 2, &b"\xc3\xa9"[..], false, "utf8"),
            ("stdout", 8, 1, &b""[..], true, "utf8"),
            ("stderr", 99, 1, &b""[..], true, "base64"),
        ].into_iter().enumerate() {
            let reply = controller_output_read(&mut server, 10 + index as u64, json!({
                "handle":handle,"stream":stream,"offset":offset,"max_bytes":limit,"encoding":encoding,
            })).await?;
            let content = if encoding == "base64" { STANDARD.encode(bytes) }
                else { std::str::from_utf8(bytes)?.to_owned() };
            ensure!(reply["error"].is_null());
            ensure!(reply["data"] == json!({
                "content":content,"encoding":encoding,"bytes_read":bytes.len(),
                "next_offset":offset + bytes.len() as u64,"eof":eof,
                "content_sha256":hex::encode(Sha256::digest(bytes)),
            }), "range reply: {reply}");
        }
        for (id, offset) in [(20, 4), (21, 5), (22, 6)] {
            let reply = controller_output_read(&mut server, id, json!({
                "handle":handle,"stream":"stdout","offset":offset,"max_bytes":1,
            })).await?;
            ensure!(reply["data"].is_null() && reply["error"]["code"] == "invalid_encoding");
            ensure!(reply["error"]["remote_state_unknown"] == false);
        }
        fixture.clean().await?;
        Ok::<_, anyhow::Error>(handle)
    }.await;
    let stopped = server.stop(false).await;
    let clean = fixture.clean().await;
    let handle = scenario?;
    let audit = stopped?;
    clean?;
    ensure!(
        controller_output_entries(&temporary)?.is_empty(),
        "shutdown leaked retained output"
    );
    ensure!(!String::from_utf8_lossy(&audit).contains(&handle));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_output_prefix_quota_disabled_storage_failure_and_expiry() -> Result<()> {
    for mode in [
        "quota", "disabled", "storage", "expiry", "timeout", "signal",
    ] {
        let script = match mode {
            "timeout" => "printf abc; printf err >&2; @SLEEP@ 10\n",
            "signal" => "printf abc; printf err >&2; kill -TERM \"$$\"\n",
            _ => {
                "x=oooooooooooooooo; y=eeeeeeeeeeeeeeee; i=0; while [ \"$i\" -lt 14 ]; do x=$x$x; y=$y$y; i=$((i+1)); done; printf '%s' \"$x\"; printf '%s' \"$y\" >&2; printf done > @OBS@/drained; exit 23\n"
            }
        };
        let fixture = Fixture::new(script, 4, if mode == "timeout" { 1 } else { 15 })?;
        let temporary = fixture.temp.path().join("ambient-tmp");
        if mode == "storage" {
            fs::write(&temporary, b"not a directory")?;
        } else {
            fs::create_dir(&temporary)?;
        }
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(&format!(
            "\n[output]\nenabled = {}\nper_stream_bytes = 8\ntotal_bytes = 16\nmax_handles = 1\nttl_secs = {}\n",
            mode != "disabled", if mode == "expiry" { 1 } else { 300 },
        ));
        fs::write(&fixture.config, config)?;
        let mut server = Server::start(&fixture).await?;
        let scenario = async {
            let mut request = arguments();
            request["retain_output"] = json!(true);
            server.call(2, request.clone()).await?;
            let frame = server.response(2).await?;
            let result = envelope(&frame)?;
            let data = &result["data"];
            cleaned(data)?;
            match mode {
                "timeout" => {
                    ensure!(result["error"]["code"] == "timeout" && data["termination"] == "timeout");
                    ensure!(data["exit_code"].is_null());
                }
                "signal" => {
                    ensure!(!result["error"].is_null());
                    ensure!(data["termination"] == "signalled" && data["signal"] == 15);
                }
                _ => {
                    ensure!(result["error"]["code"] == "command_failed");
                    ensure!(data["exit_code"] == 23 && data["termination"] == "exited");
                    ensure!(data["stdout"] == "oooo" && data["stderr"] == "eeee");
                    ensure!(fs::read(fixture.observations.join("drained"))? == b"done");
                }
            }
            if matches!(mode, "disabled" | "storage") {
                ensure!(data["output"] == json!({"status":"unavailable","reason":
                    if mode == "disabled" {"retention_disabled"} else {"io_error"}}));
                if mode == "disabled" { ensure!(controller_output_entries(&temporary)?.is_empty()); }
            } else {
                let receipt = &data["output"];
                ensure!(receipt["status"] == "ready", "receipt: {receipt}");
                let handle = receipt["handle"].as_str().context("handle")?.to_owned();
                if matches!(mode, "quota" | "expiry") {
                    for stream in ["stdout", "stderr"] {
                        ensure!(receipt[stream] == json!({
                            "bytes_retained":8,"total_bytes":262144,"truncated":true,
                        }));
                        let expected = if stream == "stdout" { b"oooooooo" } else { b"eeeeeeee" };
                        let reply = controller_output_read(&mut server,
                            if stream == "stdout" { 3 } else { 4 },
                            json!({"handle":handle,"stream":stream,"max_bytes":8})).await?;
                        ensure!(reply["error"].is_null());
                        ensure!(reply["data"] == json!({
                            "content":std::str::from_utf8(expected)?,"encoding":"utf8","bytes_read":8,
                            "next_offset":8,"eof":true,"content_sha256":hex::encode(Sha256::digest(expected)),
                        }));
                    }
                    if mode == "quota" {
                        server.call(5, request).await?;
                        let frame = server.response(5).await?;
                        let reply = envelope(&frame)?;
                        cleaned(&reply["data"])?;
                        ensure!(reply["error"]["code"] == "command_failed" && reply["data"]["exit_code"] == 23);
                        ensure!(reply["data"]["output"] == json!({"status":"unavailable","reason":"resource_limit"}));
                    } else {
                        timeout(WAIT, async {
                            while !controller_output_entries(&temporary)?.is_empty() { sleep(Duration::from_millis(10)).await; }
                            Ok::<_, anyhow::Error>(())
                        }).await??;
                        let reply = controller_output_read(&mut server, 5,
                            json!({"handle":handle,"stream":"stdout"})).await?;
                        ensure!(reply["error"]["code"] == "not_found" && reply["error"]["remote_state_unknown"] == false);
                    }
                }
            }
            fixture.clean().await
        }.await;
        let stopped = server.stop(false).await;
        let clean = fixture.clean().await;
        scenario.with_context(|| mode)?;
        stopped?;
        clean?;
        if mode == "storage" {
            ensure!(fs::read(&temporary)? == b"not a directory");
        } else {
            ensure!(controller_output_entries(&temporary)?.is_empty());
        }
    }
    Ok(())
}
