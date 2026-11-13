//! Opt-in real Runner acceptance. No Python test driver or synthetic adapter.
#![cfg(unix)]

#[allow(dead_code)]
mod support;

use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use serde_json::{Value, json};
use support::{Fixture, Log, WireServer};
use tokio::{
    process::Command,
    time::{sleep, timeout},
};

const PRIVATE: &str = "RUNNER_PRIVATE_PAYLOAD_8d29";
const WAIT: Duration = Duration::from_secs(12);

fn text(path: &Path) -> Result<String> {
    Ok(path.to_str().context("UTF-8 acceptance path")?.to_owned())
}

fn table(value: Value) -> Result<toml::Value> {
    Ok(toml::Value::try_from(value)?)
}

enum RuntimeSource {
    Bundle(PathBuf),
    InstalledLauncher,
}

struct Acceptance {
    fixture: Fixture,
    workspace: PathBuf,
    python: PathBuf,
    runtime: RuntimeSource,
    forbidden: PathBuf,
}

impl Acceptance {
    async fn start() -> Result<Self> {
        let runtime = match std::env::var_os("SSH_MCP_TEST_ANSIBLE_RUNTIME") {
            Some(path) => RuntimeSource::Bundle(fs::canonicalize(path)?),
            None => {
                let launcher = support::executable(Path::new(
                    &std::env::var_os("SSH_MCP_TEST_WHEEL_BINARY")
                        .context("set SSH_MCP_TEST_ANSIBLE_RUNTIME or SSH_MCP_TEST_WHEEL_BINARY")?,
                ))?;
                let selected = support::executable(Path::new(
                    &std::env::var_os("SSH_MCP_TEST_BINARY")
                        .context("installed runtime acceptance requires SSH_MCP_TEST_BINARY to select the public wheel launcher")?,
                ))?;
                ensure!(
                    fs::canonicalize(launcher)? == fs::canonicalize(selected)?,
                    "SSH_MCP_TEST_BINARY must select SSH_MCP_TEST_WHEEL_BINARY for installed runtime acceptance"
                );
                RuntimeSource::InstalledLauncher
            }
        };
        let python = support::executable(Path::new(
            &std::env::var_os("SSH_MCP_TEST_TARGET_PYTHON")
                .context("set SSH_MCP_TEST_TARGET_PYTHON to the pinned target interpreter")?,
        ))?;
        let mut fixture = Fixture::start().await?;
        // The second existing isolated listener supplies a real refused SSH destination.
        fixture
            .listeners
            .pop()
            .context("second isolated SSH listener")?
            .stop()
            .await?;
        let workspace = fixture.root.path().join("runner-private-workspaces");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let forbidden = fixture.root.path().join("lookup-must-not-run");
        let this = Self {
            fixture,
            workspace,
            python,
            runtime,
            forbidden,
        };
        this.configure().await?;
        Ok(this)
    }

    async fn configure(&self) -> Result<()> {
        // Import uses the same real product CLI as an operator, with no execution enabled.
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&self.fixture.config)?)?;
        let runtime_config = match &self.runtime {
            RuntimeSource::Bundle(path) => json!({"runtime":text(path)?}),
            // The actual installed public launcher supplies its own descriptor.
            RuntimeSource::InstalledLauncher => json!({}),
        };
        config.insert("automation".into(), table(runtime_config)?);
        fs::write(&self.fixture.config, toml::to_string(&config)?)?;
        let empty = json!({"type":"object","properties":{},"additionalProperties":false,"maxProperties":0,"const":{}});
        let string = json!({"type":"string","maxLength":4096});
        let definitions = [
            (
                "probe",
                "ansible.builtin.ping",
                false,
                json!({"input_schema":{"type":"object","properties":{"data":string},"required":["data"],"additionalProperties":false,"maxProperties":1},"fixed_args":{},"input_map":{"data":"data"}}),
            ),
            (
                "command",
                "ansible.builtin.command",
                false,
                json!({"input_schema":{"type":"object","properties":{"argv":{"type":"array","items":{"type":"string","maxLength":8192},"minItems":1,"maxItems":32}},"required":["argv"],"additionalProperties":false},"fixed_args":{"expand_argument_vars":false},"input_map":{"argv":"argv"}}),
            ),
            (
                "secret",
                "ansible.builtin.command",
                true,
                json!({"input_schema":empty,"fixed_args":{"argv":[text(&self.python)?,"-c",format!("print({PRIVATE:?})")],"expand_argument_vars":false},"input_map":{}}),
            ),
            (
                "choice",
                "ansible.builtin.ping",
                false,
                json!({"input_schema":{"type":"object","properties":{"data":{"type":"string","enum":["pong"]}},"required":["data"],"additionalProperties":false,"maxProperties":1,"const":{"data":"pong"}},"fixed_args":{},"input_map":{"data":"data"}}),
            ),
        ];
        let mut tools = toml::map::Map::new();
        for (name, module, no_log, overlay) in definitions {
            let snapshot = self
                .fixture
                .root
                .path()
                .join(format!("{name}-reviewed.json"));
            let overlay_path = self
                .fixture
                .root
                .path()
                .join(format!("{name}-overlay.json"));
            fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
            let mut command = support::server_command(&self.fixture.config)?;
            command
                .args(["schema", "import", module])
                .arg("--output")
                .arg(&snapshot)
                .arg("--overlay")
                .arg(&overlay_path);
            let output = support::run(&mut command).await?;
            ensure!(
                output.status.success(),
                "real schema import failed for {module}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            let report: Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                report["binding_validated"] == true,
                "overlay was not reviewed"
            );
            let mut binding = json!({
                "description":"Explicit reviewed fixture module", "revision":"fixture-1",
                "authority":"automation", "effects":[if name == "probe" { "probe" } else { "runtime_write" }], "targets":["plain","nosftp"],
                "execution":{"kind":"ansible_module","snapshot":text(&snapshot)?,"no_log":no_log},
                "result":{"kind":"ansible_summary"}, "limits":{"timeout_secs":12}
            });
            for key in ["input_schema", "fixed_args", "input_map"] {
                binding[key] = overlay[key].clone();
            }
            tools.insert(name.to_owned(), table(binding)?);
        }
        config.insert(
            "enabled_tools".into(),
            table(json!(["probe", "command", "secret", "choice"]))?,
        );
        config.insert("tools".into(), toml::Value::Table(tools));
        let limits = config
            .entry("limits")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .context("limits table")?;
        limits.insert("operation_timeout_secs".into(), 12.into());
        limits.insert("max_timeout_secs".into(), 15.into());
        limits.insert("max_output_bytes".into(), 8192.into());
        let mut automation = json!({
            "required":true,"workspace_root":text(&self.workspace)?,
            "ssh_executable":text(&self.fixture.ssh)?,
            "max_concurrent":2,"max_scratch_bytes":16777216,"max_scratch_files":512,
            "targets":{"plain":{"destination":"plain","python":text(&self.python)?},
                "nosftp":{"destination":"nosftp","python":text(&self.python)?}}
        });
        if let RuntimeSource::Bundle(path) = &self.runtime {
            automation["runtime"] = json!(text(path)?);
        }
        config.insert("automation".into(), table(automation)?);
        fs::write(&self.fixture.config, toml::to_string(&config)?)?;
        Ok(())
    }

    fn private(&self, bytes: &str) -> Result<()> {
        if let RuntimeSource::Bundle(path) = &self.runtime {
            ensure!(
                !bytes.contains(path.to_str().context("runtime path")?),
                "private bundle runtime path escaped the bounded summary/audit"
            );
        }
        for secret in [
            PRIVATE,
            self.fixture.root.path().to_str().context("fixture path")?,
            self.python.to_str().context("Python path")?,
            "Traceback",
        ] {
            ensure!(
                !bytes.contains(secret),
                "private execution data escaped the bounded summary/audit"
            );
        }
        Ok(())
    }

    fn clean(&self) -> Result<()> {
        ensure!(
            fs::read_dir(&self.workspace)?.next().is_none(),
            "owned Runner workspace survived completion"
        );
        ensure!(
            !self.forbidden.exists(),
            "caller template invoked a controller lookup"
        );
        Ok(())
    }

    async fn server(&self) -> Result<WireServer> {
        let mut server = WireServer::start(&self.fixture.config)?;
        if let Err(error) = server.initialize().await {
            let cleanup = server.stop(None).await;
            return match cleanup {
                Ok(_) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("initialization cleanup failed: {cleanup:#}")))
                }
            };
        }
        Ok(server)
    }

    fn argv(&self, script: &str, extra: &[Value]) -> Value {
        let mut argv = vec![json!(self.python), json!("-c"), json!(script)];
        argv.extend_from_slice(extra);
        json!({"host":"plain", "inputs":{"argv":argv}})
    }

    async fn call(
        &self,
        server: &mut WireServer,
        id: u64,
        name: &str,
        args: Value,
    ) -> Result<Value> {
        let response = server
            .request(id, "tools/call", json!({"name":name,"arguments":args}))
            .await?;
        self.private(&response.to_string())?;
        ensure!(response["error"].is_null(), "MCP call rejected: {response}");
        let envelope = response["result"]["structuredContent"].clone();
        ensure!(
            envelope["data"].is_object(),
            "missing automation summary: {response}"
        );
        self.clean()?;
        Ok(envelope)
    }

    async fn finish(&self, log: &Log, id: u64) -> Result<Value> {
        timeout(WAIT, async {
            loop {
                if let Some(record) = log
                    .records()?
                    .into_iter()
                    .find(|record| record["event"] == "finish" && record["request_id"] == id)
                {
                    self.private(&record.to_string())?;
                    return Ok::<_, anyhow::Error>(record);
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("automation completion audit deadline")?
    }

    async fn stop(&self, server: WireServer) -> Result<()> {
        let log = server.stop(None).await?;
        self.private(&log.text())?;
        self.clean()
    }
}

#[derive(Clone)]
struct OwnedProcess {
    pid: i32,
    parent: i32,
    command: String,
}

async fn processes() -> Result<Vec<OwnedProcess>> {
    let output = support::run(
        Command::new(support::find_program("ps")?).args(["-axo", "pid=,ppid=,command="]),
    )
    .await?;
    ensure!(
        output.status.success(),
        "process ownership observation failed"
    );
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line
                .split_once(char::is_whitespace)
                .context("process PID")?;
            let (parent, command) = rest
                .trim_start()
                .split_once(char::is_whitespace)
                .context("process parent")?;
            Ok(OwnedProcess {
                pid: pid.parse()?,
                parent: parent.parse()?,
                command: command.trim_start().to_owned(),
            })
        })
        .collect()
}

async fn owned(workspace: &Path) -> Result<Vec<OwnedProcess>> {
    let all = processes().await?;
    let needle = text(workspace)?;
    let mut selected: BTreeSet<i32> = all
        .iter()
        // Only the product adapter's explicit source/input argv roots ownership.
        // A localhost remote task belongs to the separate sshd process tree.
        .filter(|process| {
            process.command.contains(&needle)
                && process.command.contains("/source")
                && process.command.contains("/input.json")
        })
        .map(|process| process.pid)
        .collect();
    ensure!(
        !selected.is_empty(),
        "real adapter process was not observed"
    );
    loop {
        let before = selected.len();
        for process in &all {
            if selected.contains(&process.parent) {
                selected.insert(process.pid);
            }
        }
        if selected.len() == before {
            break;
        }
    }
    Ok(all
        .into_iter()
        .filter(|process| selected.contains(&process.pid))
        .collect())
}

async fn gone(owned: &[OwnedProcess]) -> Result<()> {
    let current = processes().await?;
    for process in owned {
        if let Some(now) = current
            .iter()
            .find(|now| now.pid == process.pid && now.command == process.command)
        {
            anyhow::bail!(
                "owned local adapter/Runner descendant survived return: pid={} captured_parent={} current_parent={} command={:?}",
                process.pid,
                process.parent,
                now.parent,
                process.command
            );
        }
    }
    Ok(())
}

async fn send_command(server: &mut WireServer, id: u64, arguments: Value) -> Result<()> {
    server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"command","arguments":arguments}})).await
}

/// Explicit entry: cargo test --test automation_exec real_runner_fixture_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected pinned Runner/target Python, Nix sshd, non-root private localhost fixture"]
async fn real_runner_fixture_acceptance() -> Result<()> {
    let mut acceptance = Acceptance::start().await?;
    let result = scenarios(&mut acceptance).await;
    let cleanup = acceptance.fixture.stop().await;
    result?;
    cleanup
}

async fn scenarios(a: &mut Acceptance) -> Result<()> {
    let mut server = a.server().await?;
    let normal: Result<()> = async {
    let listed = server.request(2, "tools/list", json!({})).await?;
    for name in ["probe", "command", "secret", "ssh_exec"] {
        ensure!(
            listed["result"]["tools"]
                .as_array()
                .context("tool list")?
                .iter()
                .any(|tool| tool["name"] == name),
            "missing reviewed or native tool {name}"
        );
    }
    for (index, arguments) in [
        json!({"host":"plain"}),
        json!({"host":"plain","inputs":[]}),
        json!({"host":"plain","inputs":{}}),
        json!({"host":"plain","inputs":{"data":false}}),
        json!({"host":"plain","inputs":{"data":"pong","unknown":true}}),
        json!({"host":"plain","inputs":{"data":"pong"},"unknown":true}),
        json!({"host":"plain","data":"pong"}),
    ].into_iter().enumerate() {
        let response = server.request(100 + index as u64, "tools/call",
            json!({"name":"probe","arguments":arguments})).await?;
        ensure!(response["error"]["code"] == -32602, "invalid module request shape accepted: {response}");
        a.private(&response.to_string())?;
        a.clean()?;
    }
    let published_choice = listed["result"]["tools"].as_array().context("tool list")?
        .iter().find(|tool| tool["name"] == "choice").context("published choice tool")?;
    let domain = &published_choice["inputSchema"]["properties"]["inputs"];
    ensure!(domain["maxProperties"] == 1 && domain["const"] == json!({"data":"pong"})
        && domain["properties"]["data"]["enum"] == json!(["pong"]),
        "reviewed root bounds/choices changed during publication");
    let choice = a.call(&mut server,110,"choice",json!({"host":"plain","inputs":{"data":"pong"}})).await?;
    ensure!(choice["error"].is_null() && choice["data"]["status"] == "successful");
    for (id, name, inputs) in [
        (111, "choice", json!({"data":"not-approved"})),
        (112, "probe", json!({"data":"x".repeat(4097)})),
    ] {
        let response = server.request(id,"tools/call",json!({"name":name,"arguments":{"host":"plain","inputs":inputs}})).await?;
        ensure!(response["error"].is_null(), "reviewed bounds must return ToolError, not shape rejection: {response}");
        let rejected = &response["result"]["structuredContent"];
        ensure!(rejected["error"]["code"] == "invalid_argument"
            && rejected["error"]["remote_state_unknown"] == false,
            "reviewed bound/choice did not fail before dispatch: {response}");
        a.private(&response.to_string())?;
        a.clean()?;
    }
    let good = a
        .call(
            &mut server,
            3,
            "probe",
            json!({"host":"plain","inputs":{"data":"pong"}}),
        )
        .await?;
    ensure!(
        good["error"].is_null()
            && good["data"]["status"] == "successful"
            && good["data"]["tasks"]["ok"] == 1
            && good["data"]["complete"] == true
    );
    let failed = a
        .call(
            &mut server,
            4,
            "probe",
            json!({"host":"plain","inputs":{"data":"crash"}}),
        )
        .await?;
    ensure!(
        !failed["error"].is_null()
            && failed["data"]["status"] == "failed"
            && failed["data"]["tasks"]["failed"] == 1
    );
    let unreachable = a
        .call(
            &mut server,
            5,
            "probe",
            json!({"host":"nosftp","inputs":{"data":"pong"}}),
        )
        .await?;
    ensure!(
        !unreachable["error"].is_null()
            && unreachable["data"]["status"] == "unreachable"
            && unreachable["data"]["tasks"]["unreachable"] == 1
    );

    // Root string and nested argv list strings must be inert, not Jinja programs.
    let literal = format!("{{{{ lookup('pipe', 'touch {}') }}}}", text(&a.forbidden)?);
    let root = a
        .call(
            &mut server,
            6,
            "probe",
            json!({"host":"plain","inputs":{"data":literal}}),
        )
        .await?;
    ensure!(root["data"]["status"] == "successful");
    let observed = a.fixture.root.path().join("literal-observed.json");
    let nested = vec![
        json!(observed),
        json!(literal),
        json!("{{ 6 * 7 }}"),
        json!("{% if true %}changed{% endif %}"),
        json!("雪 \"quoted\"\nnext line"),
        json!(PRIVATE),
    ];
    let args = a.argv(
        "import json,sys;open(sys.argv[1],'w').write(json.dumps(sys.argv[2:]))",
        &nested,
    );
    let reply = a.call(&mut server, 7, "command", args).await?;
    ensure!(reply["data"]["status"] == "successful");
    // A04 projections are intentionally absent: inspect the actual effect over native SSH.
    let observed_reply = server.request(8,"tools/call",json!({"name":"ssh_exec","arguments":{"host":"plain","command":format!("cat {}",support::quote(&text(&observed)?))}})).await?;
    let stdout = observed_reply["result"]["structuredContent"]["data"]["stdout"]
        .as_str()
        .context("native observed contents")?;
    ensure!(
        serde_json::from_str::<Value>(stdout)? == Value::Array(nested[1..].to_vec()),
        "nested values were templated or coerced"
    );
    ensure!(!a.forbidden.exists());
    let secret = a
        .call(&mut server, 9, "secret", json!({"host":"plain","inputs":{}}))
        .await?;
    ensure!(secret["data"]["status"] == "successful" && secret["data"]["censored"] == true);

    // The caller deliberately stops reading MCP while real module stdout is large.
    let output_done = a.fixture.root.path().join("large-output-done");
    send_command(
        &mut server,
        10,
        a.argv(
            &format!(
                "import sys;sys.stdout.write({PRIVATE:?}*65536);open({:?},'w').write('done')",
                text(&output_done)?
            ),
            &[],
        ),
    )
    .await?;
    a.finish(&server.log, 10).await?;
    let (large, bytes) = server.receive(json!(10)).await?;
    a.private(&large.to_string())?;
    ensure!(
        bytes < 16384 && large["result"]["structuredContent"]["data"]["status"] == "successful",
        "large module output escaped summary boundary: {large}"
    );
    ensure!(output_done.exists());
    a.clean()?;
        Ok(())
    }.await;
    let cleanup = a.stop(server).await;
    normal?;
    cleanup?;
    agent_only(a).await?;

    // Termination scenarios each get a fresh real server, preserving ownership evidence.
    for (index, mode) in ["cancel", "deadline", "eof", "adapter_loss"]
        .into_iter()
        .enumerate()
    {
        let id = 20 + index as u64;
        let mut server = a.server().await?;
        let done = a.fixture.root.path().join(format!("{mode}-remote-done"));
        let result: Result<Option<Vec<OwnedProcess>>> = async {
        let started = a.fixture.root.path().join(format!("{mode}-started"));
        // SSH cancellation cannot prove remote process termination. This finite remote
        // command intentionally records completion and is awaited before fixture removal.
        a.fixture.eventual_markers.push(done.clone());
        let script = format!(
            "import signal,time;signal.signal(signal.SIGHUP,signal.SIG_IGN);open({:?},'w').write('started');time.sleep(8);open({:?},'w').write('done')",
            text(&started)?,
            text(&done)?
        );
        let mut args = a.argv(&script, &[]);
        if mode == "deadline" {
            args["timeout_secs"] = json!(6);
        }
        send_command(&mut server, id, args).await?;
        Fixture::await_file(&started).await?;
        let children = owned(&a.workspace).await?;
        match mode {
            "cancel" => {
                let occupied = server.request(id + 1000, "tools/call", json!({
                    "name":"probe","arguments":{"host":"plain","inputs":{"data":"pong"}}
                })).await?;
                a.private(&occupied.to_string())?;
                ensure!(occupied["error"].is_null()
                    && occupied["result"]["structuredContent"]["error"]["code"] == "resource_limit"
                    && occupied["result"]["structuredContent"]["error"]["remote_state_unknown"] == false,
                    "per-target admission allowed a second real module: {occupied}");
                let malformed = server.request(id + 2000, "tools/call", json!({
                    "name":"probe","arguments":{"host":"plain","inputs":{"data":false}}
                })).await?;
                a.private(&malformed.to_string())?;
                ensure!(malformed["error"]["code"] == -32602,
                    "occupied admission obscured malformed request shape: {malformed}");
                server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id,"reason":"real fixture cancellation"}})).await?;
                let finish = a.finish(&server.log, id).await?;
                ensure!(finish["error_code"] == "cancelled");
                ensure!(finish["owned_group_cleanup"] == "signalled_and_reaped");
                a.clean()?;
                gone(&children).await?;
                let released = a.call(&mut server, id + 3000, "probe",
                    json!({"host":"plain","inputs":{"data":"pong"}})).await?;
                ensure!(released["error"].is_null() && released["data"]["status"] == "successful",
                    "cancel completion retained the target admission permit: {released}");
            }
            "eof" => return Ok(Some(children)),
            _ => {
                if mode == "adapter_loss" {
                    let adapter = children
                        .iter()
                        .find(|child| {
                            child
                                .command
                                .contains(&format!("{}/", a.workspace.display()))
                                && child.command.contains("/source")
                        })
                        .context("owned real Python adapter")?;
                    // Match identity immediately before signalling, never a remembered PID.
                    ensure!(
                        processes()
                            .await?
                            .iter()
                            .any(|now| now.pid == adapter.pid && now.command == adapter.command)
                    );
                    kill(Pid::from_raw(adapter.pid), Signal::SIGKILL)?;
                }
                let (reply, _) = server.receive(json!(id)).await?;
                a.private(&reply.to_string())?;
                let envelope = &reply["result"]["structuredContent"];
                ensure!(!envelope["error"].is_null());
                ensure!(
                    envelope["data"]["status"]
                        == if mode == "deadline" {
                            "timeout"
                        } else {
                            "worker_lost"
                        }
                );
                ensure!(envelope["data"]["owned_group_cleanup"] == "signalled_and_reaped");
                if mode == "adapter_loss" {
                    ensure!(envelope["error"]["remote_state_unknown"] == true);
                    ensure!(envelope["data"]["complete"] == false);
                }
                a.clean()?;
                gone(&children).await?;
            }
        }
            Ok(None)
        }.await;
        // Always close MCP stdin and await product shutdown, including assertion failures.
        let cleanup = a.stop(server).await;
        let descendants = match &result {
            Ok(Some(children)) => gone(children).await,
            _ => Ok(()),
        };
        result?;
        cleanup?;
        descendants?;
        Fixture::await_file(&done).await?;
    }

    // Real workspace accounting fails closed before a module can dispatch.
    let mut config: toml::Value = toml::from_str(&fs::read_to_string(&a.fixture.config)?)?;
    config["automation"]["max_scratch_files"] = 1.into();
    fs::write(&a.fixture.config, toml::to_string(&config)?)?;
    let mut server = a.server().await?;
    let limited_result: Result<()> = async {
        let limited = a
            .call(
                &mut server,
                40,
                "probe",
                json!({"host":"plain","inputs":{"data":"pong"}}),
            )
            .await?;
        ensure!(!limited["error"].is_null() && limited["data"]["status"] == "resource_limit");
        Ok(())
    }
    .await;
    let cleanup = a.stop(server).await;
    limited_result?;
    cleanup
}

async fn agent_only(a: &Acceptance) -> Result<()> {
    let original_config = fs::read(&a.fixture.config)?;
    let original_ssh = fs::read_to_string(&a.fixture.ssh_config)?;
    let socket = a.fixture.root.path().join("a.sock");
    let mut agent = support::Process::start(
        Command::new(support::find_program("ssh-agent")?)
            .args(["-D", "-a"])
            .arg(&socket)
            .env("HOME", a.fixture.root.path())
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID"),
    )?;
    let result: Result<()> = async {
        let ssh_add = support::find_program("ssh-add")?;
        timeout(Duration::from_secs(5), async {
            loop {
                ensure!(agent.child.try_wait()?.is_none(), "owned ssh-agent exited during startup");
                let ready = support::run(Command::new(&ssh_add).arg("-l")
                    .env("SSH_AUTH_SOCK", &socket).env_remove("SSH_AGENT_PID")
                    .env("SSH_ASKPASS_REQUIRE", "never")).await?;
                // ssh-add: 1 means a reachable agent with no identities, 2 no agent.
                if matches!(ready.status.code(), Some(0 | 1)) {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("owned authentication agent readiness deadline")??;
        let added = support::run(Command::new(&ssh_add)
            .arg(a.fixture.root.path().join("client"))
            .env("SSH_AUTH_SOCK", &socket).env_remove("SSH_AGENT_PID")
            .env("SSH_ASKPASS_REQUIRE", "never")).await?;
        ensure!(added.status.success(), "cannot load the owned unencrypted fixture key");
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
            .context("current fixture account")?.name;
        let identities = original_ssh.lines().filter(|line|
            line.trim_start().starts_with("IdentityFile ")).count();
        ensure!(identities == 1, "unexpected fixture identity configuration");
        // IdentityFile directives accumulate, unlike most SSH options. Remove the
        // fixture's ordinary file identity during this case so agent-only is real.
        let without_identity = original_ssh.lines().filter(|line|
            !line.trim_start().starts_with("IdentityFile ")).collect::<Vec<_>>().join("\n");
        let ssh = format!(
            "Host agent-only\n    HostName 127.0.0.1\n    Port {}\n    User {user}\n    IdentityAgent SSH_AUTH_SOCK\n    IdentityFile none\n    IdentitiesOnly no\nHost *\n{without_identity}\n",
            a.fixture.ports.first().context("primary fixture port")?,
        );
        fs::write(&a.fixture.ssh_config, ssh)?;
        let mut config: toml::Value = toml::from_str(std::str::from_utf8(&original_config)?)?;
        config["automation"]["targets"]["plain"]["destination"] = "agent-only".into();
        fs::write(&a.fixture.config, toml::to_string(&config)?)?;
        let mut command = support::server_command(&a.fixture.config)?;
        command.env("SSH_AUTH_SOCK", &socket).env_remove("SSH_AGENT_PID");
        let mut server = WireServer::start_command(command)?;
        let call: Result<()> = async {
            server.initialize().await?;
            let reply = a.call(&mut server, 70, "probe",
                json!({"host":"plain","inputs":{"data":"pong"}})).await?;
            ensure!(reply["error"].is_null() && reply["data"]["status"] == "successful"
                && reply["data"]["tasks"]["ok"] == 1 && reply["data"]["complete"] == true,
                "real Runner could not use the owned out-of-band agent: {reply}");
            Ok(())
        }.await;
        let cleanup = a.stop(server).await;
        call?;
        cleanup
    }.await;
    // Restore both owned files even when an assertion failed; later scenarios
    // retain their original ordinary-key authority and destination mapping.
    let restore_config = fs::write(&a.fixture.config, original_config);
    let restore_ssh = fs::write(&a.fixture.ssh_config, original_ssh);
    let agent_cleanup = agent.stop().await;
    let socket_cleanup = match fs::remove_file(&socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    };
    result?;
    restore_config?;
    restore_ssh?;
    agent_cleanup?;
    socket_cleanup?;
    ensure!(!socket.exists(), "owned agent socket survived cleanup");
    Ok(())
}
