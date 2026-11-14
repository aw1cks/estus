//! Opt-in real Runner acceptance. No Python test driver or synthetic adapter.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/isolated.rs"]
mod isolated;
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
        let runtime = match std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME") {
            Some(path) => RuntimeSource::Bundle(fs::canonicalize(path)?),
            None => {
                let launcher = support::executable(Path::new(
                    &std::env::var_os("ESTUS_TEST_WHEEL_BINARY")
                        .context("set ESTUS_TEST_ANSIBLE_RUNTIME or ESTUS_TEST_WHEEL_BINARY")?,
                ))?;
                let selected = support::executable(Path::new(
                    &std::env::var_os("ESTUS_TEST_BINARY")
                        .context("installed runtime acceptance requires ESTUS_TEST_BINARY to select the public wheel launcher")?,
                ))?;
                ensure!(
                    fs::canonicalize(launcher)? == fs::canonicalize(selected)?,
                    "ESTUS_TEST_BINARY must select ESTUS_TEST_WHEEL_BINARY for installed runtime acceptance"
                );
                RuntimeSource::InstalledLauncher
            }
        };
        let python = support::executable(Path::new(
            &std::env::var_os("ESTUS_TEST_TARGET_PYTHON")
                .context("set ESTUS_TEST_TARGET_PYTHON to the pinned target interpreter")?,
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
        config["ssh"]
            .as_table_mut()
            .context("fixture SSH table")?
            .insert("executable".into(), text(&self.fixture.ssh)?.into());
        let mut automation = json!({
            "required":true,"workspace_root":text(&self.workspace)?,
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

    async fn configure_projection(&self) -> Result<()> {
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&self.fixture.config)?)?;
        let command = json!({
            "input_schema":{"type":"object","properties":{"argv":{"type":"array",
                "items":{"type":"string","maxLength":8192},"minItems":1,"maxItems":32}},
                "required":["argv"],"additionalProperties":false},
            "fixed_args":{"expand_argument_vars":false},"input_map":{"argv":"argv"}
        });
        let stdout = json!({"type":"object","properties":{"text":{"type":"string","maxLength":256}},
            "required":["text"],"additionalProperties":false});
        let lines = json!({"type":"object","properties":{"lines":{"type":"array",
            "items":{"type":"string","maxLength":32},"minItems":1,"maxItems":3}},
            "required":["lines"],"additionalProperties":false});
        let mut item_lines = lines.clone();
        item_lines["properties"]["lines"]["maxItems"] = json!(16);
        let definitions = [
            (
                "facts",
                "ansible.builtin.setup",
                false,
                facts_overlay(),
                facts_result(),
            ),
            (
                "summary",
                "ansible.builtin.command",
                false,
                command.clone(),
                json!({"kind":"ansible_summary"}),
            ),
            (
                "text",
                "ansible.builtin.command",
                false,
                command.clone(),
                projection_result(json!({"text":["stdout"]}), stdout.clone(), 1024, 32, 4),
            ),
            (
                "scalar",
                "ansible.builtin.command",
                false,
                command.clone(),
                projection_result(json!({"text":["stdout"]}), stdout.clone(), 64, 32, 4),
            ),
            (
                "lines",
                "ansible.builtin.command",
                false,
                command.clone(),
                projection_result(json!({"lines":["stdout_lines"]}), lines, 256, 32, 4),
            ),
            (
                "items",
                "ansible.builtin.command",
                false,
                command.clone(),
                projection_result(json!({"lines":["stdout_lines"]}), item_lines, 256, 5, 4),
            ),
            (
                "censored",
                "ansible.builtin.command",
                true,
                command.clone(),
                projection_result(json!({"text":["stdout"]}), stdout.clone(), 1024, 32, 4),
            ),
            (
                "invalid",
                "ansible.builtin.command",
                false,
                command.clone(),
                projection_result(
                    json!({"text":["stdout"]}),
                    json!({"type":"object",
                    "properties":{"text":{"type":"integer"}},"required":["text"],
                    "additionalProperties":false}),
                    1024,
                    32,
                    4,
                ),
            ),
            (
                "unavailable",
                "ansible.builtin.command",
                false,
                command,
                projection_result(json!({"text":["stdout"]}), stdout, 1024, 32, 4),
            ),
        ];
        let mut tools = toml::map::Map::new();
        let mut enabled = Vec::new();
        for (name, module, no_log, overlay, result) in definitions {
            let snapshot = self
                .fixture
                .root
                .path()
                .join(format!("projection-{name}-reviewed.json"));
            import_reviewed(&self.fixture.config, &snapshot, module, &overlay).await?;
            let mut binding = json!({
                "description":"Explicit reviewed projection acceptance","revision":"fixture-1",
                "authority":"automation","effects":[if name == "facts" {"probe"} else {"runtime_write"}],
                "targets":["plain"],"execution":{"kind":"ansible_module",
                    "snapshot":text(&snapshot)?,"no_log":no_log},
                "result":result,"limits":{"timeout_secs":12}
            });
            for key in ["input_schema", "fixed_args", "input_map"] {
                binding[key] = overlay[key].clone();
            }
            enabled.push(name);
            tools.insert(name.into(), table(binding)?);
        }
        config.insert("enabled_tools".into(), table(json!(enabled))?);
        config.insert("tools".into(), toml::Value::Table(tools));
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
            "_ansible_no_log",
            "the output has been hidden",
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
            let log = server.log.clone();
            let cleanup = server.stop(None).await;
            self.private(&log.text())?;
            let error = error.context(format!("startup audit: {}", log.text()));
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

// Fixed named setup parameters follow the public setup module contract. The
// selected runtime's real schema import remains authoritative for these types.
// https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/setup_module.html
// stdout/stdout_lines follow the command module's documented return values:
// https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/command_module.html
fn facts_overlay() -> Value {
    json!({
        "input_schema":{"type":"object","properties":{},"additionalProperties":false,
            "maxProperties":0,"const":{}},
        "fixed_args":{"gather_subset":["!all","!min","platform","python_version"],
            "filter":["ansible_system","ansible_python_version"],"gather_timeout":5},
        "input_map":{}
    })
}

fn projection_result(
    fields: Value,
    schema: Value,
    bytes: usize,
    items: usize,
    depth: usize,
) -> Value {
    json!({"kind":"ansible_projection","fields":fields,"schema":schema,
        "max_bytes":bytes,"max_items":items,"max_depth":depth})
}

fn facts_result() -> Value {
    projection_result(
        json!({"platform":["ansible_facts","ansible_system"],
        "python":["ansible_facts","ansible_python_version"]}),
        json!({"type":"object","properties":{"platform":{"type":"string","maxLength":64},
            "python":{"type":"string","maxLength":64}},"required":["platform","python"],
            "additionalProperties":false}),
        1024,
        32,
        4,
    )
}

fn projection_safe_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                ensure!(
                    !key.starts_with('_')
                        && ![
                            "invocation",
                            "module_args",
                            "args",
                            "argv",
                            "cmd",
                            "env",
                            "environment",
                            "ansible_env",
                            "diff",
                            "event_data",
                            "events",
                            "res",
                        ]
                        .contains(&key.as_str()),
                    "private container escaped projection: {key}"
                );
                projection_safe_keys(value)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                projection_safe_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn import_reviewed(
    config: &Path,
    snapshot: &Path,
    module: &str,
    overlay: &Value,
) -> Result<()> {
    let overlay_path = snapshot.with_extension("overlay.json");
    fs::write(&overlay_path, serde_json::to_vec(overlay)?)?;
    let mut command = support::server_command(config)?;
    command
        .args(["schema", "import", module])
        .arg("--output")
        .arg(snapshot)
        .arg("--overlay")
        .arg(overlay_path);
    let output = support::run(&mut command).await?;
    ensure!(
        output.status.success(),
        "real projection schema import failed for {module}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["binding_validated"] == true,
        "projection overlay was not reviewed"
    );
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectedFacts {
    platform: String,
    python: String,
}

fn projected_facts(envelope: &Value) -> Result<ProjectedFacts> {
    projection_safe_keys(envelope)?;
    ensure!(
        envelope["error"].is_null()
            && envelope["data"]["status"] == "successful"
            && envelope["data"]["complete"] == true
            && envelope["data"]["runner_rc"] == 0
            && envelope["data"]["changed"] == false
            && envelope["data"]["tasks"]["ok"] == 1
            && envelope["data"]["projection"]["status"] == "complete",
        "facts projection did not preserve verified successful execution: {envelope}"
    );
    let facts: ProjectedFacts =
        serde_json::from_value(envelope["data"]["projection"]["value"].clone())?;
    ensure!(!facts.platform.is_empty() && facts.platform.len() <= 64);
    ensure!(
        facts.python.split('.').count() == 3
            && facts
                .python
                .split('.')
                .all(|part| part.parse::<u32>().is_ok()),
        "Python fact is not a typed version"
    );
    Ok(facts)
}

fn projection_value_schemas<'a>(node: &'a Value, found: &mut Vec<&'a Value>) {
    match node {
        Value::Object(object) => {
            if let Some(value) = object.get("properties").and_then(|v| v.get("value")) {
                found.push(value);
            }
            for value in object.values() {
                projection_value_schemas(value, found);
            }
        }
        Value::Array(array) => {
            for value in array {
                projection_value_schemas(value, found);
            }
        }
        _ => {}
    }
}

fn verified_command(envelope: &Value) -> Result<()> {
    projection_safe_keys(envelope)?;
    let expected_changed = if envelope["data"]["censored"] == true {
        Value::Null
    } else {
        json!(true)
    };
    ensure!(
        envelope["data"]["status"] == "successful"
            && envelope["data"]["complete"] == true
            && envelope["data"]["changed"] == expected_changed
            && envelope["data"]["runner_rc"] == 0
            && envelope["data"]["tasks"]["ok"] == 1
            && envelope["data"]["tasks"]["failed"] == 0
            && envelope["data"]["owned_group_cleanup"] == "signalled_and_reaped",
        "projection erased authoritative command evidence: {envelope}"
    );
    Ok(())
}

// Pure product-reducer probes complement, rather than replace, real Runner calls.
// The bridge contains no test policy: Rust owns every input and assertion.
async fn projection_reducer_probes(a: &Acceptance) -> Result<()> {
    let interpreter = match &a.runtime {
        RuntimeSource::Bundle(root) => root.join("python/bin/python"),
        RuntimeSource::InstalledLauncher => PathBuf::from(
            std::env::var_os("ESTUS_TEST_WHEEL_BINARY")
                .context("installed launcher for reducer interpreter")?,
        )
        .parent()
        .context("installed launcher scripts directory")?
        .join("python"),
    };
    let interpreter = support::executable(&interpreter)?;
    let source = tempfile::Builder::new()
        .prefix("owned-projection-product-")
        .suffix(".py")
        .tempfile_in(a.fixture.root.path())?;
    source
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    fs::write(source.path(), include_str!("../src/automation_runner.py"))?;
    let bridge = "import json,runpy,sys; module=runpy.run_path(sys.argv[1],run_name='estus_projection_probe'); plan=json.loads(sys.argv[2]); result=json.loads(sys.argv[3]); print(json.dumps(module['Projection'](plan).reduce(result,False)))";
    let cases = [
        (
            projection_result(
                json!({"x":["numbers"]}),
                json!({"type":"object","properties":{"x":{"type":"array",
                    "items":{"type":"number"},"minItems":7,"maxItems":16}},
                    "required":["x"],"additionalProperties":false}),
                64,
                32,
                3,
            ),
            json!({"numbers":vec![0.00001;10]}),
            json!({"status":"truncated","value":{"x":vec![0.00001;7]}}),
        ),
        (
            projection_result(
                json!({"_text":["stdout"]}),
                json!({"type":"object","properties":{"_text":{"type":"string","maxLength":16}},
                    "required":["_text"],"additionalProperties":false}),
                128,
                32,
                3,
            ),
            json!({"stdout":"alias-literal"}),
            json!({"status":"complete","value":{"_text":"alias-literal"}}),
        ),
    ];
    for (mut plan, result, expected) in cases {
        plan.as_object_mut()
            .context("projection plan")?
            .remove("kind");
        let mut command = Command::new(&interpreter);
        command
            .args(["-I", "-c", bridge])
            .arg(source.path())
            .arg(serde_json::to_string(&plan)?)
            .arg(serde_json::to_string(&result)?);
        let output = support::run(&mut command).await?;
        ensure!(
            output.status.success(),
            "actual product reducer probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            observed == expected,
            "product reducer violated selected value contract for {plan}: {observed}"
        );
        ensure!(
            serde_json::to_vec(&observed["value"])?.len()
                <= plan["max_bytes"]
                    .as_u64()
                    .context("projection byte limit")? as usize,
            "Python-selected value exceeded its Rust JSON byte budget: {observed}"
        );
    }
    Ok(())
}

/// Real selected-runtime milestones, without exposing the private Runner stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected pinned Runner/target Python, Nix sshd, non-root private localhost fixture"]
async fn real_runner_progress_setup_acceptance() -> Result<()> {
    let acceptance = Acceptance::start().await?;
    let result: Result<()> = async {
        acceptance.configure_projection().await?;
        runner_progress_setup(&acceptance).await
    }
    .await;
    let cleanup = acceptance.fixture.stop().await;
    result?;
    cleanup
}

async fn runner_progress_setup(a: &Acceptance) -> Result<()> {
    let mut server = a.server().await?;
    let result: Result<()> = async {
        // The same actual module without metadata must remain notification-free.
        server
            .send(
                json!({"jsonrpc":"2.0","id":70,"method":"tools/call","params":{
            "name":"facts","arguments":{"host":"plain","inputs":{}}}}),
            )
            .await?;
        let (baseline, _) = server.frame().await?;
        ensure!(
            baseline["id"] == 70 && baseline["error"].is_null(),
            "no-token setup emitted a notification or failed: {baseline}"
        );
        a.private(&baseline.to_string())?;
        let baseline_facts = projected_facts(&baseline["result"]["structuredContent"])?;
        a.clean()?;

        let token = "runner-progress-private-token-97c2";
        server
            .send(
                json!({"jsonrpc":"2.0","id":71,"method":"tools/call","params":{
            "name":"facts","arguments":{"host":"plain","inputs":{}},
            "_meta":{"progressToken":token}}}),
            )
            .await?;
        let mut previous = None;
        let mut observed_execution = false;
        let response = timeout(WAIT, async {
            loop {
                let (frame, bytes) = server.frame().await?;
                a.private(&frame.to_string())?;
                if frame["id"] == 71 {
                    break Ok::<_, anyhow::Error>(frame);
                }
                ensure!(
                    frame["method"] == "notifications/progress",
                    "unexpected setup frame: {frame}"
                );
                let params = frame["params"].as_object().context("progress parameters")?;
                ensure!(
                    params.len() == 3
                        && params.contains_key("message")
                        && params.contains_key("progress")
                        && params.contains_key("progressToken")
                        && !params.contains_key("total")
                        && bytes <= 512,
                    "progress exposed extra data or exceeded its fixed bound: {frame}"
                );
                ensure!(
                    params["progressToken"] == token,
                    "wrong progress correlation"
                );
                let progress = params["progress"].as_f64().context("milestone ordinal")?;
                ensure!(
                    progress > 0.0
                        && progress <= 3.0
                        && progress.fract() == 0.0
                        && previous.is_none_or(|last| progress > last),
                    "milestones did not strictly increase within the actual stage bound: {frame}"
                );
                previous = Some(progress);
                let message = params["message"].as_str().context("fixed progress label")?;
                ensure!(
                    matches!(
                        message,
                        "Runner started" | "Runner ready" | "Runner task observed"
                    ),
                    "private stream bytes or an unfixed label escaped: {frame}"
                );
                observed_execution |= matches!(message, "Runner ready" | "Runner task observed");
                for private in [
                    "\"kind\"",
                    "\"schema\"",
                    "\"tasks\"",
                    "\"projection\"",
                    "invocation",
                    "runner.lease",
                    "stdout",
                    "stderr",
                ] {
                    ensure!(
                        !frame.to_string().contains(private),
                        "private frame data escaped progress"
                    );
                }
            }
        })
        .await
        .context("selected Runner progress deadline")??;
        ensure!(
            observed_execution,
            "no accepted ready/task milestone reached the client"
        );
        ensure!(
            response["error"].is_null(),
            "token-bearing setup failed: {response}"
        );
        let envelope = &response["result"]["structuredContent"];
        let facts = projected_facts(envelope)?;
        ensure!(
            envelope["error"].is_null()
                && envelope["data"]["owned_group_cleanup"] == "signalled_and_reaped"
                && envelope["data"]["tasks"]["failed"] == 0
                && facts.platform == baseline_facts.platform
                && facts.python == baseline_facts.python,
            "progress changed actual setup evidence: {envelope}"
        );
        ensure!(
            !response.to_string().contains(token),
            "progress token leaked into result"
        );
        a.clean()?;

        // Consume every public frame through a later response, not a filtered receive.
        server
            .send(json!({"jsonrpc":"2.0","id":72,"method":"tools/list","params":{}}))
            .await?;
        loop {
            let (frame, _) = server.frame().await?;
            ensure!(
                frame["method"] != "notifications/progress",
                "progress arrived after the terminal response: {frame}"
            );
            ensure!(
                frame["id"] == 72 && frame["error"].is_null(),
                "unexpected post-terminal frame: {frame}"
            );
            if frame["id"] == 72 {
                break;
            }
        }
        let audit = a.finish(&server.log, 71).await?;
        ensure!(
            !audit.to_string().contains(token) && !server.log.text().contains(token),
            "progress token leaked into audit"
        );
        Ok(())
    }
    .await;
    let cleanup = a.stop(server).await;
    result?;
    cleanup
}

/// Explicit entry: cargo test --test automation_exec real_runner_projection_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected pinned Runner/target Python, Nix sshd, non-root private localhost fixture"]
async fn real_runner_projection_acceptance() -> Result<()> {
    let acceptance = Acceptance::start().await?;
    let result: Result<()> = async {
        acceptance.configure_projection().await?;
        projection_reducer_probes(&acceptance).await?;
        projection_scenarios(&acceptance).await
    }
    .await;
    let cleanup = acceptance.fixture.stop().await;
    result?;
    cleanup
}

async fn projection_scenarios(a: &Acceptance) -> Result<()> {
    let mut server = a.server().await?;
    let result: Result<()> = async {
        let listed = server.request(2, "tools/list", json!({})).await?;
        let config: toml::Value = toml::from_str(&fs::read_to_string(&a.fixture.config)?)?;
        for name in ["facts","text","scalar","lines","items","censored","invalid","unavailable"] {
            let tool = listed["result"]["tools"].as_array().context("projection tool list")?
                .iter().find(|tool| tool["name"] == name).context("published projected tool")?;
            let expected = serde_json::to_value(&config["tools"][name]["result"]["schema"])?;
            let mut schemas = Vec::new();
            projection_value_schemas(&tool["outputSchema"], &mut schemas);
            ensure!(schemas.len() == 2 && schemas.iter().all(|schema| **schema == expected),
                "{name} did not publish exact complete/truncated value schemas: {tool}");
        }
        let summary = a.call(&mut server, 90, "summary",
            a.argv("print('summary-only compatibility')", &[])).await?;
        ensure!(summary["error"].is_null() && summary["data"]["complete"] == true);
        ensure!(!summary["data"].as_object().context("summary data")?.contains_key("projection"),
            "summary-only calls must not acquire a projected result");
        let facts = a.call(&mut server, 3, "facts", json!({"host":"plain","inputs":{}})).await?;
        projected_facts(&facts)?;
        // Observe facts independently over the existing native public tool path.
        let native = server.request(4,"tools/call",json!({"name":"ssh_exec","arguments":{
            "host":"plain","command":format!("{} -I -c 'import platform; print(platform.system()); print(platform.python_version())'",
                support::quote(&text(&a.python)?))}})).await?;
        ensure!(native["error"].is_null());
        let selected = projected_facts(&facts)?;
        ensure!(native["result"]["structuredContent"]["data"]["stdout"]
            == format!("{}\n{}\n", selected.platform, selected.python),
            "setup did not return actual target facts");
        let source = "雪😀 \"quoted\"\nnext\\line\tend";
        let text_reply = a.call(&mut server, 5, "text",
            a.argv("import sys;sys.stdout.write(sys.argv[1])", &[json!(source)])).await?;
        verified_command(&text_reply)?;
        ensure!(text_reply["error"].is_null()
            && text_reply["data"]["projection"] == json!({"status":"complete","value":{"text":source}}),
            "Unicode/quote/control escaping changed selected stdout");
        let long = source.repeat(10);
        let bounded = a.call(&mut server, 6, "scalar",
            a.argv("import sys;sys.stdout.write(sys.argv[1])", &[json!(long)])).await?;
        verified_command(&bounded)?;
        let prefix = bounded["data"]["projection"]["value"]["text"].as_str().context("string prefix")?;
        ensure!(bounded["error"].is_null() && bounded["data"]["projection"]["status"] == "truncated"
            && !prefix.is_empty() && prefix.len() < long.len() && long.starts_with(prefix)
            && prefix.chars().count() <= 256, "scalar was not a schema-valid prefix: {bounded}");
        ensure!(bounded["data"]["projection"]["value"].as_object().context("scalar value")?.len() == 1
            && bounded["data"]["projection"].as_object().context("scalar projection")?.len() == 2,
            "scalar projection included undeclared data");
        // Private frames use ASCII JSON: non-ASCII code points cost one or two \\uXXXX units.
        let encoded = serde_json::to_string(&bounded["data"]["projection"]["value"])?;
        let ascii_bytes: usize = encoded.chars().map(|c| if c.is_ascii() {1} else {6 * c.len_utf16()}).sum();
        ensure!(ascii_bytes <= 64, "escaped projection exceeded configured bytes");
        for (id, name) in [(7,"lines"),(8,"items")] {
            let reply = a.call(&mut server, id, name,
                a.argv("print('雪\\nsecond\\nthird\\nfourth\\nfifth')", &[])).await?;
            verified_command(&reply)?;
            ensure!(reply["error"].is_null()
                && reply["data"]["projection"] == json!({"status":"truncated",
                    "value":{"lines":["雪","second","third"]}}),
                "array prefix violated schema or global item budget: {reply}");
        }
        let censored = a.call(&mut server, 9, "censored",
            a.argv("import sys;print(sys.argv[1])", &[json!(PRIVATE)])).await?;
        verified_command(&censored)?;
        ensure!(censored["error"].is_null() && censored["data"]["censored"] == true
            && censored["data"]["projection"] == json!({"status":"censored"}),
            "no_log must suppress all projected values: {censored}");
        for (id, name, script, status) in [
            (10,"invalid","print('wrong-type')","invalid"),
            (11,"unavailable","print('x' * 800000)","unavailable"),
        ] {
            let reply = a.call(&mut server,id,name,a.argv(script, &[])).await?;
            verified_command(&reply)?;
            ensure!(reply["error"]["code"] == "invalid_result"
                && reply["error"]["remote_state_unknown"] == false
                && reply["data"]["projection"] == json!({"status":status}),
                "projection failure erased successful workflow or fabricated a value: {reply}");
        }
        Ok(())
    }.await;
    // Always send EOF and await shutdown, including failed assertions and calls.
    let cleanup = a.stop(server).await;
    result?;
    cleanup
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

/// Linux FHS target consumer, separate from the unprivileged localhost fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires automation Nix fixture artifact, explicit DOCKER_HOST, Nix Docker CLI and pinned Runner runtime"]
async fn real_runner_isolated_fixture_smoke() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned controller runtime")?,
    )?;
    let private = tempfile::Builder::new()
        .prefix("runner-isolated-private-")
        .tempdir()?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let workspace = private.path().join("workspaces");
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let snapshot = private.path().join("ping-reviewed.json");
    let overlay_path = private.path().join("ping-overlay.json");
    let overlay = json!({
        "input_schema":{"type":"object","properties":{"data":{"type":"string","enum":["pong"]}},
            "required":["data"],"additionalProperties":false,"maxProperties":1},
        "fixed_args":{},"input_map":{"data":"data"}
    });
    fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
    let fixture = isolated::Fixture::start(isolated::ImageKind::Automation).await?;
    let result: Result<()> = async {
        let assert_private = |output: &str| -> Result<()> {
            for secret in [PRIVATE, private.path().to_str().context("private path")?,
                runtime.to_str().context("runtime path")?,
                fixture.config.parent().context("fixture root")?.to_str().context("fixture path")?] {
                ensure!(!output.contains(secret), "isolated summary/audit disclosed private paths or payloads");
            }
            Ok(())
        };
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config.insert("automation".into(), table(json!({"runtime":text(&runtime)?}))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut import = support::server_command(&fixture.config)?;
        import.args(["schema","import","ansible.builtin.ping"])
            .arg("--output").arg(&snapshot).arg("--overlay").arg(&overlay_path);
        let imported = support::run(&mut import).await?;
        ensure!(imported.status.success(), "isolated real schema import failed");
        let report: Value = serde_json::from_slice(&imported.stdout)?;
        ensure!(report["binding_validated"] == true);
        let facts_snapshot = private.path().join("facts-reviewed.json");
        let facts_overlay = facts_overlay();
        import_reviewed(&fixture.config, &facts_snapshot, "ansible.builtin.setup", &facts_overlay).await?;
        config.insert("enabled_tools".into(), table(json!(["isolated_probe","isolated_facts"]))?);
        let mut binding = json!({
            "description":"Explicit pinned Linux fixture probe","revision":"fixture-1",
            "targets":["plain"],"authority":"automation","effects":["probe"],
            "execution":{"kind":"ansible_module","snapshot":text(&snapshot)?,"no_log":false},
            "result":{"kind":"ansible_summary"},"limits":{"timeout_secs":15}
        });
        for key in ["input_schema","fixed_args","input_map"] {
            binding[key] = overlay[key].clone();
        }
        let mut facts_binding = json!({
            "description":"Explicit pinned Linux projected facts","revision":"fixture-1",
            "targets":["plain"],"authority":"automation","effects":["probe"],
            "execution":{"kind":"ansible_module","snapshot":text(&facts_snapshot)?,"no_log":false},
            "result":facts_result(),"limits":{"timeout_secs":15}
        });
        for key in ["input_schema","fixed_args","input_map"] {
            facts_binding[key] = facts_overlay[key].clone();
        }
        config.insert("tools".into(), table(json!({
            "isolated_probe":binding,"isolated_facts":facts_binding
        }))?);
        config["ssh"]
            .as_table_mut()
            .context("fixture SSH table")?
            .insert("executable".into(), text(&fixture.ssh)?.into());
        config.insert("automation".into(), table(json!({
            "required":true,"runtime":text(&runtime)?,"workspace_root":text(&workspace)?,
            "targets":{"plain":{"destination":"plain","python":"/usr/bin/python3"}}
        }))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut server = WireServer::start(&fixture.config)?;
        let calls: Result<Value> = async {
            server.initialize().await?;
            let response = server.request(2,"tools/call",json!({
                "name":"isolated_probe","arguments":{"host":"plain","inputs":{"data":"pong"}}
            })).await?;
            assert_private(&response.to_string())?;
            ensure!(response["error"].is_null(), "isolated MCP call rejected: {response}");
            let envelope = &response["result"]["structuredContent"];
            ensure!(envelope["error"].is_null()
                && envelope["data"]["host"] == "plain"
                && envelope["data"]["status"] == "successful"
                && envelope["data"]["runner_rc"] == 0
                && envelope["data"]["tasks"]["ok"] == 1
                && envelope["data"]["complete"] == true
                && envelope["data"]["owned_group_cleanup"] == "signalled_and_reaped",
                "real isolated Runner probe failed: {response}");
            // Observe the distinct Linux/Python target via the existing native MCP path.
            let native = server.request(3,"tools/call",json!({
                "name":"ssh_exec","arguments":{"host":"plain",
                    "command":"uname -s; /usr/bin/python3 -I -c 'import sys; print(\"%s.%s\" % sys.version_info[:2])'"}
            })).await?;
            let observed = &native["result"]["structuredContent"];
            ensure!(native["error"].is_null() && observed["error"].is_null()
                && observed["data"]["exit_code"] == 0
                && observed["data"]["stdout"] == "Linux\n3.14\n",
                "automation fixture target is not the pinned Linux Python consumer: {native}");
            let projected = server.request(4,"tools/call",json!({
                "name":"isolated_facts","arguments":{"host":"plain","inputs":{}}
            })).await?;
            assert_private(&projected.to_string())?;
            ensure!(projected["error"].is_null(), "isolated projected facts MCP rejection: {projected}");
            let facts = projected_facts(&projected["result"]["structuredContent"])?;
            ensure!(facts.platform == "Linux" && facts.python.starts_with("3.14."),
                "projected facts did not describe the pinned Linux Python 3.14 image");
            ensure!(fs::read_dir(&workspace)?.next().is_none(),
                "isolated Runner workspace survived its response");
            Ok(response)
        }.await;
        // Also on failed assertions: EOF, await shutdown, drain audit, then report failure.
        let stopped = server.stop(None).await;
        let log = stopped?;
        assert_private(&log.text())?;
        let response = calls?;
        assert_private(&response.to_string())?;
        ensure!(fs::read_dir(&workspace)?.next().is_none(),
            "isolated Runner workspace survived shutdown");
        Ok(())
    }.await;
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSummary {
    system: String,
    distribution: Option<String>,
    distribution_version: Option<String>,
    kernel: String,
    architecture: String,
    boot_id: Option<String>,
    uptime_seconds: Option<u64>,
    observed_at: String,
    scope: String,
    virtualization_type: Option<String>,
    virtualization_role: Option<String>,
    unavailable: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSummaryObservation {
    system: String,
    kernel: String,
    architecture: String,
    boot_id: String,
    uptime: f64,
    observed_at: String,
    os_release: Option<std::collections::BTreeMap<String, String>>,
    local_fact_ran: bool,
    uid: u32,
}

// Independent target observations, not Ansible facts or the role's proc parser.
// No caller-controlled script, fact, or path is supplied to the reviewed role.
async fn observe_host_summary(fixture: &isolated::Fixture) -> Result<HostSummaryObservation> {
    let script = r#"
import datetime, json, os, platform
try:
    release = platform.freedesktop_os_release()
except OSError:
    release = None
uname = os.uname()
with open('/proc/sys/kernel/random/boot_id') as source:
    boot_id = source.read().strip()
with open('/proc/uptime') as source:
    uptime = float(source.read().split()[0])
print(json.dumps(dict(system=uname.sysname, kernel=uname.release,
    architecture=uname.machine, boot_id=boot_id, uptime=uptime,
    observed_at=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    os_release=release, local_fact_ran=os.path.exists('/tmp/estus-host-summary-local-ran'),
    uid=os.geteuid())))
"#;
    let output = fixture
        .direct(
            "plain",
            &format!("/usr/bin/python3 -I -c {}", support::quote(script)),
        )
        .await?;
    ensure!(
        output.status.success(),
        "independent host observation failed"
    );
    let observed: HostSummaryObservation = serde_json::from_slice(&output.stdout)?;
    ensure!(
        observed.system == "Linux"
            && observed.uid == 1000
            && observed.uptime.is_finite()
            && observed.uptime > 0.0
            && observed.uptime <= 9_007_199_254_740_991.0
            && !observed.local_fact_ran,
        "ordinary Linux observer/procfs or !local sentinel evidence failed"
    );
    Ok(observed)
}

fn host_summary_schema() -> Value {
    json!({
        "type":"object",
        "properties":{
            "system":{"type":"string","maxLength":64},
            "distribution":{"type":"string","maxLength":128},
            "distribution_version":{"type":"string","maxLength":128},
            "kernel":{"type":"string","maxLength":256},
            "architecture":{"type":"string","maxLength":64},
            "boot_id":{"type":"string","minLength":36,"maxLength":36},
            "uptime_seconds":{"type":"integer","minimum":0,"maximum":9007199254740991_u64},
            "observed_at":{"type":"string","maxLength":32},
            "scope":{"type":"string","const":"ssh_process_view","maxLength":32},
            "virtualization_type":{"type":"string","maxLength":64},
            "virtualization_role":{"type":"string","maxLength":5,"enum":["guest","host"]},
            "unavailable":{"type":"array","maxItems":6,"uniqueItems":true,"items":{"type":"string","maxLength":32,"enum":[
                "distribution","distribution_version","boot_id","uptime_seconds",
                "virtualization_type","virtualization_role"]}}
        },
        "required":["system","kernel","architecture","observed_at","scope","unavailable"],
        "additionalProperties":false
    })
}

fn host_summary_private(bytes: &str, secrets: &[String]) -> Result<()> {
    for secret in secrets {
        ensure!(
            !bytes.contains(secret),
            "host summary discovery/reply/audit disclosed private execution data"
        );
    }
    Ok(())
}

async fn host_summary_session(
    fixture: &isolated::Fixture,
    workspace: &Path,
    secrets: &[String],
    enabled: bool,
) -> Result<()> {
    let mut server = WireServer::start(&fixture.config)?;
    let result: Result<()> = async {
        server.initialize().await?;
        let listed = server.request(2, "tools/list", json!({})).await?;
        host_summary_private(&listed.to_string(), secrets)?;
        let tools = listed["result"]["tools"].as_array().context("host summary tool list")?;
        let tool = tools.iter().find(|tool| tool["name"] == "host_summary");
        if !enabled {
            ensure!(tool.is_none(), "host_summary was enabled without operator opt-in");
            let authentications = fixture.authentication_count().await?;
            let denied = server.request(3, "tools/call", json!({
                "name":"host_summary","arguments":{"host":"plain","inputs":{}}
            })).await?;
            host_summary_private(&denied.to_string(), secrets)?;
            ensure!(
                !denied["error"].is_null()
                    || !denied["result"]["structuredContent"]["error"].is_null(),
                "disabled host_summary executed"
            );
            ensure!(
                fixture.authentication_count().await? == authentications,
                "disabled host_summary reached SSH"
            );
            return Ok(());
        }
        let tool = tool.context("opted-in host_summary discovery")?;
        ensure!(
            tool["inputSchema"]["properties"]["inputs"] == json!({
                "type":"object","properties":{},"required":[],"additionalProperties":false
            }),
            "host_summary exposed caller role parameters: {tool}"
        );
        let mut schemas = Vec::new();
        projection_value_schemas(&tool["outputSchema"], &mut schemas);
        let expected_schema = host_summary_schema();
        ensure!(
            schemas.len() == 2 && schemas.iter().all(|schema| **schema == expected_schema),
            "host_summary did not publish the exact bounded typed output contract: {tool}"
        );
        let authentications = fixture.authentication_count().await?;
        for (index, arguments) in [
            json!({"host":"plain","inputs":[]}),
            json!({"host":"plain","inputs":{"target_python":"/tmp/host-summary-private-override"}}),
            json!({"host":"plain","inputs":{"payload":"HOST_SUMMARY_PRIVATE_OVERRIDE_6b31"}}),
            json!({"host":"plain","inputs":{"gather_subset":["all"]}}),
            json!({"host":"plain","inputs":{"fact_path":"/tmp/host-summary-private-override"}}),
            json!({"host":"plain","inputs":{},"authority":"automation:ops"}),
            json!({"host":"plain","inputs":{},"become":true}),
            json!({"host":"plain","inputs":{},"role_path":"/tmp/host-summary-private-override"}),
            json!({"host":"plain","inputs":{},"target_python":"/tmp/host-summary-private-override"}),
            json!({"host":"plain","inputs":{},"fixed_args":{"target_python":"/tmp/host-summary-private-override"}}),
            json!({"host":"plain","inputs":{},"input_map":{"payload":"target_python"}}),
            json!({"host":"plain","inputs":{},"extra_vars":{"ansible_connection":"local"}}),
            json!({"host":"plain","inputs":{},"ansible_connection":"local"}),
            json!({"host":"plain","inputs":{},"argv":["/tmp/host-summary-private-override"]}),
        ].into_iter().enumerate() {
            let reply = server.request(10 + index as u64, "tools/call", json!({
                "name":"host_summary","arguments":arguments
            })).await?;
            host_summary_private(&reply.to_string(), secrets)?;
            ensure!(
                reply["error"]["code"] == -32602
                    || (reply["result"]["structuredContent"]["error"]["code"] == "invalid_argument"
                        && reply["result"]["structuredContent"]["error"]["remote_state_unknown"] == false),
                "malformed host_summary control reached execution: {reply}"
            );
            ensure!(fs::read_dir(workspace)?.next().is_none(), "rejected call created scratch");
        }
        for host in ["nosftp", "HOST_SUMMARY_UNDECLARED_TARGET_12b8"] {
            let reply = server.request(30 + u64::from(host == "nosftp"), "tools/call", json!({
                "name":"host_summary","arguments":{"host":host,"inputs":{}}
            })).await?;
            host_summary_private(&reply.to_string(), secrets)?;
            let error = &reply["result"]["structuredContent"]["error"];
            ensure!(
                reply["error"]["code"] == -32602
                    || (!error.is_null() && error["remote_state_unknown"] == false),
                "undeclared host_summary target reached execution: {reply}"
            );
        }
        ensure!(
            fixture.authentication_count().await? == authentications,
            "invalid controls or undeclared targets reached SSH"
        );
        let before = observe_host_summary(fixture).await?;
        let response = server.request(40, "tools/call", json!({
            "name":"host_summary","arguments":{"host":"plain","inputs":{}}
        })).await?;
        host_summary_private(&response.to_string(), secrets)?;
        ensure!(response["error"].is_null(), "host_summary MCP rejection: {response}");
        let envelope = &response["result"]["structuredContent"];
        verified_role(envelope, "successful", json!(false))?;
        ensure!(
            envelope["error"].is_null()
                && envelope["data"]["runner_rc"] == 0
                && envelope["data"]["tasks"]["failed"] == 0
                && envelope["data"]["tasks"]["unreachable"] == 0
                && envelope["data"]["host"] == "plain"
                && envelope["data"]["projection"]["status"] == "complete",
            "host_summary lost completion/change/cleanup evidence: {response}"
        );
        ensure!(fs::read_dir(workspace)?.next().is_none(), "workspace survived reply");
        let after = observe_host_summary(fixture).await?;
        let value = &envelope["data"]["projection"]["value"];
        projection_safe_keys(value)?;
        ensure!(
            value.as_object().context("flat host_summary value")?.values().all(|value| !value.is_null())
                && serde_json::to_vec(value)?.len() <= 4096,
            "host_summary projection was not exact and bounded"
        );
        let summary: HostSummary = serde_json::from_value(value.clone())?;
        let missing: BTreeSet<&str> = [
            "distribution", "distribution_version", "boot_id", "uptime_seconds",
            "virtualization_type", "virtualization_role",
        ].into_iter().filter(|field| value.get(*field).is_none()).collect();
        let unavailable: BTreeSet<&str> = summary.unavailable.iter().map(String::as_str).collect();
        ensure!(
            unavailable == missing && unavailable.len() == summary.unavailable.len()
                && summary.unavailable.len() <= 6
                && value.as_object().context("host summary fields")?.len() == 12 - missing.len(),
            "unknown host fields were not omitted and accounted for exactly once"
        );
        ensure!(
            summary.system == before.system && summary.system == after.system
                && summary.kernel == before.kernel && summary.kernel == after.kernel
                && summary.architecture == before.architecture && summary.architecture == after.architecture
                && summary.boot_id.as_deref() == Some(before.boot_id.as_str())
                && before.boot_id == after.boot_id
                && summary.scope == "ssh_process_view",
            "summary disagrees with independent SSH uname/procfs observations"
        );
        let boot_id = summary.boot_id.as_deref().context("real positive boot ID")?;
        ensure!(
            boot_id.len() == 36 && boot_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) { byte == b'-' }
                else { byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) }
            }),
            "boot ID is not canonical"
        );
        let uptime = summary.uptime_seconds.context("real positive proc uptime")?;
        ensure!(
            uptime > 0 && uptime <= 9_007_199_254_740_991
                && before.uptime.floor() as u64 <= uptime
                && uptime <= after.uptime.floor() as u64,
            "summary uptime is outside independent finite SSH observation bounds"
        );
        ensure!(
            summary.observed_at.len() == 20
                && summary.observed_at.ends_with('Z')
                && before.observed_at <= summary.observed_at
                && summary.observed_at <= after.observed_at,
            "collection timestamp is outside target UTC observation bounds"
        );
        if let Some(release) = &before.os_release {
            ensure!(after.os_release.as_ref() == Some(release), "target OS identity changed");
            if let Some(name) = release.get("NAME") {
                ensure!(summary.distribution.as_deref() == Some(name.as_str()),
                    "distribution disagrees with independent os-release NAME");
            }
            if let Some(version) = release.get("VERSION_ID") {
                ensure!(summary.distribution_version.as_deref() == Some(version.as_str()),
                    "distribution version disagrees with independent os-release VERSION_ID");
            }
        }
        for (value, max) in [
            (Some(&summary.system), 64), (summary.distribution.as_ref(), 128),
            (summary.distribution_version.as_ref(), 128), (Some(&summary.kernel), 256),
            (Some(&summary.architecture), 64), (summary.virtualization_type.as_ref(), 64),
        ] {
            ensure!(value.is_none_or(|value| !value.is_empty() && value.chars().count() <= max),
                "host_summary text violates its field bound");
        }
        // Virtualization is an optional setup hint, never an isolation assertion.
        ensure!(
            summary.virtualization_type.as_deref() != Some("NA")
                && matches!(summary.virtualization_role.as_deref(), None | Some("guest" | "host")),
            "unavailable virtualization hint was presented as an attestation"
        );
        Ok(())
    }.await;
    // EOF and awaited shutdown/audit draining also happen on any failed assertion.
    let stopped = server.stop(None).await;
    let log = stopped?;
    host_summary_private(&log.text(), secrets)?;
    ensure!(
        fs::read_dir(workspace)?.next().is_none(),
        "workspace survived shutdown"
    );
    result
}

/// cargo test --test automation_exec real_host_summary_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Automation Nix fixture artifact, explicit DOCKER_HOST and pinned Runner runtime"]
async fn real_host_summary_acceptance() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned controller runtime")?,
    )?;
    let private = tempfile::Builder::new()
        .prefix("host-summary-private-")
        .tempdir()?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let workspace = private.path().join("workspaces");
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let fixture = isolated::Fixture::start(isolated::ImageKind::Automation).await?;
    let result: Result<()> = async {
        // Deploy the shipped role unchanged; only operator-private config paths,
        // selected controller runtime and target alias mapping are adapted.
        let mut example: toml::Value = toml::from_str(include_str!("../examples/host_summary.toml"))?;
        let role = private.path().join("roles/host_summary");
        for (file, source) in [
            ("meta/argument_specs.yml", include_str!("../examples/roles/host_summary/meta/argument_specs.yml")),
            ("tasks/main.yml", include_str!("../examples/roles/host_summary/tasks/main.yml")),
        ] {
            let path = role.join(file);
            fs::create_dir_all(path.parent().context("role asset parent")?)?;
            fs::write(path, source)?;
        }
        let snapshot = private.path().join("host_summary.schema.json");
        let mut overlay = json!({});
        for key in ["input_schema", "fixed_args", "input_map"] {
            overlay[key] = serde_json::to_value(&example["tools"]["host_summary"][key])?;
        }
        let overlay_path = private.path().join("host_summary.overlay.json");
        fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config.insert("automation".into(), table(json!({"runtime":text(&runtime)?}))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut import = support::server_command(&fixture.config)?;
        import.args(["schema", "import-role", "host_summary"])
            .arg("--role-path").arg(&role)
            .arg("--output").arg(&snapshot)
            .arg("--overlay").arg(&overlay_path);
        let imported = support::run(&mut import).await?;
        ensure!(imported.status.success(), "installed host_summary importer failed: {}",
            String::from_utf8_lossy(&imported.stdout));
        let report: Value = serde_json::from_slice(&imported.stdout)?;
        ensure!(report["binding_validated"] == true, "host_summary overlay was not reviewed");
        example["tools"]["host_summary"]["execution"]["snapshot"] = text(&snapshot)?.into();
        example["tools"]["host_summary"]["execution"]["role_path"] = text(&role)?.into();
        example["tools"]["host_summary"]["targets"] = table(json!(["plain"]))?;
        config.insert("tools".into(), example["tools"].clone());
        let mut automation = example["automation"].as_table().context("example automation table")?.clone();
        automation.insert("runtime".into(), text(&runtime)?.into());
        automation.insert("workspace_root".into(), text(&workspace)?.into());
        config["ssh"]
            .as_table_mut()
            .context("fixture SSH table")?
            .insert("executable".into(), text(&fixture.ssh)?.into());
        automation.insert("targets".into(), table(json!({
            "plain":{"destination":"plain","python":"/usr/bin/python3"}
        }))?);
        config.insert("automation".into(), toml::Value::Table(automation));
        config.insert("profile".into(), example["profile"].clone());
        config.insert("enabled_tools".into(), table(json!([]))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        // A real executable custom fact would leave an effect if !local regressed.
        fixture.primary_exec(
            "mkdir -p /etc/ansible/facts.d\ncat > /etc/ansible/facts.d/host_summary_private.fact <<'FACT'\n#!/usr/bin/python3\nfrom pathlib import Path\nPath('/tmp/estus-host-summary-local-ran').touch()\nprint('{\"private\":\"HOST_SUMMARY_LOCAL_FACT_PRIVATE_2c70\"}')\nFACT\nchmod 755 /etc/ansible/facts.d/host_summary_private.fact"
        ).await?;
        let mut secrets = fixture.credential_markers()?;
        secrets.extend([
            text(private.path())?, text(&runtime)?, PRIVATE.into(),
            "/usr/bin/python3".into(), "target_python".into(),
            "/tmp/host-summary-private-override".into(),
            "HOST_SUMMARY_PRIVATE_OVERRIDE_6b31".into(),
            "HOST_SUMMARY_UNDECLARED_TARGET_12b8".into(),
            "HOST_SUMMARY_LOCAL_FACT_PRIVATE_2c70".into(),
            "ansible_facts".into(), "event_data".into(), "Traceback".into(),
        ]);
        host_summary_session(&fixture, &workspace, &secrets, false).await?;
        config.insert("enabled_tools".into(), example["enabled_tools"].clone());
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        host_summary_session(&fixture, &workspace, &secrets, true).await
    }.await;
    // Always await both container removals, including import/protocol/assertion failures.
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

const CPU_FIELDS: [&str; 10] = [
    "user",
    "nice",
    "system",
    "idle",
    "iowait",
    "irq",
    "softirq",
    "steal",
    "guest",
    "guest_nice",
];
const CPU_JSON_MAX: u64 = 9_007_199_254_740_991;

struct CpuObservation {
    counters: Vec<u64>,
    ids: Vec<u64>,
    hz: u64,
    boot: Option<String>,
    utc: String,
    topology: std::collections::BTreeMap<u64, [Option<u64>; 2]>,
}

// Direct SSH returns raw kernel text. Parsing and all comparisons happen here,
// independently of Ansible and the shipped Python collector.
async fn observe_cpu_stats(fixture: &isolated::Fixture) -> Result<CpuObservation> {
    // The fixture already supplies target Python, but not awk/getconf. This
    // independent observer returns raw file text; Rust parses the observations.
    let script = r#"
import datetime, os, sys
print('UTC')
print(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
print('UID')
print(os.geteuid())
print('HZ')
print(os.sysconf('SC_CLK_TCK'))
print('BOOT')
try:
    with open('/proc/sys/kernel/random/boot_id') as source:
        print(source.read(128).strip())
except OSError:
    print()
print('\nSTAT')
labels = []
with open('/proc/stat') as source:
    for line in source:
        if not line.startswith('cpu'):
            break
        sys.stdout.write(line)
        label = line.split()[0]
        if label != 'cpu':
            labels.append(label[3:])
print('TOPOLOGY')
for label in labels[:16]:
    for field in ('physical_package_id', 'core_id'):
        print(label, end=' ')
        try:
            with open('/sys/devices/system/cpu/cpu%s/topology/%s' % (label, field)) as source:
                print(source.read(128).strip())
        except OSError:
            print('missing')
"#;
    let output = fixture
        .direct(
            "plain",
            &format!("/usr/bin/python3 -I -c {}", support::quote(script),),
        )
        .await?;
    ensure!(
        output.status.success(),
        "independent CPU SSH observation failed"
    );
    let raw = std::str::from_utf8(&output.stdout)?;
    let (header, rest) = raw.split_once("\nSTAT\n").context("raw proc/stat marker")?;
    let (stat, topology) = rest.split_once("TOPOLOGY\n").context("raw sysfs marker")?;
    let mut header = header.lines();
    ensure!(header.next() == Some("UTC"), "raw UTC marker");
    let utc = header.next().context("raw UTC")?.to_owned();
    ensure!(
        header.next() == Some("UID") && header.next() == Some("1000"),
        "CPU observer did not use ordinary SSH authority"
    );
    ensure!(header.next() == Some("HZ"), "raw HZ marker");
    let hz: u64 = header.next().context("raw HZ")?.parse()?;
    ensure!(
        (1..=1_000_000).contains(&hz),
        "independent HZ outside bounds"
    );
    ensure!(header.next() == Some("BOOT"), "raw boot marker");
    let boot = header
        .next()
        .filter(|line| !line.is_empty())
        .map(str::to_owned);
    if let Some(boot) = &boot {
        ensure!(
            boot.len() == 36
                && boot.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                    }
                }),
            "independent boot ID is not canonical"
        );
    }
    let mut lines = stat.lines();
    let mut aggregate = lines
        .next()
        .context("raw aggregate CPU row")?
        .split_whitespace();
    ensure!(aggregate.next() == Some("cpu"), "raw aggregate CPU label");
    let counters = aggregate
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        counters.len() == 10 && counters.iter().all(|n| *n <= CPU_JSON_MAX),
        "independent aggregate counters are incomplete or unbounded"
    );
    let mut ids = Vec::new();
    for row in lines {
        let label = row.split_whitespace().next().context("raw CPU row label")?;
        ids.push(
            label
                .strip_prefix("cpu")
                .context("raw CPU prefix")?
                .parse::<u64>()?,
        );
    }
    ids.sort_unstable();
    ensure!(
        !ids.is_empty()
            && ids.len() <= 4096
            && ids.iter().all(|id| *id <= 262143)
            && ids.windows(2).all(|pair| pair[0] < pair[1]),
        "raw CPU IDs are invalid"
    );
    let rows: Vec<&str> = topology.lines().collect();
    ensure!(
        rows.len() == ids.len().min(16) * 2,
        "raw topology rows missing"
    );
    let mut topology = std::collections::BTreeMap::new();
    for (id, rows) in ids.iter().take(16).zip(rows.as_chunks::<2>().0) {
        let mut fields = [None, None];
        for (index, row) in rows.iter().enumerate() {
            let (label, value) = row.split_once(' ').context("raw topology delimiter")?;
            ensure!(label.parse::<u64>()? == *id, "raw topology CPU mismatch");
            if value != "missing" {
                let value: i64 = value.trim().parse()?;
                if value >= 0 {
                    ensure!(value <= 2_147_483_647, "raw topology ID outside bounds");
                    fields[index] = Some(value as u64);
                }
            }
        }
        topology.insert(*id, fields);
    }
    Ok(CpuObservation {
        counters,
        ids,
        hz,
        boot,
        utc,
        topology,
    })
}

fn cpu_counters(value: &Value) -> Result<Vec<u64>> {
    let object = value.as_object().context("typed CPU counters object")?;
    ensure!(
        object.len() == CPU_FIELDS.len(),
        "CPU counters added rates or omitted raw fields"
    );
    CPU_FIELDS
        .iter()
        .map(|field| {
            let counter = object
                .get(*field)
                .and_then(Value::as_u64)
                .context("integer CPU counter")?;
            ensure!(
                counter <= CPU_JSON_MAX,
                "CPU counter exceeds JSON-safe bound"
            );
            Ok(counter)
        })
        .collect()
}

fn assert_cpu_stats(
    value: &Value,
    before: &CpuObservation,
    after: &CpuObservation,
    sample_ms: u64,
    limit: usize,
) -> Result<()> {
    let object = value.as_object().context("CPU projection object")?;
    ensure!(
        object.values().all(|v| !v.is_null()) && serde_json::to_vec(value)?.len() <= 4096,
        "CPU projection contains nulls or exceeds byte bound"
    );
    let required = [
        "system",
        "scope",
        "observed_at",
        "clock_ticks_per_second",
        "online_cpu_count",
        "counters",
        "topology",
        "topology_truncated",
        "unavailable",
    ];
    let optional = [
        "boot_id",
        "sample_elapsed_ns",
        "counters_end",
        "delta",
        "counter_decrease",
        "identity_changed",
    ];
    ensure!(
        required.iter().all(|key| object.contains_key(*key))
            && object
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())),
        "CPU projection fields differ from the observation contract"
    );
    ensure!(
        value["system"] == "Linux" && value["scope"] == "procfs_sysfs_view",
        "CPU view was misrepresented as host isolation or utilization"
    );
    ensure!(
        before.ids == after.ids && before.boot == after.boot && before.hz == after.hz,
        "independent CPU identities changed during acceptance"
    );
    ensure!(
        value["clock_ticks_per_second"] == before.hz
            && value["online_cpu_count"] == before.ids.len()
            && value.get("boot_id").and_then(Value::as_str) == before.boot.as_deref(),
        "CPU HZ, boot identity, or global logical count disagrees with independent SSH"
    );
    let observed = value["observed_at"].as_str().context("CPU UTC timestamp")?;
    ensure!(
        observed.is_ascii()
            && observed.len() >= 20
            && observed.len() <= 32
            && observed.ends_with('Z')
            && observed.as_bytes().get(10) == Some(&b'T')
            && before.utc[..19] <= observed[..19]
            && observed[..19] <= after.utc[..19],
        "CPU observation timestamp falls outside independent UTC bounds"
    );
    let start = cpu_counters(&value["counters"])?;
    if sample_ms == 0 {
        for field in [
            "sample_elapsed_ns",
            "counters_end",
            "delta",
            "counter_decrease",
            "identity_changed",
        ] {
            ensure!(
                !object.contains_key(field),
                "default CPU observation unexpectedly sampled: {field}"
            );
        }
    } else {
        let elapsed = value["sample_elapsed_ns"]
            .as_u64()
            .context("actual CPU sample elapsed")?;
        ensure!(
            (sample_ms * 1_000_000..=CPU_JSON_MAX).contains(&elapsed),
            "CPU sampling used requested duration instead of actual elapsed time"
        );
    }
    let finish = if sample_ms > 0 {
        Some(cpu_counters(&value["counters_end"])?)
    } else {
        None
    };
    for counters in [Some(&start), finish.as_ref()].into_iter().flatten() {
        for (index, field) in CPU_FIELDS.iter().enumerate() {
            // Linux explicitly allows iowait to decrease; never treat it as a reset.
            if *field != "iowait" {
                ensure!(
                    before.counters[index] <= counters[index]
                        && counters[index] <= after.counters[index],
                    "raw {field} counter is outside independent before/after bounds"
                );
            }
        }
    }
    let mut missing = BTreeSet::new();
    if before.boot.is_none() {
        missing.insert("boot_id");
    }
    if let Some(finish) = finish {
        let decrease = start.iter().zip(&finish).any(|(a, b)| b < a);
        ensure!(
            value["counter_decrease"] == decrease && value["identity_changed"] == false,
            "CPU decrease was clamped or confused with a confirmed identity change"
        );
        if !decrease && before.boot.is_some() {
            let delta = cpu_counters(&value["delta"])?;
            for (index, field) in CPU_FIELDS.iter().enumerate() {
                ensure!(
                    delta[index] == finish[index] - start[index],
                    "raw {field} delta differs from the two published observations"
                );
            }
        } else {
            ensure!(
                !object.contains_key("delta"),
                "CPU delta survived unknown identity or counter decrease"
            );
            missing.insert("delta");
        }
    }
    let unavailable = value["unavailable"]
        .as_array()
        .context("CPU unavailable fields")?;
    let actual: BTreeSet<&str> = unavailable
        .iter()
        .map(|v| v.as_str().context("CPU unavailable name"))
        .collect::<Result<_>>()?;
    ensure!(
        actual == missing && actual.len() == unavailable.len() && actual.len() <= 2,
        "CPU unavailable/omission semantics disagree"
    );
    let rows = value["topology"].as_array().context("CPU topology array")?;
    ensure!(
        rows.len() == before.ids.len().min(limit)
            && rows.len() <= 16
            && value["topology_truncated"] == (before.ids.len() > limit),
        "CPU topology limit or truncation is incorrect"
    );
    for (row, id) in rows.iter().zip(&before.ids) {
        let row_object = row.as_object().context("CPU topology object")?;
        ensure!(
            row["cpu_id"] == *id
                && row_object
                    .keys()
                    .all(|key| ["cpu_id", "package_id", "core_id", "unavailable"]
                        .contains(&key.as_str())),
            "CPU topology is not the sorted logical-ID prefix"
        );
        let raw = before
            .topology
            .get(id)
            .context("independent topology CPU")?;
        ensure!(
            after.topology.get(id) == Some(raw),
            "independent topology changed"
        );
        let mut missing = BTreeSet::new();
        for (index, field) in ["package_id", "core_id"].iter().enumerate() {
            ensure!(
                row.get(*field).and_then(Value::as_u64) == raw[index],
                "raw sysfs {field} was reinterpreted or omitted"
            );
            if raw[index].is_none() {
                ensure!(
                    row.get(*field).is_none(),
                    "unavailable topology ID was not omitted"
                );
                missing.insert(*field);
            }
        }
        let unavailable = row["unavailable"]
            .as_array()
            .context("topology unavailable array")?;
        let actual: BTreeSet<&str> = unavailable
            .iter()
            .map(|v| v.as_str().context("topology unavailable name"))
            .collect::<Result<_>>()?;
        ensure!(
            actual == missing && actual.len() == unavailable.len() && actual.len() <= 2,
            "topology unavailable semantics disagree"
        );
    }
    Ok(())
}

async fn cpu_stats_session(
    fixture: &isolated::Fixture,
    workspace: &Path,
    secrets: &[String],
    enabled: bool,
) -> Result<()> {
    let mut server = WireServer::start(&fixture.config)?;
    let result: Result<()> = async {
        server.initialize().await?;
        let listed = server.request(2, "tools/list", json!({})).await?;
        host_summary_private(&listed.to_string(), secrets)?;
        let tools = listed["result"]["tools"]
            .as_array()
            .context("CPU tool discovery")?;
        let tool = tools.iter().find(|tool| tool["name"] == "cpu_stats");
        if !enabled {
            ensure!(tool.is_none(), "CPU tool enabled without opt-in");
            let auth = fixture.authentication_count().await?;
            let reply = server
                .request(
                    3,
                    "tools/call",
                    json!({
                        "name":"cpu_stats","arguments":{"host":"plain","inputs":{}}
                    }),
                )
                .await?;
            host_summary_private(&reply.to_string(), secrets)?;
            ensure!(
                !reply["error"].is_null()
                    || !reply["result"]["structuredContent"]["error"].is_null(),
                "disabled CPU tool executed"
            );
            ensure!(
                fixture.authentication_count().await? == auth
                    && fs::read_dir(workspace)?.next().is_none(),
                "disabled CPU tool reached SSH or scratch"
            );
            return Ok(());
        }
        let tool = tool.context("opted-in CPU tool")?;
        let inputs = &tool["inputSchema"]["properties"]["inputs"];
        for (name, min, max) in [("limit", 1, 16), ("sample_ms", 0, 2000)] {
            let field = &inputs["properties"][name];
            ensure!(
                field["type"] == "integer" && field["minimum"] == min && field["maximum"] == max,
                "CPU advertised {name} bounds are missing"
            );
        }
        ensure!(
            inputs["additionalProperties"] == false,
            "CPU inputs allow undeclared controls"
        );
        let mut schemas = Vec::new();
        projection_value_schemas(&tool["outputSchema"], &mut schemas);
        ensure!(!schemas.is_empty(), "CPU output discovery is untyped");
        for schema in schemas {
            let fields = &schema["properties"];
            ensure!(
                schema["type"] == "object" && schema["additionalProperties"] == false,
                "CPU output discovery is not a closed object"
            );
            for (name, min, max) in [
                ("clock_ticks_per_second", 1, 1_000_000),
                ("online_cpu_count", 1, 4096),
                ("sample_elapsed_ns", 1, CPU_JSON_MAX),
            ] {
                ensure!(
                    fields[name]["type"] == "integer"
                        && fields[name]["minimum"] == min
                        && fields[name]["maximum"] == max,
                    "CPU advertised {name} bound is missing"
                );
            }
            for (name, max) in [
                ("system", 64),
                ("scope", 32),
                ("observed_at", 32),
                ("boot_id", 36),
            ] {
                ensure!(
                    fields[name]["type"] == "string" && fields[name]["maxLength"] == max,
                    "CPU advertised {name} string bound is missing"
                );
            }
            ensure!(
                fields["boot_id"]["minLength"] == 36,
                "CPU boot identity is unbounded"
            );
            for name in ["topology_truncated", "counter_decrease", "identity_changed"] {
                ensure!(
                    fields[name]["type"] == "boolean",
                    "CPU advertised {name} flag is untyped"
                );
            }
            for name in ["counters", "counters_end", "delta"] {
                let counters = &fields[name];
                ensure!(
                    counters["type"] == "object" && counters["additionalProperties"] == false,
                    "CPU advertised {name} is not a closed counter object"
                );
                let required = counters["required"]
                    .as_array()
                    .context("required raw CPU fields")?;
                for field in CPU_FIELDS {
                    ensure!(
                        counters["properties"][field]["type"] == "integer"
                            && counters["properties"][field]["minimum"] == 0
                            && counters["properties"][field]["maximum"] == CPU_JSON_MAX
                            && required.contains(&json!(field)),
                        "CPU advertised {name}.{field} bounds are missing"
                    );
                }
            }
            let topology = &fields["topology"];
            let row = &topology["items"];
            ensure!(
                topology["type"] == "array"
                    && topology["maxItems"] == 16
                    && row["type"] == "object"
                    && row["additionalProperties"] == false,
                "CPU advertised topology is not bounded and typed"
            );
            for (name, max) in [
                ("cpu_id", 262143),
                ("package_id", 2_147_483_647),
                ("core_id", 2_147_483_647),
            ] {
                ensure!(
                    row["properties"][name]["type"] == "integer"
                        && row["properties"][name]["minimum"] == 0
                        && row["properties"][name]["maximum"] == max,
                    "CPU advertised topology {name} bound is missing"
                );
            }
            for unavailable in [&fields["unavailable"], &row["properties"]["unavailable"]] {
                ensure!(
                    unavailable["type"] == "array"
                        && unavailable["maxItems"] == 2
                        && unavailable["uniqueItems"] == true
                        && unavailable["items"]["type"] == "string"
                        && unavailable["items"]["maxLength"] == 16,
                    "CPU advertised unavailable fields are unbounded"
                );
            }
        }
        let auth = fixture.authentication_count().await?;
        let mut invalid = Vec::new();
        for inputs in [
            json!([]),
            json!({"limit":0}),
            json!({"limit":17}),
            json!({"limit":1.5}),
            json!({"limit":"2"}),
            json!({"limit":true}),
            json!({"limit":null}),
            json!({"sample_ms":-1}),
            json!({"sample_ms":2001}),
            json!({"sample_ms":0.5}),
            json!({"sample_ms":"100"}),
            json!({"sample_ms":false}),
            json!({"sample_ms":null}),
            json!({"target_python":"/tmp/CPU_PRIVATE_OVERRIDE_1d37"}),
            json!({"extra_vars":{"ansible_connection":"local"}}),
            json!({"ansible_ssh_common_args":"CPU_PRIVATE_OVERRIDE_1d37"}),
            json!({"transport":{"destination":"CPU_UNDECLARED_TARGET_5e61"}}),
            json!({"retain_output":true}),
            json!({"environment":{"CPU_PRIVATE_OVERRIDE_1d37":"1"}}),
        ] {
            invalid.push(json!({"host":"plain","inputs":inputs}));
        }
        for extra in [
            json!({"authority":"automation:ops"}),
            json!({"become":true}),
            json!({"retention":"keep"}),
            json!({"retain_workspace":true}),
            json!({"retain_output":true}),
            json!({"extra_vars":{"ansible_connection":"local"}}),
            json!({"role_path":"/tmp/CPU_PRIVATE_OVERRIDE_1d37"}),
            json!({"transport":{"destination":"CPU_UNDECLARED_TARGET_5e61"}}),
            json!({"runtime":"/tmp/CPU_PRIVATE_OVERRIDE_1d37"}),
        ] {
            let mut arguments = json!({"host":"plain","inputs":{}});
            arguments
                .as_object_mut()
                .context("CPU rejected controls")?
                .extend(extra.as_object().context("CPU extra controls")?.clone());
            invalid.push(arguments);
        }
        for host in ["nosftp", "CPU_UNDECLARED_TARGET_5e61"] {
            invalid.push(json!({"host":host,"inputs":{}}));
        }
        for (index, arguments) in invalid.into_iter().enumerate() {
            let reply = server
                .request(
                    10 + index as u64,
                    "tools/call",
                    json!({"name":"cpu_stats","arguments":arguments}),
                )
                .await?;
            host_summary_private(&reply.to_string(), secrets)?;
            let error = &reply["result"]["structuredContent"]["error"];
            ensure!(
                reply["error"]["code"] == -32602
                    || (!error.is_null() && error["remote_state_unknown"] == false),
                "invalid CPU controls or target reached execution: {reply}"
            );
            ensure!(
                fs::read_dir(workspace)?.next().is_none(),
                "invalid CPU call created scratch"
            );
        }
        ensure!(
            fixture.authentication_count().await? == auth,
            "invalid CPU call reached SSH"
        );
        for (id, inputs, sample_ms, limit) in [
            (100, json!({}), 0, 8),
            (101, json!({"sample_ms":100,"limit":2}), 100, 2),
        ] {
            let before = observe_cpu_stats(fixture).await?;
            let reply = server
                .request(
                    id,
                    "tools/call",
                    json!({"name":"cpu_stats","arguments":{"host":"plain","inputs":inputs}}),
                )
                .await?;
            host_summary_private(&reply.to_string(), secrets)?;
            ensure!(reply["error"].is_null(), "CPU MCP call rejected: {reply}");
            let envelope = &reply["result"]["structuredContent"];
            verified_role(envelope, "successful", json!(false))?;
            ensure!(
                envelope["error"].is_null()
                    && envelope["data"]["runner_rc"] == 0
                    && envelope["data"]["tasks"]["failed"] == 0
                    && envelope["data"]["tasks"]["unreachable"] == 0
                    && envelope["data"]["host"] == "plain"
                    && envelope["data"]["projection"]["status"] == "complete",
                "ordinary CPU observation lost completion/change/cleanup evidence: {reply}"
            );
            ensure!(
                envelope["data"].get("stdout").is_none()
                    && envelope["data"].get("stderr").is_none(),
                "CPU observation exposed raw command streams"
            );
            ensure!(
                fs::read_dir(workspace)?.next().is_none(),
                "CPU workspace survived completion"
            );
            let after = observe_cpu_stats(fixture).await?;
            let value = &envelope["data"]["projection"]["value"];
            projection_safe_keys(value)?;
            assert_cpu_stats(value, &before, &after, sample_ms, limit)?;
        }
        Ok(())
    }
    .await;
    // Drain audit and await the owned process group even when an assertion fails.
    let stopped = server.stop(None).await;
    let log = stopped?;
    host_summary_private(&log.text(), secrets)?;
    ensure!(
        fs::read_dir(workspace)?.next().is_none(),
        "CPU workspace survived shutdown"
    );
    result
}

/// cargo test --test automation_exec real_cpu_stats_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Automation Nix fixture artifact, explicit DOCKER_HOST and pinned Runner runtime"]
async fn real_cpu_stats_acceptance() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned controller runtime")?,
    )?;
    let private = tempfile::Builder::new()
        .prefix("cpu-stats-private-")
        .tempdir()?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let workspace = private.path().join("workspaces");
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let fixture = isolated::Fixture::start(isolated::ImageKind::Automation).await?;
    let result: Result<()> = async {
        let mut example: toml::Value = toml::from_str(include_str!("../examples/cpu_stats.toml"))?;
        let role = private.path().join("roles/cpu_stats");
        for (file, source) in [
            (
                "meta/argument_specs.yml",
                include_str!("../examples/roles/cpu_stats/meta/argument_specs.yml"),
            ),
            (
                "tasks/main.yml",
                include_str!("../examples/roles/cpu_stats/tasks/main.yml"),
            ),
        ] {
            let path = role.join(file);
            fs::create_dir_all(path.parent().context("CPU role asset parent")?)?;
            fs::write(path, source)?;
        }
        let snapshot = private.path().join("cpu_stats.schema.json");
        let mut overlay = json!({});
        for key in ["input_schema", "fixed_args", "input_map"] {
            overlay[key] = serde_json::to_value(&example["tools"]["cpu_stats"][key])?;
        }
        let overlay_path = private.path().join("cpu_stats.overlay.json");
        fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config.insert(
            "automation".into(),
            table(json!({"runtime":text(&runtime)?}))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut import = support::server_command(&fixture.config)?;
        import
            .args(["schema", "import-role", "cpu_stats"])
            .arg("--role-path")
            .arg(&role)
            .arg("--output")
            .arg(&snapshot)
            .arg("--overlay")
            .arg(&overlay_path);
        let imported = support::run(&mut import).await?;
        ensure!(
            imported.status.success(),
            "installed CPU importer failed: {}",
            String::from_utf8_lossy(&imported.stdout)
        );
        let report: Value = serde_json::from_slice(&imported.stdout)?;
        ensure!(
            report["binding_validated"] == true,
            "CPU role overlay was not reviewed"
        );
        let tool = example["tools"]["cpu_stats"]
            .as_table_mut()
            .context("CPU binding table")?;
        let execution = tool
            .get_mut("execution")
            .and_then(toml::Value::as_table_mut)
            .context("CPU execution table")?;
        execution.insert("snapshot".into(), text(&snapshot)?.into());
        execution.insert("role_path".into(), text(&role)?.into());
        tool.insert("targets".into(), table(json!(["plain"]))?);
        config.insert("tools".into(), example["tools"].clone());
        let mut automation = example["automation"]
            .as_table()
            .context("CPU automation table")?
            .clone();
        automation.insert("runtime".into(), text(&runtime)?.into());
        automation.insert("workspace_root".into(), text(&workspace)?.into());
        config["ssh"]
            .as_table_mut()
            .context("fixture SSH table")?
            .insert("executable".into(), text(&fixture.ssh)?.into());
        automation.insert(
            "targets".into(),
            table(json!({
                "plain":{"destination":"plain","python":"/usr/bin/python3"}
            }))?,
        );
        config.insert("automation".into(), toml::Value::Table(automation));
        config.insert("profile".into(), example["profile"].clone());
        config.insert("enabled_tools".into(), table(json!([]))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut secrets = fixture.credential_markers()?;
        secrets.extend([
            text(private.path())?,
            text(&runtime)?,
            PRIVATE.into(),
            "/usr/bin/python3".into(),
            "target_python".into(),
            "/proc/stat".into(),
            "/sys/devices/system/cpu".into(),
            "/proc/sys/kernel/random/boot_id".into(),
            "SC_CLK_TCK".into(),
            "CPU_PRIVATE_OVERRIDE_1d37".into(),
            "CPU_UNDECLARED_TARGET_5e61".into(),
            "event_data".into(),
            "Traceback".into(),
        ]);
        cpu_stats_session(&fixture, &workspace, &secrets, false).await?;
        config.insert("enabled_tools".into(), example["enabled_tools"].clone());
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        cpu_stats_session(&fixture, &workspace, &secrets, true).await
    }
    .await;
    // Container removal is awaited after import, MCP, and assertion failures too.
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

const MEMORY_FIELDS: [(&str, &str); 12] = [
    ("mem_total_bytes", "MemTotal"),
    ("mem_free_bytes", "MemFree"),
    ("mem_available_bytes", "MemAvailable"),
    ("buffers_bytes", "Buffers"),
    ("cached_bytes", "Cached"),
    ("swap_total_bytes", "SwapTotal"),
    ("swap_free_bytes", "SwapFree"),
    ("dirty_bytes", "Dirty"),
    ("writeback_bytes", "Writeback"),
    ("slab_bytes", "Slab"),
    ("sreclaimable_bytes", "SReclaimable"),
    ("sunreclaim_bytes", "SUnreclaim"),
];
const MEMORY_VM_FIELDS: [(&str, &str); 7] = [
    ("page_faults", "pgfault"),
    ("major_page_faults", "pgmajfault"),
    ("swap_in_pages", "pswpin"),
    ("swap_out_pages", "pswpout"),
    ("oom_kill_events", "oom_kill"),
    ("kswapd_scan_pages", "pgscan_kswapd"),
    ("direct_scan_pages", "pgscan_direct"),
];
const MEMORY_JSON_MAX: u64 = 9_007_199_254_740_991;

struct MemoryObservation {
    memory_kib: std::collections::BTreeMap<String, u64>,
    vm: std::collections::BTreeMap<String, u64>,
    page_size: u64,
    physical_pages: u64,
    boot: Option<String>,
    utc: String,
}

// This ordinary SSH observer only transports raw files and OS API results.
// The oracle parses kernel text in Rust, not through the production collector.
async fn observe_memory_stats(fixture: &isolated::Fixture) -> Result<MemoryObservation> {
    let script = r#"
import datetime, json, os
def raw(path):
    try:
        with open(path, 'r', encoding='ascii') as source:
            return source.read()
    except OSError:
        return None
print(json.dumps({
    'meminfo': raw('/proc/meminfo'),
    'vmstat': raw('/proc/vmstat'),
    'boot': raw('/proc/sys/kernel/random/boot_id'),
    'page_size': os.sysconf('SC_PAGE_SIZE'),
    'physical_pages': os.sysconf('SC_PHYS_PAGES'),
    'uid': os.geteuid(),
    'utc': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
}))
"#;
    let output = fixture
        .direct(
            "plain",
            &format!("/usr/bin/python3 -I -c {}", support::quote(script)),
        )
        .await?;
    ensure!(
        output.status.success(),
        "independent memory SSH observer failed"
    );
    let raw: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        raw["uid"] == 1000,
        "memory observer used non-ordinary authority"
    );
    let page_size = raw["page_size"].as_u64().context("independent page size")?;
    ensure!(
        (1..=1_048_576).contains(&page_size),
        "independent page size outside bounds"
    );
    let physical_pages = raw["physical_pages"]
        .as_u64()
        .context("independent physical-page count")?;
    ensure!(
        physical_pages > 0,
        "independent physical-page count must be positive"
    );
    let boot = raw["boot"].as_str().map(|s| s.trim().to_owned());
    if let Some(boot) = &boot {
        ensure!(
            boot.len() == 36
                && boot.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                    }
                }),
            "independent memory boot identity is not canonical"
        );
    }
    let meminfo = raw["meminfo"].as_str().context("independent raw meminfo")?;
    ensure!(
        meminfo.len() <= 131_072 && meminfo.lines().count() <= 4096,
        "raw meminfo bounds"
    );
    let mut memory_kib = std::collections::BTreeMap::new();
    for line in meminfo.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        if let Some((alias, _)) = MEMORY_FIELDS.iter().find(|(_, source)| *source == key) {
            let tokens: Vec<_> = rest.split_ascii_whitespace().collect();
            ensure!(
                line.len() <= 4096
                    && tokens.len() == 2
                    && tokens[1] == "kB"
                    && !tokens[0].is_empty()
                    && tokens[0].bytes().all(|b| b.is_ascii_digit()),
                "independent selected meminfo field has invalid units or shape: {key}"
            );
            let kib: u64 = tokens[0].parse()?;
            ensure!(
                kib <= MEMORY_JSON_MAX / 1024,
                "independent memory integer bound"
            );
            ensure!(
                memory_kib.insert((*alias).to_owned(), kib).is_none(),
                "duplicate raw memory field"
            );
        }
    }
    ensure!(
        memory_kib.get("mem_total_bytes").is_some_and(|n| *n > 0)
            && memory_kib.contains_key("mem_free_bytes"),
        "independent required memory fields absent"
    );
    let mut vm = std::collections::BTreeMap::new();
    if let Some(vmstat) = raw["vmstat"].as_str() {
        ensure!(
            vmstat.len() <= 262_144 && vmstat.lines().count() <= 4096,
            "raw vmstat bounds"
        );
        for line in vmstat.lines() {
            let mut tokens = line.split_ascii_whitespace();
            let Some(key) = tokens.next() else { continue };
            if let Some((alias, _)) = MEMORY_VM_FIELDS.iter().find(|(_, source)| *source == key) {
                let digits = tokens.next().context("independent VM counter digits")?;
                ensure!(
                    line.len() <= 4096
                        && tokens.next().is_none()
                        && digits.bytes().all(|b| b.is_ascii_digit()),
                    "independent VM counter shape"
                );
                let count: u64 = digits.parse()?;
                ensure!(count <= MEMORY_JSON_MAX, "independent VM counter bound");
                ensure!(
                    vm.insert((*alias).to_owned(), count).is_none(),
                    "duplicate raw VM counter"
                );
            }
        }
    }
    Ok(MemoryObservation {
        memory_kib,
        vm,
        page_size,
        physical_pages,
        boot,
        utc: raw["utc"]
            .as_str()
            .context("independent memory UTC")?
            .to_owned(),
    })
}

fn assert_memory_stats(
    value: &Value,
    before: &MemoryObservation,
    after: &MemoryObservation,
) -> Result<()> {
    let object = value.as_object().context("typed memory observation")?;
    let required = [
        "system",
        "scope",
        "observed_at",
        "page_size_bytes",
        "memory_bytes",
        "vm_counters",
        "unavailable",
    ];
    ensure!(
        required.iter().all(|key| object.contains_key(*key))
            && object
                .keys()
                .all(|key| required.contains(&key.as_str()) || key == "boot_id")
            && object.values().all(|v| !v.is_null())
            && serde_json::to_vec(value)?.len() <= 4096,
        "memory root is incomplete, unbounded, or contains undeclared fields"
    );
    ensure!(
        value["system"] == "Linux" && value["scope"] == "procfs_view",
        "memory observation misrepresents non-atomic procfs gauges as effective container allowance"
    );
    ensure!(
        before.page_size == after.page_size && before.boot == after.boot,
        "independent page size or boot changed"
    );
    ensure!(
        before.physical_pages == after.physical_pages,
        "independent physical-page count changed during acceptance"
    );
    // This fixture exposes normal procfs, not a virtualized production memory
    // view. A distinct OS API independently establishes the byte-unit oracle.
    let physical_bytes = before
        .physical_pages
        .checked_mul(before.page_size)
        .context("independent physical memory byte product overflow")?;
    ensure!(
        before
            .memory_kib
            .get("mem_total_bytes")
            .and_then(|kib| kib.checked_mul(1024))
            == Some(physical_bytes)
            && after
                .memory_kib
                .get("mem_total_bytes")
                .and_then(|kib| kib.checked_mul(1024))
                == Some(physical_bytes)
            && value["memory_bytes"]["mem_total_bytes"].as_u64() == Some(physical_bytes),
        "stable MemTotal bytes disagree with independent physical pages times page size"
    );
    ensure!(
        value["page_size_bytes"].as_u64() == Some(before.page_size)
            && value.get("boot_id").and_then(Value::as_str) == before.boot.as_deref(),
        "memory page size or boot differs from independent OS APIs"
    );
    if before.boot.is_none() {
        ensure!(
            value.get("boot_id").is_none(),
            "unknown memory boot was not omitted"
        );
    }
    let observed = value["observed_at"].as_str().context("memory timestamp")?;
    ensure!(
        observed.is_ascii()
            && (20..=32).contains(&observed.len())
            && observed.ends_with('Z')
            && observed.as_bytes().get(10) == Some(&b'T')
            && before.utc[..19] <= observed[..19]
            && observed[..19] <= after.utc[..19],
        "memory collection-end UTC outside independent observations"
    );
    let mut missing = BTreeSet::new();
    for (group, fields, start, end) in [
        (
            "memory_bytes",
            MEMORY_FIELDS.as_slice(),
            &before.memory_kib,
            &after.memory_kib,
        ),
        (
            "vm_counters",
            MEMORY_VM_FIELDS.as_slice(),
            &before.vm,
            &after.vm,
        ),
    ] {
        let actual = value[group].as_object().context("memory integer object")?;
        ensure!(
            actual
                .keys()
                .all(|key| fields.iter().any(|(alias, _)| key.as_str() == *alias)),
            "memory object added derived gauges or fallback counters"
        );
        for (alias, _) in fields {
            ensure!(
                start.contains_key(*alias) == end.contains_key(*alias),
                "raw memory availability changed: {alias}"
            );
            if let Some(first) = start.get(*alias) {
                let n = actual
                    .get(*alias)
                    .and_then(Value::as_u64)
                    .context("exposed kernel field omitted or not an integer")?;
                ensure!(
                    n <= MEMORY_JSON_MAX,
                    "memory integer exceeds JSON-safe bound"
                );
                if group == "memory_bytes" {
                    ensure!(
                        n % 1024 == 0,
                        "memory byte gauge lost its kernel kB unit: {alias}"
                    );
                }
                let last = end.get(*alias).context("independent ending memory field")?;
                if group == "vm_counters" {
                    // Only cumulative events/base-page counts admit endpoint bounds,
                    // and only when independent boot identity is known and unchanged.
                    if before.boot.is_some() {
                        ensure!(
                            *first <= n && n <= *last,
                            "VM counter outside independent same-boot bounds: {alias}"
                        );
                    }
                } else if ["mem_total_bytes", "swap_total_bytes"].contains(alias) {
                    ensure!(
                        first == last,
                        "stable memory total changed during acceptance"
                    );
                    ensure!(
                        n == first * 1024,
                        "memory kB must normalize by 1024, not 1000: {alias}"
                    );
                } else if *alias == "swap_free_bytes"
                    && before.memory_kib.get("swap_total_bytes") == Some(&0)
                    && after.memory_kib.get("swap_total_bytes") == Some(&0)
                {
                    ensure!(n == 0, "real zero swap must remain available zero");
                }
                // All other memory fields are volatile non-atomic gauges. Their
                // presence, integer type, and bounds matter, not endpoint ordering.
            } else {
                ensure!(
                    !actual.contains_key(*alias),
                    "unknown memory value was invented"
                );
                missing.insert(format!("{group}.{alias}"));
            }
        }
    }
    if before.boot.is_none() {
        missing.insert("boot_id".to_owned());
    }
    let unavailable = value["unavailable"]
        .as_array()
        .context("memory unavailable array")?;
    let actual: BTreeSet<String> = unavailable
        .iter()
        .map(|v| {
            let path = v.as_str().context("memory unavailable path")?;
            ensure!(path.len() <= 64, "memory unavailable path unbounded");
            Ok(path.to_owned())
        })
        .collect::<Result<_>>()?;
    ensure!(
        actual == missing && actual.len() == unavailable.len() && actual.len() <= 18,
        "memory unknown/zero/omission semantics disagree with independent procfs"
    );
    Ok(())
}

async fn memory_stats_session(
    fixture: &isolated::Fixture,
    workspace: &Path,
    secrets: &[String],
    enabled: bool,
) -> Result<()> {
    let mut server = WireServer::start(&fixture.config)?;
    let result: Result<()> = async {
        server.initialize().await?;
        let listed = server.request(2, "tools/list", json!({})).await?;
        host_summary_private(&listed.to_string(), secrets)?;
        let tools = listed["result"]["tools"]
            .as_array()
            .context("memory discovery")?;
        let tool = tools.iter().find(|tool| tool["name"] == "memory_stats");
        if !enabled {
            ensure!(tool.is_none(), "memory observation enabled without opt-in");
            let auth = fixture.authentication_count().await?;
            let reply = server
                .request(
                    3,
                    "tools/call",
                    json!({
                        "name":"memory_stats","arguments":{"host":"plain","inputs":{}}
                    }),
                )
                .await?;
            host_summary_private(&reply.to_string(), secrets)?;
            ensure!(
                !reply["error"].is_null()
                    || !reply["result"]["structuredContent"]["error"].is_null(),
                "disabled memory tool executed"
            );
            ensure!(
                fixture.authentication_count().await? == auth
                    && fs::read_dir(workspace)?.next().is_none(),
                "disabled memory tool reached SSH or scratch"
            );
            return Ok(());
        }
        let tool = tool.context("opted-in memory tool")?;
        let inputs = &tool["inputSchema"]["properties"]["inputs"];
        ensure!(
            inputs["type"] == "object"
                && inputs["additionalProperties"] == false
                && inputs["properties"]
                    .as_object()
                    .is_some_and(|p| p.is_empty())
                && inputs["required"].as_array().is_some_and(|r| r.is_empty()),
            "memory input discovery allows caller controls"
        );
        let mut schemas = Vec::new();
        projection_value_schemas(&tool["outputSchema"], &mut schemas);
        ensure!(!schemas.is_empty(), "memory output discovery is untyped");
        for schema in schemas {
            let fields = &schema["properties"];
            let required = [
                "system",
                "scope",
                "observed_at",
                "page_size_bytes",
                "memory_bytes",
                "vm_counters",
                "unavailable",
            ];
            ensure!(
                schema["type"] == "object"
                    && schema["additionalProperties"] == false
                    && fields.as_object().is_some_and(|p| p.len() == 8)
                    && schema["required"].as_array().is_some_and(|r| {
                        r.len() == required.len()
                            && required.iter().all(|name| r.contains(&json!(name)))
                    }),
                "memory discovery root is not exactly closed and required"
            );
            for (name, max) in [
                ("system", 64),
                ("scope", 32),
                ("observed_at", 32),
                ("boot_id", 36),
            ] {
                ensure!(
                    fields[name]["type"] == "string" && fields[name]["maxLength"] == max,
                    "memory discovery string bound: {name}"
                );
            }
            ensure!(
                fields["system"]["const"] == "Linux"
                    && fields["scope"]["const"] == "procfs_view"
                    && fields["boot_id"]["minLength"] == 36
                    && fields["page_size_bytes"]["type"] == "integer"
                    && fields["page_size_bytes"]["minimum"] == 1
                    && fields["page_size_bytes"]["maximum"] == 1_048_576,
                "memory discovery identity/page-size contract"
            );
            for (group, selected, mandatory) in [
                (
                    "memory_bytes",
                    MEMORY_FIELDS.as_slice(),
                    vec!["mem_total_bytes", "mem_free_bytes"],
                ),
                ("vm_counters", MEMORY_VM_FIELDS.as_slice(), vec![]),
            ] {
                let child = &fields[group];
                ensure!(
                    child["type"] == "object"
                        && child["additionalProperties"] == false
                        && child["properties"]
                            .as_object()
                            .is_some_and(|p| p.len() == selected.len())
                        && child["required"].as_array().is_some_and(|r| {
                            r.len() == mandatory.len()
                                && mandatory.iter().all(|name| r.contains(&json!(name)))
                        }),
                    "memory discovery nested object contract: {group}"
                );
                for (alias, _) in selected {
                    ensure!(
                        child["properties"][*alias]["type"] == "integer"
                            && child["properties"][*alias]["minimum"] == 0
                            && child["properties"][*alias]["maximum"] == MEMORY_JSON_MAX,
                        "memory discovery integer bound: {group}.{alias}"
                    );
                }
            }
            let unavailable = &fields["unavailable"];
            let mut expected = BTreeSet::from(["boot_id".to_owned()]);
            expected.extend(
                MEMORY_FIELDS
                    .iter()
                    .skip(2)
                    .map(|(alias, _)| format!("memory_bytes.{alias}")),
            );
            expected.extend(
                MEMORY_VM_FIELDS
                    .iter()
                    .map(|(alias, _)| format!("vm_counters.{alias}")),
            );
            let names = unavailable["items"]["enum"]
                .as_array()
                .context("memory unavailable discovery enum")?;
            let actual: BTreeSet<_> = names
                .iter()
                .map(|v| {
                    v.as_str()
                        .context("unavailable enum string")
                        .map(str::to_owned)
                })
                .collect::<Result<_>>()?;
            ensure!(
                unavailable["type"] == "array"
                    && unavailable["maxItems"] == 18
                    && unavailable["uniqueItems"] == true
                    && unavailable["items"]["type"] == "string"
                    && unavailable["items"]["maxLength"] == 64
                    && actual == expected
                    && names.len() == expected.len(),
                "memory discovery unknown paths not exactly bounded"
            );
        }
        let auth = fixture.authentication_count().await?;
        let mut invalid = Vec::new();
        for inputs in [
            json!([]),
            json!(null),
            json!({"target_python":"/tmp/MEMORY_PRIVATE_OVERRIDE_8b24"}),
            json!({"path":"/proc/meminfo"}),
            json!({"sample_ms":1}),
            json!({"limit":1}),
            json!({"extra_vars":{"ansible_connection":"local"}}),
            json!({"ansible_ssh_common_args":"MEMORY_PRIVATE_OVERRIDE_8b24"}),
            json!({"transport":{"destination":"MEMORY_UNKNOWN_TARGET_6e39"}}),
            json!({"retain_output":true}),
            json!({"environment":{"MEMORY_PRIVATE_OVERRIDE_8b24":"1"}}),
        ] {
            invalid.push(json!({"host":"plain","inputs":inputs}));
        }
        for extra in [
            json!({"authority":"automation:ops"}),
            json!({"become":true}),
            json!({"retention":"keep"}),
            json!({"retain_workspace":true}),
            json!({"retain_output":true}),
            json!({"extra_vars":{"ansible_connection":"local"}}),
            json!({"role_path":"/tmp/MEMORY_PRIVATE_OVERRIDE_8b24"}),
            json!({"snapshot":"/tmp/MEMORY_PRIVATE_OVERRIDE_8b24"}),
            json!({"transport":{"destination":"MEMORY_UNKNOWN_TARGET_6e39"}}),
            json!({"runtime":"/tmp/MEMORY_PRIVATE_OVERRIDE_8b24"}),
        ] {
            let mut arguments = json!({"host":"plain","inputs":{}});
            arguments
                .as_object_mut()
                .context("memory controls")?
                .extend(extra.as_object().context("memory extra controls")?.clone());
            invalid.push(arguments);
        }
        for host in [
            "nosftp",
            "MEMORY_UNKNOWN_TARGET_6e39",
            "/tmp/MEMORY_PRIVATE_OVERRIDE_8b24",
        ] {
            invalid.push(json!({"host":host,"inputs":{}}));
        }
        for (index, arguments) in invalid.into_iter().enumerate() {
            let reply = server
                .request(
                    10 + index as u64,
                    "tools/call",
                    json!({"name":"memory_stats","arguments":arguments}),
                )
                .await?;
            host_summary_private(&reply.to_string(), secrets)?;
            let error = &reply["result"]["structuredContent"]["error"];
            ensure!(
                reply["error"]["code"] == -32602
                    || (!error.is_null() && error["remote_state_unknown"] == false),
                "invalid memory control or target reached execution: {reply}"
            );
            ensure!(
                fs::read_dir(workspace)?.next().is_none(),
                "invalid memory call created scratch"
            );
        }
        ensure!(
            fixture.authentication_count().await? == auth,
            "rejected memory calls reached SSH"
        );
        let before = observe_memory_stats(fixture).await?;
        let reply = server
            .request(
                100,
                "tools/call",
                json!({
                    "name":"memory_stats","arguments":{"host":"plain","inputs":{}}
                }),
            )
            .await?;
        host_summary_private(&reply.to_string(), secrets)?;
        ensure!(
            reply["error"].is_null(),
            "memory MCP call rejected: {reply}"
        );
        let envelope = &reply["result"]["structuredContent"];
        verified_role(envelope, "successful", json!(false))?;
        ensure!(
            envelope["error"].is_null()
                && envelope["data"]["runner_rc"] == 0
                && envelope["data"]["tasks"]["failed"] == 0
                && envelope["data"]["tasks"]["unreachable"] == 0
                && envelope["data"]["host"] == "plain"
                && envelope["data"]["projection"]["status"] == "complete",
            "memory observation lost successful no-change completion/cleanup evidence: {reply}"
        );
        ensure!(
            envelope["data"].get("stdout").is_none()
                && envelope["data"].get("stderr").is_none()
                && fs::read_dir(workspace)?.next().is_none(),
            "memory observation leaked command streams or retained workspace"
        );
        let after = observe_memory_stats(fixture).await?;
        let value = &envelope["data"]["projection"]["value"];
        projection_safe_keys(value)?;
        assert_memory_stats(value, &before, &after)?;
        Ok(())
    }
    .await;
    // Stop/drain before propagating assertions, including protocol failures.
    let stopped = server.stop(None).await;
    let log = stopped?;
    host_summary_private(&log.text(), secrets)?;
    ensure!(
        fs::read_dir(workspace)?.next().is_none(),
        "memory workspace survived shutdown"
    );
    result
}

/// cargo test --test automation_exec real_memory_stats_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Automation Nix fixture artifact, explicit DOCKER_HOST and pinned Runner runtime"]
async fn real_memory_stats_acceptance() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned controller runtime")?,
    )?;
    let private = tempfile::Builder::new()
        .prefix("memory-stats-private-")
        .tempdir()?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let workspace = private.path().join("workspaces");
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let fixture = isolated::Fixture::start(isolated::ImageKind::Automation).await?;
    let result: Result<()> = async {
        // Shipped assets stay unchanged; only private operator bindings adapt.
        let mut example: toml::Value =
            toml::from_str(include_str!("../examples/memory_stats.toml"))?;
        let role = private.path().join("roles/memory_stats");
        for (file, source) in [
            (
                "meta/argument_specs.yml",
                include_str!("../examples/roles/memory_stats/meta/argument_specs.yml"),
            ),
            (
                "tasks/main.yml",
                include_str!("../examples/roles/memory_stats/tasks/main.yml"),
            ),
        ] {
            let path = role.join(file);
            fs::create_dir_all(path.parent().context("memory role asset parent")?)?;
            fs::write(path, source)?;
        }
        let snapshot = private.path().join("memory_stats.schema.json");
        let mut overlay = json!({});
        for key in ["input_schema", "fixed_args", "input_map"] {
            overlay[key] = serde_json::to_value(&example["tools"]["memory_stats"][key])?;
        }
        let overlay_path = private.path().join("memory_stats.overlay.json");
        fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config.insert(
            "automation".into(),
            table(json!({"runtime":text(&runtime)?}))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut import = support::server_command(&fixture.config)?;
        import
            .args(["schema", "import-role", "memory_stats"])
            .arg("--role-path")
            .arg(&role)
            .arg("--output")
            .arg(&snapshot)
            .arg("--overlay")
            .arg(&overlay_path);
        let imported = support::run(&mut import).await?;
        ensure!(
            imported.status.success(),
            "installed memory importer failed: {}",
            String::from_utf8_lossy(&imported.stdout)
        );
        let report: Value = serde_json::from_slice(&imported.stdout)?;
        ensure!(
            report["binding_validated"] == true,
            "memory overlay was not reviewed"
        );
        let tool = example["tools"]["memory_stats"]
            .as_table_mut()
            .context("memory binding table")?;
        let execution = tool
            .get_mut("execution")
            .and_then(toml::Value::as_table_mut)
            .context("memory execution table")?;
        execution.insert("snapshot".into(), text(&snapshot)?.into());
        execution.insert("role_path".into(), text(&role)?.into());
        tool.insert("targets".into(), table(json!(["plain"]))?);
        config.insert("tools".into(), example["tools"].clone());
        let mut automation = example["automation"]
            .as_table()
            .context("memory automation table")?
            .clone();
        automation.insert("runtime".into(), text(&runtime)?.into());
        automation.insert("workspace_root".into(), text(&workspace)?.into());
        config["ssh"]
            .as_table_mut()
            .context("fixture SSH table")?
            .insert("executable".into(), text(&fixture.ssh)?.into());
        automation.insert(
            "targets".into(),
            table(json!({"plain":{"destination":"plain","python":"/usr/bin/python3"}}))?,
        );
        config.insert("automation".into(), toml::Value::Table(automation));
        config.insert("profile".into(), example["profile"].clone());
        config.insert("enabled_tools".into(), table(json!([]))?);
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        let mut secrets = fixture.credential_markers()?;
        secrets.extend([
            text(private.path())?,
            text(&runtime)?,
            PRIVATE.into(),
            "/usr/bin/python3".into(),
            "target_python".into(),
            "/proc/meminfo".into(),
            "/proc/vmstat".into(),
            "/proc/sys/kernel/random/boot_id".into(),
            "SC_PAGE_SIZE".into(),
            "MemTotal:".into(),
            "MemFree:".into(),
            "pgfault ".into(),
            "MEMORY_PRIVATE_OVERRIDE_8b24".into(),
            "MEMORY_UNKNOWN_TARGET_6e39".into(),
            "event_data".into(),
            "Traceback".into(),
        ]);
        memory_stats_session(&fixture, &workspace, &secrets, false).await?;
        config.insert("enabled_tools".into(), example["enabled_tools"].clone());
        fs::write(&fixture.config, toml::to_string(&config)?)?;
        memory_stats_session(&fixture, &workspace, &secrets, true).await
    }
    .await;
    // Await both container removals even after importer, protocol, or oracle errors.
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

/// Real broader authority, using only the public import and MCP protocol.
/// cargo test --test automation_exec real_runner_authority_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires rebuilt automation Nix image, explicit Docker backend and pinned Runner runtime"]
async fn real_runner_authority_acceptance() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned controller bundle")?,
    )?;
    let private = tempfile::Builder::new()
        .prefix("authority-private-")
        .tempdir()?;
    fs::set_permissions(private.path(), fs::Permissions::from_mode(0o700))?;
    let workspace = private.path().join("workspaces");
    fs::create_dir(&workspace)?;
    fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
    let fixture = isolated::Fixture::start(isolated::ImageKind::Automation).await?;
    let result = authority_scenarios(&fixture, private.path(), &runtime, &workspace).await;
    // Await removal even after a failed protocol/effect assertion.
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

const AUTHORITY_MARKER: &str = "/root/estus-a08-authority";
const AUTHORITY_PASSWORD_MARKER: &str = "/root/estus-a08-password";
const AUTHORITY_CANCEL_MARKER: &str = "/root/estus-a08-cancel";
const AUTHORITY_DONE_MARKER: &str = "/root/estus-a08-done";
const AUTHORITY_OVERRIDE: &str = "A08_REJECTED_PRIVATE_OVERRIDE_7c39";
const AUTHORITY_UNKNOWN: &str = "A08_UNDECLARED_PRIVATE_TARGET_29c1";

async fn authority_python(
    fixture: &isolated::Fixture,
    script: &str,
) -> Result<std::process::Output> {
    fixture
        .authority_direct(
            "authority-ops-private",
            &format!(
                "/usr/bin/sudo -H -n -k -u root -- /usr/bin/python3 -I -c {}",
                support::quote(script),
            ),
        )
        .await
}

async fn authority_absent(fixture: &isolated::Fixture, paths: &[&str]) -> Result<()> {
    let script = format!(
        "import os,sys;sys.exit(any(os.path.exists(p) for p in {:?}))",
        paths
    );
    let output = authority_python(fixture, &script).await?;
    ensure!(
        output.status.success(),
        "rejected request had a privileged effect"
    );
    Ok(())
}

async fn authority_readback(fixture: &isolated::Fixture, path: &str, bytes: &str) -> Result<()> {
    let script = format!(
        "import json,os; p={path:?}; print(json.dumps({{'uid':os.stat(p).st_uid,'bytes':open(p).read()}}))"
    );
    let output = authority_python(fixture, &script).await?;
    ensure!(
        output.status.success(),
        "independent privileged SSH readback failed"
    );
    let observed: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        observed == json!({"uid":0,"bytes":bytes}),
        "privileged module did not write the actual root-owned bytes: {observed}"
    );
    Ok(())
}

async fn authority_wait_marker(fixture: &isolated::Fixture, path: &str) -> Result<()> {
    timeout(WAIT, async {
        loop {
            let observed = fixture
                .primary_exec(&format!(
                    "if test -f {}; then printf ready; fi",
                    support::quote(path),
                ))
                .await?;
            if observed == b"ready" {
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("finite privileged effect marker deadline")?
}

async fn authority_scenarios(
    fixture: &isolated::Fixture,
    private: &Path,
    runtime: &Path,
    workspace: &Path,
) -> Result<()> {
    let mut secrets = fixture.credential_markers()?;
    secrets.extend([
        text(private)?,
        text(runtime)?,
        text(&fixture.authority_ssh_config)?,
        "authority-ops-private".into(),
        "authority-password-private".into(),
        "mcp-automation".into(),
        PRIVATE.into(),
        AUTHORITY_OVERRIDE.into(),
        AUTHORITY_UNKNOWN.into(),
        "fixture-cache-only".into(),
    ]);
    let assert_private = |output: &str| -> Result<()> {
        for secret in &secrets {
            ensure!(
                !output.contains(secret),
                "authority discovery/summary/audit disclosed private data"
            );
        }
        Ok(())
    };
    // Neither ordinary replacement file can route to a privileged identity.
    for file in [
        &fixture.ssh_config,
        &fixture
            .ssh_config
            .parent()
            .context("fixture root")?
            .join("included.conf"),
    ] {
        let ordinary = fs::read_to_string(file)?;
        ensure!(
            !ordinary.contains("mcp-automation") && !ordinary.contains("authority-"),
            "ordinary replacement SSH config contains privileged identity"
        );
    }
    fixture.reject_native_authority_keys().await?;
    let mut fingerprints = BTreeSet::new();
    for (account, alias, uid, authority) in [
        ("mcp", "plain", b"1000\n".as_slice(), false),
        ("mcp-sudo", "same", b"1001\n".as_slice(), false),
        ("mcp-admin", "split-admin", b"1002\n".as_slice(), false),
        (
            "mcp-automation",
            "authority-ops-private",
            b"1005\n".as_slice(),
            true,
        ),
        (
            "mcp-automation-password",
            "authority-password-private",
            b"1006\n".as_slice(),
            true,
        ),
    ] {
        ensure!(
            fingerprints.insert(fixture.key_fingerprint(account).await?),
            "fixture reused an authority credential"
        );
        let login = if authority {
            fixture.authority_direct(alias, "/usr/bin/id -u").await?
        } else {
            fixture.direct(alias, "/usr/bin/id -u").await?
        };
        ensure!(
            login.status.success() && login.stdout == uid,
            "wrong fixture login identity"
        );
    }
    let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
    config.insert(
        "automation".into(),
        table(json!({"runtime":text(runtime)?}))?,
    );
    fs::write(&fixture.config, toml::to_string(&config)?)?;
    let empty =
        json!({"type":"object","properties":{},"additionalProperties":false,"maxProperties":0});
    let partial_marker = "/root/estus-authority-partial";
    let partial = format!(
        "import os; p={partial_marker:?}; f=open(p,'w'); f.write({PRIVATE:?}); f.close(); os.chmod(p,0o600); raise SystemExit(7)"
    );
    let write = format!(
        "import os; p={AUTHORITY_MARKER:?}; f=open(p,'w'); f.write({PRIVATE:?}); f.close(); os.chmod(p,0o600)"
    );
    let password_write = format!("open({AUTHORITY_PASSWORD_MARKER:?},'w').write({PRIVATE:?})");
    let cancel = format!(
        "import signal,time;signal.signal(signal.SIGHUP,signal.SIG_IGN);open({AUTHORITY_CANCEL_MARKER:?},'w').write({PRIVATE:?});time.sleep(8);open({AUTHORITY_DONE_MARKER:?},'w').write('finite-done')"
    );
    let mut tools = toml::map::Map::new();
    for (name, authority, host, argv) in [
        (
            "authority_write",
            "automation:ops",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", write]),
        ),
        (
            "authority_partial",
            "automation:ops",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", partial]),
        ),
        (
            "ordinary_write",
            "automation",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", write]),
        ),
        (
            "ordinary_read",
            "automation",
            "plain",
            json!([
                "/usr/bin/python3",
                "-I",
                "-c",
                format!("open({AUTHORITY_MARKER:?}).read()")
            ]),
        ),
        (
            "narrow_python",
            "automation",
            "same",
            json!([
                "/usr/bin/sudo",
                "-H",
                "-n",
                "-k",
                "-u",
                "root",
                "--",
                "/usr/bin/python3",
                "-I",
                "-c",
                write
            ]),
        ),
        (
            "password_write",
            "automation:password",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", password_write]),
        ),
        (
            "authority_cancel",
            "automation:ops",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", cancel]),
        ),
        (
            "hidden_authority",
            "automation:ops",
            "plain",
            json!(["/usr/bin/python3", "-I", "-c", write]),
        ),
    ] {
        let overlay = json!({"input_schema":empty,"fixed_args":{"argv":argv,"expand_argument_vars":false},"input_map":{}});
        let snapshot = private.join(format!("{name}-reviewed.json"));
        import_reviewed(
            &fixture.config,
            &snapshot,
            "ansible.builtin.command",
            &overlay,
        )
        .await?;
        let mut binding = json!({
            "description":"Reviewed fixed authority acceptance","revision":"a08-1",
            "authority":authority,"targets":[host],"effects":["persistent_write"],
            "execution":{"kind":"ansible_module","snapshot":text(&snapshot)?,"no_log":false},
            "result":{"kind":"ansible_summary"},"limits":{"timeout_secs":12}
        });
        for key in ["input_schema", "fixed_args", "input_map"] {
            binding[key] = overlay[key].clone();
        }
        tools.insert(name.into(), table(binding)?);
    }
    config.insert("tools".into(), toml::Value::Table(tools));
    config.insert(
        "enabled_tools".into(),
        table(json!([
            "authority_write",
            "authority_partial",
            "ordinary_write",
            "ordinary_read",
            "narrow_python",
            "password_write",
            "authority_cancel"
        ]))?,
    );
    config["ssh"]
        .as_table_mut()
        .context("fixture SSH table")?
        .insert("executable".into(), text(&fixture.ssh)?.into());
    config.insert("automation".into(), table(json!({
        "required":true,"runtime":text(runtime)?,"workspace_root":text(workspace)?,
        "targets":{"plain":{"destination":"plain","python":"/usr/bin/python3"},
            "same":{"destination":"same","python":"/usr/bin/python3"}},
        "authorities":{
            "ops":{"ssh_config_file":text(&fixture.authority_ssh_config)?,
                "become":{"method":"sudo","user":"root"},
                "targets":{"plain":{"destination":"authority-ops-private","python":"/usr/bin/python3"}}},
            "password":{"ssh_config_file":text(&fixture.authority_ssh_config)?,
                "become":{"method":"sudo","user":"root"},
                "targets":{"plain":{"destination":"authority-password-private","python":"/usr/bin/python3"}}}
        }
    }))?);
    config.insert(
        "limits".into(),
        table(json!({
            "operation_timeout_secs":12,"max_timeout_secs":15,"max_output_bytes":8192
        }))?,
    );
    fs::write(&fixture.config, toml::to_string(&config)?)?;
    let mut hidden_config = config.clone();
    hidden_config.insert("profile".into(), "read-only-files".into());
    let hidden_path = private.join("profile-hidden.toml");
    fs::write(&hidden_path, toml::to_string(&hidden_config)?)?;
    let mut hidden_server = WireServer::start(&hidden_path)?;
    let hidden_calls: Result<()> = async {
        hidden_server.initialize().await?;
        let listed = hidden_server.request(2, "tools/list", json!({})).await?;
        assert_private(&listed.to_string())?;
        ensure!(
            !listed["result"]["tools"]
                .as_array()
                .context("profile tool discovery")?
                .iter()
                .any(|tool| tool["name"] == "authority_write"),
            "profile-hidden named authority was published"
        );
        let denied = hidden_server
            .request(
                3,
                "tools/call",
                json!({
                    "name":"authority_write","arguments":{"host":"plain","inputs":{}}
                }),
            )
            .await?;
        assert_private(&denied.to_string())?;
        ensure!(
            !denied["error"].is_null(),
            "startup profile did not hide named authority route"
        );
        authority_absent(fixture, &[AUTHORITY_MARKER]).await?;
        Ok(())
    }
    .await;
    let hidden_stopped = hidden_server.stop(None).await;
    let hidden_log = hidden_stopped?;
    let ops_key = fixture.key_fingerprint("mcp-automation").await?;
    let password_key = fixture.key_fingerprint("mcp-automation-password").await?;
    assert_private(&hidden_log.text())?;
    hidden_calls?;
    let mut server = WireServer::start(&fixture.config)?;
    let mut rejected_requests = Vec::new();
    let calls: Result<()> = async {
        server.initialize().await?;
        let listed = server.request(2,"tools/list",json!({})).await?;
        assert_private(&listed.to_string())?;
        let published = listed["result"]["tools"].as_array().context("authority tool discovery")?;
        let tool = published.iter().find(|tool| tool["name"] == "authority_write")
            .context("named authority tool not published")?;
        ensure!(tool["_meta"]["authority"] == "automation:ops", "logical authority metadata missing");
        ensure!(!published.iter().any(|tool| tool["name"] == "hidden_authority"),
            "disabled authority binding was published");
        authority_absent(fixture, &[AUTHORITY_MARKER, AUTHORITY_PASSWORD_MARKER, AUTHORITY_CANCEL_MARKER]).await?;
        // All transport/privilege knobs are operator-only, at either MCP nesting level.
        let mut id = 100;
        for key in [
            "authority","become","become_user","become_method","become_password","password",
            "credential","ssh_key","ssh_config_file","ssh_auth_sock","ssh_executable",
            "transport","runtime","user","ansible_become","argv",
        ] {
            for nested in [false, true] {
                let mut arguments = json!({"host":"plain","inputs":{}});
                if nested {
                    arguments["inputs"][key] = json!(AUTHORITY_OVERRIDE);
                } else {
                    arguments[key] = json!(AUTHORITY_OVERRIDE);
                }
                let response = server.request(id,"tools/call",json!({
                    "name":"authority_write","arguments":arguments
                })).await?;
                assert_private(&response.to_string())?;
                ensure!(response["error"]["code"] == -32602,
                    "unknown caller privilege/transport input was not rejected at the shape boundary: {response}");
                rejected_requests.push(id);
                id += 1;
            }
        }
        for host in ["same", AUTHORITY_UNKNOWN] {
            let denied = server.request(id,"tools/call",json!({
                "name":"authority_write","arguments":{"host":host,"inputs":{}}
            })).await?;
            assert_private(&denied.to_string())?;
            ensure!(!denied["result"]["structuredContent"]["error"].is_null()
                && denied["result"]["structuredContent"]["error"]["remote_state_unknown"] == false,
                "undeclared named-authority target was dispatched: {denied}");
            id += 1;
        }
        for name in ["hidden_authority","ops"] {
            let denied = server.request(id,"tools/call",json!({
                "name":name,"arguments":{"host":"plain","inputs":{}}
            })).await?;
            assert_private(&denied.to_string())?;
            ensure!(!denied["error"].is_null(), "hidden authority callable");
            id += 1;
        }
        authority_absent(fixture, &[AUTHORITY_MARKER]).await?;
        for (name, host) in [("ordinary_write","plain"),("narrow_python","same")] {
            let denied = server.request(id,"tools/call",json!({
                "name":name,"arguments":{"host":host,"inputs":{}}
            })).await?;
            assert_private(&denied.to_string())?;
            ensure!(denied["error"].is_null()
                && !denied["result"]["structuredContent"]["error"].is_null()
                && denied["result"]["structuredContent"]["data"]["status"] == "failed",
                "ordinary/narrow module obtained root Python: {denied}");
            id += 1;
        }
        authority_absent(fixture, &[AUTHORITY_MARKER]).await?;
        // Prove actual root mutation, not merely sudo id or echoed module output.
        let before_ops = fixture.authentication_keys().await?.into_iter()
            .filter(|(account, key)| account == "mcp-automation" && key == &ops_key).count();
        let written = server.request(300,"tools/call",json!({
            "name":"authority_write","arguments":{"host":"plain","inputs":{}}
        })).await?;
        assert_private(&written.to_string())?;
        let envelope = &written["result"]["structuredContent"];
        ensure!(written["error"].is_null() && envelope["error"].is_null()
            && envelope["data"]["status"] == "successful" && envelope["data"]["complete"] == true,
            "named authority did not execute real module: {written}");
        let after_ops = fixture.authentication_keys().await?.into_iter()
            .filter(|(account, key)| account == "mcp-automation" && key == &ops_key).count();
        ensure!(after_ops > before_ops, "product write did not use independent automation credentials");
        authority_readback(fixture, AUTHORITY_MARKER, PRIVATE).await?;
        for alias in ["plain","same","split-admin"] {
            for script in [
                format!("open({AUTHORITY_MARKER:?}).read()"),
                format!("open({AUTHORITY_MARKER:?},'w').write('forbidden')"),
            ] {
                let denied = fixture.direct(alias, &format!(
                    "/usr/bin/python3 -I -c {}", support::quote(&script),
                )).await?;
                ensure!(!denied.status.success(), "native identity read/mutated root marker");
            }
            let denied = fixture.direct(alias,
                "/usr/bin/sudo -H -n -k -u root -- /usr/bin/python3 -I -c 'import os; print(os.getuid())'").await?;
            ensure!(!denied.status.success(), "native narrow policy elevated module Python");
        }
        let native_denied = server.request(301,"tools/call",json!({
            "name":"ssh_sudo","arguments":{"host":"same","user":"root",
                "argv":["/usr/bin/python3","-I","-c","print('forbidden')"]}
        })).await?;
        ensure!(!native_denied["result"]["structuredContent"]["error"].is_null(),
            "native sudo policy widened to Python: {native_denied}");
        let ordinary_read = server.request(302,"tools/call",json!({
            "name":"ordinary_read","arguments":{"host":"plain","inputs":{}}
        })).await?;
        assert_private(&ordinary_read.to_string())?;
        ensure!(ordinary_read["result"]["structuredContent"]["data"]["status"] == "failed",
            "ordinary module read root marker");
        authority_readback(fixture, AUTHORITY_MARKER, PRIVATE).await?;
        let partial = server.request(303, "tools/call", json!({
            "name":"authority_partial","arguments":{"host":"plain","inputs":{}}
        })).await?;
        ensure!(partial["error"].is_null(), "partial-failure binding was rejected: {partial}");
        let partial = &partial["result"]["structuredContent"];
        ensure!(partial["data"]["status"] == "failed" && partial["data"]["complete"] == true
            && partial["data"]["changed"] == true && partial["error"]["remote_state_unknown"] == false,
            "failed module erased observed privileged mutation or completion: {partial}");
        authority_readback(fixture, partial_marker, PRIVATE).await?;
        // Refuse both a cold password account and an independently proven live timestamp.
        for (request_id, cached) in [(400, false), (401, true)] {
            if cached {
                fixture.prime_automation_password_cache().await?;
            }
            let before_password = fixture.authentication_keys().await?.into_iter()
                .filter(|(account, key)| account == "mcp-automation-password" && key == &password_key).count();
            let refused = timeout(WAIT, server.request(request_id,"tools/call",json!({
                "name":"password_write","arguments":{"host":"plain","inputs":{}}
            }))).await.context("cached/password sudo refusal must be finite")??;
            assert_private(&refused.to_string())?;
            ensure!(refused["error"].is_null()
                && !refused["result"]["structuredContent"]["error"].is_null()
                && refused["result"]["structuredContent"]["data"]["status"] == "failed",
                "product reused a sudo timestamp or requested a password: {refused}");
            let after_password = fixture.authentication_keys().await?.into_iter()
                .filter(|(account, key)| account == "mcp-automation-password" && key == &password_key).count();
            ensure!(after_password > before_password,
                "product password refusal did not use selected authority credentials");
            authority_absent(fixture, &[AUTHORITY_PASSWORD_MARKER]).await?;
        }
        server.send(json!({"jsonrpc":"2.0","id":500,"method":"tools/call","params":{
            "name":"authority_cancel","arguments":{"host":"plain","inputs":{}}
        }})).await?;
        authority_wait_marker(fixture, AUTHORITY_CANCEL_MARKER).await?;
        authority_readback(fixture, AUTHORITY_CANCEL_MARKER, PRIVATE).await?;
        server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{
            "requestId":500,"reason":"finite authority effect cancellation"
        }})).await?;
        timeout(WAIT, async {
            loop {
                if let Some(finish) = server.log.records()?.into_iter()
                    .find(|record| record["event"] == "finish" && record["request_id"] == 500)
                {
                    ensure!(finish["identity_role"] == "automation"
                        && finish["error_code"] == "cancelled"
                        && finish["remote_state_unknown"] == true
                        && finish["complete"] == false
                        && finish["owned_group_cleanup"] == "signalled_and_reaped",
                        "cancellation claimed privileged rollback or lost uncertainty: {finish}");
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("named authority cancellation audit deadline")??;
        // Cancellation is not rollback: the independently observed root effect persists.
        authority_readback(fixture, AUTHORITY_CANCEL_MARKER, PRIVATE).await?;
        authority_wait_marker(fixture, AUTHORITY_DONE_MARKER).await?;
        authority_readback(fixture, AUTHORITY_DONE_MARKER, "finite-done").await?;
        Ok(())
    }.await;
    let stopped = server.stop(None).await;
    let log = stopped?;
    assert_private(&log.text())?;
    calls?;
    for id in rejected_requests {
        ensure!(
            log.records()?
                .iter()
                .any(|record| record["request_id"] == id
                    && record["identity_role"] == "automation"
                    && record.get("sudo_mode").is_none()),
            "rejected authority override lost its authority audit identity"
        );
    }
    for id in [300, 303, 400, 401, 500] {
        let records = log.records()?;
        for event in ["start", "finish"] {
            ensure!(
                records.iter().any(|record| record["request_id"] == id
                    && record["event"] == event
                    && record["identity_role"] == "automation"),
                "named execution lacks correlated automation audit: {id}/{event}"
            );
        }
    }
    // Explicit named runtimes/disabled agents must not consult ordinary ambient references.
    let mut dedicated_config = config.clone();
    dedicated_config["enabled_tools"] = toml::Value::try_from(vec!["authority_write"])?;
    dedicated_config["automation"]["runtime"] = "/missing/inherited-runtime-private".into();
    dedicated_config["automation"]["authorities"]["ops"]
        .as_table_mut()
        .context("ops")?
        .insert("runtime".into(), text(runtime)?.into());
    let dedicated_path = fixture.config.with_file_name("authority-dedicated.toml");
    fs::write(&dedicated_path, toml::to_string(&dedicated_config)?)?;
    let mut command = support::server_command(&dedicated_path)?;
    command.env("SSH_AUTH_SOCK", "relative-ambient-agent-private");
    let mut dedicated = WireServer::start_command(command)?;
    let dedicated_calls: Result<()> = async {
        dedicated.initialize().await?;
        let response = dedicated
            .request(
                600,
                "tools/call",
                json!({"name":"authority_write","arguments":{"host":"plain","inputs":{}}}),
            )
            .await?;
        ensure!(
            response["result"]["structuredContent"]["data"]["status"] == "successful",
            "explicit authority consulted unavailable ordinary runtime/ambient agent: {response}"
        );
        authority_readback(fixture, AUTHORITY_MARKER, PRIVATE).await?;
        Ok(())
    }
    .await;
    let dedicated_log = dedicated.stop(None).await?;
    assert_private(&dedicated_log.text())?;
    dedicated_calls?;
    ensure!(
        fs::read_dir(workspace)?.next().is_none(),
        "authority workspace survived shutdown"
    );
    Ok(())
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

fn role_receipt_result() -> Value {
    projection_result(
        json!({"instance":["mcp_result","instance"],"path":["mcp_result","path"],
            "checksum":["mcp_result","checksum"],"verified":["mcp_result","verified"]}),
        json!({"type":"object","properties":{
            "instance":{"type":"string","maxLength":512},
            "path":{"type":"string","maxLength":4096},
            "checksum":{"type":"string","minLength":64,"maxLength":64},
            "verified":{"type":"boolean","const":true}},
            "required":["instance","path","checksum","verified"],"additionalProperties":false}),
        4096,
        32,
        4,
    )
}

fn write_role(parent: &Path, name: &str, tasks: &str) -> Result<PathBuf> {
    let role = parent.join(name);
    fs::create_dir_all(role.join("tasks"))?;
    fs::create_dir_all(role.join("meta"))?;
    fs::write(role.join("tasks/main.yml"), tasks)?;
    fs::write(
        role.join("meta/argument_specs.yml"),
        "---\nargument_specs:\n  main:\n    short_description: Fixed acceptance role\n    options:\n      marker:\n        type: path\n        required: true\n",
    )?;
    Ok(role)
}

async fn import_reviewed_role(a: &Acceptance, role: &Path, overlay: &Value) -> Result<PathBuf> {
    let name = role
        .file_name()
        .context("role name")?
        .to_str()
        .context("UTF-8 role name")?;
    let snapshot = a
        .fixture
        .root
        .path()
        .join(format!("role-{name}-reviewed.json"));
    let overlay_path = snapshot.with_extension("overlay.json");
    fs::write(&overlay_path, serde_json::to_vec(overlay)?)?;
    let mut command = support::server_command(&a.fixture.config)?;
    command
        .args(["schema", "import-role", name])
        .arg("--role-path")
        .arg(role)
        .arg("--output")
        .arg(&snapshot)
        .arg("--overlay")
        .arg(&overlay_path);
    let output = support::run(&mut command).await?;
    ensure!(
        output.status.success(),
        "real role import failed for {name}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["binding_validated"] == true,
        "role overlay was not reviewed: {report}"
    );
    Ok(snapshot)
}

async fn configure_roles(a: &Acceptance) -> Result<PathBuf> {
    let parent = a.fixture.root.path().join("reviewed-roles");
    fs::create_dir(&parent)?;
    // Ansible must receive the verified canonical source, not reinterpret this
    // legitimate installation-root alias as a search-path list or $HOME.
    let aliased_parent = a.fixture.root.path().join("roles:$HOME");
    std::os::unix::fs::symlink(&parent, &aliased_parent)?;
    let example: toml::Value = toml::from_str(include_str!("../examples/app_config.toml"))?;
    let mut overlay = json!({});
    for key in ["input_schema", "fixed_args", "input_map"] {
        overlay[key] = serde_json::to_value(&example["tools"]["app_config"][key])?;
    }
    overlay["fixed_args"]["config_root"] = json!(text(&a.fixture.root.path().join("application"))?);
    let app = parent.join("app_config");
    for (file, source) in [
        (
            "meta/argument_specs.yml",
            include_str!("../examples/roles/app_config/meta/argument_specs.yml"),
        ),
        (
            "tasks/main.yml",
            include_str!("../examples/roles/app_config/tasks/main.yml"),
        ),
        (
            "templates/config.json.j2",
            include_str!("../examples/roles/app_config/templates/config.json.j2"),
        ),
    ] {
        let path = app.join(file);
        fs::create_dir_all(path.parent().context("role file parent")?)?;
        fs::write(path, source)?;
    }
    let dependency_marker = a.fixture.root.path().join("dependency-ran");
    let dependency = write_role(
        &parent,
        "dependency",
        &format!(
            "---\n- name: Observe actual dependency execution\n  ansible.builtin.copy:\n    dest: {}\n    content: dependency-ran\n    mode: '0600'\n",
            serde_json::to_string(&text(&dependency_marker)?)?
        ),
    )?;
    // The dependency has no inputs; it must not fail for an unrelated missing marker.
    fs::remove_file(dependency.join("meta/argument_specs.yml"))?;
    fs::write(
        app.join("meta/main.yml"),
        "---\ndependencies:\n  - role: dependency\n",
    )?;
    let mutation = "- name: Make an owned observable mutation\n  ansible.builtin.copy:\n    dest: \"{{ marker }}\"\n    content: owned-change\n    mode: '0600'\n";
    let mut definitions = vec![(
        "app_config".to_owned(),
        app,
        overlay,
        role_receipt_result(),
        false,
    )];
    for (name, tasks, projected, no_log) in [
        (
            "partial",
            format!(
                "---\n{mutation}- name: Fail after mutation\n  ansible.builtin.fail:\n    msg: expected failure\n"
            ),
            false,
            false,
        ),
        (
            "unavailable",
            format!(
                "---\n{mutation}- name: Fail before domain collection\n  ansible.builtin.fail:\n    msg: expected failure\n"
            ),
            true,
            false,
        ),
        (
            "recovered",
            format!(
                "---\n{mutation}- name: Recover an ordinary failed block\n  block:\n    - ansible.builtin.fail:\n        msg: rescued failure\n  rescue:\n    - ansible.builtin.debug:\n        msg: recovered\n- name: Ignore one ordinary failure\n  ansible.builtin.fail:\n    msg: ignored failure\n  ignore_errors: true\n- name: Skip an ordinary task\n  ansible.builtin.debug:\n    msg: skipped\n  when: false\n"
            ),
            false,
            false,
        ),
        ("summary", format!("---\n{mutation}"), false, false),
        (
            "invalid",
            "---\n- ansible.builtin.set_fact:\n    mcp_result:\n      verified: wrong-type\n"
                .to_owned(),
            true,
            false,
        ),
        (
            "missing",
            "---\n- ansible.builtin.debug:\n    msg: no-domain-result\n".to_owned(),
            true,
            false,
        ),
        (
            "censored",
            format!(
                "---\n- ansible.builtin.set_fact:\n    mcp_result:\n      verified: {PRIVATE}\n"
            ),
            true,
            true,
        ),
        ("drift", format!("---\n{mutation}"), false, false),
        (
            "handler",
            format!("---\n{mutation}  notify: role_receipt\n"),
            true,
            false,
        ),
        (
            "repeat_handler",
            format!(
                "---\n{}  notify: role_receipt\n- ansible.builtin.meta: flush_handlers\n{mutation}  notify: role_receipt\n",
                mutation.replace("content: owned-change", "content: first-phase")
            ),
            true,
            false,
        ),
    ] {
        let role = write_role(&parent, name, &tasks)?;
        if name == "handler" {
            fs::create_dir(role.join("handlers"))?;
            fs::write(
                role.join("handlers/main.yml"),
                "---\n- name: role_receipt\n  ansible.builtin.set_fact:\n    mcp_result:\n      verified: true\n",
            )?;
        }
        if name == "repeat_handler" {
            fs::create_dir(role.join("handlers"))?;
            fs::write(
                role.join("handlers/main.yml"),
                "---\n- name: Read handler postcondition\n  listen: role_receipt\n  ansible.builtin.slurp:\n    src: \"{{ marker }}\"\n  register: handler_bytes\n- name: Publish handler postcondition\n  listen: role_receipt\n  ansible.builtin.set_fact:\n    mcp_result:\n      verified: \"{{ (handler_bytes.content | b64decode) == 'owned-change' }}\"\n",
            )?;
        }
        let overlay = json!({"input_schema":{"type":"object","properties":{},
            "additionalProperties":false},"fixed_args":{"marker":text(&a.fixture.root.path().join(format!("{name}-marker")))?},
            "input_map":{}});
        let result = if projected {
            projection_result(
                json!({"verified":["mcp_result","verified"]}),
                json!({"type":"object","properties":{"verified":{"type":"boolean"}},
                    "required":["verified"],"additionalProperties":false}),
                1024,
                16,
                4,
            )
        } else {
            json!({"kind":"ansible_summary"})
        };
        definitions.push((name.to_owned(), role, overlay, result, no_log));
    }
    let mut tools = toml::map::Map::new();
    let mut enabled = Vec::new();
    for (name, role, overlay, result, no_log) in definitions {
        let snapshot = import_reviewed_role(a, &role, &overlay).await?;
        let mut binding = json!({"description":"Reviewed real SSH role acceptance","revision":"1",
            "authority":"automation","effects":["persistent_write","read"],"targets":["plain"],
            "execution":{"kind":"ansible_role","snapshot":text(&snapshot)?,
                "role_path":text(&if name == "summary" { aliased_parent.join(&name) } else { role })?,"no_log":no_log},
            "result":result,"limits":{"timeout_secs":12}});
        for key in ["input_schema", "fixed_args", "input_map"] {
            binding[key] = overlay[key].clone();
        }
        enabled.push(name.clone());
        tools.insert(name, table(binding)?);
    }
    let mut config: toml::Table = toml::from_str(&fs::read_to_string(&a.fixture.config)?)?;
    config.insert("enabled_tools".into(), table(json!(enabled))?);
    config.insert("tools".into(), toml::Value::Table(tools));
    fs::write(&a.fixture.config, toml::to_string(&config)?)?;
    Ok(parent)
}

fn verified_role(envelope: &Value, status: &str, changed: Value) -> Result<()> {
    ensure!(
        envelope["data"]["status"] == status
            && envelope["data"]["complete"] == true
            && envelope["data"]["changed"] == changed
            && envelope["data"]["owned_group_cleanup"] == "signalled_and_reaped",
        "role lost authoritative task evidence: {envelope}"
    );
    ensure!(
        envelope["data"]["tasks"]["ok"]
            .as_u64()
            .is_some_and(|count| count >= 2),
        "multi-task role evidence is missing: {envelope}"
    );
    Ok(())
}

/// cargo test --test automation_exec real_runner_role_acceptance -- --ignored --exact --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected pinned Runner/target Python, Nix sshd, non-root private localhost fixture"]
async fn real_runner_role_acceptance() -> Result<()> {
    let acceptance = Acceptance::start().await?;
    let result: Result<()> = async {
        let roles = configure_roles(&acceptance).await?;
        role_scenarios(&acceptance, &roles).await
    }
    .await;
    let cleanup = acceptance.fixture.stop().await;
    result?;
    cleanup
}

async fn role_scenarios(a: &Acceptance, roles: &Path) -> Result<()> {
    let mut server = a.server().await?;
    let result: Result<()> = async {
        let literal = format!("{{{{ lookup('pipe', 'touch {}') }}}}", text(&a.forbidden)?);
        let banner = format!("雪😀 \"quoted\"\n{literal} {{{{ 6 * 7 }}}}");
        let inputs = json!({"instance":literal,"config":{"banner":banner,"enabled":true,"port":8080}});
        // Invalid schema and immutable executor/mapping controls are rejected at
        // the real MCP boundary, before even the declared dependency can run.
        for (index, arguments) in [
            json!({"host":"plain","inputs":[]}),
            json!({"host":"plain","inputs":{"instance":false,"config":{"banner":"x","enabled":false}}}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":42,"enabled":false}}}),
            json!({"host":"plain","inputs":{"config":{"banner":"x","enabled":false}}}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":"x","enabled":true}}}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":"x","enabled":false,"port":1}}}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":"x","enabled":false},"config_root":"/tmp/not-approved"}}),
            json!({"host":"plain","inputs":inputs,"role_path":"/tmp/not-approved"}),
            json!({"host":"plain","inputs":inputs,"entry_point":"other"}),
            json!({"host":"plain","inputs":inputs,"fixed_args":{"config_root":"/tmp/not-approved"}}),
            json!({"host":"plain","inputs":inputs,"input_map":{"instance":"config_root"}}),
            json!({"host":"plain","inputs":inputs,"no_log":false}),
            json!({"host":"plain","inputs":inputs,"ansible_connection":"local"}),
            json!({"host":"plain","inputs":inputs,"extra_vars":{"ansible_connection":"local"}}),
        ].into_iter().enumerate() {
            let reply = server.request(200 + index as u64, "tools/call",
                json!({"name":"app_config","arguments":arguments})).await?;
            ensure!(reply["error"]["code"] == -32602
                || (reply["result"]["structuredContent"]["error"]["code"] == "invalid_argument"
                    && reply["result"]["structuredContent"]["error"]["remote_state_unknown"] == false),
                "invalid role inputs reached execution: {reply}");
            ensure!(!a.fixture.root.path().join("dependency-ran").exists(),
                "Rust-invalid inputs ran an Ansible dependency");
            ensure!(!a.fixture.root.path().join("application").exists());
            a.clean()?;
        }
        for (id, changed) in [(220, true), (221, false)] {
            // Receipt paths and literal labels are explicitly public domain data;
            // do not apply the module-only private-path assertion to this reply.
            let response = server.request(id, "tools/call", json!({"name":"app_config",
                "arguments":{"host":"plain","inputs":inputs}})).await?;
            ensure!(response["error"].is_null(), "MCP role call rejected: {response}");
            let envelope = &response["result"]["structuredContent"];
            verified_role(envelope, "successful", json!(changed))?;
            ensure!(envelope["error"].is_null() && envelope["data"]["runner_rc"] == 0);
            let projection = &envelope["data"]["projection"];
            ensure!(projection["status"] == "complete"
                && projection["value"]["instance"] == inputs["instance"]
                && projection["value"]["verified"] == true);
            let path = a.fixture.root.path().join("application/config.json");
            ensure!(projection["value"]["path"] == text(&path)?);
            let checksum = projection["value"]["checksum"].as_str().context("receipt checksum")?;
            ensure!(checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()));
            // Independent SSH reads, not the role's slurp or projected claim.
            let observed = a.fixture.direct("plain",
                &format!("cat {}", support::quote(&text(&path)?))).await?;
            ensure!(observed.status.success(), "independent target read failed");
            let bytes: Value = serde_json::from_slice(&observed.stdout)?;
            ensure!(bytes == json!({"instance":inputs["instance"],"config":inputs["config"]}),
                "root or nested caller data was interpreted rather than written literally");
            use sha2::{Digest, Sha256};
            ensure!(checksum == hex::encode(Sha256::digest(&observed.stdout)),
                "receipt did not describe actual independently observed target bytes");
            ensure!(fs::read_to_string(a.fixture.root.path().join("dependency-ran"))? == "dependency-ran");
            a.clean()?;
        }
        // The disabled branch genuinely accepts an omitted optional port.
        // Observe the target bytes rather than treating argspec metadata as data.
        let disabled_inputs = json!({"instance":"disabled-instance",
            "config":{"banner":"Disabled 雪","enabled":false}});
        let disabled = server.request(222,"tools/call",json!({"name":"app_config",
            "arguments":{"host":"plain","inputs":disabled_inputs}})).await?;
        ensure!(disabled["error"].is_null());
        let disabled = &disabled["result"]["structuredContent"];
        verified_role(disabled, "successful", json!(true))?;
        ensure!(disabled["error"].is_null());
        let disabled_path = text(&a.fixture.root.path().join("application/config.json"))?;
        let observed = a.fixture.direct("plain",
            &format!("cat {}", support::quote(&disabled_path))).await?;
        ensure!(observed.status.success());
        ensure!(serde_json::from_slice::<Value>(&observed.stdout)?
            == json!({"instance":disabled_inputs["instance"],"config":disabled_inputs["config"]}));
        a.clean()?;
        // Quoted unsafe scalars must not be re-resolved as YAML native values.
        // Check both flat role parameters and nested data through target bytes.
        for (id, scalar, banner) in [(223, "0", ""), (224, "false", "false"), (225, "null", "null")] {
            let scalar_inputs = json!({"instance":scalar,
                "config":{"banner":banner,"enabled":false}});
            let response = server.request(id, "tools/call", json!({"name":"app_config",
                "arguments":{"host":"plain","inputs":scalar_inputs}})).await?;
            let envelope = &response["result"]["structuredContent"];
            verified_role(envelope, "successful", json!(true))?;
            ensure!(envelope["error"].is_null()
                && envelope["data"]["projection"]["status"] == "complete"
                && envelope["data"]["projection"]["value"]["instance"] == scalar,
                "string-like role scalar changed type: {response}");
            let observed = a.fixture.direct("plain",
                &format!("cat {}", support::quote(&disabled_path))).await?;
            ensure!(observed.status.success(), "independent scalar read failed");
            ensure!(serde_json::from_slice::<Value>(&observed.stdout)? == scalar_inputs,
                "flat or nested string-like scalar changed type in managed bytes");
            ensure!(!a.forbidden.exists(), "caller data executed a controller lookup");
            a.clean()?;
        }
        let partial = a.call(&mut server, 230, "partial", json!({"host":"plain","inputs":{}})).await?;
        verified_role(&partial, "failed", json!(true))?;
        ensure!(!partial["error"].is_null() && partial["error"]["remote_state_unknown"] == false
            && partial["data"]["runner_rc"] == 2 && partial["data"]["tasks"]["failed"] == 1);
        ensure!(fs::read(a.fixture.root.path().join("partial-marker"))? == b"owned-change");
        let unavailable = a.call(&mut server, 237, "unavailable",
            json!({"host":"plain","inputs":{}})).await?;
        verified_role(&unavailable, "failed", json!(true))?;
        ensure!(!unavailable["error"].is_null()
            && unavailable["data"]["projection"] == json!({"status":"unavailable"}),
            "unreached collector fabricated a domain value: {unavailable}");
        ensure!(fs::read(a.fixture.root.path().join("unavailable-marker"))? == b"owned-change");
        let recovered = a.call(&mut server, 231, "recovered", json!({"host":"plain","inputs":{}})).await?;
        verified_role(&recovered, "successful", json!(true))?;
        ensure!(recovered["error"].is_null() && recovered["data"]["tasks"]["failed"] == 0
            && recovered["data"]["tasks"]["rescued"] == 1
            && recovered["data"]["tasks"]["ignored"] == 1
            && recovered["data"]["tasks"]["skipped"] == 1);
        ensure!(fs::read(a.fixture.root.path().join("recovered-marker"))? == b"owned-change");
        let summary = a.call(&mut server, 232, "summary", json!({"host":"plain","inputs":{}})).await?;
        verified_role(&summary, "successful", json!(true))?;
        ensure!(summary["error"].is_null() && summary["data"].get("projection").is_none());
        ensure!(fs::read(a.fixture.root.path().join("summary-marker"))? == b"owned-change");
        let handled = a.call(&mut server, 238, "handler", json!({"host":"plain","inputs":{}})).await?;
        verified_role(&handled, "successful", json!(true))?;
        ensure!(handled["error"].is_null()
            && handled["data"]["projection"]["status"] == "complete"
            && handled["data"]["projection"]["value"]["verified"] == true,
            "handler receipt was collected before handlers finished: {handled}");
        ensure!(fs::read(a.fixture.root.path().join("handler-marker"))? == b"owned-change");
        let repeated = a.call(&mut server, 239, "repeat_handler", json!({"host":"plain","inputs":{}})).await?;
        verified_role(&repeated, "successful", json!(true))?;
        ensure!(repeated["error"].is_null()
            && repeated["data"]["projection"]["status"] == "complete"
            && repeated["data"]["projection"]["value"]["verified"] == true,
            "repeated handler execution lost final postcondition: {repeated}");
        ensure!(fs::read(a.fixture.root.path().join("repeat_handler-marker"))? == b"owned-change");
        for (id, name, status) in [(233,"invalid","invalid"),(234,"missing","unavailable")] {
            let reply = a.call(&mut server,id,name,json!({"host":"plain","inputs":{}})).await?;
            verified_role(&reply, "successful", json!(false))?;
            ensure!(reply["error"]["code"] == "invalid_result"
                && reply["error"]["remote_state_unknown"] == false
                && reply["data"]["projection"] == json!({"status":status}),
                "domain failure erased verified role execution: {reply}");
        }
        let censored = a.call(&mut server,235,"censored",json!({"host":"plain","inputs":{}})).await?;
        verified_role(&censored, "successful", Value::Null)?;
        ensure!(censored["error"].is_null() && censored["data"]["censored"] == true
            && censored["data"]["projection"] == json!({"status":"censored"}));
        // Keep the marker-writing workload executable: running drifted content
        // must fail this test, not look like a pre-dispatch refusal.
        let source = roles.join("drift/tasks/main.yml");
        let mut changed = fs::read(&source)?;
        changed.extend_from_slice(b"\n# post-startup source drift\n");
        fs::write(&source, changed)?;
        let response = server.request(236,"tools/call",json!({"name":"drift",
            "arguments":{"host":"plain","inputs":{}}})).await?;
        ensure!(response["error"].is_null());
        let drift = &response["result"]["structuredContent"];
        ensure!(!drift["error"].is_null() && drift["error"]["remote_state_unknown"] == false,
            "post-startup source drift was not refused before dispatch: {response}");
        ensure!(!a.fixture.root.path().join("drift-marker").exists());
        a.clean()?;
        Ok(())
    }.await;
    let cleanup = a.stop(server).await;
    result?;
    cleanup
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaybookReceipt {
    instance: String,
    path: String,
    checksum: String,
    verified: bool,
}

async fn import_reviewed_playbook(
    a: &Acceptance,
    project: &Path,
    entry: &str,
    name: &str,
    contract: &Value,
    overlay: &Value,
) -> Result<PathBuf> {
    let snapshot = a
        .fixture
        .root
        .path()
        .join(format!("playbook-{name}-reviewed.json"));
    let contract_path = snapshot.with_extension("contract.json");
    let overlay_path = snapshot.with_extension("overlay.json");
    let input_path = snapshot.with_extension("input.json");
    fs::write(&contract_path, serde_json::to_vec(contract)?)?;
    fs::write(&overlay_path, serde_json::to_vec(overlay)?)?;
    fs::write(
        &input_path,
        serde_json::to_vec(&json!({
            "instance":"review-only","config":{"banner":"not executed","enabled":false}
        }))?,
    )?;
    let mut command = support::server_command(&a.fixture.config)?;
    command
        .args(["schema", "import-playbook", entry])
        .arg("--project-root")
        .arg(project)
        .arg("--input-schema")
        .arg(&contract_path)
        .arg("--overlay")
        .arg(&overlay_path)
        .arg("--output")
        .arg(&snapshot);
    let output = support::run(&mut command).await?;
    ensure!(
        output.status.success(),
        "public playbook import failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["binding_validated"] == true,
        "playbook overlay was not reviewed: {report}"
    );
    let mut command = support::server_command(&a.fixture.config)?;
    command
        .args(["schema", "verify-playbook"])
        .arg(&snapshot)
        .arg("--project-root")
        .arg(project)
        .arg("--overlay")
        .arg(&overlay_path)
        .arg("--input")
        .arg(&input_path);
    let output = support::run(&mut command).await?;
    ensure!(
        output.status.success(),
        "public playbook verification failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    Ok(snapshot)
}

async fn configure_playbooks(a: &Acceptance) -> Result<PathBuf> {
    let project = a.fixture.root.path().join("reviewed-project");
    fs::create_dir_all(project.join("tasks/nested"))?;
    fs::create_dir(project.join("vars"))?;
    fs::create_dir(project.join("templates"))?;
    let modules = project.join("collections/ansible_collections/reviewed/fixture/plugins/modules");
    fs::create_dir_all(&modules)?;
    fs::write(
        modules.join("read_file.py"),
        r#"#!/usr/bin/python
import base64
from ansible.module_utils.basic import AnsibleModule

def main():
    module = AnsibleModule(argument_spec={"path": {"type": "path", "required": True}},
                           supports_check_mode=True)
    try:
        with open(module.params["path"], "rb") as stream:
            content = stream.read(65537)
        if len(content) > 65536:
            module.fail_json(msg="File exceeds reviewed read bound")
        module.exit_json(changed=False, content=base64.b64encode(content).decode("ascii"))
    except OSError:
        module.fail_json(msg="Reviewed file could not be read")

if __name__ == "__main__":
    main()
"#,
    )?;
    fs::write(
        project.join("vars/site.yml"),
        "---\nreviewed_label: fixed-project\n",
    )?;
    fs::write(
        project.join("templates/document.json.j2"),
        "{{ {'instance': estus_arguments.instance, 'config': estus_arguments.config, 'source': reviewed_label} | to_json }}\n",
    )?;
    fs::write(
        project.join("tasks/first.yml"),
        "---\n- name: Nested fixed include\n  ansible.builtin.include_tasks: nested/write.yml\n",
    )?;
    fs::write(
        project.join("tasks/nested/write.yml"),
        r#"---
- name: Prove first play executed
  ansible.builtin.copy:
    dest: "{{ estus_arguments.first_marker }}"
    content: first-play
    mode: '0600'
- name: Render reviewed project template with literal caller data
  ansible.builtin.template:
    src: "{{ playbook_dir }}/templates/document.json.j2"
    dest: "{{ estus_arguments.destination }}"
    mode: '0600'
"#,
    )?;
    fs::write(
        project.join("site.yml"),
        r#"---
- name: Fixed project first play
  hosts: all
  no_log: false
  vars_files:
    - vars/site.yml
  tasks:
    - name: Include reviewed tasks
      ansible.builtin.include_tasks: tasks/first.yml
- name: Fixed project second play
  hosts: all
  gather_facts: false
  no_log: false
  tasks:
    - name: Prove second play executed
      ansible.builtin.copy:
        dest: "{{ estus_arguments.second_marker }}"
        content: second-play
        mode: '0600'
    - name: Read actual converged bytes
      reviewed.fixture.read_file:
        path: "{{ estus_arguments.destination }}"
      register: observed_document
    - name: Publish typed receipt
      ansible.builtin.set_fact:
        mcp_result:
          instance: "{{ estus_arguments.instance }}"
          path: "{{ estus_arguments.destination }}"
          checksum: "{{ observed_document.content | b64decode | hash('sha256') }}"
          verified: "{{ (observed_document.content | b64decode | from_json).config == estus_arguments.config }}"
"#,
    )?;
    fs::write(
        project.join("partial.yml"),
        r#"---
- name: Partial mutation is not rollback
  hosts: all
  gather_facts: false
  tasks:
    - name: Mutate before ordinary failure
      ansible.builtin.copy:
        dest: "{{ estus_arguments.first_marker }}"
        content: partial-change
        mode: '0600'
    - name: Deliberate known failure
      ansible.builtin.fail:
        msg: expected-playbook-failure
"#,
    )?;
    fs::write(
        project.join("drift.yml"),
        r#"---
- name: Drift must not dispatch
  hosts: all
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: tasks/drift.yml
"#,
    )?;
    fs::write(
        project.join("tasks/drift.yml"),
        r#"---
- name: Observable drift workload
  ansible.builtin.copy:
    dest: "{{ estus_arguments.first_marker }}"
    content: drift-workload-ran
    mode: '0600'
"#,
    )?;
    // The alternate tree is valid operator content but never selected by a call.
    let alternate = a.fixture.root.path().join("hostile-project");
    fs::create_dir(&alternate)?;
    fs::write(
        alternate.join("site.yml"),
        format!(
            "---\n- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.copy:\n        dest: {}\n        content: alternate-project-ran\n",
            serde_json::to_string(&text(
                &a.fixture.root.path().join("alternate-project-marker")
            )?)?
        ),
    )?;
    let input_schema = json!({"type":"object","properties":{
        "instance":{"type":"string","minLength":1,"maxLength":512},
        "config":{"type":"object","properties":{
            "banner":{"type":"string","maxLength":2048},
            "enabled":{"type":"boolean"},
            "port":{"type":"integer","minimum":1024,"maximum":65535}},
            "required":["banner","enabled"],"additionalProperties":false,
            "if":{"properties":{"enabled":{"const":true}},"required":["enabled"]},
            "then":{"required":["port"]}}},
        "required":["instance","config"],"additionalProperties":false});
    let mut contract = input_schema.clone();
    for key in ["destination", "first_marker", "second_marker"] {
        contract["properties"][key] = json!({"type":"string","minLength":1,"maxLength":4096});
        contract["required"]
            .as_array_mut()
            .context("contract required")?
            .push(json!(key));
    }
    let mut tools = toml::map::Map::new();
    let mut enabled = Vec::new();
    for (name, entry, result) in [
        ("document", "site.yml", role_receipt_result()),
        ("censored", "site.yml", role_receipt_result()),
        ("summary", "site.yml", json!({"kind":"ansible_summary"})),
        ("partial", "partial.yml", json!({"kind":"ansible_summary"})),
        ("drift", "drift.yml", json!({"kind":"ansible_summary"})),
    ] {
        let overlay = json!({"input_schema":input_schema,"fixed_args":{
            "destination":text(&a.fixture.root.path().join(format!("playbook-{name}-document.json")))?,
            "first_marker":text(&a.fixture.root.path().join(format!("playbook-{name}-first")))?,
            "second_marker":text(&a.fixture.root.path().join(format!("playbook-{name}-second")))?},
            "input_map":{"instance":"instance","config":"config"}});
        let snapshot =
            import_reviewed_playbook(a, &project, entry, name, &contract, &overlay).await?;
        let mut binding = json!({"description":"Reviewed fixed project real SSH acceptance",
            "revision":"1","authority":"automation","effects":["persistent_write","read"],
            "targets":["plain"],"execution":{"kind":"ansible_playbook",
                "snapshot":text(&snapshot)?,"project_root":text(&project)?,"no_log":name == "censored"},
            "result":result,"limits":{"timeout_secs":12}});
        for key in ["input_schema", "fixed_args", "input_map"] {
            binding[key] = overlay[key].clone();
        }
        tools.insert(name.into(), table(binding)?);
        enabled.push(name);
    }
    // Public authoring must refuse an output inside the hashed source and an
    // internal source symlink. Neither rejection is allowed to execute tasks.
    let contract_path = a
        .fixture
        .root
        .path()
        .join("playbook-document-reviewed.contract.json");
    let inside_output = project.join("not-a-snapshot.json");
    for linked in [false, true] {
        let link = project.join("linked-source");
        if linked {
            std::os::unix::fs::symlink(&alternate, &link)?;
        }
        let output_path = if linked {
            a.fixture.root.path().join("symlink-project-refused.json")
        } else {
            inside_output.clone()
        };
        let mut command = support::server_command(&a.fixture.config)?;
        command
            .args(["schema", "import-playbook", "site.yml"])
            .arg("--project-root")
            .arg(&project)
            .arg("--input-schema")
            .arg(&contract_path)
            .arg("--output")
            .arg(&output_path);
        let output = support::run(&mut command).await?;
        if linked {
            fs::remove_file(&link)?;
        }
        ensure!(
            !output.status.success() && !output_path.exists(),
            "unsafe source/output was accepted by public playbook import"
        );
        let report: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            report["error_code"]
                == if linked {
                    "playbook_content_symlink"
                } else {
                    "playbook_output_inside_source"
                },
            "source/output rejection came from an unrelated error: {report}"
        );
    }
    let mut guarded = vec![(PathBuf::from("/tmp"), "invalid_playbook_source")];
    // APFS aliases may have distinct lexical paths but identical directory identity.
    let case_alias = project.with_file_name("REVIEWED-PROJECT");
    if case_alias.is_dir() {
        guarded.push((case_alias, "playbook_output_inside_source"));
    }
    for (source, expected) in guarded {
        let output_path = project.join("case-alias-snapshot.json");
        let mut command = support::server_command(&a.fixture.config)?;
        command
            .args(["schema", "import-playbook", "site.yml"])
            .arg("--project-root")
            .arg(source)
            .arg("--input-schema")
            .arg(&contract_path)
            .arg("--output")
            .arg(&output_path);
        let output = support::run(&mut command).await?;
        let report: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            !output.status.success() && report["error_code"] == expected && !output_path.exists(),
            "source identity/workspace overlap guard failed: {report}"
        );
    }
    let mut config: toml::Table = toml::from_str(&fs::read_to_string(&a.fixture.config)?)?;
    config.insert("enabled_tools".into(), table(json!(enabled))?);
    config.insert("tools".into(), toml::Value::Table(tools));
    fs::write(&a.fixture.config, toml::to_string(&config)?)?;
    Ok(project)
}

async fn playbook_target_bytes(a: &Acceptance, name: &str) -> Result<Vec<u8>> {
    let path = a.fixture.root.path().join(name);
    let output = a
        .fixture
        .direct("plain", &format!("cat {}", support::quote(&text(&path)?)))
        .await?;
    ensure!(
        output.status.success(),
        "independent SSH target read failed for {name}"
    );
    Ok(output.stdout)
}

async fn playbook_markers_absent(a: &Acceptance, names: &[&str]) -> Result<()> {
    for name in names {
        let path = a.fixture.root.path().join(name);
        let output = a
            .fixture
            .direct(
                "plain",
                &format!("test ! -e {}", support::quote(&text(&path)?)),
            )
            .await?;
        ensure!(
            output.status.success(),
            "refused operation mutated target {name}"
        );
    }
    a.clean()
}

/// cargo test --test automation_exec real_runner_playbook_acceptance -- --ignored --exact --nocapture
/// Uses the same selected pinned Runner, target Python, Nix sshd and unprivileged
/// localhost prerequisites as the role entry. No external network is contacted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected pinned Runner/target Python, Nix sshd, non-root private localhost fixture"]
async fn real_runner_playbook_acceptance() -> Result<()> {
    let acceptance = Acceptance::start().await?;
    let result: Result<()> = async {
        let project = configure_playbooks(&acceptance).await?;
        playbook_scenarios(&acceptance, &project).await
    }
    .await;
    let cleanup = acceptance.fixture.stop().await;
    result?;
    cleanup
}

async fn playbook_scenarios(a: &Acceptance, project: &Path) -> Result<()> {
    let untouched = [
        "playbook-document-first",
        "playbook-document-second",
        "playbook-document-document.json",
        "playbook-summary-first",
        "playbook-partial-first",
        "playbook-drift-first",
        "alternate-project-marker",
    ];
    // Import and verification above are source-only, even for a mutating play.
    playbook_markers_absent(a, &untouched).await?;
    let mut server = a.server().await?;
    let result: Result<()> = async {
        let literal = format!("{{{{ lookup('pipe', 'touch {}') }}}}", text(&a.forbidden)?);
        let inputs = json!({"instance":literal,"config":{
            "banner":format!("雪😀 \"quoted\"\nnext\\line\t{literal} {{{{ 6 * 7 }}}}"),
            "enabled":true,"port":8080}});
        let mut invalid = vec![
            json!({"host":"plain","inputs":[]}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":"x","enabled":true}}}),
            json!({"host":"plain","inputs":{"instance":"x","config":{"banner":42,"enabled":false}}}),
        ];
        for (key, value) in [
            ("inventory", json!("/tmp/unreviewed-inventory")),
            ("tags", json!(["skip-reviewed"])),
            ("ansible_connection", json!("local")),
            ("ansible_python_interpreter", json!("/tmp/unreviewed-python")),
            ("ansible_become", json!(true)),
            ("become", json!(true)),
            ("playbook", json!("partial.yml")),
            ("project_root", json!(text(&a.fixture.root.path().join("hostile-project"))?)),
            ("extra_vars", json!({"ansible_connection":"local"})),
            ("fixed_args", json!({"destination":"/tmp/unreviewed-destination"})),
            ("input_map", json!({"instance":"ansible_connection"})),
        ] {
            let mut top = json!({"host":"plain","inputs":inputs});
            top[key] = value.clone();
            invalid.push(top);
            let mut nested = json!({"host":"plain","inputs":inputs});
            nested["inputs"][key] = value;
            invalid.push(nested);
        }
        for (index, arguments) in invalid.into_iter().enumerate() {
            let reply = server.request(310 + index as u64, "tools/call",
                json!({"name":"document","arguments":arguments})).await?;
            ensure!(reply["error"]["code"] == -32602
                || (reply["result"]["structuredContent"]["error"]["code"] == "invalid_argument"
                    && reply["result"]["structuredContent"]["error"]["remote_state_unknown"] == false),
                "invalid controls or conditional inputs reached playbook execution: {reply}");
            playbook_markers_absent(a, &untouched).await?;
        }
        for (id, changed) in [(350, true), (351, false)] {
            // The receipt intentionally publishes domain paths and literal labels;
            // only the private audit and summary-only replies exclude these.
            let response = server.request(id, "tools/call", json!({"name":"document",
                "arguments":{"host":"plain","inputs":inputs}})).await?;
            ensure!(response["error"].is_null(), "MCP playbook call rejected: {response}");
            let envelope = &response["result"]["structuredContent"];
            verified_role(envelope, "successful", json!(changed))?;
            ensure!(envelope["error"].is_null() && envelope["data"]["runner_rc"] == 0);
            let projection = &envelope["data"]["projection"];
            let receipt: PlaybookReceipt = serde_json::from_value(projection["value"].clone())?;
            ensure!(projection["status"] == "complete" && receipt.verified
                && receipt.instance == inputs["instance"].as_str().context("literal instance")?);
            ensure!(receipt.path ==
                text(&a.fixture.root.path().join("playbook-document-document.json"))?);
            let observed = playbook_target_bytes(a, "playbook-document-document.json").await?;
            let document: Value = serde_json::from_slice(&observed)?;
            ensure!(document == json!({"instance":inputs["instance"],"config":inputs["config"],
                "source":"fixed-project"}), "literal inputs or fixed vars/template/include changed target bytes");
            use sha2::{Digest, Sha256};
            ensure!(receipt.checksum == hex::encode(Sha256::digest(&observed)),
                "projected checksum did not describe independently read target bytes");
            ensure!(playbook_target_bytes(a, "playbook-document-first").await? == b"first-play");
            ensure!(playbook_target_bytes(a, "playbook-document-second").await? == b"second-play");
            playbook_markers_absent(a, &["alternate-project-marker"]).await?;
        }
        let disabled_inputs = json!({"instance":"disabled","config":{"banner":"disabled 雪","enabled":false}});
        let response = server.request(352, "tools/call", json!({"name":"document",
            "arguments":{"host":"plain","inputs":disabled_inputs}})).await?;
        ensure!(response["error"].is_null());
        verified_role(&response["result"]["structuredContent"], "successful", json!(true))?;
        ensure!(response["result"]["structuredContent"]["error"].is_null());
        let observed = playbook_target_bytes(a, "playbook-document-document.json").await?;
        ensure!(serde_json::from_slice::<Value>(&observed)? ==
            json!({"instance":"disabled","config":disabled_inputs["config"],"source":"fixed-project"}));
        let summary = a.call(&mut server, 353, "summary",
            json!({"host":"plain","inputs":inputs})).await?;
        verified_role(&summary, "successful", json!(true))?;
        ensure!(summary["error"].is_null() && summary["data"].get("projection").is_none());
        let summary_bytes = playbook_target_bytes(a, "playbook-summary-document.json").await?;
        ensure!(serde_json::from_slice::<Value>(&summary_bytes)? ==
            json!({"instance":inputs["instance"],"config":inputs["config"],"source":"fixed-project"}));
        let censored = a.call(&mut server, 357, "censored",
            json!({"host":"plain","inputs":inputs})).await?;
        verified_role(&censored, "successful", Value::Null)?;
        ensure!(censored["error"].is_null() && censored["data"]["censored"] == true
            && censored["data"]["projection"] == json!({"status":"censored"}),
            "trusted no_log:false play overrode public binding censorship: {censored}");
        let censored_bytes = playbook_target_bytes(a, "playbook-censored-document.json").await?;
        ensure!(serde_json::from_slice::<Value>(&censored_bytes)? ==
            json!({"instance":inputs["instance"],"config":inputs["config"],"source":"fixed-project"}));
        let partial = a.call(&mut server, 354, "partial",
            json!({"host":"plain","inputs":inputs})).await?;
        ensure!(partial["data"]["status"] == "failed" && partial["data"]["complete"] == true
            && partial["data"]["changed"] == true && partial["data"]["runner_rc"] == 2
            && partial["data"]["tasks"]["failed"] == 1
            && partial["data"]["owned_group_cleanup"] == "signalled_and_reaped"
            && !partial["error"].is_null() && partial["error"]["remote_state_unknown"] == false,
            "ordinary playbook failure erased known partial mutation: {partial}");
        ensure!(playbook_target_bytes(a, "playbook-partial-first").await? == b"partial-change");
        // Exercise both included-source and entry-source drift independently:
        // restore the first exact byte sequence before changing the other file.
        for (id, source) in [(355, "tasks/drift.yml"), (356, "drift.yml")] {
            let path = project.join(source);
            let reviewed = fs::read(&path)?;
            let mut changed = reviewed.clone();
            changed.extend_from_slice(b"\n# post-startup source drift\n");
            fs::write(&path, changed)?;
            let response = server.request(id, "tools/call", json!({"name":"drift",
                "arguments":{"host":"plain","inputs":inputs}})).await;
            fs::write(&path, reviewed)?;
            let response = response?;
            ensure!(response["error"].is_null());
            let envelope = &response["result"]["structuredContent"];
            ensure!(!envelope["error"].is_null()
                && envelope["error"]["remote_state_unknown"] == false,
                "changed reviewed {source} was dispatched: {response}");
            playbook_markers_absent(a, &["playbook-drift-first", "alternate-project-marker"]).await?;
        }
        Ok(())
    }.await;
    // Await EOF/reaping and private-workspace cleanup even after a failed assertion.
    let cleanup = a.stop(server).await;
    result?;
    cleanup
}
