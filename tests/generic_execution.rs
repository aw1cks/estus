//! Public MCP acceptance for the separately opted-in broad execution surface.
#![cfg(unix)]
#[allow(dead_code)]
mod support;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};
use support::{Fixture, WireServer};

// Calls the shipped reducer, never a replacement implementation.
fn reduce(result: Value, no_log: bool, bytes: usize) -> Result<Value> {
    let bridge = "import json,runpy,sys; m=runpy.run_path(sys.argv[1],run_name='generic_consumer'); print(json.dumps(m['module_result'](json.loads(sys.argv[2]),sys.argv[3]=='true',dict(max_bytes=int(sys.argv[4]),max_items=32,max_depth=4))))";
    let output =
        Command::new(std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
            .args(["-I", "-B", "-c", bridge])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/automation/python/runner.py"))
            .arg(serde_json::to_string(&result)?)
            .arg(if no_log { "true" } else { "false" })
            .arg(bytes.to_string())
            .output()?;
    ensure!(
        output.status.success(),
        "product reducer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
#[test]
fn explicit_module_result_honors_nested_censorship_and_bounds() -> Result<()> {
    ensure!(reduce(json!({"value":"secret"}), true, 512)? == json!({"status":"censored"}));
    ensure!(
        reduce(
            json!({"value":{"_ansible_no_log":true,"secret":"private"}}),
            false,
            512
        )? == json!({"status":"censored"})
    );
    let public = reduce(
        json!({"invocation":{"module_args":{"secret":"private"}},"stdout":"literal {{ x }}","nested":{"environment":{"secret":"private"},"ok":true}}),
        false,
        512,
    )?;
    let value: Value = serde_json::from_str(
        public["value"]["module_result_json"]
            .as_str()
            .context("JSON text publication")?,
    )?;
    ensure!(value == json!({"stdout":"literal {{ x }}","nested":{"ok":true}}));
    ensure!(
        reduce(json!({"stdout":"x".repeat(1024)}), false, 64)? == json!({"status":"unavailable"})
    );
    Ok(())
}

#[test]
fn runner_evidence_treats_failed_false_as_unknown_while_reconciling_stats() -> Result<()> {
    let script = r#"
import json, runpy, sys
m = runpy.run_path(sys.argv[1], run_name='evidence_test')
class Sink:
    def __init__(self):
        self.events = []
    def emit(self, kind, **fields):
        self.events.append((kind, fields))
def run_case(changed, stats_changed, no_log=False):
    sink = Sink()
    ev = m['Evidence'](sink, 'ansible.builtin.command', no_log)
    ev.status({'status': 'starting'}, {})
    ev.status({'status': 'running'}, {})
    ev.status({'status': 'failed'}, {})
    ev.event({'event': 'playbook_on_task_start', 'event_data': {'host': 'estus_target', 'task': 'estus_module', 'task_action': 'ansible.builtin.command', 'task_uuid': 'u1'}})
    ev.event({'event': 'runner_on_failed', 'event_data': {'host': 'estus_target', 'task': 'estus_module', 'task_action': 'ansible.builtin.command', 'task_uuid': 'u1', 'res': {'changed': changed}}})
    ev.event({'event': 'playbook_on_stats', 'event_data': {'ok': {}, 'failures': {'estus_target': 1}, 'dark': {}, 'skipped': {}, 'changed': {'estus_target': stats_changed} if stats_changed else {}, 'processed': {'estus_target': 1}, 'rescued': {}, 'ignored': {}}})
    class R:
        rc = 2
        status = 'failed'
    try:
        ev.reconcile(R())
    except m['Invalid']:
        pass
    return dict(invalid=ev.invalid, changed=ev.changed, task=[e[1] for e in sink.events if e[0] == 'task'][0])
out = {
    'failed_false': run_case(False, 0),
    'failed_true': run_case(True, 0),
    'failed_censored': run_case(True, 1, no_log=True),
    'contradiction': run_case(False, 1),
}
print(json.dumps(out))
"#;
    let output =
        Command::new(std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
            .args(["-I", "-B", "-c", script])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/automation/python/runner.py"))
            .output()?;
    ensure!(
        output.status.success(),
        "runner evidence check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(parsed["failed_false"]["invalid"] == false);
    ensure!(parsed["failed_false"]["changed"].is_null());
    ensure!(parsed["failed_false"]["task"]["changed"].is_null());
    ensure!(parsed["failed_true"]["invalid"] == false);
    ensure!(parsed["failed_true"]["changed"] == true);
    ensure!(parsed["failed_true"]["task"]["changed"] == true);
    ensure!(parsed["failed_censored"]["invalid"] == false);
    ensure!(parsed["failed_censored"]["changed"].is_null());
    ensure!(parsed["contradiction"]["invalid"] == true);
    Ok(())
}

async fn call(server: &mut WireServer, id: u64, args: Value) -> Result<Value> {
    let response = server
        .request(id, "tools/call", json!({"name":"generic","arguments":args}))
        .await?;
    ensure!(
        response["error"].is_null(),
        "MCP rejected bounded call: {response}"
    );
    Ok(response["result"]["structuredContent"].clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_ANSIBLE_RUNTIME, ESTUS_TEST_TARGET_PYTHON and existing disposable SSH fixture"]
async fn real_mcp_generic_disposable_smoke() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME").context("selected pinned runtime")?,
    )?;
    let python = PathBuf::from(
        std::env::var_os("ESTUS_TEST_TARGET_PYTHON").context("selected target Python")?,
    );
    let fixture = Fixture::start().await?;
    let result:Result<()>=async {
        let workspace=fixture.root.path().join("generic-workspaces");fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let approval=fixture.root.path().join("generic-inventory.json");
        let owned=fixture.root.path().join("owned-generic-file");let canary=fixture.root.path().join("forbidden-generic-lookup");
        let mut config:toml::Table=toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config["limits"]["operation_timeout_secs"] = 60.into();
        config["limits"]["max_timeout_secs"] = 60.into();
        config.insert("automation".into(),toml::Value::try_from(json!({"runtime":runtime,"workspace_root":workspace,"targets":{"plain":{"destination":"plain","python":python}}}))?);
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut import=support::server_command(&fixture.config)?;import.args(["schema","import-inventory","--output"]).arg(&approval);
        let output=support::run_authoring(&mut import).await.context("generic inventory authoring")?;ensure!(output.status.success(),"explicit inventory import failed: {}",String::from_utf8_lossy(&output.stdout));
        let binding=json!({"description":"Owned disposable generic acceptance","revision":"1","targets":["plain"],"authority":"automation","effects":["sensitive_read","runtime_write","persistent_write","availability","unknown"],"execution":{"kind":"ansible_generic","policy":{"snapshot":approval,"scope":{"kind":"exact","modules":["ansible.builtin.copy","ansible.builtin.debug","ansible.builtin.file"]},"deny":["ansible.builtin.file"],"disclosure":{"kind":"module_result","max_bytes":1024,"max_items":32,"max_depth":4},"retention":{"max_entries":4,"max_bytes":32768,"lifetime_secs":60}}},"result":{"kind":"ansible_summary"}});
        config.insert("tools".into(),toml::Value::try_from(json!({"generic":binding}))?);
        config.insert("enabled_tools".into(),toml::Value::try_from(json!([]))?);
        // Generic execution is not enabled by an ordinary named-tool profile.
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut disabled=WireServer::start(&fixture.config)?;
        disabled.initialize().await?;
        let denied=disabled.request(2,"tools/call",json!({"name":"generic","arguments":{"operation":"list","host":"plain"}})).await?;
        ensure!(!denied["error"].is_null(),"generic tool became callable without independent enablement");
        disabled.stop(None).await?;
        config.insert("enabled_generic_tools".into(),toml::Value::try_from(json!(["generic"]))?);
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut server=WireServer::start(&fixture.config)?;
        let calls:Result<()>=async {
            server.initialize().await?;
            let listed=call(&mut server,2,json!({"operation":"list","host":"plain","limit":1})).await?;
            ensure!(listed["data"]["modules"].as_array().context("module list")?.len()==1);
            let described=call(&mut server,20,json!({"operation":"describe","host":"plain","module":"ansible.builtin.copy"})).await?;
            ensure!(described["data"]["documentation"]["status"]=="partial"
                && described["data"]["documentation"]["short_description"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=512),
                "real selected-runtime public documentation was not captured: {described}");
            ensure!(described["data"]["generation"]==listed["data"]["generation"]);
            let denied=call(&mut server,3,json!({"operation":"call","host":"plain","module":"ansible.builtin.file","arguments":{"path":owned,"state":"absent"}})).await?;ensure!(denied["error"]["code"]=="policy_denied");
            let alias=call(&mut server,4,json!({"operation":"call","host":"plain","module":"ansible.legacy.copy","arguments":{}})).await?;ensure!(alias["error"]["code"]=="policy_denied");
            let literal=format!("{{{{ lookup('pipe', 'touch {}') }}}}; $(false)",canary.display());
            let copied=call(&mut server,5,json!({"operation":"call","host":"plain","module":"ansible.builtin.copy","arguments":{"dest":owned,"content":literal,"mode":"0600"}})).await?;
            ensure!(copied["error"].is_null() && copied["data"]["complete"]==true,"generic raw metadata module failed: {copied}");
            ensure!(fs::read_to_string(&owned)?==literal && !canary.exists(),"caller strings were evaluated or wrong effect");
            let controller_source=fixture.root.path().join("owned-controller-source");
            fs::write(&controller_source,"approved controller canary")?;
            let copied_source=call(&mut server,21,json!({"operation":"call","host":"plain","module":"ansible.builtin.copy","arguments":{"src":controller_source,"dest":owned,"mode":"0600"}})).await?;
            ensure!(copied_source["error"].is_null() && fs::read_to_string(&owned)?=="approved controller canary",
                "controller-side copy action did not read the owned canary: {copied_source}");
            let invalid=call(&mut server,6,json!({"operation":"call","host":"plain","module":"ansible.builtin.copy","arguments":{"dest":owned,"not_a_module_option":true}})).await?;ensure!(invalid["data"]["status"]=="failed","Ansible did not reject invalid args: {invalid}");
            let receipt=copied["data"]["receipt"].as_str().context("retained receipt")?;
            let retained=call(&mut server,7,json!({"operation":"receipts","host":"plain","receipt":receipt})).await?;
            ensure!(retained["data"]["data"]["generic"]["module"]=="ansible.builtin.copy");
            let inject=server.request(8,"tools/call",json!({"name":"generic","arguments":{"operation":"call","host":"plain","module":"ansible.builtin.debug","arguments":{},"become":true}})).await?;ensure!(!inject["error"].is_null());
            Ok(())
        }.await;
        let stopped=server.stop(None).await?;ensure!(!stopped.text().contains("lookup('pipe'"),"argument value reached audit");calls?;
        reviewed_raw_file(&fixture, &config, &owned).await?;
        // Locked approval mismatch fails startup; no request refreshes it.
        let mut snapshot:Value=serde_json::from_slice(&fs::read(&approval)?)?;snapshot["content_sha256"]=json!("0".repeat(64));fs::write(&approval,serde_json::to_vec(&snapshot)?)?;
        rejected_activation(&fixture.config, "generic_runtime_drift").await?;
        // Follow-selected is advance consent, but only an explicit new startup activates it.
        let policy = config["tools"]["generic"]["execution"]["policy"].as_table_mut().context("generic policy")?;
        policy.insert("runtime_policy".into(), "follow_selected_runtime".into());
        policy.insert("no_log".into(), true.into());
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut follow=WireServer::start(&fixture.config)?;
        let followed:Result<()>=async {
            follow.initialize().await?;
            let result=call(&mut follow,10,json!({"operation":"call","host":"plain","module":"ansible.builtin.debug","arguments":{"msg":"PRIVATE_GENERIC_NO_LOG_SENTINEL"}})).await?;
            ensure!(result["data"]["censored"]==true && result["data"]["projection"]["status"]=="censored","no_log lost precedence: {result}");
            ensure!(!result.to_string().contains("PRIVATE_GENERIC_NO_LOG_SENTINEL"));
            ensure!(result["data"]["generic"]["policy_generation"].as_str().is_some_and(|v|v.len()==64));
            Ok(())
        }.await;
        let log=follow.stop(None).await?;ensure!(!log.text().contains("PRIVATE_GENERIC_NO_LOG_SENTINEL"));followed?;
        Ok(())
    }.await;
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

async fn reviewed_raw_file(
    fixture: &Fixture,
    base: &toml::Table,
    owned: &std::path::Path,
) -> Result<()> {
    let overlay = json!({
        "input_schema":{"type":"object","properties":{},"additionalProperties":false},
        "fixed_args":{"path":owned,"state":"file","mode":"0644"},
        "input_map":{},
        "argument_types":{"mode":{"type":"string","enum":["0644"]}}
    });
    let overlay_path = fixture.root.path().join("reviewed-overlay.json");
    let snapshot = fixture.root.path().join("reviewed-file.json");
    fs::write(&overlay_path, serde_json::to_vec(&overlay)?)?;
    let mut import = support::server_command(&fixture.config)?;
    import
        .args(["schema", "import", "ansible.builtin.file", "--overlay"])
        .arg(&overlay_path)
        .arg("--output")
        .arg(&snapshot);
    let result = support::run_authoring(&mut import).await?;
    ensure!(
        result.status.success(),
        "reviewed raw-mode import failed: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    let binding = json!({
        "description":"Owned reviewed file mode", "revision":"1", "targets":["plain"],
        "authority":"automation", "effects":["persistent_write"],
        "execution":{"kind":"ansible_module","snapshot":snapshot},
        "input_schema":overlay["input_schema"], "fixed_args":overlay["fixed_args"],
        "input_map":overlay["input_map"], "argument_types":overlay["argument_types"],
        "result":{"kind":"ansible_summary"}
    });
    let mut config = base.clone();
    config.insert(
        "tools".into(),
        toml::Value::try_from(json!({"reviewed_file":binding}))?,
    );
    config.insert(
        "enabled_generic_tools".into(),
        toml::Value::try_from(json!([]))?,
    );
    config.insert(
        "enabled_tools".into(),
        toml::Value::try_from(json!(["reviewed_file"]))?,
    );
    let path = fixture.root.path().join("reviewed.toml");
    fs::write(&path, toml::to_string(&config)?)?;
    fs::set_permissions(owned, fs::Permissions::from_mode(0o600))?;
    let mut server = WireServer::start(&path)?;
    let calls: Result<()> = async {
        server.initialize().await?;
        let result = server
            .request(
                2,
                "tools/call",
                json!({
                    "name":"reviewed_file","arguments":{"host":"plain","inputs":{}}
                }),
            )
            .await?;
        let receipt = &result["result"]["structuredContent"];
        ensure!(
            receipt["error"].is_null() && receipt["data"]["changed"] == true,
            "reviewed file mode did not execute: {result}"
        );
        ensure!(
            fs::metadata(owned)?.permissions().mode() & 0o777 == 0o644,
            "independent mode observation disagrees"
        );
        let denied = server.request(3,"tools/call",json!({
            "name":"reviewed_file","arguments":{"host":"plain","inputs":{"path":"/unapproved"}}
        })).await?;
        ensure!(
            denied["error"]["code"] == -32602,
            "fixed path override escaped review: {denied}"
        );
        Ok(())
    }
    .await;
    server.stop(None).await?;
    calls?;
    config["tools"]["reviewed_file"]["fixed_args"]["mode"] = "0777".into();
    fs::write(&path, toml::to_string(&config)?)?;
    rejected_activation(&path, "invalid_config").await?;
    ensure!(
        fs::metadata(owned)?.permissions().mode() & 0o777 == 0o644,
        "rejected approval changed the file"
    );
    Ok(())
}

fn mutable_runtime(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
    fn copy_tree(source: &std::path::Path, destination: &std::path::Path) -> Result<()> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if entry.file_name() == "__pycache__" {
                continue;
            }
            ensure!(!kind.is_symlink(), "fixture source has an interior symlink");
            let output = destination.join(entry.file_name());
            if kind.is_dir() {
                copy_tree(&entry.path(), &output)?;
            } else {
                fs::copy(entry.path(), output)?;
            }
        }
        Ok(())
    }
    fs::create_dir(destination)?;
    fs::create_dir(destination.join("bin"))?;
    std::os::unix::fs::symlink(source.join("bin/python3"), destination.join("bin/python3"))?;
    std::os::unix::fs::symlink(source.join("python"), destination.join("python"))?;
    std::os::unix::fs::symlink(source.join("collections"), destination.join("collections"))?;
    std::os::unix::fs::symlink(source.join("ansible.cfg"), destination.join("ansible.cfg"))?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(source.join("runtime.json"))?)?;
    let core = fs::canonicalize(
        source
            .join(manifest["site_packages"].as_str().context("runtime site")?)
            .join("ansible"),
    )?;
    copy_tree(&core, &destination.join("site-packages/ansible"))?;
    manifest["site_packages"] = json!("site-packages");
    fs::write(
        destination.join("runtime.json"),
        serde_json::to_vec(&manifest)?,
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected runtime and disposable local SSH fixture"]
async fn real_mcp_generic_generation_cutover() -> Result<()> {
    let selected =
        fs::canonicalize(std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME").context("runtime")?)?;
    let fixture = Fixture::start().await?;
    let result: Result<()> = async {
        let runtime = fixture.root.path().join("mutable-runtime");
        mutable_runtime(&selected, &runtime)?;
        let workspace = fixture.root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let owned = fixture.root.path().join("generation-canary");
        fs::write(&owned, "unchanged generation canary")?;
        let approval = fixture.root.path().join("inventory.json");
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config["limits"]["operation_timeout_secs"] = 60.into();
        config["limits"]["max_timeout_secs"] = 60.into();
        config.insert("automation".into(),toml::Value::try_from(json!({
            "runtime":runtime,"workspace_root":workspace,
            "targets":{"plain":{"destination":"plain","python":selected.join("bin/python3")}}
        }))?);
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut import = support::server_command(&fixture.config)?;
        import.args(["schema","import-inventory","--output"]).arg(&approval);
        ensure!(support::run_authoring(&mut import).await?.status.success(), "mutable runtime inventory import failed");
        let binding = json!({
            "description":"Explicit generation acceptance","revision":"1","targets":["plain"],
            "authority":"automation","effects":["sensitive_read","runtime_write","persistent_write","availability","unknown"],
            "execution":{"kind":"ansible_generic","policy":{
                "snapshot":approval,"scope":{"kind":"collections","collections":["ansible.builtin"]},
                "deny":["ansible.builtin.file"],
                "restrictions":{"ansible.builtin.stat":{
                    "input_schema":{"type":"object","properties":{},"additionalProperties":false},
                    "fixed_args":{"path":owned},"input_map":{}
                }}
            }},
            "result":{"kind":"ansible_summary"}
        });
        config.insert("tools".into(),toml::Value::try_from(json!({"generic":binding}))?);
        config.insert("enabled_tools".into(),toml::Value::try_from(json!([]))?);
        config.insert("enabled_generic_tools".into(),toml::Value::try_from(json!(["generic"]))?);
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut collections = WireServer::start(&fixture.config)?;
        let checked: Result<()> = async {
            collections.initialize().await?;
            let outside = call(&mut collections,2,json!({"operation":"describe","host":"plain","module":"community.general.modprobe"})).await?;
            ensure!(outside["error"]["code"]=="policy_denied", "collection scope widened");
            let fixed = call(&mut collections,3,json!({"operation":"call","host":"plain","module":"ansible.builtin.stat","arguments":{}})).await?;
            ensure!(fixed["error"].is_null() && fixed["data"]["generic"]["validation"]=="reviewed_restriction");
            let override_path = call(&mut collections,4,json!({"operation":"call","host":"plain","module":"ansible.builtin.stat","arguments":{"dest":"/unapproved"}})).await?;
            ensure!(override_path["error"]["code"]=="invalid_argument", "fixed argument alias override escaped restriction");
            Ok(())
        }.await;
        collections.stop(None).await?;
        checked?;
        config["tools"]["generic"]["execution"]["policy"]["scope"] = toml::Value::try_from(json!({"kind":"selected_runtime"}))?;
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut active = WireServer::start(&fixture.config)?;
        let checked: Result<()> = async {
            active.initialize().await?;
            let modules = runtime.join("site-packages/ansible/modules");
            fs::copy(modules.join("stat.py"), modules.join("estus_generation_probe.py"))?;
            let absent = call(&mut active,5,json!({"operation":"describe","host":"plain","module":"ansible.builtin.estus_generation_probe"})).await?;
            ensure!(absent["error"]["code"]=="policy_denied", "active inventory silently acquired new code");
            let drift = call(&mut active,6,json!({"operation":"call","host":"plain","module":"ansible.builtin.copy","arguments":{"dest":owned,"content":"must not execute"}})).await?;
            ensure!(!drift["error"].is_null() && fs::read_to_string(&owned)?=="unchanged generation canary",
                "content drift reached mutation: {drift}");
            Ok(())
        }.await;
        active.stop(None).await?;
        checked?;
        rejected_activation(&fixture.config, "generic_runtime_drift").await?;
        config["tools"]["generic"]["execution"]["policy"].as_table_mut().context("generic policy")?
            .insert("runtime_policy".into(), "follow_selected_runtime".into());
        fs::write(&fixture.config,toml::to_string(&config)?)?;
        let mut follow = WireServer::start(&fixture.config)?;
        let checked: Result<()> = async {
            follow.initialize().await?;
            let permitted = call(&mut follow,7,json!({"operation":"call","host":"plain","module":"ansible.builtin.estus_generation_probe","arguments":{"path":owned}})).await?;
            ensure!(permitted["error"].is_null() && permitted["data"]["complete"]==true, "explicit generation did not acquire provisioned module: {permitted}");
            let denied = call(&mut follow,8,json!({"operation":"call","host":"plain","module":"ansible.builtin.file","arguments":{"path":owned,"state":"absent"}})).await?;
            ensure!(denied["error"]["code"]=="policy_denied" && owned.exists(), "deny lost precedence on upgrade");
            let tools = follow.request(9,"tools/list",json!({})).await?;
            let tool = tools["result"]["tools"].as_array().context("tools")?.iter().find(|tool|tool["name"]=="generic").context("generic tool")?;
            ensure!(tool["_meta"]["generic_policy"]["scope_diff"]["added"].as_array()
                .is_some_and(|added|added.contains(&json!("ansible.builtin.estus_generation_probe"))),
                "activation hid module-scope widening");
            Ok(())
        }.await;
        follow.stop(None).await?;
        checked
    }.await;
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

async fn rejected_activation(path: &std::path::Path, code: &str) -> Result<()> {
    let mut command = support::server_command(path)?;
    let output = support::run_authoring(&mut command).await?;
    ensure!(
        output.status.code() == Some(1) && output.stdout.is_empty(),
        "invalid approval activated instead of failing closed"
    );
    ensure!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .any(|record| record["event"] == "error" && record["code"] == code),
        "activation failed for a different reason: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
