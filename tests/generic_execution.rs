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

#[test]
fn runner_check_mode_skipped_is_never_an_observation() -> Result<()> {
    let script = r#"
import json, runpy, sys
m = runpy.run_path(sys.argv[1], run_name='skipped_preview_test')
class Sink:
    def __init__(self):
        self.events = []
    def emit(self, kind, **fields):
        self.events.append((kind, fields))
sink = Sink()
plan = {'fields': {'changed': ['changed']}, 'schema': {'type': 'object', 'properties': {'changed': {'type': 'boolean'}}, 'required': ['changed'], 'additionalProperties': False}, 'max_bytes': 1024, 'max_items': 16, 'max_depth': 4}
ev = m['Evidence'](sink, 'ansible.posix.sysctl', False, plan, None, True, False)
ev.status({'status': 'starting'}, {})
ev.status({'status': 'running'}, {})
ev.status({'status': 'successful'}, {})
ev.event({'event': 'playbook_on_task_start', 'event_data': {'host': 'estus_target', 'task': 'estus_module', 'task_action': 'ansible.posix.sysctl', 'task_uuid': 'u1'}})
ev.event({'event': 'runner_on_skipped', 'event_data': {'host': 'estus_target', 'task': 'estus_module', 'task_action': 'ansible.posix.sysctl', 'task_uuid': 'u1', 'res': {'changed': False, 'skip_reason': 'Conditional result was False'}}})
ev.event({'event': 'playbook_on_stats', 'event_data': {'ok': {}, 'failures': {}, 'dark': {}, 'skipped': {'estus_target': 1}, 'changed': {}, 'processed': {'estus_target': 1}, 'rescued': {}, 'ignored': {}}})
class R:
    rc = 0
    status = 'successful'
ev.reconcile(R())
print(json.dumps({'tasks': ev.tasks, 'events': sink.events}))
"#;
    let output =
        Command::new(std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
            .args(["-I", "-B", "-c", script])
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/automation/python/runner.py"))
            .output()?;
    ensure!(
        output.status.success(),
        "skipped preview check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(parsed["tasks"]["skipped"] == 1 && parsed["tasks"]["ok"] == 0);
    let proj = parsed["events"]
        .as_array()
        .context("events")?
        .iter()
        .find(|e| e[0] == "projection")
        .context("projection event")?;
    ensure!(proj[1]["projection"] == json!({"status": "unavailable"}));
    Ok(())
}

async fn import_module_snapshot(
    config: &std::path::Path,
    module: &str,
    overlay: &Value,
    overlay_path: &std::path::Path,
    snapshot_path: &std::path::Path,
) -> Result<()> {
    fs::write(overlay_path, serde_json::to_vec(overlay)?)?;
    let mut import = support::server_command(config)?;
    import
        .args(["schema", "import", module, "--overlay"])
        .arg(overlay_path)
        .arg("--output")
        .arg(snapshot_path);
    let result = support::run_authoring(&mut import).await?;
    ensure!(
        result.status.success(),
        "schema import {module} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_ANSIBLE_RUNTIME, ESTUS_TEST_TARGET_PYTHON and existing disposable SSH fixture"]
async fn real_mcp_named_module_disposable_smoke() -> Result<()> {
    let runtime = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME").context("selected pinned runtime")?,
    )?;
    let python = std::env::var("ESTUS_TEST_TARGET_PYTHON").context("target python")?;
    let fixture = Fixture::start().await?;
    let result: Result<()> = async {
        let workspace = fixture.root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let owned = fixture.root.path().join("owned-named-target");
        let canary = fixture.root.path().join("template-canary");
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config["limits"]["operation_timeout_secs"] = 60.into();
        config["limits"]["max_timeout_secs"] = 60.into();
        config.insert(
            "automation".into(),
            toml::Value::try_from(json!({
                "runtime": runtime, "workspace_root": workspace,
                "targets": {"plain": {"destination": "plain", "python": python}}
            }))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;

        // Reject ansible.builtin.setup without reviewed fixed gather_subset and gather_timeout.
        let setup_bad = json!({
            "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
            "fixed_args": {},
            "input_map": {}
        });
        let setup_overlay_path = fixture.root.path().join("setup-bad-overlay.json");
        let setup_snap = fixture.root.path().join("setup-bad.json");
        fs::write(&setup_overlay_path, serde_json::to_vec(&setup_bad)?)?;
        let mut bad_import = support::server_command(&fixture.config)?;
        bad_import
            .args(["schema", "import", "ansible.builtin.setup", "--overlay"])
            .arg(&setup_overlay_path)
            .arg("--output")
            .arg(&setup_snap);
        let bad_out = support::run_authoring(&mut bad_import).await?;
        ensure!(!bad_out.status.success(), "setup without gather_subset/gather_timeout succeeded");

        let copy_overlay = json!({
            "input_schema": {"type": "object", "properties": {
                "content": {"type": "string", "maxLength": 512},
                "src": {"type": "string", "maxLength": 512}
            }, "additionalProperties": false},
            "fixed_args": {"dest": owned, "mode": "0600"},
            "input_map": {"content": "content", "src": "src"},
            "argument_types": {"mode": {"type": "string", "enum": ["0600"]}}
        });
        let copy_snap = fixture.root.path().join("copy.json");
        import_module_snapshot(
            &fixture.config,
            "ansible.builtin.copy",
            &copy_overlay,
            &fixture.root.path().join("copy-overlay.json"),
            &copy_snap,
        )
        .await?;

        let debug_overlay = json!({
            "input_schema": {"type": "object", "properties": {
                "msg": {"type": "string", "maxLength": 256}
            }, "required": ["msg"], "additionalProperties": false},
            "fixed_args": {},
            "input_map": {"msg": "msg"}
        });
        let debug_snap = fixture.root.path().join("debug.json");
        import_module_snapshot(
            &fixture.config,
            "ansible.builtin.debug",
            &debug_overlay,
            &fixture.root.path().join("debug-overlay.json"),
            &debug_snap,
        )
        .await?;

        let tools_table = json!({
            "change_owned_copy": {
                "description": "Reviewed copy to owned file.",
                "revision": "1",
                "targets": ["plain"],
                "authority": "automation",
                "effects": ["persistent_write"],
                "execution": {"kind": "ansible_module", "snapshot": copy_snap},
                "input_schema": copy_overlay["input_schema"],
                "fixed_args": copy_overlay["fixed_args"],
                "input_map": copy_overlay["input_map"],
                "argument_types": copy_overlay["argument_types"],
                "result": {"kind": "ansible_summary"}
            },
            "inspect_secret_debug": {
                "description": "No-log debug check.",
                "revision": "1",
                "targets": ["plain"],
                "authority": "automation",
                "effects": ["sensitive_read"],
                "execution": {"kind": "ansible_module", "snapshot": debug_snap, "no_log": true},
                "input_schema": debug_overlay["input_schema"],
                "fixed_args": debug_overlay["fixed_args"],
                "input_map": debug_overlay["input_map"],
                "result": {
                    "kind": "ansible_projection",
                    "fields": {"msg": ["msg"]},
                    "max_bytes": 512, "max_items": 16, "max_depth": 4,
                    "schema": {"type": "object", "properties": {"msg": {"type": "string", "maxLength": 256}}, "required": ["msg"], "additionalProperties": false}
                }
            }
        });
        config.insert("tools".into(), toml::Value::try_from(tools_table)?);
        config.insert(
            "enabled_tools".into(),
            toml::Value::try_from(json!(["change_owned_copy", "inspect_secret_debug"]))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;

        let mut server = WireServer::start(&fixture.config)?;
        let calls: Result<()> = async {
            server.initialize().await?;
            let listed = server.request(2, "tools/list", json!({})).await?;
            let names: Vec<_> = listed["result"]["tools"]
                .as_array()
                .context("tools list")?
                .iter()
                .filter_map(|t| t["name"].as_str())
                .collect();
            ensure!(
                names.contains(&"change_owned_copy") && names.contains(&"inspect_secret_debug"),
                "named bindings missing from tools/list: {names:?}"
            );

            let literal = format!("{{{{ lookup('pipe', 'touch {}') }}}}; $(false)", canary.display());
            let copied = server
                .request(
                    3,
                    "tools/call",
                    json!({"name": "change_owned_copy", "arguments": {"host": "plain", "inputs": {"content": literal}}}),
                )
                .await?;
            let sc = &copied["result"]["structuredContent"];
            ensure!(sc["error"].is_null() && sc["data"]["complete"] == true, "copy failed: {copied}");
            ensure!(fs::read_to_string(&owned)? == literal && !canary.exists());

            let controller_source = fixture.root.path().join("owned-controller-source");
            fs::write(&controller_source, "approved controller canary")?;
            let copied_src = server
                .request(
                    4,
                    "tools/call",
                    json!({"name": "change_owned_copy", "arguments": {"host": "plain", "inputs": {"src": controller_source}}}),
                )
                .await?;
            ensure!(
                copied_src["result"]["structuredContent"]["error"].is_null()
                    && fs::read_to_string(&owned)? == "approved controller canary",
                "controller-side copy failed: {copied_src}"
            );

            let nolog = server
                .request(
                    5,
                    "tools/call",
                    json!({"name": "inspect_secret_debug", "arguments": {"host": "plain", "inputs": {"msg": "PRIVATE_NAMED_NO_LOG_SENTINEL"}}}),
                )
                .await?;
            let nolog_sc = &nolog["result"]["structuredContent"];
            ensure!(
                nolog_sc["data"]["censored"] == true
                    && nolog_sc["data"]["projection"]["status"] == "censored",
                "no_log lost precedence: {nolog}"
            );
            ensure!(!nolog.to_string().contains("PRIVATE_NAMED_NO_LOG_SENTINEL"));

            let inject = server
                .request(
                    6,
                    "tools/call",
                    json!({"name": "change_owned_copy", "arguments": {"host": "plain", "inputs": {"dest": "/unapproved"}}}),
                )
                .await?;
            ensure!(inject["error"]["code"] == -32602);
            Ok(())
        }
        .await;
        let stopped = server.stop(None).await?;
        ensure!(!stopped.text().contains("lookup('pipe'"), "argument leaked to audit");
        ensure!(!stopped.text().contains("PRIVATE_NAMED_NO_LOG_SENTINEL"));
        calls?;

        // Tampered snapshot content digest fails activation.
        let mut snapshot: Value = serde_json::from_slice(&fs::read(&copy_snap)?)?;
        snapshot["content_sha256"] = json!("0".repeat(64));
        fs::write(&copy_snap, serde_json::to_vec(&snapshot)?)?;
        rejected_activation(&fixture.config, "invalid_schema_snapshot").await?;
        Ok(())
    }
    .await;
    let cleanup = fixture.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires selected runtime and disposable local SSH fixture"]
async fn real_mcp_named_module_generation_and_preview_gate() -> Result<()> {
    let selected =
        fs::canonicalize(std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME").context("runtime")?)?;
    let fixture = Fixture::start().await?;
    let result: Result<()> = async {
        let workspace = fixture.root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let sysctl_conf = fixture.root.path().join("99-estus-preview.conf");
        let mut config: toml::Table = toml::from_str(&fs::read_to_string(&fixture.config)?)?;
        config["limits"]["operation_timeout_secs"] = 60.into();
        config["limits"]["max_timeout_secs"] = 60.into();
        config.insert(
            "automation".into(),
            toml::Value::try_from(json!({
                "runtime": selected, "workspace_root": workspace,
                "targets": {"plain": {"destination": "plain", "python": selected.join("bin/python3")}}
            }))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;

        let sysctl_overlay = json!({
            "input_schema": {"type": "object", "properties": {
                "value": {"type": "string", "enum": ["1", "2"]}
            }, "required": ["value"], "additionalProperties": false},
            "fixed_args": {
                "name": "net.ipv4.ip_forward",
                "sysctl_file": sysctl_conf,
                "sysctl_set": false,
                "reload": false,
                "state": "present"
            },
            "input_map": {"value": "value"}
        });
        let sysctl_snap = fixture.root.path().join("sysctl.json");
        import_module_snapshot(
            &fixture.config,
            "ansible.posix.sysctl",
            &sysctl_overlay,
            &fixture.root.path().join("sysctl-overlay.json"),
            &sysctl_snap,
        )
        .await?;

        config.insert(
            "rules".into(),
            toml::Value::try_from(json!({
                "plain": {"require_preview": true}
            }))?,
        );
        config.insert(
            "tools".into(),
            toml::Value::try_from(json!({
                "preview_sysctl": {
                    "description": "Check-mode preview with diff for sysctl file.",
                    "revision": "1",
                    "targets": ["plain"],
                    "authority": "automation",
                    "effects": ["read"],
                    "execution": {"kind": "ansible_module", "snapshot": sysctl_snap, "check_mode": true, "diff": true},
                    "input_schema": sysctl_overlay["input_schema"],
                    "fixed_args": sysctl_overlay["fixed_args"],
                    "input_map": sysctl_overlay["input_map"],
                    "result": {
                        "kind": "ansible_projection",
                        "fields": {"changed": ["changed"], "diff": ["diff"]},
                        "max_bytes": 4096, "max_items": 64, "max_depth": 5,
                        "schema": {
                            "type": "object",
                            "properties": {
                                "changed": {"type": "boolean"},
                                "diff": {
                                    "type": "object",
                                    "properties": {
                                        "before": {"type": "string", "maxLength": 2048},
                                        "after": {"type": "string", "maxLength": 2048},
                                        "before_header": {"type": "string", "maxLength": 256},
                                        "after_header": {"type": "string", "maxLength": 256},
                                        "prepared": {"type": "string", "maxLength": 2048}
                                    },
                                    "additionalProperties": false
                                }
                            },
                            "required": ["changed"],
                            "additionalProperties": false
                        }
                    }
                },
                "change_sysctl": {
                    "description": "Apply reviewed sysctl file setting.",
                    "revision": "1",
                    "targets": ["plain"],
                    "authority": "automation",
                    "effects": ["persistent_write"],
                    "execution": {"kind": "ansible_module", "snapshot": sysctl_snap},
                    "input_schema": sysctl_overlay["input_schema"],
                    "fixed_args": sysctl_overlay["fixed_args"],
                    "input_map": sysctl_overlay["input_map"],
                    "result": {"kind": "ansible_summary"}
                }
            }))?,
        );
        config.insert(
            "enabled_tools".into(),
            toml::Value::try_from(json!(["preview_sysctl", "change_sysctl"]))?,
        );
        fs::write(&fixture.config, toml::to_string(&config)?)?;

        let mut server = WireServer::start(&fixture.config)?;
        let checked: Result<()> = async {
            server.initialize().await?;
            // Apply without prior preview fails closed with preview_required.
            let before = server
                .request(
                    2,
                    "tools/call",
                    json!({"name": "change_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            ensure!(
                before["result"]["structuredContent"]["error"]["code"] == "preview_required",
                "apply without preview did not reject: {before}"
            );
            ensure!(!sysctl_conf.exists());

            // Preview runs in check mode (non-mutating) and captures diff.
            let preview = server
                .request(
                    3,
                    "tools/call",
                    json!({"name": "preview_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            let preview_sc = &preview["result"]["structuredContent"];
            ensure!(
                preview_sc["error"].is_null()
                    && preview_sc["data"]["changed"] == true
                    && preview_sc["data"]["projection"]["status"] == "complete",
                "preview_sysctl failed: {preview}"
            );
            ensure!(!sysctl_conf.exists(), "preview mutated target file");

            // Argument mismatch rejects with preview_required and leaves preview unconsumed or separate.
            let arg_mismatch = server
                .request(
                    4,
                    "tools/call",
                    json!({"name": "change_sysctl", "arguments": {"host": "plain", "inputs": {"value": "2"}}}),
                )
                .await?;
            ensure!(
                arg_mismatch["result"]["structuredContent"]["error"]["code"] == "preview_required",
                "mismatched args bypassed require_preview: {arg_mismatch}"
            );

            // Out-of-band target state drift invalidates pre_state_digest.
            fs::write(&sysctl_conf, "net.ipv4.ip_forward = 0\n")?;
            let drifted = server
                .request(
                    5,
                    "tools/call",
                    json!({"name": "change_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            ensure!(
                drifted["result"]["structuredContent"]["error"]["code"] == "preview_required",
                "pre-state drift bypassed require_preview: {drifted}"
            );

            // Re-preview under current pre-state, then apply succeeds and consumes entry.
            let preview2 = server
                .request(
                    6,
                    "tools/call",
                    json!({"name": "preview_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            ensure!(preview2["result"]["structuredContent"]["error"].is_null());

            let applied = server
                .request(
                    7,
                    "tools/call",
                    json!({"name": "change_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            ensure!(
                applied["result"]["structuredContent"]["error"].is_null()
                    && applied["result"]["structuredContent"]["data"]["changed"] == true,
                "apply after matching preview failed: {applied}"
            );
            ensure!(fs::read_to_string(&sysctl_conf)?.contains("net.ipv4.ip_forward=1"));

            // Re-applying without a fresh preview fails closed because the entry was consumed.
            let replay = server
                .request(
                    8,
                    "tools/call",
                    json!({"name": "change_sysctl", "arguments": {"host": "plain", "inputs": {"value": "1"}}}),
                )
                .await?;
            ensure!(
                replay["result"]["structuredContent"]["error"]["code"] == "preview_required",
                "consumed preview was reused: {replay}"
            );
            Ok(())
        }
        .await;
        server.stop(None).await?;
        checked
    }
    .await;
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
