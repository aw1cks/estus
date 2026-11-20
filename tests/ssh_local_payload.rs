//! Native payload discovery, workstation health payloads and the preview gate.
#[path = "support/ssh_local.rs"]
#[allow(dead_code)]
mod sshl;
#[path = "support/core.rs"]
#[allow(dead_code)]
// Shared support items used by other suites are inert here.
mod support;
use sshl::*;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use support::Fixture;
use support::WireServer;
use support::assert_masters_gone;
use support::masters;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils, python3, and a non-root local account"]
async fn ssh_workstation_dynamic_bundled_health_payloads() -> Result<()> {
    let python3 = support::find_program("python3")?;
    let python_dir = python3.parent().context("python3 dir")?;
    let fixture = Fixture::start_with_sshd_config(&format!(
        "SetEnv PATH={}:/usr/bin:/bin\n",
        python_dir.display()
    ))
    .await?;
    let scenario = async {
        let mut command = support::raw_server_command()?;
        command
            .arg("--workstation")
            .arg("--ssh-config")
            .arg(&fixture.ssh_config);
        let mut server = WireServer::start_command(command)?;
        let cases = async {
            server.initialize().await?;
            let listed = server.request(2, "tools/list", json!({})).await?;
            let tools = listed["result"]["tools"]
                .as_array()
                .context("workstation tools")?;
            // Only catalog templates that declare a workstation policy load here.
            for name in [
                "observe_cpu",
                "observe_memory",
                "observe_pressure",
                "observe_kernel_state",
                "inspect_processes",
            ] {
                let tool = tools
                    .iter()
                    .find(|t| t["name"] == name)
                    .with_context(|| format!("missing bundled dynamic tool {name}"))?;
                ensure!(
                    tool["inputSchema"]["properties"]["host"]
                        == json!({"type": "string", "minLength": 1, "maxLength": 256}),
                    "unexpected host schema on {name}: {}",
                    tool["inputSchema"]["properties"]["host"]
                );
            }
            ensure!(
                !tools.iter().any(|t| t["name"] == "exec_sudo"),
                "workstation mode without configured sudo exposed ssh_sudo"
            );

            let targets = script_wire_call(&mut server, 3, "observe_targets", json!({})).await?;
            let targets_data = succeeded(&targets)?;
            ensure!(targets_data["mode"] == "open");
            ensure!(targets_data["targets"] == json!([]));

            let stat = script_wire_call(
                &mut server,
                30,
                "observe_stat",
                json!({"host": "plain", "path": "/"}),
            )
            .await?;
            ensure!(stat["error"].is_null(), "observe_stat failed: {stat}");
            for (id, name, inputs) in [
                (4, "observe_cpu", json!({"limit": 4})),
                (5, "observe_memory", json!({})),
                (6, "observe_pressure", json!({})),
                (7, "observe_kernel_state", json!({})),
                (
                    8,
                    "inspect_processes",
                    json!({"uid": 0, "name_contains": "", "limit": 4}),
                ),
            ] {
                let reply = script_wire_call(
                    &mut server,
                    id,
                    name,
                    json!({"host": "plain", "inputs": inputs}),
                )
                .await?;
                let data = succeeded(&reply)?;
                ensure!(
                    data["status"] == "successful" && data["projection"]["status"] == "complete",
                    "{name} failed: {data}"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = server.log.clone();
        let owned = masters(&log);
        let stopped = server.stop(None).await;
        if let Err(err) = cases {
            anyhow::bail!("{err}; stderr: {}", log.text());
        }
        let gone = match owned {
            Ok(owned) => {
                ensure!(
                    owned.len() == 1,
                    "expected native SFTP and native payloads to share 1 SSH ControlMaster, saw {}: {owned:?}",
                    owned.len()
                );
                assert_masters_gone(&owned).await
            }
            Err(error) => Err(error),
        };
        let _ = stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils, python3, and a non-root local account"]
async fn ssh_native_payload_candidate_and_python_min_discovery_failures() -> Result<()> {
    let python = support::find_program("python3")?;
    let fixture = Fixture::start().await?;
    let scenario = async {
        let marker = fixture.root.path().join("must_not_dispatch");
        let payload_src = format!(
            "import json, pathlib; pathlib.Path({:?}).write_text('ran'); print(json.dumps({{'ok': True}}))\n",
            marker
        );
        let src_path = fixture.root.path().join("probe.py");
        fs::write(&src_path, &payload_src)?;
        let source_sha256 = hex::encode(Sha256::digest(payload_src.as_bytes()));

        #[derive(serde::Serialize)]
        struct Requirements {
            python_min: [u16; 2],
            interpreters: Vec<String>,
            modules: Vec<String>,
            executables: Vec<String>,
            paths: Vec<String>,
            #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
            executable_candidates: std::collections::BTreeMap<String, Vec<String>>,
        }
        // Two payload directories share the collector, so each can pin a
        // different requirement set against identical bytes.
        let write_manifest = |dir_name: &str,
                              python_min: [u16; 2],
                              exec_cands: std::collections::BTreeMap<String, Vec<String>>|
         -> Result<PathBuf> {
            let directory = fixture.root.path().join(dir_name);
            fs::create_dir_all(&directory)?;
            let source = directory.join("collector.py");
            fs::copy(&src_path, &source)?;
            let contract = json!({"schema":{"type":"object","additionalProperties":false,"required":["target_python"],"properties":{"target_python":{"type":"string","minLength":1,"maxLength":4096}}},"aliases":{"aliases":{},"properties":{"target_python":{"aliases":{},"properties":{}}}},"defaults":{},"review_required":[]});
            let argv: Vec<Value> = Vec::new();
            let requirements = Requirements {
                python_min,
                interpreters: Vec::new(),
                modules: vec!["json".to_owned()],
                executables: Vec::new(),
                paths: Vec::new(),
                executable_candidates: exec_cands,
            };
            fs::write(
                directory.join("manifest.json"),
                serde_json::to_vec_pretty(&json!({
                    "schema": 1, "protocol": 1, "adapter_version": 1, "change_policy": "read_only",
                    "source_sha256": source_sha256, "max_source_bytes": 1_048_576usize,
                    "argv": argv, "requirements": requirements, "contract": contract
                }))?,
            )?;
            Ok(source)
        };

        let missing_exec = write_manifest(
            "missing_exec",
            [3, 8],
            std::collections::BTreeMap::from([(
                "missing-tool".to_owned(),
                vec!["/usr/sbin/definitely-missing-estus-c17".to_owned()],
            )]),
        )?;
        let high_py = write_manifest("high_py", [3, 99], Default::default())?;
        let config_path = fixture.root.path().join("operator.toml");
        fs::write(
            &config_path,
            format!(
                r#"
mode = "headless"
capabilities = {{ named = true }}
[selection]
allow = ["observe_missing_exec", "observe_high_py"]
[ssh]
config_file = {ssh_config:?}
[targets.plain]
ssh_host = "plain"
[automation.targets.plain]
destination = "plain"
python = {python:?}
[tools.observe_missing_exec]
description = "Missing executable candidate"
revision = "r1"
targets = ["plain"]
authority = "automation"
effects = ["read"]
execution = {{ kind = "native_payload", source = {missing_exec:?}, no_log = false }}
fixed_args = {{ target_python = {python:?} }}
input_map = {{}}
input_schema = {{ type = "object", additionalProperties = false, required = [], properties = {{}} }}
result = {{ kind = "capability_projection", fields = {{ ok = ["mcp_result", "ok"] }}, max_bytes = 1024, max_items = 16, max_depth = 3, schema = {{ type = "object", additionalProperties = false, required = ["ok"], properties = {{ ok = {{ type = "boolean" }} }} }} }}
[tools.observe_high_py]
description = "Higher python_min requirement"
revision = "r1"
targets = ["plain"]
authority = "automation"
effects = ["read"]
execution = {{ kind = "native_payload", source = {high_py:?}, no_log = false }}
fixed_args = {{ target_python = {python:?} }}
input_map = {{}}
input_schema = {{ type = "object", additionalProperties = false, required = [], properties = {{}} }}
result = {{ kind = "capability_projection", fields = {{ ok = ["mcp_result", "ok"] }}, max_bytes = 1024, max_items = 16, max_depth = 3, schema = {{ type = "object", additionalProperties = false, required = ["ok"], properties = {{ ok = {{ type = "boolean" }} }} }} }}
"#,
                ssh_config = fixture.ssh_config,
                python = python.to_string_lossy(),
            ),
        )?;
        let mut server = WireServer::start(&config_path)?;
        let cases = async {
            server.initialize().await?;
            for (id, tool) in [(2, "observe_missing_exec"), (3, "observe_high_py")] {
                let reply = script_wire_call(&mut server, id, tool, json!({"host": "plain", "inputs": {}})).await?;
                ensure!(
                    reply["error"]["code"] == "resource_unavailable",
                    "{tool} did not fail with resource_unavailable: {reply}"
                );
                ensure!(
                    reply["data"]["status"] == "not_started",
                    "{tool} started remote execution: {reply}"
                );
            }
            ensure!(!marker.exists(), "payload executed despite failed discovery");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = server.log.clone();
        let owned = masters(&log);
        let stopped = server.stop(None).await;
        if let Err(err) = cases {
            anyhow::bail!("{err}; stderr: {}", log.text());
        }
        let _ = stopped?;
        assert_masters_gone(&owned?).await
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils, python3, and a non-root local account"]
async fn ssh_native_payload_preview_gate_across_revisions() -> Result<()> {
    let python = support::find_program("python3")?;
    let fixture = Fixture::start().await?;
    let scenario = async {
        let applied_marker = fixture.root.path().join("applied_kmod");
        let preview_src = "import json\nprint(json.dumps({'ok': True}))\n";
        let apply_src = format!(
            "import json, pathlib\npathlib.Path({:?}).write_text('applied')\nprint(json.dumps({{'ok': True, 'outcome': 'verified'}}))\n",
            applied_marker
        );
        let preview_py = fixture.root.path().join("preview_kmod.py");
        let apply_py = fixture.root.path().join("apply_kmod.py");
        fs::write(&preview_py, preview_src)?;
        fs::write(&apply_py, &apply_src)?;

        #[derive(serde::Serialize)]
        struct Requirements {
            python_min: [u16; 2],
            interpreters: Vec<String>,
            modules: Vec<String>,
            executables: Vec<String>,
            paths: Vec<String>,
        }
        let write_kmod_manifest = |dir_name: &str,
                                   src: &str,
                                   policy: &'static str,
                                   with_params: bool|
         -> Result<(PathBuf, Value, Value, Value)> {
            let directory = fixture.root.path().join(dir_name);
            fs::create_dir_all(&directory)?;
            let source_path = directory.join("collector.py");
            fs::write(&source_path, src)?;
            let source_sha256 = hex::encode(Sha256::digest(src.as_bytes()));
            let (input_schema, contract, input_map) = if with_params {
                (
                    json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["name", "parameters"],
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 64},
                            "parameters": {"type": "object", "additionalProperties": false, "required": [], "properties": {}}
                        }
                    }),
                    json!({
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["target_python", "name", "parameters"],
                            "properties": {
                                "target_python": {"type": "string", "minLength": 1, "maxLength": 4096},
                                "name": {"type": "string", "minLength": 1, "maxLength": 64},
                                "parameters": {"type": "object", "additionalProperties": false, "required": [], "properties": {}}
                            }
                        },
                        "aliases": {
                            "aliases": {},
                            "properties": {
                                "target_python": {"aliases": {}, "properties": {}},
                                "name": {"aliases": {}, "properties": {}},
                                "parameters": {"aliases": {}, "properties": {}}
                            }
                        },
                        "defaults": {},
                        "review_required": []
                    }),
                    json!({"name": "name", "parameters": "parameters"}),
                )
            } else {
                (
                    json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string", "minLength": 1, "maxLength": 64}
                        }
                    }),
                    json!({
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["target_python", "name"],
                            "properties": {
                                "target_python": {"type": "string", "minLength": 1, "maxLength": 4096},
                                "name": {"type": "string", "minLength": 1, "maxLength": 64}
                            }
                        },
                        "aliases": {
                            "aliases": {},
                            "properties": {
                                "target_python": {"aliases": {}, "properties": {}},
                                "name": {"aliases": {}, "properties": {}}
                            }
                        },
                        "defaults": {},
                        "review_required": []
                    }),
                    json!({"name": "name"}),
                )
            };
            let overlay = json!({
                "input_schema": input_schema,
                "fixed_args": {"target_python": python.to_string_lossy()},
                "input_map": input_map
            });
            let result = json!({
                "kind": "capability_projection",
                "fields": {"ok": ["mcp_result", "ok"]},
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["ok"],
                    "properties": {"ok": {"type": "boolean"}}
                },
                "max_bytes": 1024,
                "max_items": 16,
                "max_depth": 3
            });
            let argv: Vec<Value> = Vec::new();
            let requirements = Requirements {
                python_min: [3, 8],
                interpreters: Vec::new(),
                modules: vec!["json".to_owned()],
                executables: Vec::new(),
                paths: Vec::new(),
            };
            fs::write(
                directory.join("manifest.json"),
                serde_json::to_vec_pretty(&json!({
                    "schema": 1,
                    "protocol": 1,
                    "adapter_version": 1,
                    "change_policy": policy,
                    "source_sha256": source_sha256,
                    "max_source_bytes": 1_048_576usize,
                    "argv": argv,
                    "requirements": requirements,
                    "contract": contract
                }))?,
            )?;
            Ok((
                source_path,
                overlay["input_schema"].clone(),
                overlay["input_map"].clone(),
                result,
            ))
        };

        let (preview_py, preview_schema, preview_map, preview_res) = write_kmod_manifest(
            "preview_payload",
            preview_src,
            "read_only",
            false,
        )?;
        let (apply_py, apply_schema, apply_map, apply_res) = write_kmod_manifest(
            "apply_payload",
            &apply_src,
            "mutation_success",
            true,
        )?;
        let config_doc = json!({
            "mode": "headless",
            "capabilities": {"named": true},
            "selection": {"allow": ["preview_kernel_module_load", "change_kernel_module_load"]},
            "ssh": {"config_file": fixture.ssh_config},
            "targets": {"plain": {"ssh_host": "plain", "require_preview": true}},
            "automation": {"targets": {"plain": {"destination": "plain", "python": python.to_string_lossy()}}},
            "tools": {
                "preview_kernel_module_load": {
                    "description": "Preview kernel module load",
                    "revision": "preview_v2",
                    "targets": ["plain"],
                    "authority": "automation",
                    "effects": ["read"],
                    "execution": {"kind": "native_payload", "source": preview_py, "no_log": false},
                    "fixed_args": {"target_python": python.to_string_lossy()},
                    "input_map": preview_map,
                    "input_schema": preview_schema,
                    "result": preview_res
                },
                "change_kernel_module_load": {
                    "description": "Apply kernel module load",
                    "revision": "apply_v1",
                    "targets": ["plain"],
                    "authority": "automation",
                    "effects": ["runtime_write"],
                    "execution": {"kind": "native_payload", "source": apply_py, "no_log": false},
                    "fixed_args": {"target_python": python.to_string_lossy()},
                    "input_map": apply_map,
                    "input_schema": apply_schema,
                    "result": apply_res
                }
            }
        });
        let config_path = fixture.root.path().join("operator-preview.toml");
        fs::write(&config_path, toml::to_string(&toml::Value::try_from(config_doc)?)?)?;
        let mut server = WireServer::start(&config_path)?;
        let cases = async {
            server.initialize().await?;
            let before = script_wire_call(
                &mut server,
                2,
                "change_kernel_module_load",
                json!({"host": "plain", "inputs": {"name": "dummy", "parameters": {}}}),
            )
            .await?;
            ensure!(
                before["error"]["code"] == "preview_required",
                "apply without preview did not reject: {before}"
            );
            ensure!(!applied_marker.exists());

            let preview = script_wire_call(
                &mut server,
                3,
                "preview_kernel_module_load",
                json!({"host": "plain", "inputs": {"name": "dummy"}}),
            )
            .await?;
            ensure!(preview["error"].is_null(), "preview failed: {preview}");

            let mismatch = script_wire_call(
                &mut server,
                4,
                "change_kernel_module_load",
                json!({"host": "plain", "inputs": {"name": "tun", "parameters": {}}}),
            )
            .await?;
            ensure!(
                mismatch["error"]["code"] == "preview_required",
                "mismatched module bypassed require_preview: {mismatch}"
            );
            ensure!(!applied_marker.exists());

            let applied = script_wire_call(
                &mut server,
                5,
                "change_kernel_module_load",
                json!({"host": "plain", "inputs": {"name": "dummy", "parameters": {}}}),
            )
            .await?;
            ensure!(
                applied["error"].is_null() && applied_marker.exists(),
                "matching cross-revision native preview failed to unlock apply: {applied}"
            );

            let replay = script_wire_call(
                &mut server,
                6,
                "change_kernel_module_load",
                json!({"host": "plain", "inputs": {"name": "dummy", "parameters": {}}}),
            )
            .await?;
            ensure!(
                replay["error"]["code"] == "preview_required",
                "consumed native preview was reused: {replay}"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let log = server.log.clone();
        let owned = masters(&log);
        let stopped = server.stop(None).await;
        if let Err(err) = cases {
            anyhow::bail!("{err}; stderr: {}", log.text());
        }
        let _ = stopped?;
        assert_masters_gone(&owned?).await
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}
