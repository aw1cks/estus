//! Write quarantine: read concurrency and uncertain-ack quarantine behaviour.
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
use indoc::formatdoc;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use support::Fixture;
use support::WireServer;
use support::assert_masters_gone;
use support::masters;
use tokio::time::sleep;
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_native_payload_read_concurrency_and_write_quarantine() -> Result<()> {
    let fixture = Fixture::start().await?;
    let python = support::find_program("python3")?;
    let scenario = async {
        let marker_dir = fixture.root.path().join("payload-markers");
        fs::create_dir(&marker_dir)?;
        let read_source_code = r#"import estus_runtime, json, os, time
cfg = estus_runtime.request()[0]
marker = cfg["marker"]
release = cfg["release"]
with open(marker, "w", encoding="utf-8") as handle:
    handle.write("started")
deadline = time.monotonic() + 10.0
while not os.path.exists(release) and time.monotonic() < deadline:
    time.sleep(0.02)
print(json.dumps({"ok": True}))
"#;
        let write_source_code = r#"import estus_runtime, json, os, time
cfg = estus_runtime.request()[0]
marker = cfg["marker"]
release = cfg["release"]
with open(marker, "w", encoding="utf-8") as handle:
    handle.write("started")
deadline = time.monotonic() + 10.0
while not os.path.exists(release) and time.monotonic() < deadline:
    time.sleep(0.02)
print(json.dumps({"ok": True}))
"#;
        #[derive(serde::Serialize)]
        struct Requirements {
            python_min: [u16; 2],
            interpreters: Vec<String>,
            modules: Vec<String>,
            executables: Vec<String>,
            paths: Vec<String>,
        }
        #[derive(serde::Serialize)]
        struct ArgumentValue {
            name: &'static str,
        }
        #[derive(serde::Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Arg {
            Object {
                fields: std::collections::BTreeMap<&'static str, ArgumentValue>,
            },
        }
        // A payload directory holds the collector and the manifest that pins
        // its bytes; site policy lives in the config, not in the manifest.
        let write_signed = |name: &str,
                            change_policy: &str,
                            source_code: &str|
         -> Result<PathBuf> {
            let directory = fixture.root.path().join(name);
            fs::create_dir_all(&directory)?;
            let source_path = directory.join("collector.py");
            fs::write(&source_path, source_code)?;
            let source_sha256 = hex::encode(Sha256::digest(source_code.as_bytes()));
            let contract = json!({
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["target_python", "marker", "release"],
                    "properties": {
                        "target_python": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "marker": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "release": {"type": "string", "minLength": 1, "maxLength": 4096}
                    }
                },
                "aliases": {
                    "aliases": {},
                    "properties": {
                        "target_python": {"aliases": {}, "properties": {}},
                        "marker": {"aliases": {}, "properties": {}},
                        "release": {"aliases": {}, "properties": {}}
                    }
                },
                "defaults": {},
                "review_required": []
            });
            let argv = vec![Arg::Object {
                fields: std::collections::BTreeMap::from([
                    ("marker", ArgumentValue { name: "marker" }),
                    ("release", ArgumentValue { name: "release" }),
                ]),
            }];
            let requirements = Requirements {
                python_min: [3, 8],
                interpreters: Vec::new(),
                modules: vec!["json".to_owned()],
                executables: Vec::new(),
                paths: Vec::new(),
            };
            let manifest = json!({
                "schema": 1,
                "protocol": 1,
                "adapter_version": 1,
                "change_policy": change_policy,
                "source_sha256": source_sha256,
                "max_source_bytes": 1_048_576,
                "argv": argv,
                "requirements": requirements,
                "contract": contract
            });
            fs::write(
                directory.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
            Ok(source_path)
        };
        let read_source = write_signed("read_probe", "read_only", read_source_code)?;
        let write_source = write_signed("write_probe", "mutation_success", write_source_code)?;
        let config = fixture.root.path().join("payload-admission.toml");
        fs::write(
            &config,
            formatdoc! {r#"
                capabilities = {{ named = true }}
                [selection]
                allow = ["read_probe", "write_probe"]
                [ssh]
                config_file = {ssh_config}
                [limits]
                connect_timeout_secs = 3
                operation_timeout_secs = 15
                max_timeout_secs = 20
                max_output_bytes = 4096
                [targets.plain]
                ssh_host = "plain"
                [automation.targets.plain]
                destination = "plain"
                python = {python_path}
                [tools.read_probe]
                description = "Read probe for concurrency tests."
                revision = "read-1"
                targets = ["plain"]
                authority = "automation"
                effects = ["read"]
                execution = {{kind="native_payload",source={read_src}}}
                fixed_args = {{target_python={python_path}}}
                input_map = {{marker="marker",release="release"}}
                input_schema = {{type="object",additionalProperties=false,required=["marker","release"],properties={{marker={{type="string",minLength=1,maxLength=4096}},release={{type="string",minLength=1,maxLength=4096}}}}}}
                result = {{kind="capability_projection",fields={{ok=["ok"]}},schema={{type="object",additionalProperties=false,required=["ok"],properties={{ok={{type="boolean"}}}}}},max_bytes=1024,max_items=16,max_depth=3}}
                [tools.write_probe]
                description = "Write probe for serialization and quarantine tests."
                revision = "write-1"
                targets = ["plain"]
                authority = "automation"
                effects = ["persistent_write"]
                execution = {{kind="native_payload",source={write_src}}}
                fixed_args = {{target_python={python_path}}}
                input_map = {{marker="marker",release="release"}}
                input_schema = {{type="object",additionalProperties=false,required=["marker","release"],properties={{marker={{type="string",minLength=1,maxLength=4096}},release={{type="string",minLength=1,maxLength=4096}}}}}}
                result = {{kind="capability_projection",fields={{ok=["ok"]}},schema={{type="object",additionalProperties=false,required=["ok"],properties={{ok={{type="boolean"}}}}}},max_bytes=1024,max_items=16,max_depth=3}}
            "#,
                ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
                python_path = serde_json::to_string(&python.to_string_lossy())?,
                read_src = serde_json::to_string(&read_source.to_string_lossy())?,
                write_src = serde_json::to_string(&write_source.to_string_lossy())?,
            },
        )?;
        let mut server = WireServer::start(&config)?;
        let cases = async {
            server.initialize().await?;
            let release_reads = marker_dir.join("release-reads");
            for idx in 1..=5u64 {
                let marker = marker_dir.join(format!("read-{idx}"));
                server
                    .send(json!({
                        "jsonrpc": "2.0",
                        "id": 10 + idx,
                        "method": "tools/call",
                        "params": {
                            "name": "read_probe",
                            "arguments": {
                                "host": "plain",
                                "inputs": {
                                    "marker": marker.to_string_lossy(),
                                    "release": release_reads.to_string_lossy()
                                }
                            }
                        }
                    }))
                    .await?;
            }
            // All 4 cold reads must overlap simultaneously without starving on the 4-channel pool.
            timeout(Duration::from_secs(10), async {
                loop {
                    let count = (1..=5u64)
                        .filter(|idx| marker_dir.join(format!("read-{idx}")).exists())
                        .count();
                    if count >= 4 {
                        break;
                    }
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("four concurrent cold reads did not overlap")?;
            sleep(Duration::from_millis(120)).await;
            let active_before_release = (1..=5u64)
                .filter(|idx| marker_dir.join(format!("read-{idx}")).exists())
                .count();
            ensure!(
                active_before_release == 4,
                "expected exactly 4 concurrent reads, observed {active_before_release}"
            );
            fs::write(&release_reads, b"go")?;
            let mut completed_reads = std::collections::BTreeSet::new();
            for _ in 1..=5 {
                let (frame, _) = server.frame().await?;
                let id = frame["id"].as_u64().context("read probe response id")?;
                let reply: Value = serde_json::from_str(
                    frame["result"]["content"][0]["text"]
                        .as_str()
                        .context("read probe text")?,
                )?;
                succeeded(&reply)?;
                completed_reads.insert(id);
            }
            ensure!(completed_reads == (11..=15).collect());

            // A write must wait behind an active read, and a subsequent read must wait behind that write.
            let release_read_barrier = marker_dir.join("release-read-barrier");
            let read_barrier_marker = marker_dir.join("read-barrier");
            let release_write_barrier = marker_dir.join("release-write-barrier");
            let write_barrier_marker = marker_dir.join("write-barrier");
            let read_after_write_marker = marker_dir.join("read-after-write");
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": {
                        "name": "read_probe",
                        "arguments": {
                            "host": "plain",
                            "inputs": {
                                "marker": read_barrier_marker.to_string_lossy(),
                                "release": release_read_barrier.to_string_lossy()
                            }
                        }
                    }
                }))
                .await?;
            Fixture::await_file(&read_barrier_marker).await?;
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "id": 21,
                    "method": "tools/call",
                    "params": {
                        "name": "write_probe",
                        "arguments": {
                            "host": "plain",
                            "inputs": {
                                "marker": write_barrier_marker.to_string_lossy(),
                                "release": release_write_barrier.to_string_lossy()
                            }
                        }
                    }
                }))
                .await?;
            sleep(Duration::from_millis(120)).await;
            ensure!(
                !write_barrier_marker.exists(),
                "write overlapped active read"
            );
            fs::write(&release_read_barrier, b"go")?;
            let r20 = server.receive(json!(20)).await?.0;
            let r20_reply: Value = serde_json::from_str(
                r20["result"]["content"][0]["text"]
                    .as_str()
                    .context("r20 text")?,
            )?;
            succeeded(&r20_reply)?;
            Fixture::await_file(&write_barrier_marker).await?;
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "id": 22,
                    "method": "tools/call",
                    "params": {
                        "name": "read_probe",
                        "arguments": {
                            "host": "plain",
                            "inputs": {
                                "marker": read_after_write_marker.to_string_lossy(),
                                "release": release_write_barrier.to_string_lossy()
                            }
                        }
                    }
                }))
                .await?;
            sleep(Duration::from_millis(120)).await;
            ensure!(
                !read_after_write_marker.exists(),
                "read overlapped active write"
            );
            fs::write(&release_write_barrier, b"go")?;
            let mut ids = std::collections::BTreeSet::new();
            for _ in 0..2 {
                let (frame, _) = server.frame().await?;
                let id = frame["id"].as_u64().context("barrier response id")?;
                let reply: Value = serde_json::from_str(
                    frame["result"]["content"][0]["text"]
                        .as_str()
                        .context("barrier text")?,
                )?;
                succeeded(&reply)?;
                ids.insert(id);
            }
            ensure!(ids == [21, 22].into_iter().collect());

            // Uncertain write quarantines mutations while reads and explicit acknowledged clear work.
            let cancel_marker = marker_dir.join("cancel-write");
            let cancel_release = marker_dir.join("cancel-write-release");
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "id": 30,
                    "method": "tools/call",
                    "params": {
                        "name": "write_probe",
                        "arguments": {
                            "host": "plain",
                            "inputs": {
                                "marker": cancel_marker.to_string_lossy(),
                                "release": cancel_release.to_string_lossy()
                            }
                        }
                    }
                }))
                .await?;
            Fixture::await_file(&cancel_marker).await?;
            server
                .send(json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": 30, "reason": "operator abort"}
                }))
                .await?;
            let log = server.log.clone();
            let r30_audit = await_audit(&log, "finish", "cancelled").await?;
            ensure!(r30_audit["request_id"] == 30);
            ensure!(r30_audit["remote_state_unknown"] == true);
            ensure!(
                log.records()?
                    .into_iter()
                    .any(|record| record["event"] == "target_quarantine"
                        && record["phase"] == "quarantined"
                        && record["target"] == "plain"
                        && record["authority"] == "automation"
                        && record["executor"] == "native_payload"
                        && record["cause"] == "cancelled")
            );
            fs::write(&cancel_release, b"done")?;

            let blocked_write = script_wire_call(
                &mut server,
                31,
                "write_probe",
                json!({
                    "host": "plain",
                    "inputs": {
                        "marker": marker_dir.join("must-not-run").to_string_lossy(),
                        "release": release_reads.to_string_lossy()
                    }
                }),
            )
            .await?;
            failed(&blocked_write, "target_quarantined")?;
            ensure!(blocked_write["error"]["remote_state_unknown"] == false);
            ensure!(!marker_dir.join("must-not-run").exists());

            // Reads remain available for reconciliation while quarantined.
            let read_while_quarantined = script_wire_call(
                &mut server,
                32,
                "read_probe",
                json!({
                    "host": "plain",
                    "inputs": {
                        "marker": marker_dir.join("reconcile-read").to_string_lossy(),
                        "release": release_reads.to_string_lossy()
                    }
                }),
            )
            .await?;
            succeeded(&read_while_quarantined)?;

            // Unknown or non-quarantined targets return no-change; false consent is rejected.
            let no_consent = script_wire_call(
                &mut server,
                33,
                "change_target_quarantine_clear",
                json!({"host": "plain", "acknowledge_remote_state_reconciled": false}),
            )
            .await?;
            failed(&no_consent, "invalid_argument")?;
            ensure!(no_consent["error"]["remote_state_unknown"] == false);
            let unknown_clear = script_wire_call(
                &mut server,
                34,
                "change_target_quarantine_clear",
                json!({"host": "unknown", "acknowledge_remote_state_reconciled": true}),
            )
            .await?;
            ensure!(
                succeeded(&unknown_clear)? == &json!({"cleared": false, "was_quarantined": false})
            );
            let cleared = script_wire_call(
                &mut server,
                35,
                "change_target_quarantine_clear",
                json!({"host": "plain", "acknowledge_remote_state_reconciled": true}),
            )
            .await?;
            ensure!(
                succeeded(&cleared)?
                    == &json!({"cleared": true, "was_quarantined": true, "previous_cause": "cancelled"})
            );
            let cleared_again = script_wire_call(
                &mut server,
                36,
                "change_target_quarantine_clear",
                json!({"host": "plain", "acknowledge_remote_state_reconciled": true}),
            )
            .await?;
            ensure!(
                succeeded(&cleared_again)? == &json!({"cleared": false, "was_quarantined": false})
            );

            let recovered_write = script_wire_call(
                &mut server,
                37,
                "write_probe",
                json!({
                    "host": "plain",
                    "inputs": {
                        "marker": marker_dir.join("recovered-write").to_string_lossy(),
                        "release": release_reads.to_string_lossy()
                    }
                }),
            )
            .await?;
            succeeded(&recovered_write)?;
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
            Ok(owned) => assert_masters_gone(&owned).await,
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
