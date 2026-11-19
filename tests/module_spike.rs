//! Ignored disposable-host Runner and immutable runtime cost benchmark (C18).
#![cfg(unix)]
#![allow(dead_code)]

#[path = "support/catalog.rs"]
mod catalog;
mod support;

use std::{
    collections::{BTreeMap, HashSet},
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use support::Client;
use tokio::process::Command;

const BENCHMARK_SAMPLES: usize = 30;
const HEALTH_SOURCE: &str = include_str!("../src/automation/python/health.py");
const RUNNER_SOURCE: &str = include_str!("../src/automation/python/runner.py");
const CLI_SOURCE: &str = include_str!("../src/automation/python/cli.py");

#[derive(Debug, Clone, Serialize)]
struct ImmutableStoreIdentity {
    store_root: String,
    canonical_root: String,
    verified_entries: usize,
    verified_symlinks: usize,
}

#[derive(Debug, Clone, Serialize)]
struct LatencyStats {
    sample_count: usize,
    cold_first_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
    samples_ms: Vec<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct RunnerPathReport {
    module: String,
    path_kind: String,
    ssh_connection_cold: bool,
    exact_command: String,
    stats: LatencyStats,
}

#[derive(Debug, Clone, Serialize)]
struct RuntimeHashReport {
    scope: String,
    module: String,
    content_sha256: String,
    exact_command: String,
    stats: LatencyStats,
}

#[derive(Debug, Clone, Serialize)]
struct StoreIdentityReport {
    identity: ImmutableStoreIdentity,
    exact_command: String,
    stats: LatencyStats,
}

#[derive(Debug, Clone, Serialize)]
struct SpikeReport {
    target_distribution: BTreeMap<String, String>,
    target_python: String,
    authority: String,
    ansible_versions: Value,
    runner_paths: Vec<RunnerPathReport>,
    runtime_hashing: Vec<RuntimeHashReport>,
    immutable_store_identity: StoreIdentityReport,
}

fn percentile_ms(sorted: &[f64], numerator: usize, denominator: usize) -> Result<f64> {
    ensure!(
        !sorted.is_empty(),
        "cannot compute percentile of empty samples"
    );
    let rank = (sorted.len() * numerator).div_ceil(denominator);
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    Ok(sorted[idx])
}

fn summarize_samples(samples_ms: Vec<f64>) -> Result<LatencyStats> {
    ensure!(!samples_ms.is_empty(), "latency samples must not be empty");
    let cold_first_ms = samples_ms[0];
    let mut sorted = samples_ms.clone();
    sorted.sort_by(f64::total_cmp);
    let p50_ms = percentile_ms(&sorted, 50, 100)?;
    let p95_ms = percentile_ms(&sorted, 95, 100)?;
    let min_ms = sorted[0];
    let max_ms = sorted[sorted.len() - 1];
    Ok(LatencyStats {
        sample_count: samples_ms.len(),
        cold_first_ms,
        p50_ms,
        p95_ms,
        min_ms,
        max_ms,
        samples_ms,
    })
}

/// Verify that `runtime_path` and every transitive directory, regular file, and
/// symlink target stay strictly inside `store_root` (not merely sharing a string prefix).
fn verify_immutable_store_tree(
    runtime_path: &Path,
    store_root: &Path,
    require_readonly: bool,
) -> Result<ImmutableStoreIdentity> {
    let canonical_store = fs::canonicalize(store_root)
        .with_context(|| format!("missing store root {}", store_root.display()))?;
    ensure!(
        runtime_path.starts_with(store_root) && runtime_path != store_root,
        "runtime path {} is not a child of store root {}",
        runtime_path.display(),
        store_root.display()
    );
    let canonical_root = fs::canonicalize(runtime_path)
        .with_context(|| format!("cannot canonicalize {}", runtime_path.display()))?;
    ensure!(
        canonical_root.starts_with(&canonical_store) && canonical_root != canonical_store,
        "canonical runtime {} escapes store root {}",
        canonical_root.display(),
        canonical_store.display()
    );

    let mut stack = vec![canonical_root.clone()];
    let mut visited_dirs: HashSet<(u64, u64)> = HashSet::new();
    let mut verified_entries = 0usize;
    let mut verified_symlinks = 0usize;

    while let Some(path) = stack.pop() {
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("stat failed for {}", path.display()))?;
        verified_entries += 1;

        if meta.file_type().is_symlink() {
            verified_symlinks += 1;
            let raw_target = fs::read_link(&path)
                .with_context(|| format!("read_link failed for {}", path.display()))?;
            let resolved_link = if raw_target.is_absolute() {
                raw_target
            } else {
                path.parent()
                    .context("symlink without parent")?
                    .join(raw_target)
            };
            let canonical_target = fs::canonicalize(&resolved_link).with_context(|| {
                format!(
                    "broken or escaping symlink {} -> {}",
                    path.display(),
                    resolved_link.display()
                )
            })?;
            ensure!(
                canonical_target.starts_with(&canonical_store)
                    && canonical_target != canonical_store,
                "symlink {} target {} escapes immutable store {}",
                path.display(),
                canonical_target.display(),
                canonical_store.display()
            );
            stack.push(canonical_target);
            continue;
        }

        let canonical_entry = fs::canonicalize(&path)
            .with_context(|| format!("canonicalize failed for {}", path.display()))?;
        ensure!(
            canonical_entry.starts_with(&canonical_store) && canonical_entry != canonical_store,
            "entry {} escapes immutable store {}",
            path.display(),
            canonical_store.display()
        );

        if require_readonly {
            let mode = meta.permissions().mode();
            ensure!(
                mode & 0o222 == 0,
                "store entry {} is writable (mode {:o})",
                path.display(),
                mode & 0o7777
            );
        }

        if meta.file_type().is_dir() {
            let id = (meta.dev(), meta.ino());
            if !visited_dirs.insert(id) {
                continue;
            }
            for child in fs::read_dir(&canonical_entry)? {
                let child = child?;
                stack.push(child.path());
            }
        } else if meta.file_type().is_file() {
            continue;
        } else {
            bail!(
                "unsupported non-regular entry {} in store tree",
                path.display()
            );
        }
    }

    Ok(ImmutableStoreIdentity {
        store_root: canonical_store.display().to_string(),
        canonical_root: canonical_root.display().to_string(),
        verified_entries,
        verified_symlinks,
    })
}

fn parse_os_release(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let unquoted = value.trim().trim_matches('"').to_owned();
            map.insert(key.trim().to_owned(), unquoted);
        }
    }
    map
}

fn toml_value(value: Value) -> Result<toml::Value> {
    Ok(toml::Value::try_from(value)?)
}

fn text_path(path: &Path) -> Result<String> {
    Ok(path.to_str().context("non-UTF-8 path")?.to_owned())
}

async fn run_mcp_schema_import(
    config: &Path,
    module: &str,
    snapshot: &Path,
    overlay_path: &Path,
) -> Result<()> {
    let mut command = support::server_command(config)?;
    command
        .args(["schema", "import", module, "--output"])
        .arg(snapshot)
        .arg("--overlay")
        .arg(overlay_path);
    let output = support::run_authoring(&mut command).await?;
    ensure!(
        output.status.success(),
        "schema import failed for {module}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["binding_validated"] == true,
        "overlay for {module} failed validation: {report}"
    );
    Ok(())
}

struct ControlMasterGuard {
    ssh: PathBuf,
    ssh_config: PathBuf,
    control_path: PathBuf,
    child: tokio::process::Child,
}

impl ControlMasterGuard {
    async fn start(ssh: PathBuf, ssh_config: PathBuf, control_path: PathBuf) -> Result<Self> {
        let mut child = Command::new(&ssh)
            .arg("-F")
            .arg(&ssh_config)
            .args([
                "-o",
                "ControlMaster=yes",
                "-o",
                &format!("ControlPath={}", text_path(&control_path)?),
                "-o",
                "ControlPersist=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-N",
                "catalog-admin",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait()? {
                let mut err = Vec::new();
                if let Some(mut stderr) = child.stderr.take() {
                    let _ = tokio::io::AsyncReadExt::read_to_end(&mut stderr, &mut err).await;
                }
                bail!(
                    "ControlMaster ssh exited prematurely ({status}): {}",
                    String::from_utf8_lossy(&err)
                );
            }
            let check = support::run(Command::new(&ssh).arg("-F").arg(&ssh_config).args([
                "-o",
                &format!("ControlPath={}", text_path(&control_path)?),
                "-O",
                "check",
                "catalog-admin",
            ]))
            .await?;
            if check.status.success() {
                return Ok(Self {
                    ssh,
                    ssh_config,
                    control_path,
                    child,
                });
            }
            ensure!(
                Instant::now() < deadline,
                "ControlMaster did not become ready within 15s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn check_alive(&self) -> Result<()> {
        let out = support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(&self.ssh_config)
                .args([
                    "-o",
                    &format!("ControlPath={}", text_path(&self.control_path)?),
                    "-O",
                    "check",
                    "catalog-admin",
                ]),
        )
        .await?;
        ensure!(
            out.status.success(),
            "ControlMaster socket was not active: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    async fn stop(mut self) -> Result<()> {
        let _ = support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(&self.ssh_config)
                .args([
                    "-o",
                    &format!("ControlPath={}", text_path(&self.control_path)?),
                    "-O",
                    "exit",
                    "catalog-admin",
                ]),
        )
        .await;
        if self.child.try_wait()?.is_none() {
            let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
            if self.child.try_wait()?.is_none() {
                let _ = self.child.kill().await;
                let _ = self.child.wait().await;
            }
        }
        Ok(())
    }
}

#[test]
fn percentile_calculation_is_exact_and_monotonic() -> Result<()> {
    let samples: Vec<f64> = (1..=30).map(|n| n as f64 * 10.0).collect();
    let stats = summarize_samples(samples)?;
    assert_eq!(stats.sample_count, 30);
    assert_eq!(stats.cold_first_ms, 10.0);
    assert_eq!(stats.min_ms, 10.0);
    assert_eq!(stats.max_ms, 300.0);
    assert_eq!(stats.p50_ms, 150.0);
    assert_eq!(stats.p95_ms, 290.0);
    Ok(())
}

#[test]
fn immutable_store_identity_rejects_prefix_spoof_and_escaping_symlinks() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = dir.path().join("store");
    let spoof_store = dir.path().join("store-spoof");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&store)?;
    fs::create_dir_all(&spoof_store)?;
    fs::create_dir_all(&outside)?;

    let spoof_runtime = spoof_store.join("fake-runtime");
    fs::create_dir_all(&spoof_runtime)?;
    assert!(
        verify_immutable_store_tree(&spoof_runtime, &store, false).is_err(),
        "prefix-spoofed sibling directory must be rejected"
    );

    let escaping_runtime = store.join("escaping-runtime");
    fs::create_dir_all(&escaping_runtime)?;
    let outside_file = outside.join("secret.py");
    fs::write(&outside_file, b"print('mutable')\n")?;
    std::os::unix::fs::symlink(&outside_file, escaping_runtime.join("escape.py"))?;
    assert!(
        verify_immutable_store_tree(&escaping_runtime, &store, false).is_err(),
        "symlink escaping store root must be rejected"
    );

    let valid_dep = store.join("dep-pkg");
    let valid_runtime = store.join("valid-runtime");
    fs::create_dir_all(valid_dep.join("sub"))?;
    fs::create_dir_all(&valid_runtime)?;
    let dep_file = valid_dep.join("sub/mod.py");
    fs::write(&dep_file, b"x = 1\n")?;
    std::os::unix::fs::symlink(&valid_dep, valid_runtime.join("dep"))?;
    fs::set_permissions(&dep_file, fs::Permissions::from_mode(0o444))?;
    fs::set_permissions(valid_dep.join("sub"), fs::Permissions::from_mode(0o555))?;
    fs::set_permissions(&valid_dep, fs::Permissions::from_mode(0o555))?;
    fs::set_permissions(&valid_runtime, fs::Permissions::from_mode(0o555))?;

    let id = verify_immutable_store_tree(&valid_runtime, &store, true)?;
    assert_eq!(id.verified_symlinks, 1);
    assert!(id.verified_entries >= 4);

    // Restore write permissions so TempDir cleanup succeeds without error.
    fs::set_permissions(&valid_runtime, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&valid_dep, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(valid_dep.join("sub"), fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&dep_file, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and ESTUS_TEST_ANSIBLE_RUNTIME"]
async fn benchmark_runner_and_immutable_runtime_costs() -> Result<()> {
    let runtime_root = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned Ansible runtime")?,
    )?;
    let runtime_manifest: Value =
        serde_json::from_slice(&fs::read(runtime_root.join("runtime.json"))?)?;
    let ansible_versions = runtime_manifest["identity"].clone();

    let guest = catalog::Guest::start_packages().await?;
    let result: Result<SpikeReport> = async {
        let os_release_out = guest.shell("cat /etc/os-release").await?;
        ensure!(
            os_release_out.status.success(),
            "failed to read /etc/os-release on disposable host"
        );
        let target_distribution = parse_os_release(&String::from_utf8(os_release_out.stdout)?);

        let py_out = guest
            .shell("/usr/bin/python3 -c 'import platform; print(platform.python_version())'")
            .await?;
        ensure!(
            py_out.status.success(),
            "failed to query target python version"
        );
        let target_python = String::from_utf8(py_out.stdout)?.trim().to_owned();

        // Pre-seed idempotent sysctl config file under /etc/estus-catalog so all 30
        // ansible.posix.sysctl calls exercise sysctl check+read without mutating host state.
        let seed_sysctl = guest
            .shell("printf 'kernel.hostname = estus-catalog\\n' > /etc/estus-catalog/sysctl-spike.conf")
            .await?;
        ensure!(
            seed_sysctl.status.success(),
            "failed to seed /etc/estus-catalog/sysctl-spike.conf"
        );

        let bench_dir = tempfile::Builder::new()
            .prefix("estus-module-spike-")
            .tempdir()?;
        fs::set_permissions(bench_dir.path(), fs::Permissions::from_mode(0o700))?;
        let workspace = bench_dir.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;

        let mut site: toml::Table = toml::from_str(&fs::read_to_string(&guest.config)?)?;
        site.insert("mode".into(), "headless".into());
        site.insert(
            "capabilities".into(),
            toml_value(json!({ "named": true }))?,
        );
        let automation = site
            .get_mut("automation")
            .and_then(toml::Value::as_table_mut)
            .context("automation table")?;
        automation.insert("runtime".into(), text_path(&runtime_root)?.into());
        automation.insert("workspace_root".into(), text_path(&workspace)?.into());
        automation.insert("max_concurrent".into(), 2.into());
        automation.insert("max_scratch_bytes".into(), (16 * 1024 * 1024).into());
        automation.insert("max_scratch_files".into(), 512.into());

        let limits = site
            .entry("limits")
            .or_insert_with(|| toml::Value::Table(Default::default()))
            .as_table_mut()
            .context("limits table")?;
        limits.insert("operation_timeout_secs".into(), 30.into());
        limits.insert("max_timeout_secs".into(), 30.into());

        let empty_schema = json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false,
            "maxProperties": 0,
            "const": {}
        });

        let module_specs = [
            (
                "observe_spike_systemd",
                "ansible.builtin.systemd_service",
                vec!["read"],
                json!({
                    "input_schema": empty_schema,
                    "fixed_args": { "name": "estus-fixture.service" },
                    "input_map": {}
                }),
            ),
            (
                "observe_spike_packages",
                "ansible.builtin.package_facts",
                vec!["read"],
                json!({
                    "input_schema": empty_schema,
                    "fixed_args": { "manager": ["apt"] },
                    "input_map": {}
                }),
            ),
            (
                "change_spike_sysctl",
                "ansible.posix.sysctl",
                vec!["runtime_write"],
                json!({
                    "input_schema": empty_schema,
                    "fixed_args": {
                        "name": "kernel.hostname",
                        "value": "estus-catalog",
                        "sysctl_file": "/etc/estus-catalog/sysctl-spike.conf",
                        "sysctl_set": true,
                        "reload": false,
                        "state": "present"
                    },
                    "input_map": {}
                }),
            ),
        ];

        let import_cfg_path = bench_dir.path().join("import.toml");
        fs::write(&import_cfg_path, toml::to_string(&site)?)?;

        let mut tools = toml::map::Map::new();
        let mut enabled = Vec::new();
        for (tool_name, module, effects, overlay) in &module_specs {
            let snapshot = bench_dir.path().join(format!("{tool_name}-snapshot.json"));
            let overlay_path = bench_dir.path().join(format!("{tool_name}-overlay.json"));
            fs::write(&overlay_path, serde_json::to_vec(overlay)?)?;
            run_mcp_schema_import(&import_cfg_path, module, &snapshot, &overlay_path).await?;
            let mut binding = json!({
                "description": format!("Benchmark binding for {module}"),
                "revision": "spike-1",
                "authority": "automation:catalog",
                "effects": effects,
                "targets": ["plain"],
                "execution": {
                    "kind": "ansible_module",
                    "snapshot": text_path(&snapshot)?,
                    "no_log": false
                },
                "result": { "kind": "ansible_summary" },
                "limits": { "timeout_secs": 30 }
            });
            for key in ["input_schema", "fixed_args", "input_map"] {
                binding[key] = overlay[key].clone();
            }
            tools.insert((*tool_name).to_owned(), toml_value(binding)?);
            enabled.push(*tool_name);
        }
        site.insert("enabled_tools".into(), toml_value(json!(enabled))?);
        site.insert("tools".into(), toml::Value::Table(tools));

        let server_cfg_path = bench_dir.path().join("estus.toml");
        fs::write(&server_cfg_path, toml::to_string(&site)?)?;

        let mut runner_paths = Vec::new();

        // 1. Production Runner calls via Estus MCP (cold runner + cold SSH per call).
        let client = Client::start(&server_cfg_path).await?;
        let mcp_result: Result<()> = async {
            for (tool_name, module, _, _) in &module_specs {
                let mut samples_ms = Vec::with_capacity(BENCHMARK_SAMPLES);
                for _ in 0..BENCHMARK_SAMPLES {
                    let started = Instant::now();
                    let reply = client
                        .call(
                            tool_name,
                            json!({"host": "plain", "inputs": {}, "timeout_secs": 30}),
                        )
                        .await?;
                    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                    ensure!(
                        reply["error"].is_null()
                            && reply["data"]["status"] == "successful"
                            && reply["data"]["complete"] == true,
                        "production Runner benchmark call failed for {tool_name}: {reply}"
                    );
                    samples_ms.push(elapsed);
                }
                ensure!(
                    fs::read_dir(&workspace)?.next().is_none(),
                    "workspace retained files after MCP Runner benchmark"
                );
                runner_paths.push(RunnerPathReport {
                    module: (*module).to_owned(),
                    path_kind: "production_runner_cold_ssh".to_owned(),
                    ssh_connection_cold: true,
                    exact_command: format!(
                        "MCP tools/call {tool_name} -> python3 -I -B runner.py -> ansible-playbook -i inventory/hosts.yml project/playbook.yml (ssh ControlMaster=no)"
                    ),
                    stats: summarize_samples(samples_ms)?,
                });
            }
            Ok(())
        }
        .await;
        let client_cleanup = client.stop().await;
        mcp_result?;
        client_cleanup?;

        // 2. Warm-SSH Runner calls (benchmark-only ControlMaster reuse; runner.py untouched).
        let warm_dir = bench_dir.path().join("warm-ssh-runner");
        fs::create_dir_all(warm_dir.join("tmp"))?;
        fs::create_dir_all(warm_dir.join("home"))?;
        fs::set_permissions(&warm_dir, fs::Permissions::from_mode(0o700))?;
        let control_sock = warm_dir.join("cm.sock");
        let ssh_bin = guest.ssh_executable().to_path_buf();
        let authority_cfg = guest.authority_ssh_config();

        let cm = ControlMasterGuard::start(ssh_bin.clone(), authority_cfg.clone(), control_sock.clone()).await?;
        let warm_result: Result<()> = async {
            let runtime_py = runtime_root.join("bin/python3");
            let runtime_collections = runtime_root.join("collections");
            let runtime_ansible_cfg = warm_dir.join("ansible.cfg");
            fs::write(
                &runtime_ansible_cfg,
                "[defaults]\ncollections_scan_sys_path = False\nretry_files_enabled = False\nfact_caching = memory\nhost_key_checking = True\ndisplay_args_to_stdout = False\n[ssh_connection]\nssh_transfer_method = piped\n",
            )?;
            let inventory_yml = warm_dir.join("hosts.yml");
            let ssh_args = format!(
                "-o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes -o PermitLocalCommand=no -o RequestTTY=no -o RemoteCommand=none -o ForkAfterAuthentication=no -o SessionType=default -o ControlMaster=auto -o ControlPath={} -o ControlPersist=no -F {}",
                text_path(&control_sock)?,
                text_path(&authority_cfg)?
            );
            let inventory_doc = json!({
                "all": {
                    "hosts": {
                        "estus_target": {
                            "ansible_host": "catalog-admin",
                            "ansible_connection": "ssh",
                            "ansible_python_interpreter": "/usr/bin/python3",
                            "ansible_ssh_executable": text_path(&ssh_bin)?,
                            "ansible_ssh_args": ssh_args,
                            "ansible_ssh_transfer_method": "piped",
                            "ansible_ssh_use_tty": false,
                            "ansible_ssh_password_mechanism": "disable",
                            "ansible_become": true,
                            "ansible_become_method": "ansible.builtin.sudo",
                            "ansible_become_user": "root",
                            "ansible_become_exe": "/usr/bin/sudo",
                            "ansible_become_flags": "-H -n -k",
                            "ansible_become_password": "",
                            "ansible_become_pass": "",
                            "ansible_sudo_pass": ""
                        }
                    }
                }
            });
            fs::write(&inventory_yml, serde_json::to_string(&inventory_doc)?)?;

            let ssh_parent = ssh_bin.parent().context("ssh parent")?.to_owned();
            let path_env = std::env::join_paths([
                runtime_root.join("bin"),
                ssh_parent,
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ])?;
            let playbook_launcher = warm_dir.join("playbook_main.py");
            let runtime_site_packages = runtime_root.join(
                runtime_manifest["site_packages"]
                    .as_str()
                    .context("site_packages in runtime.json")?,
            );
            fs::write(
                &playbook_launcher,
                format!(
                    "import runpy, sys\nsys.path.insert(0, {:?})\nrunpy.run_module('ansible.cli.playbook', run_name='__main__')\n",
                    text_path(&runtime_site_packages)?
                ),
            )?;

            for (idx, (_, module, _, overlay)) in module_specs.iter().enumerate() {
                let playbook_yml = warm_dir.join(format!("playbook_{idx}.yml"));
                let play_doc = json!([{
                    "name": "estus_spike_warm",
                    "hosts": "estus_target",
                    "gather_facts": false,
                    "become": true,
                    "tasks": [{
                        "name": "estus_module",
                        (*module): overlay["fixed_args"].clone()
                    }]
                }]);
                fs::write(&playbook_yml, serde_json::to_string(&play_doc)?)?;

                let exact_cmd = format!(
                    "{} -I -B {} -i {} {}",
                    text_path(&runtime_py)?,
                    text_path(&playbook_launcher)?,
                    text_path(&inventory_yml)?,
                    text_path(&playbook_yml)?
                );
                let mut samples_ms = Vec::with_capacity(BENCHMARK_SAMPLES);
                for _ in 0..BENCHMARK_SAMPLES {
                    let started = Instant::now();
                    let mut cmd = Command::new(&runtime_py);
                    cmd.arg("-I")
                        .arg("-B")
                        .arg(&playbook_launcher)
                        .arg("-i")
                        .arg(&inventory_yml)
                        .arg(&playbook_yml)
                        .env_clear()
                        .env("PATH", &path_env)
                        .env("HOME", warm_dir.join("home"))
                        .env("TMPDIR", warm_dir.join("tmp"))
                        .env("LANG", "C.UTF-8")
                        .env("LC_ALL", "C.UTF-8")
                        .env("PYTHONDONTWRITEBYTECODE", "1")
                        .env("ANSIBLE_CONFIG", &runtime_ansible_cfg)
                        .env("ANSIBLE_HOME", warm_dir.join("home/ansible"))
                        .env("ANSIBLE_LOCAL_TEMP", warm_dir.join("tmp/ansible-local"))
                        .env("ANSIBLE_COLLECTIONS_PATH", &runtime_collections)
                        .env("ANSIBLE_COLLECTIONS_SCAN_SYS_PATH", "False")
                        .env("ANSIBLE_NOCOWS", "True")
                        .env("ANSIBLE_RETRY_FILES_ENABLED", "False")
                        .env("ANSIBLE_PIPELINING", "True");
                    let out = support::run_authoring(&mut cmd).await?;
                    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                    ensure!(
                        out.status.success(),
                        "warm-SSH ansible-playbook failed for {module}: {} {}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                    samples_ms.push(elapsed);
                }
                cm.check_alive().await?;
                runner_paths.push(RunnerPathReport {
                    module: (*module).to_owned(),
                    path_kind: "benchmark_runner_warm_ssh".to_owned(),
                    ssh_connection_cold: false,
                    exact_command: exact_cmd,
                    stats: summarize_samples(samples_ms)?,
                });
            }
            Ok(())
        }
        .await;
        let cm_stop = cm.stop().await;
        warm_result?;
        cm_stop?;

        // 3. Measure runtime-tree hashing separately using runner.py's selected_runtime + health.py's content_hash.
        let hash_ws = bench_dir.path().join("hash-ws");
        fs::create_dir_all(hash_ws.join("tmp"))?;
        fs::set_permissions(&hash_ws, fs::Permissions::from_mode(0o700))?;
        let runner_embedded = hash_ws.join("runner_embedded.py");
        fs::write(
            &runner_embedded,
            format!(
                "_ESTUS_HEALTH_SOURCE = {}\n_ESTUS_CLI_SOURCE = {}\n{}",
                serde_json::to_string(HEALTH_SOURCE)?,
                serde_json::to_string(CLI_SOURCE)?,
                RUNNER_SOURCE
            ),
        )?;

        let runtime_py = runtime_root.join("bin/python3");
        let runtime_descriptor = json!({
            "schema": 2,
            "source": "bundle",
            "runtime_root": text_path(&runtime_root)?
        });

        let hash_targets = [
            (
                "core_only",
                "ansible.builtin.systemd_service",
                "ansible/modules/systemd_service.py",
                Value::Null,
            ),
            (
                "core_plus_collection",
                "ansible.posix.sysctl",
                "ansible.posix/plugins/modules/sysctl.py",
                runtime_manifest["identity"]["collections"]
                    .as_array()
                    .context("collections array")?
                    .iter()
                    .find(|c| c["name"] == "ansible.posix")
                    .cloned()
                    .context("ansible.posix metadata")?,
            ),
        ];

        let mut runtime_hashing = Vec::new();
        for (scope, module, source, collection_meta) in hash_targets {
            let probe_script = hash_ws.join(format!("hash_{scope}.py"));
            let script_body = r#"
import json, runpy, sys, time
from pathlib import Path

runner = runpy.run_path(sys.argv[1], run_name="estus_runner_bench")
spec = json.loads(sys.argv[2])
workspace = Path(sys.argv[3])
samples = int(sys.argv[4])

# First obtain the expected content_sha256 using health.content_hash so selected_runtime validates identically to production.
helper = workspace / "health.py"
helper.write_text(runner["_ESTUS_HEALTH_SOURCE"], encoding="utf-8")
ns = {"__name__": "estus_health", "__file__": str(helper)}
exec(compile(runner["_ESTUS_HEALTH_SOURCE"], str(helper), "exec"), ns)
observed, roots = ns["check"](spec["runtime"], role_request=False)
spec["expected"]["identity"] = observed
import ansible
core = Path(ansible.__file__).parent.resolve(strict=True)
trees = [("ansible", core)]
collection = ".".join(spec["expected"]["module"].split(".")[:2])
if collection != "ansible.builtin":
    ns_name, col_name = collection.split(".")
    col_dir = [
        (r / "ansible_collections" / ns_name / col_name).resolve(strict=True)
        for r in roots
        if (r / "ansible_collections" / ns_name / col_name).is_dir()
    ][0]
    trees.append((collection, col_dir))
label, root = trees[-1]
documented = root.joinpath(*spec["expected"]["source"].split("/")[1:])
digest = ns["content_hash"](trees, documented)
spec["expected"]["content_sha256"] = digest

elapsed_ms = []
for _ in range(samples):
    t0 = time.perf_counter()
    runner["selected_runtime"](spec, workspace)
    elapsed_ms.append((time.perf_counter() - t0) * 1000.0)

print(json.dumps({"content_sha256": digest, "samples_ms": elapsed_ms}))
"#;
            fs::write(&probe_script, script_body)?;
            let expected = json!({
                "identity": Value::Null,
                "module": module,
                "collection": collection_meta,
                "source": source,
                "content_sha256": ""
            });
            let spec = json!({
                "runtime": runtime_descriptor,
                "expected": expected
            });
            let exact_cmd = format!(
                "{} -I -B {} {} <spec:{module}> {} {BENCHMARK_SAMPLES}",
                text_path(&runtime_py)?,
                text_path(&probe_script)?,
                text_path(&runner_embedded)?,
                text_path(&hash_ws)?
            );
            let mut cmd = Command::new(&runtime_py);
            cmd.arg("-I")
                .arg("-B")
                .arg(&probe_script)
                .arg(&runner_embedded)
                .arg(serde_json::to_string(&spec)?)
                .arg(&hash_ws)
                .arg(BENCHMARK_SAMPLES.to_string())
                .env_clear()
                .env("TMPDIR", hash_ws.join("tmp"))
                .env("LANG", "C.UTF-8")
                .env("LC_ALL", "C.UTF-8");
            let out = support::run_authoring(&mut cmd).await?;
            ensure!(
                out.status.success(),
                "selected_runtime/content_hash benchmark failed for {scope}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let parsed: Value = serde_json::from_slice(&out.stdout)?;
            let samples_ms: Vec<f64> = serde_json::from_value(parsed["samples_ms"].clone())?;
            let content_sha256 = parsed["content_sha256"]
                .as_str()
                .context("content_sha256")?
                .to_owned();
            runtime_hashing.push(RuntimeHashReport {
                scope: scope.to_owned(),
                module: module.to_owned(),
                content_sha256,
                exact_command: exact_cmd,
                stats: summarize_samples(samples_ms)?,
            });
        }

        // 4. Measure immutable Nix store transitive identity verification separately.
        let mut store_samples_ms = Vec::with_capacity(BENCHMARK_SAMPLES);
        let mut store_identity = None;
        for _ in 0..BENCHMARK_SAMPLES {
            let started = Instant::now();
            let id = verify_immutable_store_tree(&runtime_root, Path::new("/nix/store"), true)?;
            let elapsed = started.elapsed().as_secs_f64() * 1000.0;
            store_samples_ms.push(elapsed);
            store_identity = Some(id);
        }
        let store_identity = store_identity.context("immutable store identity")?;

        Ok(SpikeReport {
            target_distribution,
            target_python,
            authority: "catalog (mcp-admin -> sudo -H -n -k root)".to_owned(),
            ansible_versions,
            runner_paths,
            runtime_hashing,
            immutable_store_identity: StoreIdentityReport {
                identity: store_identity,
                exact_command: format!(
                    "verify_immutable_store_tree({}, /nix/store, require_readonly=true)",
                    runtime_root.display()
                ),
                stats: summarize_samples(store_samples_ms)?,
            },
        })
    }
    .await;

    let cleanup = guest.stop().await;
    let report = result?;
    cleanup?;

    // Verify invariants without asserting which cost dominates.
    assert_eq!(report.runner_paths.len(), 6);
    for path in &report.runner_paths {
        assert!(path.stats.sample_count >= BENCHMARK_SAMPLES);
        assert!(path.stats.p50_ms > 0.0);
        assert!(path.stats.p95_ms >= path.stats.p50_ms);
    }
    assert_eq!(report.runtime_hashing.len(), 2);
    for h in &report.runtime_hashing {
        assert!(h.stats.sample_count >= BENCHMARK_SAMPLES);
        assert!(h.stats.p50_ms > 0.0);
    }
    assert!(report.immutable_store_identity.stats.sample_count >= BENCHMARK_SAMPLES);
    assert!(report.immutable_store_identity.identity.verified_symlinks > 0);

    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
