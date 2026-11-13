// CLI/MCP consumer of the broader process fixture module; no SSH listener is needed.
#[allow(dead_code)]
mod support;

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinHandle,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(40);
const SECRET: &str = "AUTOMATION_PRIVATE_SENTINEL";

struct Local {
    root: TempDir,
    config: PathBuf,
    marker: PathBuf,
}

impl Local {
    fn new(automation: &str) -> Result<Self> {
        let root = tempfile::Builder::new()
            .prefix("automation-private-")
            .tempdir()?;
        let config = root.path().join("operator.toml");
        let ssh = root.path().join("ssh_config");
        let marker = root.path().join("forbidden-ssh");
        fs::write(
            &ssh,
            format!(
                "Host *\n HostName 127.0.0.1\n ProxyCommand /bin/sh -c {}\n BatchMode yes\n IdentityAgent none\n",
                support::quote(&format!(
                    "printf forbidden > {}; exit 1",
                    support::quote(&marker.to_string_lossy())
                ))
            ),
        )?;
        fs::write(
            &config,
            format!(
                "[ssh]\nconfig_file = {}\n[targets.allowed]\nssh_host = '{SECRET}'\n{automation}",
                serde_json::to_string(&ssh.to_string_lossy())?
            ),
        )?;
        Ok(Self {
            root,
            config,
            marker,
        })
    }

    fn command(&self) -> Result<Command> {
        let mut command = support::server_command(&self.config)?;
        command
            .current_dir(self.root.path())
            .env("HOME", self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path())
            .env_remove("SSH_MCP_ANSIBLE_RUNTIME");
        Ok(command)
    }

    fn doctor(&self) -> Result<Command> {
        let mut command = self.command()?;
        command.args(["doctor", "--runtime", "ansible"]);
        Ok(command)
    }

    fn private(&self, output: &Output) -> Result<()> {
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for secret in [
                SECRET,
                self.root.path().to_str().context("UTF-8 fixture")?,
                "/nix/store/",
                "Traceback",
                "PYTHON_INJECTION_RAN",
            ] {
                ensure!(!text.contains(secret), "private runtime diagnostics leaked");
            }
        }
        ensure!(!self.marker.exists(), "runtime health dispatched SSH");
        Ok(())
    }
}

// Keep stdin open while waiting: doctor/startup failure must not depend on MCP EOF.
async fn output(mut command: Command) -> Result<Output> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let input = child.stdin.take().context("stdin")?;
    let mut stdout = child.stdout.take().context("stdout")?;
    let mut stderr = child.stderr.take().context("stderr")?;
    let out = tokio::spawn(async move {
        let mut b = Vec::new();
        stdout.read_to_end(&mut b).await?;
        Ok::<_, std::io::Error>(b)
    });
    let err = tokio::spawn(async move {
        let mut b = Vec::new();
        stderr.read_to_end(&mut b).await?;
        Ok::<_, std::io::Error>(b)
    });
    let status = timeout(WAIT, child.wait())
        .await
        .context("process did not exit with open stdin")??;
    drop(input);
    Ok(Output {
        status,
        stdout: timeout(WAIT, out).await???,
        stderr: timeout(WAIT, err).await???,
    })
}

fn report(output: &Output, exit: i32) -> Result<Value> {
    ensure!(
        output.status.code() == Some(exit),
        "unexpected exit {}",
        output.status
    );
    ensure!(output.stdout.len() <= 65_536);
    ensure!(output.stdout.last() == Some(&b'\n'));
    ensure!(output.stdout.iter().filter(|&&b| b == b'\n').count() == 1);
    let value: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(value["ok"] == (exit == 0));
    ensure!(value["targets"] == json!([]));
    ensure!(
        value
            .as_object()
            .context("report")?
            .keys()
            .all(|key| matches!(key.as_str(), "ok" | "targets" | "runtime" | "error_code"))
    );
    Ok(value)
}

fn runtime_failed(value: &Value, code: &str) -> Result<()> {
    ensure!(value["runtime"] == json!({"kind":"ansible", "status":"failed", "error_code":code}));
    Ok(())
}

struct Server {
    child: Child,
    input: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
}

impl Server {
    fn start(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("MCP stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("MCP stdout")?);
        let mut error = child.stderr.take().context("MCP stderr")?;
        let stderr = tokio::spawn(async move {
            let mut b = Vec::new();
            error.read_to_end(&mut b).await?;
            Ok(b)
        });
        Ok(Self {
            child,
            input,
            stdout,
            stderr,
        })
    }

    async fn send(&mut self, value: Value) -> Result<()> {
        self.input.write_all(&serde_json::to_vec(&value)?).await?;
        self.input.write_all(b"\n").await?;
        self.input.flush().await?;
        Ok(())
    }

    async fn response(&mut self, id: u64) -> Result<Value> {
        loop {
            let mut line = Vec::new();
            let n = timeout(
                WAIT,
                (&mut self.stdout)
                    .take(1_048_577)
                    .read_until(b'\n', &mut line),
            )
            .await??;
            ensure!(
                n > 0 && n <= 1_048_576 && line.last() == Some(&b'\n'),
                "invalid MCP frame"
            );
            let value: Value = serde_json::from_slice(&line)?;
            ensure!(value["jsonrpc"] == "2.0");
            if value.get("id") == Some(&json!(id)) {
                return Ok(value);
            }
            ensure!(value.get("id").is_none() && value["method"].is_string());
        }
    }

    async fn catalog(&mut self) -> Result<Value> {
        self.send(json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"automation-acceptance","version":"1"}
        }})).await?;
        let initialized = self.response(1).await?;
        ensure!(initialized["result"]["protocolVersion"] == "2025-11-25");
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await?;
        self.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}))
            .await?;
        let first = self.response(2).await?;
        let tools = first["result"]["tools"]
            .as_array()
            .context("native tool list")?;
        ensure!(!tools.is_empty());
        for tool in tools {
            ensure!(
                tool["name"]
                    .as_str()
                    .context("tool name")?
                    .starts_with("ssh_"),
                "runtime auto-registered a tool"
            );
        }
        self.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}))
            .await?;
        ensure!(
            self.response(3).await?["result"] == first["result"],
            "tool metadata changed"
        );
        Ok(first["result"].clone())
    }

    async fn stop(mut self) -> Result<Vec<u8>> {
        drop(self.input);
        ensure!(timeout(WAIT, self.child.wait()).await??.success());
        let mut trailing = Vec::new();
        timeout(WAIT, self.stdout.read_to_end(&mut trailing)).await??;
        ensure!(trailing.is_empty(), "unsolicited MCP output");
        Ok(timeout(WAIT, self.stderr).await???)
    }
}

#[tokio::test]
async fn native_startup_ignores_absent_bad_and_disabled_runtime_references() -> Result<()> {
    let missing = Local::new("")?;
    let mut baseline = Server::start(missing.command()?)?;
    let expected = baseline.catalog().await?;
    baseline.stop().await?;
    for reference in [
        "relative-private-invalid",
        "/AUTOMATION_PRIVATE_SENTINEL/no-runtime",
    ] {
        let mut command = missing.command()?;
        command.env("SSH_MCP_ANSIBLE_RUNTIME", reference);
        let mut server = Server::start(command)?;
        ensure!(server.catalog().await? == expected);
        server.stop().await?;
    }
    let disabled = Local::new("[automation]\nrequired = false\n")?;
    // A FIFO makes accidental reads observable as a hang, not a passing missing-file shortcut.
    let unread = disabled.root.path().join("unread-runtime");
    fs::create_dir(&unread)?;
    nix::unistd::mkfifo(
        &unread.join("runtime.json"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let mut config = fs::read_to_string(&disabled.config)?;
    config.push_str(&format!(
        "runtime = {}\n",
        serde_json::to_string(&unread.to_string_lossy())?
    ));
    fs::write(&disabled.config, config)?;
    let mut server = Server::start(disabled.command()?)?;
    ensure!(server.catalog().await? == expected);
    server.stop().await?;
    ensure!(!missing.marker.exists() && !disabled.marker.exists());
    Ok(())
}

#[tokio::test]
async fn required_missing_runtime_fails_before_mcp_but_doctor_can_report_it() -> Result<()> {
    let fixture = Local::new("[automation]\nrequired = true\n")?;
    let startup = output(fixture.command()?).await?;
    ensure!(startup.status.code() == Some(1) && startup.stdout.is_empty());
    let error: Value = serde_json::from_slice(&startup.stderr)?;
    ensure!(error["event"] == "error" && error["code"] == "automation_runtime_unavailable");
    fixture.private(&startup)?;
    let checked = output(fixture.doctor()?).await?;
    runtime_failed(&report(&checked, 1)?, "runtime_unavailable")?;
    fixture.private(&checked)
}

#[tokio::test]
async fn doctor_runtime_only_and_invalid_targets_are_private_and_network_free() -> Result<()> {
    let fixture = Local::new("")?;
    let checked = output(fixture.doctor()?).await?;
    runtime_failed(&report(&checked, 1)?, "runtime_unavailable")?;
    fixture.private(&checked)?;
    for args in [
        vec!["--target", SECRET],
        vec!["--target", "allowed", "--target", "allowed"],
        vec!["--timeout-secs", "0"],
    ] {
        let mut command = fixture.doctor()?;
        command
            .args(&args)
            .env("SSH_MCP_ANSIBLE_RUNTIME", "relative-private-invalid");
        let rejected = output(command).await?;
        let expected = if args.contains(&"--timeout-secs") {
            "invalid_timeout"
        } else {
            "invalid_target_selection"
        };
        ensure!(report(&rejected, 2)? == json!({"ok":false,"targets":[],"error_code":expected}));
        fixture.private(&rejected)?;
    }
    let mut target_only = fixture.command()?;
    target_only.args(["doctor", "--target", SECRET]);
    let rejected = output(target_only).await?;
    ensure!(
        report(&rejected, 2)?
            == json!({"ok":false,"targets":[],"error_code":"invalid_target_selection"})
    );
    fixture.private(&rejected)
}

#[tokio::test]
async fn automation_config_and_cli_rejections_do_not_disclose_private_values() -> Result<()> {
    for body in [
        format!("[automation]\n{SECRET} = true\n"),
        format!("[automation]\nrequired = '{SECRET}'\n"),
        format!("[automation]\nruntime = '{SECRET}'\n"),
        "[automation]\nruntime = \"\\u0000\"\n".to_owned(),
        format!("[automation]\nruntime = '/{}'\n", SECRET.repeat(400)),
    ] {
        let fixture = Local::new(&body)?;
        let rejected = output(fixture.doctor()?).await?;
        ensure!(rejected.status.code() == Some(2) && rejected.stdout.is_empty());
        let error: Value = serde_json::from_slice(&rejected.stderr)?;
        ensure!(error["event"] == "error" && error["code"] == "invalid_config");
        fixture.private(&rejected)?;
    }
    let fixture = Local::new("")?;
    for args in [
        vec!["--runtime-path", "unknown"],
        vec!["--playbook", "unknown"],
        vec!["--runtime", "unknown"],
    ] {
        let mut command = fixture.doctor()?;
        command.args(args);
        let rejected = output(command).await?;
        ensure!(rejected.status.code() == Some(2) && rejected.stdout.is_empty());
        fixture.private(&rejected)?;
    }
    Ok(())
}

fn real_runtime() -> Result<PathBuf> {
    // Explicit acceptance never silently substitutes a Cargo binary or ambient Python.
    let binary = std::env::var_os("SSH_MCP_TEST_BINARY")
        .context("set SSH_MCP_TEST_BINARY to the installed native executable")?;
    ensure!(Path::new(&binary).is_absolute() && Path::new(&binary).is_file());
    let root = PathBuf::from(
        std::env::var_os("SSH_MCP_TEST_ANSIBLE_RUNTIME")
            .context("set SSH_MCP_TEST_ANSIBLE_RUNTIME to the shipped runtime")?,
    );
    ensure!(root.is_absolute() && root.join("runtime.json").is_file());
    Ok(root)
}

fn configured_runtime(root: &Path, required: bool) -> Result<Local> {
    Local::new(&format!(
        "[automation]\nrequired = {required}\nruntime = {}\n",
        serde_json::to_string(&root.to_string_lossy())?
    ))
}

// Snapshot links without traversing the Python closure; include the actual immutable metadata.
fn runtime_metadata(root: &Path) -> Result<Vec<(PathBuf, Vec<u8>, u32)>> {
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("runtime.json"))?)?;
    let mut paths = vec![root.join("runtime.json"), root.join("ansible.cfg")];
    for collection in manifest["identity"]["collections"]
        .as_array()
        .context("collections")?
    {
        let name = collection["name"].as_str().context("collection name")?;
        paths.push(
            root.join("collections/ansible_collections")
                .join(name.replace('.', "/"))
                .join("MANIFEST.json"),
        );
    }
    for path in [root.join("python"), root.join("bin/python3")] {
        paths.push(path);
    }
    paths
        .into_iter()
        .map(|path| {
            let metadata = fs::symlink_metadata(&path)?;
            let bytes = if metadata.file_type().is_symlink() {
                fs::read_link(&path)?
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                fs::read(&path)?
            };
            Ok((path, bytes, metadata.permissions().mode()))
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_runtime_imports_are_pinned_isolated_repeatable_and_do_not_register_tools()
-> Result<()> {
    let root = real_runtime()?;
    let before = runtime_metadata(&root)?;
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("runtime.json"))?)?;
    let expected = bundle_identity(&manifest)?;
    let collections = expected["collections"].as_array().context("collections")?;
    for collection in collections {
        let path = root
            .join("collections/ansible_collections")
            .join(
                collection["name"]
                    .as_str()
                    .context("name")?
                    .replace('.', "/"),
            )
            .join("MANIFEST.json");
        let bytes = fs::read(path)?;
        let observed: Value = serde_json::from_slice(&bytes)?;
        ensure!(collection["version"] == observed["collection_info"]["version"]);
        use sha2::Digest;
        ensure!(collection["manifest_sha256"] == hex::encode(sha2::Sha256::digest(&bytes)));
    }
    let fixture = configured_runtime(&root, false)?;
    let injected = fixture.root.path().join("python-injection-ran");
    let poison = format!(
        "from pathlib import Path\nPath({:?}).write_text('forbidden')\nraise RuntimeError('PYTHON_INJECTION_RAN')\n",
        injected.to_str().context("injection path")?
    );
    for name in [
        "sitecustomize.py",
        "usercustomize.py",
        "ansible.py",
        "ansible_runner.py",
    ] {
        fs::write(fixture.root.path().join(name), &poison)?;
    }
    let ambient_cfg = fixture.root.path().join("ansible.cfg");
    fs::write(
        &ambient_cfg,
        format!("[defaults]\ncollections_path = /{SECRET}\nlocal_tmp = /{SECRET}\n"),
    )?;
    for _ in 0..2 {
        let mut command = fixture.doctor()?;
        command
            .env("PYTHONPATH", fixture.root.path())
            .env("PYTHONHOME", fixture.root.path())
            .env(
                "PYTHONSTARTUP",
                fixture.root.path().join("sitecustomize.py"),
            )
            .env("ANSIBLE_CONFIG", &ambient_cfg)
            .env("ANSIBLE_COLLECTIONS_PATH", fixture.root.path())
            .env(
                "ANSIBLE_LOCAL_TEMP",
                fixture.root.path().join("forbidden-local-temp"),
            )
            .env(
                "SSH_MCP_ANSIBLE_RUNTIME",
                "/AUTOMATION_PRIVATE_SENTINEL/ignored-env",
            );
        let checked = output(command).await?;
        let value = report(&checked, 0)?;
        ensure!(
            value["runtime"] == json!({"kind":"ansible", "status":"passed", "identity":expected})
        );
        fixture.private(&checked)?;
    }
    ensure!(!injected.exists() && !fixture.root.path().join("forbidden-local-temp").exists());
    let native = Local::new("")?;
    let mut baseline = Server::start(native.command()?)?;
    let catalog = baseline.catalog().await?;
    baseline.stop().await?;
    let required = configured_runtime(&root, true)?;
    let mut server = Server::start(required.command()?)?;
    ensure!(
        server.catalog().await? == catalog,
        "required runtime altered native metadata"
    );
    let stderr = server.stop().await?;
    required.private(&Output {
        status: std::process::ExitStatus::default(),
        stdout: Vec::new(),
        stderr,
    })?;
    ensure!(
        runtime_metadata(&root)? == before,
        "runtime metadata mutated"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_AUTOMATION_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn packaged_automation_wrapper_authoritatively_selects_its_pinned_runtime() -> Result<()> {
    let root = real_runtime()?;
    let binary = PathBuf::from(
        std::env::var_os("SSH_MCP_TEST_AUTOMATION_BINARY")
            .context("set SSH_MCP_TEST_AUTOMATION_BINARY to the installed automation wrapper")?,
    );
    ensure!(binary.is_absolute() && binary.is_file());
    let manifest: Value = serde_json::from_slice(&fs::read(root.join("runtime.json"))?)?;
    let expected = bundle_identity(&manifest)?;
    let before = runtime_metadata(&root)?;
    let fixture = Local::new("[automation]\nrequired = true\n")?;
    let wrapper_command = || {
        let mut command = Command::new(&binary);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SSH_MCP_") {
                command.env_remove(name);
            }
        }
        command
            .arg("--config")
            .arg(&fixture.config)
            .current_dir(fixture.root.path())
            .env("HOME", fixture.root.path())
            .env(
                "SSH_MCP_ANSIBLE_RUNTIME",
                "/AUTOMATION_PRIVATE_SENTINEL/must-be-overridden",
            )
            .kill_on_drop(true);
        command
    };
    let mut doctor = wrapper_command();
    doctor.args(["doctor", "--runtime", "ansible"]);
    let checked = output(doctor).await?;
    ensure!(
        report(&checked, 0)?["runtime"]
            == json!({
                "kind":"ansible", "status":"passed", "identity":expected
            })
    );
    fixture.private(&checked)?;
    let native = Local::new("")?;
    let mut baseline = Server::start(native.command()?)?;
    let catalog = baseline.catalog().await?;
    baseline.stop().await?;
    let mut server = Server::start(wrapper_command())?;
    ensure!(server.catalog().await? == catalog);
    let stderr = server.stop().await?;
    for secret in [SECRET, root.to_str().context("runtime path")?] {
        ensure!(!String::from_utf8_lossy(&stderr).contains(secret));
    }
    ensure!(!fixture.marker.exists());
    ensure!(runtime_metadata(&root)? == before);
    Ok(())
}

fn linked_runtime(actual: &Path, parent: &Path) -> Result<PathBuf> {
    let root = parent.join("mutable-runtime");
    fs::create_dir(&root)?;
    for name in ["bin", "python", "ansible.cfg", "collections"] {
        symlink(actual.join(name), root.join(name))?;
    }
    fs::copy(actual.join("runtime.json"), root.join("runtime.json"))?;
    // Nix source permissions must not make this temp-owned manifest immutable.
    fs::set_permissions(root.join("runtime.json"), fs::Permissions::from_mode(0o600))?;
    Ok(root)
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_runtime_rejects_manifest_version_health_hash_and_collection_drift() -> Result<()> {
    let actual = real_runtime()?;
    let before = runtime_metadata(&actual)?;
    for case in [
        "malformed",
        "unknown",
        "oversized",
        "health_hash",
        "site_packages",
        "version",
        "collection",
    ] {
        let owned = tempfile::tempdir()?;
        let root = linked_runtime(&actual, owned.path())?;
        let path = root.join("runtime.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let code = match case {
            "malformed" => {
                fs::write(&path, b"{")?;
                "invalid_runtime_manifest"
            }
            "oversized" => {
                fs::write(&path, vec![b' '; 16_385])?;
                "invalid_runtime_manifest"
            }
            "unknown" => {
                manifest[SECRET] = json!(true);
                "invalid_runtime_manifest"
            }
            "health_hash" => {
                manifest["health_sha256"] = json!("0".repeat(64));
                "invalid_runtime_manifest"
            }
            "site_packages" => {
                manifest["site_packages"] = json!(format!("../{SECRET}"));
                "invalid_runtime_manifest"
            }
            "version" => {
                manifest["identity"]["python"] = json!("0.0.0");
                "runtime_version_mismatch"
            }
            "collection" => {
                // Only the changed collection is copied; executable/import assets remain real links.
                fs::remove_file(root.join("collections"))?;
                let base = root.join("collections/ansible_collections");
                fs::create_dir_all(&base)?;
                let selected = manifest["identity"]["collections"]
                    .as_array()
                    .context("collections")?;
                for (index, collection) in selected.iter().enumerate() {
                    let name = collection["name"]
                        .as_str()
                        .context("collection")?
                        .replace('.', "/");
                    let source = actual.join("collections/ansible_collections").join(&name);
                    let destination = base.join(&name);
                    fs::create_dir_all(destination.parent().context("namespace")?)?;
                    if index == 0 {
                        fs::create_dir(&destination)?;
                        for entry in fs::read_dir(&source)? {
                            let entry = entry?;
                            if entry.file_name() == "MANIFEST.json" {
                                let mut bytes = fs::read(entry.path())?;
                                bytes.push(b' ');
                                fs::write(destination.join(entry.file_name()), bytes)?;
                            } else {
                                symlink(entry.path(), destination.join(entry.file_name()))?;
                            }
                        }
                    } else {
                        symlink(source, destination)?;
                    }
                }
                "runtime_collection_mismatch"
            }
            _ => unreachable!(),
        };
        if !matches!(case, "malformed" | "oversized") {
            fs::write(&path, serde_json::to_vec(&manifest)?)?;
        }
        let fixture = configured_runtime(&root, false)?;
        let checked = output(fixture.doctor()?).await?;
        runtime_failed(&report(&checked, 1)?, code)
            .with_context(|| format!("drift case {case}"))?;
        fixture.private(&checked)?;
        for bytes in [&checked.stdout, &checked.stderr] {
            ensure!(
                !String::from_utf8_lossy(bytes).contains(root.to_str().context("runtime path")?)
            );
        }
        let required = configured_runtime(&root, true)?;
        let startup = output(required.command()?).await?;
        ensure!(startup.status.code() == Some(1) && startup.stdout.is_empty());
        let error: Value = serde_json::from_slice(&startup.stderr)?;
        ensure!(error["code"] == "automation_runtime_unavailable");
        required.private(&startup)?;
    }
    ensure!(
        runtime_metadata(&actual)? == before,
        "drift acceptance changed shipped assets"
    );
    Ok(())
}

fn bundle_identity(manifest: &Value) -> Result<Value> {
    let mut identity = manifest["identity"].clone();
    let fields = identity.as_object_mut().context("bundle identity")?;
    let runtime_id = fields.remove("runtime_id").context("bundle runtime_id")?;
    fields.insert(
        "provenance".to_owned(),
        json!({"kind":"nix_bundle", "runtime_id":runtime_id}),
    );
    Ok(identity)
}
