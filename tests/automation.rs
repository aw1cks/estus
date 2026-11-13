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

    fn installed_command(&self, reference: &str) -> Result<Command> {
        let binary = installed_path(reference)?;
        let mut command = Command::new(binary);
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("SSH_MCP_") {
                command.env_remove(name);
            }
        }
        command
            .arg("--config")
            .arg(&self.config)
            .current_dir(self.root.path())
            .env("HOME", self.root.path())
            .env("XDG_CONFIG_HOME", self.root.path())
            .kill_on_drop(true);
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
        for reference in [
            "SSH_MCP_TEST_WHEEL_BINARY",
            "SSH_MCP_TEST_BASE_WHEEL_BINARY",
            "SSH_MCP_TEST_MUTABLE_PYTHON",
        ] {
            if let Some(binary) = std::env::var_os(reference)
                && let Some(prefix) = Path::new(&binary).parent().and_then(Path::parent)
            {
                let private = prefix
                    .to_str()
                    .context("UTF-8 installed environment prefix")?;
                for bytes in [&output.stdout, &output.stderr] {
                    ensure!(
                        !String::from_utf8_lossy(bytes).contains(private),
                        "installed environment path leaked"
                    );
                }
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
    for descriptor in ["{".to_owned(), "x".repeat(65_537)] {
        let mut command = missing.command()?;
        command.env("SSH_MCP_PYTHON_RUNTIME", descriptor);
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

fn installed_path(reference: &str) -> Result<PathBuf> {
    let path = PathBuf::from(
        std::env::var_os(reference)
            .with_context(|| format!("set {reference} to its installed path"))?,
    );
    ensure!(path.is_absolute() && path.is_file(), "invalid {reference}");
    Ok(path)
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

fn wheel_prefix(reference: &str) -> Result<PathBuf> {
    let binary = installed_path(reference)?;
    let scripts = binary.parent().context("wheel scripts directory")?;
    ensure!(scripts.file_name().is_some_and(|name| name == "bin"));
    Ok(scripts
        .parent()
        .context("wheel environment prefix")?
        .to_owned())
}

fn distribution_metadata(prefix: &Path, distribution: &str) -> Result<PathBuf> {
    let site = prefix.join("lib/python3.14/site-packages");
    let mut matches = Vec::new();
    for entry in fs::read_dir(site)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .context("distribution filename")?
            .to_string_lossy();
        if name.starts_with(&format!("{distribution}-")) && name.ends_with(".dist-info") {
            matches.push(path.join("METADATA"));
        }
    }
    ensure!(
        matches.len() == 1,
        "expected one {distribution} distribution"
    );
    Ok(matches.remove(0))
}

fn observed_environment_identity(value: &Value, prefix: &Path) -> Result<Value> {
    ensure!(value["runtime"]["kind"] == "ansible");
    ensure!(value["runtime"]["status"] == "passed");
    let identity = &value["runtime"]["identity"];
    ensure!(identity["provenance"] == json!({"kind":"python_environment"}));
    let fields = identity.as_object().context("environment identity")?;
    ensure!(fields.keys().all(|key| matches!(
        key.as_str(),
        "provenance"
            | "platform"
            | "python"
            | "ansible_core"
            | "ansible_runner"
            | "collection_bundle"
            | "collections"
    )));
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => anyhow::bail!("unsupported acceptance architecture {other}"),
    };
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => anyhow::bail!("unsupported acceptance OS {other}"),
    };
    ensure!(identity["platform"] == format!("{arch}-{os}"));
    ensure!(
        identity["python"]
            .as_str()
            .context("Python version")?
            .starts_with("3.14.")
    );
    for (distribution, field, expected) in [
        ("ansible", "collection_bundle", "14.4.0"),
        ("ansible_core", "ansible_core", "2.21.5"),
        ("ansible_runner", "ansible_runner", "2.4.3"),
    ] {
        let metadata = fs::read_to_string(distribution_metadata(prefix, distribution)?)?;
        let versions: Vec<_> = metadata
            .lines()
            .filter_map(|line| line.strip_prefix("Version: "))
            .collect();
        ensure!(
            versions == [expected],
            "installed {distribution} pin drifted"
        );
        ensure!(identity[field] == expected);
    }
    let collections = identity["collections"]
        .as_array()
        .context("observed collections")?;
    ensure!(collections.len() == 2);
    for (collection, name) in collections
        .iter()
        .zip(["ansible.posix", "community.general"])
    {
        ensure!(collection["name"] == name);
        let path = prefix
            .join("lib/python3.14/site-packages/ansible_collections")
            .join(name.replace('.', "/"))
            .join("MANIFEST.json");
        let bytes = fs::read(path)?;
        let manifest: Value = serde_json::from_slice(&bytes)?;
        let (namespace, collection_name) = name.split_once('.').context("collection name")?;
        ensure!(manifest["collection_info"]["namespace"] == namespace);
        ensure!(manifest["collection_info"]["name"] == collection_name);
        ensure!(collection["version"] == manifest["collection_info"]["version"]);
        use sha2::Digest;
        ensure!(collection["manifest_sha256"] == hex::encode(sha2::Sha256::digest(&bytes)));
    }
    Ok(identity.clone())
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
                "kind":"ansible", "status":"passed", "identity":bundle_identity(&manifest)?
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

fn schema_report(fixture: &Local, output: &Output, ok: bool) -> Result<Value> {
    fixture.private(output)?;
    let value: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        output.status.code() == Some(i32::from(!ok)),
        "schema report: {value}"
    );
    ensure!(output.stderr.is_empty());
    ensure!(value["ok"] == ok, "schema report: {value}");
    Ok(value)
}

#[tokio::test]
async fn schema_authoring_rejects_invalid_names_and_duplicate_json_without_runtime() -> Result<()> {
    let fixture = Local::new("")?;
    let destination = fixture.root.path().join("review.json");
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.ping;private"])
        .arg("--output")
        .arg(&destination);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "invalid_module_name");
    ensure!(!destination.exists());
    let overlay = fixture.root.path().join("overlay.json");
    fs::write(
        &overlay,
        r#"{"fixed_args":{},"fixed_args":{"state":"absent"}}"#,
    )?;
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.ping"])
        .arg("--output")
        .arg(&destination)
        .arg("--overlay")
        .arg(&overlay);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "invalid_schema_json");
    ensure!(!destination.exists());
    Ok(())
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_schema_import_review_and_fixed_binding_validation_never_execute() -> Result<()> {
    let root = real_runtime()?;
    let fixture = configured_runtime(&root, false)?;
    let snapshot = fixture.root.path().join("stat.json");
    let overlay = fixture.root.path().join("binding.json");
    let input = fixture.root.path().join("request.json");
    fs::write(
        &overlay,
        serde_json::to_vec(&json!({
            "input_schema":{"type":"object","properties":{"follow":{"type":"boolean"}},
                "required":["follow"],"additionalProperties":false},
            "fixed_args":{"path":"/not-an-approved-execution-target"},
            "input_map":{"follow":"follow"}
        }))?,
    )?;
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.stat"])
        .arg("--output")
        .arg(&snapshot)
        .arg("--overlay")
        .arg(&overlay);
    let imported = output(command).await?;
    ensure!(schema_report(&fixture, &imported, true)?["binding_validated"] == true);
    let reviewed = fs::read(&snapshot)?;
    let value: Value = serde_json::from_slice(&reviewed)?;
    ensure!(value["module"] == "ansible.builtin.stat");
    ensure!(value["runtime"]["provenance"]["kind"] == "nix_bundle");
    ensure!(value["contract"]["schema"]["properties"]["path"]["type"] == "string");
    ensure!(value["contract"]["schema"]["properties"]["follow"]["type"] == "boolean");
    ensure!(!String::from_utf8_lossy(&reviewed).contains("/nix/store/"));

    for (request, valid) in [
        (json!({"follow":false}), true),
        (json!({"follow":true,"path":"/fixed-override"}), false),
        (json!({"follow":"false"}), false),
    ] {
        fs::write(&input, serde_json::to_vec(&request)?)?;
        let mut command = fixture.command()?;
        command
            .args(["schema", "verify"])
            .arg(&snapshot)
            .arg("--input")
            .arg(&input);
        let checked = output(command).await?;
        let report = schema_report(&fixture, &checked, valid)?;
        if valid {
            ensure!(report["input_validated"] == true);
        }
    }
    // An import never replaces a previously reviewed file.
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.ping"])
        .arg("--output")
        .arg(&snapshot);
    let rejected = output(command).await?;
    ensure!(
        schema_report(&fixture, &rejected, false)?["error_code"]
            == "schema_output_exists_or_failed"
    );
    ensure!(fs::read(&snapshot)? == reviewed);
    // Altering a reviewed contract without its digest is not a refresh operation.
    let mut tampered = value;
    tampered["contract"]["schema"]["properties"]["path"]["type"] = json!("boolean");
    fs::write(&snapshot, serde_json::to_vec(&tampered)?)?;
    let mut command = fixture.command()?;
    command.args(["schema", "verify"]).arg(&snapshot);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "invalid_schema_snapshot");
    // Selected collection provenance is separate from the baseline runtime inventory.
    let collection_snapshot = fixture.root.path().join("mount.json");
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.posix.mount"])
        .arg("--output")
        .arg(&collection_snapshot);
    let imported = output(command).await?;
    schema_report(&fixture, &imported, true)?;
    let collection: Value = serde_json::from_slice(&fs::read(&collection_snapshot)?)?;
    let manifest: Value = serde_json::from_slice(&fs::read(
        root.join("collections/ansible_collections/ansible/posix/MANIFEST.json"),
    )?)?;
    ensure!(collection["collection"]["name"] == "ansible.posix");
    ensure!(collection["collection"]["version"] == manifest["collection_info"]["version"]);
    let mut command = fixture.command()?;
    command.args(["schema", "verify"]).arg(&collection_snapshot);
    let verified = output(command).await?;
    schema_report(&fixture, &verified, true)?;
    Ok(())
}

fn copy_runtime_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_name() == "__pycache__" {
            continue;
        }
        let path = entry.path();
        let target = destination.join(entry.file_name());
        if path.is_dir() {
            copy_runtime_tree(&path, &target)?;
        } else {
            fs::copy(&path, &target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_schema_verify_detects_implementation_drift_without_documentation_changes()
-> Result<()> {
    let actual = real_runtime()?;
    let owner = tempfile::tempdir()?;
    let runtime = linked_runtime(&actual, owner.path())?;
    fs::remove_file(runtime.join("python"))?;
    let manifest: Value = serde_json::from_slice(&fs::read(runtime.join("runtime.json"))?)?;
    let site = runtime.join(manifest["site_packages"].as_str().context("site")?);
    let source_site = actual.join(manifest["site_packages"].as_str().context("site")?);
    fs::create_dir_all(&site)?;
    for entry in fs::read_dir(&source_site)? {
        let entry = entry?;
        if entry.file_name() == "ansible" {
            copy_runtime_tree(&entry.path(), &site.join("ansible"))?;
        } else {
            symlink(entry.path(), site.join(entry.file_name()))?;
        }
    }
    let fixture = configured_runtime(&runtime, false)?;
    let snapshot = fixture.root.path().join("ping.json");
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.ping"])
        .arg("--output")
        .arg(&snapshot);
    let imported = output(command).await?;
    schema_report(&fixture, &imported, true)?;
    let source = site.join("ansible/module_utils/basic.py");
    let mut bytes = fs::read(&source)?;
    bytes.extend_from_slice(b"\n# owned acceptance drift, no documentation or version change\n");
    fs::write(source, bytes)?;
    let mut command = fixture.command()?;
    command.args(["schema", "verify"]).arg(&snapshot);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "schema_drift");
    Ok(())
}

// These cases require installer-managed environments, not just the immutable bundle.
mod wheel {
    use super::*;

    fn environment_descriptor(interpreter: &Path, prefix: &Path) -> Value {
        json!({"schema":2, "interpreter":interpreter, "prefix":prefix,
            "package_root":prefix.join("lib/python3.14/site-packages/ssh_mcp"),
            "scripts":prefix.join("bin")})
    }

    #[tokio::test]
    #[ignore = "requires SSH_MCP_TEST_WHEEL_BINARY extra and SSH_MCP_TEST_BASE_WHEEL_BINARY clean base Python3.14 public launchers; no network"]
    async fn installed_extra_is_observed_and_required_without_changing_native_catalog() -> Result<()>
    {
        let prefix = wheel_prefix("SSH_MCP_TEST_WHEEL_BINARY")?;
        let base_prefix = wheel_prefix("SSH_MCP_TEST_BASE_WHEEL_BINARY")?;
        let native = Local::new("")?;
        let mut baseline =
            Server::start(native.installed_command("SSH_MCP_TEST_BASE_WHEEL_BINARY")?)?;
        let catalog = baseline.catalog().await?;
        baseline.stop().await?;
        let fixture = Local::new("[automation]\nrequired = true\n")?;
        let mut observed = None;
        for _ in 0..2 {
            let mut command = fixture.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
            command
                .args(["doctor", "--runtime", "ansible"])
                // No activation; another real interpreter is first on PATH. The launcher must also
                // replace a caller's descriptor instead of trusting this broken selection.
                .env("PATH", base_prefix.join("bin"))
                .env_remove("VIRTUAL_ENV")
                .env("SSH_MCP_PYTHON_RUNTIME", "{");
            let checked = output(command).await?;
            let identity = observed_environment_identity(&report(&checked, 0)?, &prefix)?;
            if let Some(previous) = &observed {
                ensure!(
                    previous == &identity,
                    "environment observation was not repeatable"
                );
            }
            observed = Some(identity);
            fixture.private(&checked)?;
        }
        let mut command = fixture.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
        command
            .env("PATH", base_prefix.join("bin"))
            .env_remove("VIRTUAL_ENV");
        let mut server = Server::start(command)?;
        ensure!(
            server.catalog().await? == catalog,
            "extra registered automation tools"
        );
        let stderr = server.stop().await?;
        fixture.private(&Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr,
        })?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires SSH_MCP_TEST_BASE_WHEEL_BINARY clean base Python3.14 public launcher without Ansible; no network"]
    async fn installed_base_remains_native_only_and_requested_extra_fails_before_mcp() -> Result<()>
    {
        let native = Local::new("")?;
        let mut server =
            Server::start(native.installed_command("SSH_MCP_TEST_BASE_WHEEL_BINARY")?)?;
        server.catalog().await?;
        server.stop().await?;
        let required = Local::new("[automation]\nrequired = true\n")?;
        let mut doctor = required.installed_command("SSH_MCP_TEST_BASE_WHEEL_BINARY")?;
        doctor.args(["doctor", "--runtime", "ansible"]);
        let checked = output(doctor).await?;
        runtime_failed(&report(&checked, 1)?, "runtime_import_failed")?;
        required.private(&checked)?;
        let startup = output(required.installed_command("SSH_MCP_TEST_BASE_WHEEL_BINARY")?).await?;
        ensure!(startup.status.code() == Some(1) && startup.stdout.is_empty());
        let error: Value = serde_json::from_slice(&startup.stderr)?;
        ensure!(error["event"] == "error" && error["code"] == "automation_runtime_unavailable");
        required.private(&startup)
    }

    #[tokio::test]
    #[ignore = "requires SSH_MCP_TEST_WHEEL_BINARY, SSH_MCP_TEST_BINARY raw native, and SSH_MCP_TEST_ANSIBLE_RUNTIME Nix bundle; no network"]
    async fn explicit_bundle_config_and_environment_precede_launcher_without_fallback() -> Result<()>
    {
        let root = real_runtime()?;
        let manifest: Value = serde_json::from_slice(&fs::read(root.join("runtime.json"))?)?;
        let expected = bundle_identity(&manifest)?;
        let configured = configured_runtime(&root, false)?;
        let mut command = configured.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
        command.args(["doctor", "--runtime", "ansible"]).env(
            "SSH_MCP_ANSIBLE_RUNTIME",
            "/AUTOMATION_PRIVATE_SENTINEL/broken",
        );
        let checked = output(command).await?;
        ensure!(report(&checked, 0)?["runtime"]["identity"] == expected);
        configured.private(&checked)?;
        let selected = Local::new("")?;
        let mut command = selected.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
        command
            .args(["doctor", "--runtime", "ansible"])
            .env("SSH_MCP_ANSIBLE_RUNTIME", &root);
        let checked = output(command).await?;
        ensure!(report(&checked, 0)?["runtime"]["identity"] == expected);
        selected.private(&checked)?;
        for config_wins in [false, true] {
            let broken = if config_wins {
                configured_runtime(Path::new("/AUTOMATION_PRIVATE_SENTINEL/broken"), true)?
            } else {
                Local::new("[automation]\nrequired = true\n")?
            };
            let reference = if config_wins {
                root.as_os_str()
            } else {
                std::ffi::OsStr::new("/AUTOMATION_PRIVATE_SENTINEL/broken")
            };
            let mut command = broken.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
            command
                .args(["doctor", "--runtime", "ansible"])
                .env("SSH_MCP_ANSIBLE_RUNTIME", reference);
            let checked = output(command).await?;
            runtime_failed(&report(&checked, 1)?, "runtime_unavailable")?;
            broken.private(&checked)?;
            let mut command = broken.installed_command("SSH_MCP_TEST_WHEEL_BINARY")?;
            command.env("SSH_MCP_ANSIBLE_RUNTIME", reference);
            let startup = output(command).await?;
            ensure!(startup.status.code() == Some(1) && startup.stdout.is_empty());
            let error: Value = serde_json::from_slice(&startup.stderr)?;
            ensure!(error["code"] == "automation_runtime_unavailable");
            broken.private(&startup)?;
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires SSH_MCP_TEST_BINARY raw native plus SSH_MCP_TEST_WHEEL_BINARY and SSH_MCP_TEST_BASE_WHEEL_BINARY Python3.14 environments; no network"]
    async fn selected_environment_worker_ignores_toxic_python_ansible_cwd_and_executable_path()
    -> Result<()> {
        installed_path("SSH_MCP_TEST_BINARY")?;
        let prefix = wheel_prefix("SSH_MCP_TEST_WHEEL_BINARY")?;
        let base = wheel_prefix("SSH_MCP_TEST_BASE_WHEEL_BINARY")?;
        let interpreter = prefix.join("bin/python");
        ensure!(interpreter.is_file());
        ensure!(
            fs::symlink_metadata(&interpreter)?.file_type().is_symlink(),
            "acceptance requires an unactivated symlink venv"
        );
        let fixture = Local::new("[automation]\nrequired = true\n")?;
        let poisoned = fixture.root.path().join("poisoned-bin");
        fs::create_dir(&poisoned)?;
        // These are real, wrong-environment interpreters, not replacement health workers.
        for name in ["python", "python3"] {
            symlink(base.join("bin/python"), poisoned.join(name))?;
        }
        let injection = "raise RuntimeError('PYTHON_INJECTION_RAN')\n";
        for name in [
            "sitecustomize.py",
            "usercustomize.py",
            "ansible.py",
            "ansible_runner.py",
        ] {
            fs::write(fixture.root.path().join(name), injection)?;
        }
        let ambient_cfg = fixture.root.path().join("ansible.cfg");
        fs::write(
            &ambient_cfg,
            format!("[defaults]\ncollections_path = /{SECRET}\nlocal_tmp = /{SECRET}\n"),
        )?;
        let descriptor = environment_descriptor(&interpreter, &prefix).to_string();
        let mut command = fixture.doctor()?;
        command
            .env("SSH_MCP_PYTHON_RUNTIME", &descriptor)
            .env("PATH", &poisoned)
            .env("VIRTUAL_ENV", &base)
            .env("PYTHONPATH", fixture.root.path())
            .env("PYTHONHOME", fixture.root.path())
            .env("PYTHONUSERBASE", fixture.root.path())
            .env(
                "PYTHONSTARTUP",
                fixture.root.path().join("sitecustomize.py"),
            )
            .env("PYTHONINSPECT", "1")
            .env("PYTHONWARNINGS", "error")
            .env("ANSIBLE_CONFIG", &ambient_cfg)
            .env("ANSIBLE_COLLECTIONS_PATH", fixture.root.path())
            .env("ANSIBLE_COLLECTIONS_PATHS", fixture.root.path())
            .env(
                "ANSIBLE_LOCAL_TEMP",
                fixture.root.path().join("forbidden-local-temp"),
            )
            .env("ANSIBLE_COLLECTIONS_SCAN_SYS_PATH", "true");
        let checked = output(command).await?;
        observed_environment_identity(&report(&checked, 0)?, &prefix)?;
        fixture.private(&checked)?;
        ensure!(!fixture.root.path().join("forbidden-local-temp").exists());
        let mut missing_package = environment_descriptor(&interpreter, &prefix);
        missing_package["package_root"] =
            json!(fixture.root.path().join("missing-package/ssh_mcp"));
        let mut missing_scripts = environment_descriptor(&interpreter, &prefix);
        missing_scripts["scripts"] = json!(fixture.root.path().join("missing-scripts"));
        for bad_descriptor in [
            environment_descriptor(&base.join("bin/python"), &prefix),
            environment_descriptor(&fixture.root.path().join("missing-python"), &prefix),
            missing_package,
            missing_scripts,
        ] {
            let mut command = fixture.doctor()?;
            command
                .env("SSH_MCP_PYTHON_RUNTIME", bad_descriptor.to_string())
                .env("PATH", prefix.join("bin"));
            let checked = output(command).await?;
            let value = report(&checked, 1)?;
            ensure!(
                value["runtime"]["status"] == "failed",
                "invalid selection fell back to PATH"
            );
            ensure!(value["runtime"].get("identity").is_none());
            fixture.private(&checked)?;
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires raw SSH_MCP_TEST_BINARY, SSH_MCP_TEST_WHEEL_BINARY, SSH_MCP_TEST_BASE_WHEEL_BINARY, owned copied SSH_MCP_TEST_MUTABLE_PYTHON and SSH_MCP_TEST_MUTABLE_PREFIX; no network"]
    async fn owned_environment_reports_manifest_observations_and_rejects_real_asset_drift()
    -> Result<()> {
        installed_path("SSH_MCP_TEST_BINARY")?;
        let interpreter = installed_path("SSH_MCP_TEST_MUTABLE_PYTHON")?;
        let prefix = PathBuf::from(
            std::env::var_os("SSH_MCP_TEST_MUTABLE_PREFIX").context("set owned mutable prefix")?,
        );
        ensure!(prefix.is_absolute() && prefix.is_dir());
        ensure!(interpreter.parent() == Some(prefix.join("bin").as_path()));
        // Refuse the supplied original environments even if accidentally configured as mutable.
        for reference in [
            "SSH_MCP_TEST_WHEEL_BINARY",
            "SSH_MCP_TEST_BASE_WHEEL_BINARY",
        ] {
            ensure!(fs::canonicalize(&prefix)? != fs::canonicalize(wheel_prefix(reference)?)?);
        }
        let descriptor = environment_descriptor(&interpreter, &prefix).to_string();
        let fixture = Local::new("[automation]\nrequired = true\n")?;
        let mut command = fixture.doctor()?;
        command.env("SSH_MCP_PYTHON_RUNTIME", &descriptor);
        let checked = output(command).await?;
        let original = observed_environment_identity(&report(&checked, 0)?, &prefix)?;
        fixture.private(&checked)?;
        let collection = prefix
            .join("lib/python3.14/site-packages/ansible_collections/ansible/posix/MANIFEST.json");
        let metadata = distribution_metadata(&prefix, "ansible_core")?;
        for case in [
            "observed_hash",
            "version",
            "namespace",
            "malformed",
            "missing",
        ] {
            let path = if case == "version" {
                &metadata
            } else {
                &collection
            };
            ensure!(
                !fs::symlink_metadata(path)?.file_type().is_symlink(),
                "mutable assets must be owned copies"
            );
            ensure!(
                fs::canonicalize(path)?.starts_with(fs::canonicalize(&prefix)?),
                "mutable assets must not resolve outside their owned environment"
            );
            let mut command = fixture.doctor()?;
            command.env("SSH_MCP_PYTHON_RUNTIME", &descriptor);
            let bytes = fs::read(path)?;
            match case {
                "observed_hash" => {
                    let mut changed = bytes.clone();
                    changed.push(b'\n');
                    fs::write(path, changed)?;
                }
                "version" => {
                    let metadata = std::str::from_utf8(&bytes)?;
                    let changed = metadata.replace("\nVersion: 2.21.5\n", "\nVersion: 0.0.0\n");
                    ensure!(changed != metadata, "installed core metadata pin diverged");
                    fs::write(path, changed)?;
                }
                "namespace" => {
                    let mut manifest: Value = serde_json::from_slice(&bytes)?;
                    manifest["collection_info"]["namespace"] = json!("wrong");
                    fs::write(path, serde_json::to_vec(&manifest)?)?;
                }
                "malformed" => fs::write(path, b"{")?,
                "missing" => fs::remove_file(path)?,
                _ => unreachable!(),
            }
            let result = output(command).await;
            // Restore before propagating process/report/assertion errors; original envs are never touched.
            fs::write(path, &bytes)?;
            let checked = result?;
            if case == "observed_hash" {
                let value = report(&checked, 0)?;
                ensure!(
                    value["runtime"]["identity"]["provenance"]
                        == json!({"kind":"python_environment"})
                );
                let changed = &value["runtime"]["identity"]["collections"][0];
                ensure!(changed["version"] == original["collections"][0]["version"]);
                use sha2::Digest;
                let mut observed = bytes.clone();
                observed.push(b'\n');
                ensure!(changed["manifest_sha256"] == hex::encode(sha2::Sha256::digest(&observed)));
                ensure!(
                    changed["manifest_sha256"] != original["collections"][0]["manifest_sha256"]
                );
            } else {
                let value =
                    report(&checked, 1).with_context(|| format!("owned drift case {case}"))?;
                ensure!(value["runtime"]["status"] == "failed");
                ensure!(value["runtime"].get("identity").is_none());
            }
            fixture.private(&checked)?;
        }
        let mut command = fixture.doctor()?;
        command.env("SSH_MCP_PYTHON_RUNTIME", descriptor);
        let checked = output(command).await?;
        ensure!(observed_environment_identity(&report(&checked, 0)?, &prefix)? == original);
        fixture.private(&checked)
    }

    #[tokio::test]
    #[ignore = "requires raw SSH_MCP_TEST_BINARY and an installed SSH_MCP_TEST_WHEEL_BINARY extra; no network"]
    async fn schema_import_uses_selected_environment_without_ambient_python_or_execution()
    -> Result<()> {
        let prefix = wheel_prefix("SSH_MCP_TEST_WHEEL_BINARY")?;
        let fixture = Local::new("")?;
        let snapshot = fixture.root.path().join("ping.json");
        let descriptor = environment_descriptor(&prefix.join("bin/python"), &prefix).to_string();
        for name in ["ansible.py", "ansible_runner.py", "sitecustomize.py"] {
            fs::write(
                fixture.root.path().join(name),
                "raise RuntimeError('PYTHON_INJECTION_RAN')\n",
            )?;
        }
        let mut command = fixture.command()?;
        command
            .args(["schema", "import", "ansible.builtin.ping"])
            .arg("--output")
            .arg(&snapshot)
            .env("SSH_MCP_PYTHON_RUNTIME", &descriptor)
            .env("PYTHONPATH", fixture.root.path())
            .env("PATH", "/nonexistent");
        let imported = output(command).await?;
        schema_report(&fixture, &imported, true)?;
        let value: Value = serde_json::from_slice(&fs::read(&snapshot)?)?;
        ensure!(value["runtime"]["provenance"] == json!({"kind":"python_environment"}));
        ensure!(value["contract"]["schema"]["properties"]["data"]["type"] == "string");
        let mut command = fixture.command()?;
        command
            .args(["schema", "verify"])
            .arg(&snapshot)
            .env("SSH_MCP_PYTHON_RUNTIME", descriptor)
            .env("PATH", "/nonexistent");
        let verified = output(command).await?;
        schema_report(&fixture, &verified, true)?;
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_schema_import_refuses_unreadable_snapshot_envelope() -> Result<()> {
    let fixture = configured_runtime(&real_runtime()?, false)?;
    let overlay = fixture.root.path().join("boundary.json");
    let destination = fixture.root.path().join("review.json");
    let mut condition = json!({"required":[]});
    for _ in 0..29 {
        condition = json!({"not":condition});
    }
    fs::write(
        &overlay,
        serde_json::to_vec(&json!({
            "input_schema":{"type":"object","properties":{},"additionalProperties":false,"not":condition},
            "fixed_args":{},"input_map":{}
        }))?,
    )?;
    let mut command = fixture.command()?;
    command
        .args(["schema", "import", "ansible.builtin.ping"])
        .arg("--overlay")
        .arg(&overlay)
        .arg("--output")
        .arg(&destination);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "schema_file_limit");
    ensure!(
        !destination.exists(),
        "import persisted an unreadable snapshot"
    );
    Ok(())
}

// These fixtures exercise the installed CLI and public ansible-doc role metadata,
// without copying or changing the selected Ansible installation.
fn standalone_role(fixture: &Local, name: &str, argspec: Option<&str>) -> Result<PathBuf> {
    let role = fixture.root.path().join("roles").join(name);
    for directory in ["tasks", "meta", "defaults"] {
        fs::create_dir_all(role.join(directory))?;
    }
    let task = serde_json::to_vec(&json!([{
        "name":"Forbidden role task",
        "ansible.builtin.command":{
            "argv":["/usr/bin/touch",fixture.root.path().join("role-task-ran")]
        },
        "delegate_to":"localhost"
    }]))?;
    fs::write(role.join("tasks/main.yml"), &task)?;
    fs::write(role.join("tasks/alternate.yaml"), &task)?;
    fs::write(
        role.join("defaults/main.yml"),
        format!("misleading_default: {SECRET}\n"),
    )?;
    fs::write(
        role.join("meta/main.yml"),
        "dependencies:\n  - role: acceptance_dependency\n",
    )?;
    let dependency = role
        .parent()
        .context("role parent")?
        .join("acceptance_dependency");
    fs::create_dir_all(dependency.join("tasks"))?;
    fs::write(
        dependency.join("tasks/main.yml"),
        serde_json::to_vec(&json!([{
            "name":"Forbidden dependency task",
            "ansible.builtin.command":{
                "argv":["/usr/bin/touch",fixture.root.path().join("role-dependency-ran")]
            },
            "delegate_to":"localhost"
        }]))?,
    )?;
    if let Some(argspec) = argspec {
        fs::write(role.join("meta/argument_specs.yml"), argspec)?;
    }
    Ok(role)
}

fn role_import_command(
    fixture: &Local,
    role: &str,
    source: &Path,
    entry: &str,
    snapshot: &Path,
) -> Result<Command> {
    let mut command = fixture.installed_command("SSH_MCP_TEST_BINARY")?;
    command
        .args(["schema", "import-role", role, "--entry-point", entry])
        .arg("--role-path")
        .arg(source)
        .arg("--output")
        .arg(snapshot);
    Ok(command)
}

fn role_verify_command(fixture: &Local, snapshot: &Path, source: &Path) -> Result<Command> {
    let mut command = fixture.installed_command("SSH_MCP_TEST_BINARY")?;
    command
        .args(["schema", "verify-role"])
        .arg(snapshot)
        .arg("--role-path")
        .arg(source);
    Ok(command)
}

fn role_no_effects(fixture: &Local) -> Result<()> {
    ensure!(!fixture.marker.exists(), "role authoring dispatched SSH");
    ensure!(
        !fixture.root.path().join("role-task-ran").exists(),
        "role authoring executed tasks"
    );
    ensure!(
        !fixture.root.path().join("role-dependency-ran").exists(),
        "role authoring executed dependencies"
    );
    Ok(())
}

fn role_snapshot(fixture: &Local, path: &Path) -> Result<Value> {
    let bytes = fs::read(path)?;
    let text = std::str::from_utf8(&bytes)?;
    for private in [
        SECRET,
        fixture.root.path().to_str().context("UTF-8 fixture")?,
        "/nix/store/",
    ] {
        ensure!(
            !text.contains(private),
            "role snapshot disclosed private source content"
        );
    }
    serde_json::from_slice(&bytes).context("role snapshot")
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_role_schema_argspec_aliases_required_defaults_entrypoints_and_drift() -> Result<()> {
    let fixture = configured_runtime(&real_runtime()?, false)?;
    let argspec = r#"argument_specs:
  main:
    short_description: Acceptance main entry
    options:
      app_name:
        type: str
        required: true
        aliases: [app]
        choices: [web, worker]
        default: web
      settings:
        type: dict
        options:
          count:
            type: int
            required: true
            aliases: [number]
          enabled:
            type: bool
            default: true
      entries:
        type: list
        elements: dict
        options:
          label:
            type: str
            required: true
            aliases: [name]
            choices: [a, b]
  alternate:
    short_description: Acceptance alternate entry
    options:
      token:
        type: str
        required: true
"#;
    let role = standalone_role(&fixture, "acceptance", Some(argspec))?;
    let snapshot = fixture.root.path().join("role.json");
    let overlay = fixture.root.path().join("binding.json");
    let input = fixture.root.path().join("input.json");
    fs::write(
        &overlay,
        serde_json::to_vec(&json!({
            "input_schema":{"type":"object","properties":{
                "application":{"type":"string","enum":["web","worker"]},
                "settings":{"type":"object","properties":{
                    "number":{"type":"integer"},"enabled":{"type":"boolean"}
                },"required":["number"],"additionalProperties":false},
                "entries":{"type":"array","items":{"type":"object","properties":{
                    "name":{"type":"string","enum":["a","b"]}
                },"required":["name"],"additionalProperties":false}}
            },"required":["application"],"additionalProperties":false},
            "fixed_args":{},"input_map":{"app":"application","settings":"settings","entries":"entries"}
        }))?,
    )?;
    let mut command = role_import_command(&fixture, "acceptance", &role, "main", &snapshot)?;
    command.arg("--overlay").arg(&overlay);
    let imported = output(command).await?;
    ensure!(schema_report(&fixture, &imported, true)?["binding_validated"] == true);
    let reviewed = fs::read(&snapshot)?;
    let value = role_snapshot(&fixture, &snapshot)?;
    ensure!(
        value["contract"]["schema"]["properties"]
            .get("misleading_default")
            .is_none()
    );
    ensure!(
        value["contract"]["schema"]["properties"]["app_name"]
            .get("default")
            .is_none()
    );
    ensure!(
        value["contract"]["schema"]["properties"]["settings"]["properties"]["enabled"]
            .get("default")
            .is_none()
    );
    for (request, valid) in [
        (json!({"application":"web"}), true),
        (
            json!({"application":"worker","settings":{"number":2},"entries":[{"name":"a"}]}),
            true,
        ),
        (json!({}), false),
        (json!({"application":"other"}), false),
        (json!({"application":"web","extra":SECRET}), false),
        (json!({"application":"web","settings":{}}), false),
        (
            json!({"application":"web","settings":{"number":"2"}}),
            false,
        ),
        (
            json!({"application":"web","settings":{"number":2,"unknown":SECRET}}),
            false,
        ),
        (json!({"application":"web","entries":[{}]}), false),
        (json!({"application":"web","entries":[{"name":"c"}]}), false),
        (
            json!({"application":"web","entries":[{"name":"a","label":"b"}]}),
            false,
        ),
    ] {
        fs::write(&input, serde_json::to_vec(&request)?)?;
        let mut command = role_verify_command(&fixture, &snapshot, &role)?;
        command.arg("--input").arg(&input);
        let checked = output(command).await?;
        let report = schema_report(&fixture, &checked, valid)?;
        if valid {
            ensure!(report["input_validated"] == true);
        }
        role_no_effects(&fixture)?;
    }
    // Alias/canonical duplication is rejected by backend canonicalization too,
    // not merely by the public request's closed schema.
    let collision = fixture.root.path().join("collision.json");
    fs::write(
        &collision,
        serde_json::to_vec(&json!({
            "input_schema":{"type":"object","properties":{
                "application":{"type":"string","enum":["web","worker"]}
            },"required":["application"],"additionalProperties":false},
            "fixed_args":{"settings":{"number":1,"count":2}},
            "input_map":{"app":"application"}
        }))?,
    )?;
    let mut command = role_verify_command(&fixture, &snapshot, &role)?;
    command.arg("--overlay").arg(&collision);
    let rejected = output(command).await?;
    schema_report(&fixture, &rejected, false)?;
    ensure!(fs::read(&snapshot)? == reviewed);
    let replacement = fixture.root.path().join("replacement.json");
    fs::write(
        &replacement,
        serde_json::to_vec(&json!({"type":"object","properties":{},"additionalProperties":false}))?,
    )?;
    let replaced_snapshot = fixture.root.path().join("replacement-role.json");
    let mut command =
        role_import_command(&fixture, "acceptance", &role, "main", &replaced_snapshot)?;
    command.arg("--schema").arg(&replacement);
    let rejected = output(command).await?;
    schema_report(&fixture, &rejected, false)?;
    ensure!(
        !replaced_snapshot.exists(),
        "explicit schema replaced present argspec"
    );
    let alternate = fixture.root.path().join("alternate.json");
    let imported = output(role_import_command(
        &fixture,
        "acceptance",
        &role,
        "alternate",
        &alternate,
    )?)
    .await?;
    schema_report(&fixture, &imported, true)?;
    let alternate_value = role_snapshot(&fixture, &alternate)?;
    ensure!(
        alternate_value["contract"]["schema"]["properties"]
            .get("token")
            .is_some()
    );
    ensure!(
        alternate_value["contract"]["schema"]["properties"]
            .get("app_name")
            .is_none()
    );
    let verified = output(role_verify_command(&fixture, &alternate, &role)?).await?;
    schema_report(&fixture, &verified, true)?;

    let rejected = output(role_import_command(
        &fixture,
        "acceptance",
        &role,
        "main",
        &snapshot,
    )?)
    .await?;
    ensure!(
        schema_report(&fixture, &rejected, false)?["error_code"]
            == "schema_output_exists_or_failed"
    );
    ensure!(fs::read(&snapshot)? == reviewed);
    // Each source class independently changes the content approval, even when
    // the public argument contract is unchanged.
    for relative in [
        "tasks/main.yml",
        "defaults/main.yml",
        "meta/argument_specs.yml",
    ] {
        let path = role.join(relative);
        let original = fs::read(&path)?;
        let mut changed = original.clone();
        changed.extend_from_slice(b"\n# acceptance content drift\n");
        fs::write(&path, changed)?;
        let rejected = output(role_verify_command(&fixture, &snapshot, &role)?).await?;
        ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "schema_drift");
        fs::write(&path, original)?;
    }
    let verified = output(role_verify_command(&fixture, &snapshot, &role)?).await?;
    schema_report(&fixture, &verified, true)?;
    role_no_effects(&fixture)
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_role_schema_missing_argspec_explicit_nested_schema_and_conditional_overlay()
-> Result<()> {
    let fixture = configured_runtime(&real_runtime()?, false)?;
    let role = standalone_role(&fixture, "undocumented", None)?;
    let snapshot = fixture.root.path().join("role.json");
    let schema = fixture.root.path().join("explicit.json");
    let overlay = fixture.root.path().join("binding.json");
    let input = fixture.root.path().join("input.json");
    let rejected = output(role_import_command(
        &fixture,
        "undocumented",
        &role,
        "main",
        &snapshot,
    )?)
    .await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "role_schema_required");
    ensure!(!snapshot.exists());
    let explicit = json!({"type":"object","properties":{
        "mode":{"type":"string","enum":["basic","advanced"]},
        "settings":{"type":"object","properties":{
            "count":{"type":"integer"},
            "entries":{"type":"array","items":{"type":"object","properties":{
                "label":{"type":"string"}
            },"required":["label"],"additionalProperties":false}}
        },"required":["count"],"additionalProperties":false}
    },"required":["mode"],"additionalProperties":false});
    fs::write(&schema, serde_json::to_vec(&explicit)?)?;
    let mut public = explicit.clone();
    public["if"] = json!({"properties":{"mode":{"const":"advanced"}},"required":["mode"]});
    public["then"] = json!({"required":["settings"]});
    public["else"] = json!({"not":{"required":["settings"]}});
    fs::write(
        &overlay,
        serde_json::to_vec(&json!({
            "input_schema":public,"fixed_args":{},"input_map":{"mode":"mode","settings":"settings"}
        }))?,
    )?;
    let mut command = role_import_command(&fixture, "undocumented", &role, "main", &snapshot)?;
    command
        .arg("--schema")
        .arg(&schema)
        .arg("--overlay")
        .arg(&overlay);
    let imported = output(command).await?;
    ensure!(schema_report(&fixture, &imported, true)?["binding_validated"] == true);
    let reviewed = role_snapshot(&fixture, &snapshot)?;
    ensure!(reviewed["contract"]["defaults"] == json!({}));
    ensure!(
        reviewed["contract"]["schema"]["properties"]
            .get("misleading_default")
            .is_none()
    );
    for (request, valid) in [
        (json!({"mode":"basic"}), true),
        (
            json!({"mode":"advanced","settings":{"count":1,"entries":[{"label":"a"}]}}),
            true,
        ),
        (json!({}), false),
        (json!({"mode":"advanced"}), false),
        (json!({"mode":"basic","settings":{"count":1}}), false),
        (json!({"mode":"advanced","settings":{}}), false),
        (json!({"mode":"advanced","settings":{"count":"1"}}), false),
        (
            json!({"mode":"advanced","settings":{"count":1,"entries":[{}]}}),
            false,
        ),
        (
            json!({"mode":"advanced","settings":{"count":1,"entries":[{"label":"a","extra":SECRET}]}}),
            false,
        ),
        (json!({"mode":"basic","misleading_default":SECRET}), false),
    ] {
        fs::write(&input, serde_json::to_vec(&request)?)?;
        let mut command = role_verify_command(&fixture, &snapshot, &role)?;
        command.arg("--input").arg(&input);
        let checked = output(command).await?;
        let report = schema_report(&fixture, &checked, valid)?;
        if valid {
            ensure!(report["input_validated"] == true);
        }
        role_no_effects(&fixture)?;
    }
    // Verification must be supplied an exact source again, not search ambient roles.
    let mut command = fixture.installed_command("SSH_MCP_TEST_BINARY")?;
    command.args(["schema", "verify-role"]).arg(&snapshot);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "role_source_required");
    role_no_effects(&fixture)
}

#[tokio::test]
#[ignore = "requires installed SSH_MCP_TEST_BINARY and shipped SSH_MCP_TEST_ANSIBLE_RUNTIME; no network"]
async fn real_role_schema_rejects_malformed_sources_and_explicit_contracts() -> Result<()> {
    let fixture = configured_runtime(&real_runtime()?, false)?;
    let role = standalone_role(&fixture, "selection", None)?;
    let snapshot = fixture.root.path().join("role.json");
    let schema = fixture.root.path().join("explicit.json");
    let closed = json!({"type":"object","properties":{},"additionalProperties":false});
    fs::write(&schema, serde_json::to_vec(&closed)?)?;
    for (name, entry, source, code) in [
        ("bad.role", "main", role.clone(), Some("invalid_role_name")),
        (
            "selection",
            "../main",
            role.clone(),
            Some("invalid_role_entry_point"),
        ),
        ("selection", "missing", role.clone(), None),
        (
            "selection",
            "main",
            PathBuf::from("roles/selection"),
            Some("invalid_role_source"),
        ),
        (
            "selection",
            "main",
            role.join("tasks/main.yml"),
            Some("invalid_role_source"),
        ),
        (
            "selection",
            "main",
            fixture.root.path().join("absent"),
            None,
        ),
        (
            "selection",
            "main",
            role.parent().context("role parent")?.to_path_buf(),
            None,
        ),
        ("wrong_name", "main", role.clone(), None),
        (
            "example.collection.selection",
            "main",
            role.clone(),
            Some("invalid_role_source"),
        ),
    ] {
        let mut command = role_import_command(&fixture, name, &source, entry, &snapshot)?;
        command.arg("--schema").arg(&schema);
        let rejected = output(command).await?;
        let report = schema_report(&fixture, &rejected, false)?;
        if let Some(code) = code {
            ensure!(report["error_code"] == code, "role selection: {report}");
        }
        ensure!(!snapshot.exists());
    }
    let mut command = fixture.installed_command("SSH_MCP_TEST_BINARY")?;
    command
        .args([
            "schema",
            "import-role",
            "selection",
            "--entry-point",
            "main",
        ])
        .arg("--output")
        .arg(&snapshot)
        .arg("--schema")
        .arg(&schema)
        .env("ANSIBLE_ROLES_PATH", role.parent().context("role parent")?);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "role_source_required");
    ensure!(!snapshot.exists());

    // Both task spellings present is ambiguous; interior symlinks are not approved content.
    fs::write(role.join("tasks/main.yaml"), "[]\n")?;
    let mut command = role_import_command(&fixture, "selection", &role, "main", &snapshot)?;
    command.arg("--schema").arg(&schema);
    let rejected = output(command).await?;
    schema_report(&fixture, &rejected, false)?;
    ensure!(!snapshot.exists());
    fs::remove_file(role.join("tasks/main.yaml"))?;
    let outside = fixture.root.path().join("outside-private");
    fs::write(&outside, SECRET)?;
    symlink(&outside, role.join("defaults/linked.yml"))?;
    let mut command = role_import_command(&fixture, "selection", &role, "main", &snapshot)?;
    command.arg("--schema").arg(&schema);
    let rejected = output(command).await?;
    schema_report(&fixture, &rejected, false)?;
    ensure!(!snapshot.exists());
    fs::remove_file(role.join("defaults/linked.yml"))?;

    for malformed in [
        json!({"type":"object","properties":{}}),
        json!({"type":"object","properties":{"nested":{"type":"object","properties":{}}},
            "additionalProperties":false}),
        json!({"type":"object","properties":{},"additionalProperties":false,"required":["missing"]}),
        json!({"type":"string"}),
    ] {
        fs::write(&schema, serde_json::to_vec(&malformed)?)?;
        let mut command = role_import_command(&fixture, "selection", &role, "main", &snapshot)?;
        command.arg("--schema").arg(&schema);
        let rejected = output(command).await?;
        schema_report(&fixture, &rejected, false)?;
        ensure!(!snapshot.exists());
    }
    fs::write(
        &schema,
        r#"{"type":"object","properties":{},"additionalProperties":false,"type":"object"}"#,
    )?;
    let mut command = role_import_command(&fixture, "selection", &role, "main", &snapshot)?;
    command.arg("--schema").arg(&schema);
    let rejected = output(command).await?;
    ensure!(schema_report(&fixture, &rejected, false)?["error_code"] == "invalid_schema_json");
    ensure!(!snapshot.exists());

    // Present but unusable metadata must never fall back to an explicit schema.
    fs::write(&schema, serde_json::to_vec(&closed)?)?;
    for argspec in [
        "argument_specs: [unterminated",
        "argument_specs:\n  alternate:\n    options: {}\n",
        "argument_specs:\n  main:\n    options:\n      first:\n        type: str\n        aliases: [second]\n      second:\n        type: str\n",
        "argument_specs:\n  main:\n    options:\n      token:\n        type: str\n    required_if:\n      - [token, secret, [other]]\n",
    ] {
        fs::write(role.join("meta/argument_specs.yml"), argspec)?;
        for explicit in [false, true] {
            let mut command = role_import_command(&fixture, "selection", &role, "main", &snapshot)?;
            if explicit {
                command.arg("--schema").arg(&schema);
            }
            let rejected = output(command).await?;
            schema_report(&fixture, &rejected, false)?;
            ensure!(!snapshot.exists());
        }
    }
    role_no_effects(&fixture)
}

