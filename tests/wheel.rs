//! Explicit, network-enabled acceptance of the portable artifact through real uv channels.
#![cfg(unix)]

#[allow(dead_code)]
mod support;

use estus::internal::catalog_assets as assets;

use anyhow::{Context, Result, ensure};
use nix::sys::signal::Signal;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};
use support::{Fixture, WireServer, assert_masters_gone, executable, find_program, masters};
use tempfile::TempDir;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const SETUP: Duration = Duration::from_secs(900);

fn selection_metadata(output: &Path, canonical: &Value, selected: &[&str]) -> Result<()> {
    let path = output.join("catalog-selection.json");
    let selection: Value = serde_json::from_slice(&fs::read(&path)?)?;
    ensure!(
        selection["schema"] == canonical["schema"]
            && selection["version"] == canonical["version"]
            && selection["scope"] == "catalog_templates"
            && selection
                .as_object()
                .is_some_and(|fields| fields.len() == 4),
        "invalid installed selection metadata: {selection}"
    );
    ensure!(
        selection["tools"]
            .as_object()
            .is_some_and(|tools| tools.len() == selected.len()),
        "exported selection inventory diverged"
    );
    for &name in selected {
        ensure!(
            selection["tools"][name]
                == json!({
                    "executor": canonical["tools"][name]["executor"],
                    "qualification": canonical["tools"][name]["qualification"],
                    "policy_required": canonical["tools"][name]["policy_required"],
                    "requires": canonical["tools"][name]["requires"],
                }),
            "{name}: installed selection metadata diverged"
        );
    }
    ensure!(
        fs::metadata(path)?.permissions().mode() & 0o777 == 0o600,
        "exported selection metadata is not private"
    );
    Ok(())
}

fn input(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).with_context(|| format!("set {name}"))?);
    ensure!(
        path.is_absolute() && path.is_file(),
        "{name} must name an absolute existing file"
    );
    Ok(path)
}

struct Installed {
    root: TempDir,
    uv: PathBuf,
    path: std::ffi::OsString,
}

impl Installed {
    fn new() -> Result<Self> {
        // Keep cached launcher shebangs and native Unix socket paths short on Darwin.
        let root = tempfile::Builder::new()
            .prefix("estus-wheel-")
            .tempdir_in("/tmp")?;
        for directory in [
            "home",
            "cache",
            "python",
            "python-bin",
            "work",
            "tmp",
            "config",
            "data",
            "runtime",
        ] {
            fs::create_dir(root.path().join(directory))?;
        }
        Ok(Self {
            root,
            uv: find_program("uv")?,
            path: std::env::var_os("PATH").context("PATH prerequisite")?,
        })
    }

    fn command(&self, program: &Path) -> Command {
        let root = self.root.path();
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", root.join("home"))
            .env("TMPDIR", root.join("tmp"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_RUNTIME_DIR", root.join("runtime"))
            .env("UV_CACHE_DIR", root.join("cache/uv"))
            .env("UV_PYTHON_INSTALL_DIR", root.join("python"))
            .env("UV_PYTHON_BIN_DIR", root.join("python-bin"))
            .env("UV_TOOL_DIR", root.join("tools-base"))
            .env("UV_TOOL_BIN_DIR", root.join("bin-base"))
            .env("UV_NO_CONFIG", "1")
            .env("UV_LINK_MODE", "copy")
            .current_dir(root.join("work"))
            .kill_on_drop(true);
        command
    }

    fn uv(&self) -> Command {
        let mut command = self.command(&self.uv);
        command.args(["--no-config", "--quiet"]);
        command
    }

    fn tools(&self, command: &mut Command, extra: bool) {
        let suffix = if extra { "extra" } else { "base" };
        command
            .env(
                "UV_TOOL_DIR",
                self.root.path().join(format!("tools-{suffix}")),
            )
            .env(
                "UV_TOOL_BIN_DIR",
                self.root.path().join(format!("bin-{suffix}")),
            );
    }

    fn launcher(&self, extra: bool) -> PathBuf {
        self.root
            .path()
            .join(if extra { "tools-extra" } else { "tools-base" })
            .join("estus/bin/estus")
    }

    async fn python(&self, version: &str) -> Result<PathBuf> {
        let env_key = format!("ESTUS_TEST_PYTHON_{}", version.replace('.', "_"));
        let python = if let Some(value) = std::env::var_os(&env_key) {
            PathBuf::from(value)
        } else if version == "3.14" && std::env::var_os("ESTUS_TEST_PYTHON").is_some() {
            input("ESTUS_TEST_PYTHON")?
        } else {
            checked(self.uv().args(["python", "install", "--no-bin", version])).await?;
            // Query output is data; uv's global quiet mode suppresses it.
            let found = checked(self.command(&self.uv).args([
                "--no-config",
                "python",
                "find",
                "--managed-python",
                version,
            ]))
            .await?;
            PathBuf::from(std::str::from_utf8(&found.stdout)?.trim())
        };
        let python = executable(&python)?;
        ensure!(
            !fs::canonicalize(&python)?.starts_with("/nix/store"),
            "wheel acceptance requires an outside-Nix Python"
        );
        let version_out = checked(self.command(&python).arg("--version")).await?;
        let expected_prefix = format!("Python {version}.");
        ensure!(
            std::str::from_utf8(&version_out.stdout)?.starts_with(&expected_prefix),
            "requires Python {version}, got {version_out:?}"
        );
        Ok(python)
    }
}

async fn verify_launcher_handshake(
    installed: &Installed,
    wheel: &Path,
    version: &str,
) -> Result<()> {
    let python = installed.python(version).await?;
    let suffix = format!("launcher-{}", version.replace('.', "_"));
    let tool_dir = installed.root.path().join(format!("tools-{suffix}"));
    let bin_dir = installed.root.path().join(format!("bin-{suffix}"));
    let mut install = installed.uv();
    install
        .env("UV_TOOL_DIR", &tool_dir)
        .env("UV_TOOL_BIN_DIR", &bin_dir)
        .args(["tool", "install", "--python"])
        .arg(&python)
        .args(["--no-python-downloads", "--link-mode", "copy"])
        .arg(wheel);
    checked(&mut install).await?;
    let launcher = executable(&tool_dir.join("estus/bin/estus"))?;
    let help = checked(installed.command(&launcher).arg("--help")).await?;
    ensure!(
        !help.stdout.is_empty(),
        "Python {version} launcher --help emitted empty output"
    );
    let mut server = WireServer::start_command(installed.command(&launcher))?;
    let handshake = server.initialize().await;
    let stopped = server.stop(None).await;
    handshake?;
    stopped?;
    Ok(())
}

// Downloads and existing compiled suites need a longer deadline than short fixture helpers.
// Drain both pipes concurrently and kill/reap the actual child on timeout.
async fn checked(command: &mut Command) -> Result<Output> {
    let description = format!("{command:?}");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("acceptance stdout")?;
    let mut stderr = child.stderr.take().context("acceptance stderr")?;
    let out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match timeout(SETUP, child.wait()).await {
        Ok(status) => status?,
        Err(error) => {
            child.kill().await?;
            out.abort();
            err.abort();
            return Err(error)
                .with_context(|| format!("acceptance command timed out: {description}"));
        }
    };
    let output = Output {
        status,
        stdout: timeout(support::CLEANUP, out).await???,
        stderr: timeout(support::CLEANUP, err).await???,
    };
    ensure!(
        output.status.success(),
        "command failed: {description}\nstatus: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

// libtest exits successfully for an empty filter. Require its final successful
// result to report real passing tests, without fixing a suite's evolving size.
async fn checked_suite(command: &mut Command) -> Result<()> {
    let description = format!("{command:?}");
    let output = checked(command).await?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    let result = stdout
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("test result: ok. "))
        .with_context(|| format!("missing libtest result: {description}\n{stdout}"))?;
    let passed: usize = result
        .split_once(" passed;")
        .context("unrecognized libtest passing count")?
        .0
        .parse()?;
    ensure!(
        passed > 0,
        "nested suite ran no tests: {description}\n{stdout}"
    );
    Ok(())
}

fn copy_environment(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            symlink(fs::read_link(entry.path())?, target)?;
        } else if kind.is_dir() {
            copy_environment(&entry.path(), &target)?;
        } else {
            ensure!(
                kind.is_file(),
                "unexpected environment asset: {}",
                entry.path().display()
            );
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

async fn catalog(server: &mut WireServer) -> Result<Value> {
    server.initialize().await?;
    let tools = server.request(2, "tools/list", json!({})).await?;
    ensure!(
        tools["result"]["tools"].is_array(),
        "discovery failed: {tools}"
    );
    let hosts = server
        .request(
            3,
            "tools/call",
            json!({"name":"observe_targets","arguments":{}}),
        )
        .await?;
    ensure!(
        hosts.get("error").is_none() && hosts["result"]["isError"] != true,
        "RPC failed: {hosts}"
    );
    Ok(tools["result"]["tools"].clone())
}

async fn ordinary_ssh(installed: &Installed) -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let path = fixture.root.path().join("wheel-file");
        fs::write(&path, b"portable-wheel\n")?;
        let mut command = installed.command(&installed.launcher(false));
        command.arg("--config").arg(&fixture.config);
        let mut server = WireServer::start_command(command)?;
        let operations = async {
            catalog(&mut server).await?;
            for (id, name, arguments, expected) in [
                (
                    4,
                    "exec_command",
                    json!({"host":"plain","command":"printf portable-command"}),
                    "portable-command",
                ),
                (
                    5,
                    "inspect_file",
                    json!({"host":"plain","path":path}),
                    "portable-wheel\n",
                ),
            ] {
                let frame = server
                    .request(id, "tools/call", json!({"name":name,"arguments":arguments}))
                    .await?;
                ensure!(
                    frame.get("error").is_none() && frame["result"]["isError"] != true,
                    "{name}: {frame}"
                );
                let reply: Value = serde_json::from_str(
                    frame["result"]["content"][0]["text"]
                        .as_str()
                        .context("tool envelope")?,
                )?;
                ensure!(
                    reply["error"].is_null() && reply["data"].is_object(),
                    "{name}: {reply}"
                );
                let field = if name == "exec_command" {
                    "stdout"
                } else {
                    "content"
                };
                ensure!(reply["data"][field] == expected, "{name}: {reply}");
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        operations?;
        stopped?;
        let owned = owned?;
        ensure!(
            !owned.is_empty(),
            "installed command did not own an SSH master"
        );
        assert_masters_gone(&owned).await
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "downloads managed Python/Ansible; requires portable wheel, installed suites, Nix OpenSSH/coreutils, trusted temporary ancestry and non-root account"]
async fn installed_wheel_channels() -> Result<()> {
    let wheel = input("ESTUS_TEST_WHEEL")?;
    ensure!(
        wheel
            .extension()
            .is_some_and(|extension| extension == "whl"),
        "expected an actual wheel file"
    );
    let stdio = executable(&input("ESTUS_TEST_STDIO_SUITE")?)?;
    let controller = executable(&input("ESTUS_TEST_CONTROLLER_SUITE")?)?;
    let automation = executable(&input("ESTUS_TEST_AUTOMATION_SUITE")?)?;
    let native = executable(&input("ESTUS_TEST_BINARY")?)?;
    let runtime = PathBuf::from(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME").context("set ESTUS_TEST_ANSIBLE_RUNTIME")?,
    );
    ensure!(
        runtime.is_absolute() && runtime.join("runtime.json").is_file(),
        "missing immutable Ansible bundle"
    );
    let catalog_assets = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    let canonical: Value = serde_json::from_slice(&fs::read(catalog_assets.join("catalog.json"))?)?;
    let installed = Installed::new()?;
    let python = installed.python("3.14").await?;
    let extra_requirement = format!("{}[ansible]", wheel.to_str().context("UTF-8 wheel path")?);
    for extra in [false, true] {
        let mut command = installed.uv();
        installed.tools(&mut command, extra);
        command
            .args(["tool", "install", "--python"])
            .arg(&python)
            .args(["--no-python-downloads", "--link-mode", "copy"])
            .arg(if extra {
                Path::new(&extra_requirement)
            } else {
                &wheel
            });
        checked(&mut command).await?;
        executable(&installed.launcher(extra))?;
    }
    let direct_catalog = checked(
        installed
            .command(&installed.root.path().join("tools-base/estus/bin/python"))
            .args([
                "-I",
                "-c",
                "from pathlib import Path; import estus; print(Path(estus.__file__).parent / '_catalog')",
            ]),
    )
    .await?;
    let direct_catalog = PathBuf::from(std::str::from_utf8(&direct_catalog.stdout)?.trim());
    ensure!(
        asset_bytes(&direct_catalog)? == asset_bytes(&catalog_assets)?,
        "installed direct wheel catalog assets diverged from approved catalog"
    );
    if let Some(versions) = std::env::var_os("ESTUS_TEST_LAUNCHER_PYTHONS") {
        let raw = versions.to_string_lossy();
        for version in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
            verify_launcher_handshake(&installed, &wheel, version).await?;
        }
    } else {
        verify_launcher_handshake(&installed, &wheel, "3.14").await?;
    }
    let config = installed.root.path().join("work/server.toml");
    fs::write(&config, "")?;
    let required_config = installed.root.path().join("work/required.toml");
    fs::write(&required_config, "[automation]\nrequired = true\n")?;
    let mut expected_identity = None;
    let mut expected = None;
    // Each real channel gets discovery/RPC and all three shutdown paths; signal
    // cases retain stdin until the launched process has exited.
    #[derive(Clone, Copy)]
    enum Channel {
        Uvx,
        Tool,
        Run,
    }
    for selection in [Channel::Uvx, Channel::Tool, Channel::Run] {
        let channel = match selection {
            Channel::Uvx => "uvx",
            Channel::Tool => "tool",
            Channel::Run => "run",
        };
        let launch = |extra| {
            let requirement = if extra {
                Path::new(&extra_requirement)
            } else {
                &wheel
            };
            let mut command = match selection {
                Channel::Tool => installed.command(&installed.launcher(extra)),
                Channel::Uvx => {
                    let mut command = installed.uv();
                    command
                        .args(["tool", "run", "--isolated", "--python"])
                        .arg(&python)
                        .args(["--no-python-downloads", "--from"])
                        .arg(requirement)
                        .arg("estus");
                    command
                }
                Channel::Run => {
                    let mut command = installed.uv();
                    command
                        .args(["run", "--no-project", "--python"])
                        .arg(&python)
                        .args(["--no-python-downloads", "--with"])
                        .arg(requirement)
                        .arg("estus");
                    command
                }
            };
            command.env(
                "ESTUS_CATALOG_ROOT",
                installed.root.path().join("untrusted-missing"),
            );
            command
        };
        let listed = checked(launch(false).args(["catalog", "list", "--json"])).await?;
        let listing: Value = serde_json::from_slice(&listed.stdout)?;
        ensure!(
            listing["schema"] == canonical["schema"]
                && listing["version"] == canonical["version"]
                && listing["tools"].is_array(),
            "{channel} invalid catalog listing: {listing}"
        );
        let tools = listing["tools"]
            .as_array()
            .context("installed catalog tools")?;
        ensure!(
            tools.len()
                == canonical["tools"]
                    .as_object()
                    .context("canonical tools")?
                    .len(),
            "{channel} installed catalog inventory is incomplete"
        );
        let mut names = std::collections::BTreeSet::new();
        for tool in tools {
            let name = tool["name"].as_str().context("catalog template name")?;
            ensure!(
                names.insert(name),
                "{channel} duplicate catalog template: {name}"
            );
            ensure!(
                canonical["tools"].get(name).is_some()
                    && matches!(
                        tool["qualification"].as_str(),
                        Some("site_policy_template" | "laboratory_only")
                    )
                    && tool["policy_required"].is_boolean()
                    && tool["requires"].is_array(),
                "{channel} missing explicit catalog qualification/prerequisites: {name}"
            );
            for field in ["qualification", "policy_required", "requires"] {
                ensure!(
                    tool[field] == canonical["tools"][name][field],
                    "{channel} installed {name}: {field} diverged"
                );
            }
        }
        for (name, prerequisite) in [
            ("observe_nic_eee", "estus_nic_model"),
            ("change_nic_eee", "estus_nic_model"),
            ("observe_nic_transceiver", "estus_nic_model"),
            ("observe_nic_fec", "netdevsim"),
            ("change_nic_fec", "netdevsim"),
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == name)
                .with_context(|| format!("{channel} missing {name}"))?;
            ensure!(
                tool["qualification"] == "laboratory_only"
                    && tool["requires"]
                        .as_array()
                        .is_some_and(|requires| requires.contains(&json!(prerequisite))),
                "{channel} {name} must retain laboratory qualification and {prerequisite}"
            );
        }
        let export = installed.root.path().join(format!("catalog-{channel}"));
        let exported = checked(
            launch(false)
                .args(["catalog", "export", "--preset", "linux-health", "--output"])
                .arg(&export),
        )
        .await?;
        let report: Value = serde_json::from_slice(&exported.stdout)?;
        ensure!(
            report["enabled"] == false
                && report["tools"] == json!(["observe_cpu", "observe_memory", "observe_pressure"]),
            "{channel} export granted authority or changed selection: {report}"
        );
        selection_metadata(
            &export,
            &canonical,
            &["observe_cpu", "observe_memory", "observe_pressure"],
        )?;
        let definitions: toml::Table = fs::read_to_string(export.join("tools.toml"))?.parse()?;
        ensure!(
            definitions["tools"]
                .as_table()
                .is_some_and(|tools| tools.len() == 3),
            "{channel} health export is incomplete"
        );
        for name in ["observe_cpu", "observe_memory", "observe_pressure"] {
            ensure!(
                export
                    .join(format!("payloads/{name}/manifest.json"))
                    .is_file()
                    && export
                        .join(format!("payloads/{name}/collector.py"))
                        .is_file()
                    && export.join(format!("overlays/{name}.json")).is_file(),
                "{channel} health export is missing production assets for {name}"
            );
        }
        let laboratory = installed.root.path().join(format!("laboratory-{channel}"));
        let exported = checked(
            launch(false)
                .args([
                    "catalog",
                    "export",
                    "--tool",
                    "observe_nic_eee",
                    "--tool",
                    "change_nic_eee",
                    "--tool",
                    "observe_nic_transceiver",
                    "--output",
                ])
                .arg(&laboratory),
        )
        .await?;
        let report: Value = serde_json::from_slice(&exported.stdout)?;
        ensure!(
            report["enabled"] == false,
            "{channel} laboratory export granted authority"
        );
        selection_metadata(
            &laboratory,
            &canonical,
            &[
                "observe_nic_eee",
                "change_nic_eee",
                "observe_nic_transceiver",
            ],
        )?;
        for signal in [None, Some(Signal::SIGINT), Some(Signal::SIGTERM)] {
            let mut command = launch(false);
            command.arg("--config").arg(&config);
            let mut server = WireServer::start_command(command)?;
            let observed = catalog(&mut server)
                .await
                .with_context(|| format!("{channel} {signal:?}"));
            let stopped = server
                .stop(signal)
                .await
                .with_context(|| format!("{channel} {signal:?} shutdown"));
            let observed = observed?;
            stopped?;
            let mut names: Vec<_> = observed
                .as_array()
                .context("default tool list")?
                .iter()
                .map(|tool| tool["name"].as_str().context("tool name"))
                .collect::<Result<_>>()?;
            names.sort_unstable();
            ensure!(
                names
                    == [
                        "change_target_quarantine_clear",
                        "inspect_output",
                        "observe_targets"
                    ],
                "{channel} omitted profile exposed native authority: {names:?}"
            );
            if let Some(expected) = &expected {
                ensure!(&observed == expected, "channel catalog diverged");
            } else {
                expected = Some(observed);
            }
        }
        // An extra in an ephemeral uv environment must be observed through the
        // selected launcher, including uv run's actual sysconfig/overlay layout.
        let checked = checked(launch(true).arg("--config").arg(&required_config).args([
            "doctor",
            "--runtime",
            "ansible",
        ]))
        .await
        .with_context(|| format!("{channel} extra doctor"))?;
        ensure!(
            checked.stdout.last() == Some(&b'\n')
                && checked.stdout.iter().filter(|&&byte| byte == b'\n').count() == 1,
            "{channel} doctor did not emit exactly one JSON report"
        );
        let report: Value = serde_json::from_slice(&checked.stdout)?;
        ensure!(
            report["ok"] == true
                && report["targets"] == json!([])
                && report["runtime"]["kind"] == "ansible"
                && report["runtime"]["status"] == "passed",
            "{channel} extra health failed: {report}"
        );
        let identity = &report["runtime"]["identity"];
        ensure!(
            identity["provenance"] == json!({"kind":"python_environment"})
                && identity["python"]
                    .as_str()
                    .is_some_and(|version| version.starts_with("3.14.")),
            "{channel} did not observe the selected installed environment: {report}"
        );
        if let Some(expected) = &expected_identity {
            ensure!(
                identity == expected,
                "{channel} extra runtime identity diverged"
            );
        } else {
            expected_identity = Some(identity.clone());
        }
        let mut command = launch(true);
        command.arg("--config").arg(&required_config);
        let mut server = WireServer::start_command(command)?;
        let observed = catalog(&mut server)
            .await
            .with_context(|| format!("{channel} required extra startup"));
        let stopped = server.stop(None).await;
        let observed = observed?;
        stopped?;
        ensure!(
            Some(&observed) == expected.as_ref(),
            "{channel} extra registered tools"
        );
    }
    checked_suite(
        installed
            .command(&stdio)
            .args(["--nocapture", "--test-threads=1"])
            .env("ESTUS_TEST_BINARY", installed.launcher(false)),
    )
    .await?;
    for case in [
        "real_stream_capture_nonzero_and_signal_are_distinct",
        "normal_exit_timeout_cancel_eof_and_sigterm_clean_actual_group_children",
    ] {
        checked_suite(
            installed
                .command(&controller)
                .args(["--include-ignored", "--exact", case, "--nocapture"])
                .env("ESTUS_TEST_BINARY", installed.launcher(true)),
        )
        .await?;
    }
    let extra_prefix = installed
        .launcher(true)
        .parent()
        .and_then(Path::parent)
        .context("extra prefix")?
        .to_owned();
    // Diagnostic availability only, not Runner execution or target readiness.
    let scripts = extra_prefix.join("bin");
    let child_path =
        std::env::join_paths([scripts.as_path(), Path::new("/usr/bin"), Path::new("/bin")])?;
    let diagnostic = checked(
        installed
            .command(&scripts.join("ansible-playbook"))
            .arg("--version")
            .env("PATH", child_path),
    )
    .await?;
    eprintln!(
        "selected-environment Ansible CLI:\n{}",
        String::from_utf8_lossy(&diagnostic.stdout)
    );
    let mutable = installed.root.path().join("mutable-extra");
    copy_environment(&extra_prefix, &mutable)?;
    checked_suite(
        installed
            .command(&automation)
            .args(["--ignored", "wheel::", "--nocapture", "--test-threads=1"])
            .env("ESTUS_TEST_BINARY", &native)
            .env("ESTUS_TEST_ANSIBLE_RUNTIME", &runtime)
            .env("ESTUS_TEST_BASE_WHEEL_BINARY", installed.launcher(false))
            .env("ESTUS_TEST_WHEEL_BINARY", installed.launcher(true))
            .env("ESTUS_TEST_MUTABLE_PREFIX", &mutable)
            .env("ESTUS_TEST_MUTABLE_PYTHON", mutable.join("bin/python")),
    )
    .await?;
    ordinary_ssh(&installed).await?;
    let root = installed.root.path().to_owned();
    installed.root.close()?;
    ensure!(!root.exists(), "owned wheel workspace survived cleanup");
    Ok(())
}

fn artifact_file(directory: &Path, extension: &str) -> Result<PathBuf> {
    let mut found = None;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some(extension) {
            ensure!(found.is_none(), "ambiguous build artifact");
            found = Some(path);
        }
    }
    found.context("missing build artifact")
}

fn asset_bytes(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &entry.path(), files)?;
            } else {
                ensure!(kind.is_file(), "unexpected catalog asset type");
                files.insert(
                    entry.path().strip_prefix(root)?.to_owned(),
                    fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(files)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires clean ESTUS_TEST_SOURCE_ARCHIVE, pinned ESTUS_TEST_BUILD_PYTHON, native ESTUS_TEST_NATIVE_CATALOG, Cargo and managed Python3.14"]
async fn source_distribution_roundtrip_preserves_manifest_selected_assets() -> Result<()> {
    let source_archive = input("ESTUS_TEST_SOURCE_ARCHIVE")?;
    let build_python = input("ESTUS_TEST_BUILD_PYTHON")?;
    let native = PathBuf::from(
        std::env::var_os("ESTUS_TEST_NATIVE_CATALOG").context("set ESTUS_TEST_NATIVE_CATALOG")?,
    );
    ensure!(native.is_absolute() && native.is_dir());
    let native_assets = asset_bytes(&native)?;
    let installed = Installed::new()?;
    let python = installed.python("3.14").await?;
    let tar = find_program("tar")?;
    let clean = installed.root.path().join("clean");
    fs::create_dir(&clean)?;
    checked(
        Command::new(&tar)
            .arg("-xf")
            .arg(&source_archive)
            .arg("-C")
            .arg(&clean),
    )
    .await?;
    ensure!(
        clean.join("Cargo.toml").is_file() && !clean.join("python/estus.egg-info").exists(),
        "source export is not clean"
    );
    let target = installed.root.path().join("cargo-target");
    for additional in [false, true] {
        let case = installed
            .root
            .path()
            .join(if additional { "additional" } else { "baseline" });
        fs::create_dir(&case)?;
        let source = case.join("source");
        copy_environment(&clean, &source)?;
        let catalog = source.join("catalog");
        let manifest_path = catalog.join("catalog.json");
        let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        let selected = if additional {
            let name = "observe_sdist_source_probe";
            let mut template = manifest["tools"]["observe_pressure"].clone();
            template["definition"] = json!(format!("{name}.toml"));
            template["executor"]["path"] = json!(format!("payloads/{name}"));
            manifest["tools"][name] = template;
            manifest["version"] = json!(format!(
                "{}-sdist-probe",
                manifest["version"].as_str().context("catalog version")?
            ));
            fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;
            let mut document: toml::Table =
                toml::from_str(&fs::read_to_string(catalog.join("observe_pressure.toml"))?)?;
            let tools = document
                .get_mut("tools")
                .and_then(toml::Value::as_table_mut)
                .context("source template tools")?;
            let definition = tools
                .remove("observe_pressure")
                .context("source template binding")?;
            tools.insert(name.to_owned(), definition);
            fs::write(
                catalog.join(format!("{name}.toml")),
                toml::to_string(&document)?,
            )?;
            copy_environment(
                &catalog.join("payloads/observe_pressure"),
                &catalog.join("payloads").join(name),
            )?;
            name
        } else {
            "observe_pressure"
        };
        let reviewed =
            assets::Catalog::load(Some(&catalog)).map_err(|code| anyhow::anyhow!(code))?;
        reviewed
            .definition(selected)
            .map_err(|code| anyhow::anyhow!(code))
            .with_context(|| format!("source entry {selected}"))?;
        let expected = asset_bytes(&catalog)?;
        if !additional {
            ensure!(
                expected == native_assets,
                "source and native approved assets disagree"
            );
        }
        // These files exist in the disposable source but must never enter an artifact.
        fs::write(catalog.join("private_state.json"), b"SDIST_PRIVATE_STATE")?;
        let cache = catalog.join("payloads/observe_pressure/__pycache__");
        fs::create_dir_all(&cache)?;
        fs::write(
            cache.join("collector.cpython-314.pyc"),
            b"SDIST_PRIVATE_CACHE",
        )?;
        fs::write(source.join("ESTUS_REVIEW.md"), b"SDIST_PRIVATE_PLAN")?;
        let sdists = case.join("sdists");
        checked(
            Command::new(&build_python)
                .args(["-I", "-m", "build", "--sdist", "--no-isolation", "--outdir"])
                .arg(&sdists)
                .arg(&source),
        )
        .await?;
        let unpacked = case.join("unpacked");
        fs::create_dir(&unpacked)?;
        checked(
            Command::new(&tar)
                .arg("-xf")
                .arg(artifact_file(&sdists, "gz")?)
                .arg("-C")
                .arg(&unpacked),
        )
        .await?;
        let mut roots = fs::read_dir(&unpacked)?;
        let extracted = roots.next().context("sdist source root")??.path();
        ensure!(
            extracted.is_dir() && roots.next().is_none(),
            "ambiguous sdist source root"
        );
        ensure!(
            asset_bytes(&extracted.join("catalog"))? == expected,
            "sdist lost approved bytes or included private/cache state"
        );
        for excluded in [
            "tests",
            "examples",
            "fuzz",
            "nix",
            "target",
            "dist",
            "build",
            "ESTUS_REVIEW.md",
        ] {
            ensure!(
                !extracted.join(excluded).exists(),
                "sdist included {excluded}"
            );
        }
        for required in [
            "Cargo.toml",
            "Cargo.lock",
            "pyproject.toml",
            "setup.py",
            "src/main.rs",
            "src/automation/python/runner.py",
            "vendor/openssh-sftp-client/Cargo.toml",
            "vendor/openssh-sftp-client/src/lib.rs",
        ] {
            ensure!(
                extracted.join(required).is_file(),
                "sdist omitted {required}"
            );
        }
        let wheels = case.join("wheels");
        checked(
            Command::new(&build_python)
                .args(["-I", "-m", "build", "--wheel", "--no-isolation", "--outdir"])
                .arg(&wheels)
                .arg(&extracted)
                .env("CARGO_TARGET_DIR", &target),
        )
        .await?;
        let venv = case.join("venv");
        checked(
            installed
                .uv()
                .arg("venv")
                .arg("--python")
                .arg(&python)
                .arg(&venv),
        )
        .await?;
        let interpreter = venv.join("bin/python");
        checked(
            installed
                .uv()
                .args(["pip", "install", "--offline", "--no-deps", "--python"])
                .arg(&interpreter)
                .arg(artifact_file(&wheels, "whl")?),
        )
        .await?;
        let launcher = venv.join("bin/estus");
        let listed = checked(
            installed
                .command(&launcher)
                .args(["catalog", "list", "--json"])
                .env("ESTUS_CATALOG_ROOT", case.join("untrusted-missing")),
        )
        .await?;
        let listing: Value = serde_json::from_slice(&listed.stdout)?;
        ensure!(listing["version"] == manifest["version"]);
        let actual: std::collections::BTreeSet<_> = listing["tools"]
            .as_array()
            .context("installed tool inventory")?
            .iter()
            .map(|tool| tool["name"].as_str().context("tool name"))
            .collect::<Result<_>>()?;
        let expected_names: std::collections::BTreeSet<_> = manifest["tools"]
            .as_object()
            .context("source tool inventory")?
            .keys()
            .map(String::as_str)
            .collect();
        ensure!(
            actual == expected_names,
            "source-only roundtrip changed the inventory"
        );
        let location = checked(installed.command(&interpreter).args(["-I", "-c",
            "from pathlib import Path; import estus; print(Path(estus.__file__).parent / '_catalog')"])).await?;
        let location = PathBuf::from(std::str::from_utf8(&location.stdout)?.trim());
        ensure!(
            asset_bytes(&location)? == expected,
            "installed source wheel changed approved assets"
        );
        let exported = case.join("exported");
        let output = checked(
            installed
                .command(&launcher)
                .args(["catalog", "export", "--tool", selected, "--output"])
                .arg(&exported),
        )
        .await?;
        let report: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(report["enabled"] == false && report["tools"] == json!([selected]));
        selection_metadata(&exported, &manifest, &[selected])?;
    }
    let root = installed.root.path().to_owned();
    installed.root.close()?;
    ensure!(
        !root.exists(),
        "owned source roundtrip workspace survived cleanup"
    );
    Ok(())
}

fn baseline_version(value: &str) -> Result<[u32; 3]> {
    let mut version = [0; 3];
    for (index, part) in value.split('.').enumerate() {
        ensure!(
            index < version.len() && !part.is_empty(),
            "unrecognized ABI version: {value}"
        );
        version[index] = part
            .parse()
            .with_context(|| format!("unrecognized ABI version: {value}"))?;
    }
    Ok(version)
}

#[tokio::test]
#[ignore = "requires ESTUS_TEST_WHEEL, unzip and pinned llvm-otool (Darwin) or llvm-readelf (Linux); no network"]
async fn wheel_payload_matches_declared_baseline() -> Result<()> {
    let wheel = input("ESTUS_TEST_WHEEL")?;
    let root = tempfile::Builder::new()
        .prefix("estus-audit-")
        .tempdir_in("/tmp")?;
    let workspace = root.path().canonicalize()?;
    let path = std::env::var_os("PATH").context("PATH prerequisite")?;
    let command = |program: &Path| {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", &path)
            .env("LC_ALL", "C")
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .current_dir(root.path())
            .kill_on_drop(true);
        command
    };
    let unzip = find_program("unzip")?;
    let listing = checked(command(&unzip).arg("-Z1").arg(&wheel)).await?;
    let listing = std::str::from_utf8(&listing.stdout)?;
    let payload_member = "estus/_bin/estus";
    ensure!(
        listing
            .lines()
            .filter(|line| *line == payload_member)
            .count()
            == 1,
        "wheel must contain exactly one native payload"
    );
    let mut seen = std::collections::BTreeSet::new();
    for member in listing.lines() {
        ensure!(
            !member.starts_with('/')
                && !member.contains('\\')
                && !member.split('/').any(|part| part == ".." || part == ".")
                && seen.insert(member),
            "unsafe or duplicate wheel member: {member}"
        );
    }
    checked(
        command(&unzip)
            .arg("-q")
            .arg(&wheel)
            .arg("estus/_catalog/*")
            .arg("-d")
            .arg(root.path()),
    )
    .await?;
    let assets = workspace.join("estus/_catalog");
    let source_catalog = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    ensure!(
        asset_bytes(&assets)? == asset_bytes(&source_catalog)?,
        "direct wheel catalog bytes diverged from source/native catalog"
    );
    let catalog = assets::Catalog::load(Some(&assets)).map_err(anyhow::Error::msg)?;
    for (name, template) in &catalog.manifest().tools {
        catalog.definition(name).map_err(anyhow::Error::msg)?;
        if !matches!(template.executor, assets::Executor::AnsibleModule { .. }) {
            catalog
                .copy_assets(name, &workspace.join(format!("assets-{name}")))
                .map_err(anyhow::Error::msg)?;
        }
    }
    for member in listing.lines() {
        if member.is_empty() || member.ends_with('/') {
            continue;
        }
        let allowed = member == payload_member
            || member == "estus/__init__.py"
            || member.starts_with("estus/_catalog/")
            || (member.starts_with("estus-") && member.contains(".dist-info/"));
        ensure!(allowed, "unexpected non-catalog wheel member: {member}");
    }
    for member in listing
        .lines()
        .filter_map(|member| member.strip_prefix("estus/_catalog/"))
    {
        if member.is_empty() || member.ends_with('/') {
            continue;
        }
        let parts: Vec<_> = member.split('/').collect();
        let permitted = match parts.as_slice() {
            ["catalog.json"] => true,
            [definition] => definition
                .strip_suffix(".toml")
                .is_some_and(|name| catalog.manifest().tools.contains_key(name)),
            ["roles", name, directory, rest @ ..] => {
                matches!(
                    catalog
                        .manifest()
                        .tools
                        .get(*name)
                        .map(|tool| &tool.executor),
                    Some(assets::Executor::AnsibleRole { .. })
                ) && matches!(
                    *directory,
                    "tasks" | "meta" | "files" | "defaults" | "vars" | "handlers"
                ) && !rest.is_empty()
                    && Path::new(member)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| matches!(ext, "yml" | "yaml" | "py" | "json" | "toml"))
            }
            ["payloads", name, rest @ ..] => {
                matches!(
                    catalog
                        .manifest()
                        .tools
                        .get(*name)
                        .map(|tool| &tool.executor),
                    Some(assets::Executor::NativePayload { .. })
                ) && !rest.is_empty()
                    && Path::new(member)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| matches!(ext, "yml" | "yaml" | "py" | "json" | "toml"))
            }
            _ => false,
        };
        ensure!(
            permitted && !member.contains("__pycache__"),
            "unexpected wheel catalog asset: {member}"
        );
    }
    let mut metadata_members = listing.lines().filter(|line| {
        line.strip_suffix("/WHEEL").is_some_and(|parent| {
            parent.starts_with("estus-")
                && parent.ends_with(".dist-info")
                && !parent.contains('/')
                && !parent.contains('\\')
        })
    });
    let metadata_member = metadata_members
        .next()
        .context("missing estus dist-info/WHEEL")?;
    ensure!(
        metadata_members.next().is_none(),
        "ambiguous wheel metadata"
    );
    checked(
        command(&unzip)
            .arg("-q")
            .arg(&wheel)
            .args([payload_member, metadata_member])
            .arg("-d")
            .arg(root.path()),
    )
    .await?;
    for member in [payload_member, metadata_member] {
        let selected = root.path().join(member);
        ensure!(
            fs::symlink_metadata(&selected)?.is_file()
                && fs::canonicalize(&selected)?.starts_with(fs::canonicalize(root.path())?),
            "selected wheel asset must be a regular owned extracted file: {member}"
        );
    }
    let payload = root.path().join(payload_member);
    let metadata = fs::read_to_string(root.path().join(metadata_member))?;
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macosx_11_0_arm64",
        ("linux", "aarch64") => "manylinux_2_17_aarch64",
        ("linux", "x86_64") => "manylinux_2_17_x86_64",
        other => anyhow::bail!("unsupported wheel audit platform: {other:?}"),
    };
    ensure!(
        wheel
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(&format!("-{platform}.whl"))),
        "wheel filename does not declare the required {platform} baseline"
    );
    let mut tags = metadata
        .lines()
        .filter_map(|line| line.strip_prefix("Tag: "));
    let first = tags.next().context("WHEEL has no compatibility tag")?;
    for tag in std::iter::once(first).chain(tags) {
        ensure!(
            tag.rsplit_once('-')
                .is_some_and(|(_, value)| value == platform),
            "wheel metadata declares an unexpected platform: {tag}"
        );
    }

    if cfg!(target_os = "macos") {
        let otool = find_program("llvm-otool")?;
        let header = checked(command(&otool).arg("-hv").arg(&payload)).await?;
        let header = std::str::from_utf8(&header.stdout)?;
        let mut architectures = header
            .lines()
            .filter(|line| line.trim_start().starts_with("MH_MAGIC"));
        let architecture = architectures
            .next()
            .context("missing Mach-O architecture")?;
        ensure!(
            architecture.split_whitespace().nth(1) == Some("ARM64")
                && architectures.next().is_none(),
            "wheel payload is not a single arm64 Mach-O: {header}"
        );
        let loads = checked(command(&otool).arg("-l").arg(&payload)).await?;
        let loads = std::str::from_utf8(&loads.stdout)?;
        ensure!(
            !loads.contains("/nix/store/"),
            "Mach-O load commands retain a Nix store reference: {loads}"
        );
        let mut current = "";
        let mut minimum_seen = false;
        let mut platform_seen = false;
        for line in loads.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("cmd ") {
                current = value;
            } else if current == "LC_BUILD_VERSION" {
                if let Some(value) = line.strip_prefix("platform ") {
                    ensure!(
                        value == "1" || value.eq_ignore_ascii_case("macos"),
                        "Mach-O declares a non-macOS platform: {value}"
                    );
                    platform_seen = true;
                } else if let Some(value) = line.strip_prefix("minos ") {
                    ensure!(
                        baseline_version(value)? <= [11, 0, 0],
                        "wheel advertises macOS 11.0 but payload requires macOS {value}"
                    );
                    minimum_seen = true;
                }
            } else if current == "LC_VERSION_MIN_MACOSX"
                && let Some(value) = line.strip_prefix("version ")
            {
                ensure!(
                    baseline_version(value)? <= [11, 0, 0],
                    "wheel advertises macOS 11.0 but payload requires macOS {value}"
                );
                minimum_seen = true;
                platform_seen = true;
            }
        }
        ensure!(
            minimum_seen && platform_seen,
            "Mach-O does not declare an auditable macOS minimum"
        );
        let libraries = checked(command(&otool).arg("-L").arg(&payload)).await?;
        let libraries = std::str::from_utf8(&libraries.stdout)?;
        let mut system_library_seen = false;
        for line in libraries
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
        {
            let library = line
                .trim()
                .split_once(" (")
                .context("unrecognized Mach-O dylib entry")?
                .0;
            ensure!(
                (library.starts_with("/usr/lib/") || library.starts_with("/System/Library/"))
                    && !library.contains("libpython")
                    && !library.contains("Python.framework"),
                "non-system or Python-linked Mach-O dependency: {library}"
            );
            system_library_seen = true;
        }
        ensure!(
            system_library_seen,
            "missing Mach-O system dependency evidence"
        );
    } else {
        let readelf = find_program("llvm-readelf")?;
        let inspected = checked(
            command(&readelf)
                .args([
                    "--file-header",
                    "--program-headers",
                    "--dynamic-table",
                    "--version-info",
                ])
                .arg(&payload),
        )
        .await?;
        let inspected = std::str::from_utf8(&inspected.stdout)?;
        ensure!(
            !inspected.contains("/nix/store/"),
            "ELF loader/dynamic metadata retains a Nix store reference: {inspected}"
        );
        let (machine, interpreter) = match std::env::consts::ARCH {
            "aarch64" => ("AArch64", "/lib/ld-linux-aarch64.so.1"),
            "x86_64" => (
                "Advanced Micro Devices X86-64",
                "/lib64/ld-linux-x86-64.so.2",
            ),
            other => anyhow::bail!("unsupported ELF architecture: {other}"),
        };
        let actual_machine = inspected
            .lines()
            .find_map(|line| line.trim().strip_prefix("Machine:"))
            .context("missing ELF machine")?
            .trim();
        ensure!(
            actual_machine == machine,
            "ELF architecture disagrees with wheel tag: {actual_machine}"
        );
        let mut interpreters = inspected.lines().filter_map(|line| {
            line.split_once("Requesting program interpreter: ")
                .map(|(_, value)| value.trim_end_matches(']').trim())
        });
        ensure!(
            interpreters.next() == Some(interpreter) && interpreters.next().is_none(),
            "ELF must use the architecture's FHS program interpreter {interpreter}"
        );
        let mut needed_seen = false;
        let mut glibc_seen = false;
        for line in inspected.lines() {
            if line.contains("(NEEDED)") {
                let library = line
                    .split_once('[')
                    .and_then(|(_, value)| value.split_once(']'))
                    .context("unrecognized ELF DT_NEEDED entry")?
                    .0;
                let dynamic_linker = Path::new(interpreter)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("missing dynamic linker name")?;
                ensure!(
                    !library.contains("libpython")
                        && (library == dynamic_linker
                            || matches!(
                                library,
                                "libc.so.6"
                                    | "libgcc_s.so.1"
                                    | "libm.so.6"
                                    | "libpthread.so.0"
                                    | "librt.so.1"
                                    | "libdl.so.2"
                            )),
                    "nonportable ELF dependency outside the system C runtime: {library}"
                );
                needed_seen = true;
            }
            for token in line.split_whitespace() {
                if let Some((_, requirement)) = token.split_once("GLIBC_") {
                    let requirement = requirement.trim_end_matches([')', ']', ',']);
                    ensure!(
                        baseline_version(requirement)? <= [2, 17, 0],
                        "wheel advertises glibc 2.17 but payload requires GLIBC_{requirement}"
                    );
                    glibc_seen = true;
                }
            }
        }
        ensure!(
            needed_seen && glibc_seen,
            "missing dynamic ELF/glibc requirement evidence"
        );
    }
    let owned = root.path().to_owned();
    root.close()?;
    ensure!(
        !owned.exists(),
        "owned artifact audit workspace survived cleanup"
    );
    Ok(())
}
