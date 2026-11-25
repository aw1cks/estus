use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn assets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog")
}
fn invoke(arguments: &[&std::ffi::OsStr]) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_estus"))
        .arg("catalog")
        .arg("--root")
        .arg(assets())
        .args(arguments)
        .env("PATH", "")
        .env("ESTUS_CONFIG", "/missing/private-config")
        .env("ESTUS_SSH", "/missing/private-ssh")
        .env("ESTUS_ANSIBLE_BUNDLE", "/missing/private-bundle")
        .output()?)
}

fn test_binary() -> std::ffi::OsString {
    std::env::var_os("ESTUS_TEST_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_estus").into())
}

/// The workflow this replaces is gone: no offline approval, comparison or
/// snapshot step exists, so none may appear in help output.
#[test]
fn catalog_help_lists_the_supported_subcommands() -> Result<()> {
    let output = Command::new(test_binary())
        .args(["catalog", "--help"])
        .env_remove("ESTUS_CONFIG")
        .output()?;
    ensure!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    for removed in ["prepare", "inspect", "diff"] {
        ensure!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with(removed)),
            "removed subcommand `{removed}` still advertised:\n{text}"
        );
    }
    for kept in ["list", "export", "install"] {
        ensure!(
            text.lines().any(|line| line.trim_start().starts_with(kept)),
            "subcommand `{kept}` is missing:\n{text}"
        );
    }
    Ok(())
}

#[test]
fn listing_is_offline_and_health_preset_does_not_expand_authority() -> Result<()> {
    let output = invoke(&["list".as_ref(), "--json".as_ref()])?;
    ensure!(
        output.status.success(),
        "offline catalog list: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let data: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(data["schema"] == 3 && data["version"] == "10");
    ensure!(
        data["presets"]["linux-health"]
            == serde_json::json!(["observe_cpu", "observe_memory", "observe_pressure"]),
        "health preset changed disclosure/effect surface"
    );
    let tools = data["tools"].as_array().context("tools")?;
    let pressure = tools
        .iter()
        .find(|v| v["name"] == "observe_pressure")
        .context("pressure template")?;
    ensure!(
        pressure["policy_required"] == false
            && pressure["description"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "health template is not usable metadata"
    );
    let tuning = tools
        .iter()
        .find(|v| v["name"] == "change_nic_features")
        .context("tuning template")?;
    ensure!(
        tuning["policy_required"] == true,
        "NIC tuning lost explicit site-policy gate"
    );
    for name in [
        "observe_nic_eee",
        "change_nic_eee",
        "observe_nic_transceiver",
        "observe_nic_fec",
        "change_nic_fec",
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .context("laboratory template")?;
        ensure!(
            tool["qualification"] == "laboratory_only"
                && tool["requires"]
                    .as_array()
                    .is_some_and(|requires| !requires.is_empty()),
            "laboratory hardware was presented without qualification/prerequisites: {tool}"
        );
    }
    ensure!(
        data["presets"].get("all").is_none() && data["presets"].get("admin").is_none(),
        "blanket privileged preset exposed"
    );
    Ok(())
}

#[test]
fn export_is_inert_and_writes_only_reviewable_inputs() -> Result<()> {
    let directory = tempfile::tempdir()?;
    // Export refuses output paths that pass through a symlink, and macOS's temp
    // directory sits under the `/var` symlink.
    let destination = directory.path().canonicalize()?.join("health");
    let output = invoke(&[
        "export".as_ref(),
        "--preset".as_ref(),
        "linux-health".as_ref(),
        "--output".as_ref(),
        destination.as_os_str(),
    ])?;
    ensure!(
        output.status.success(),
        "export: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["enabled"] == false,
        "export activated unreviewed definitions"
    );
    let selection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(destination.join("catalog-selection.json"))?)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(assets().join("catalog.json"))?)?;
    ensure!(
        selection["schema"] == 3
            && selection["version"] == manifest["version"]
            && selection["scope"] == "catalog_templates"
    );
    for name in ["observe_cpu", "observe_memory", "observe_pressure"] {
        for field in ["qualification", "policy_required", "requires"] {
            ensure!(
                selection["tools"][name][field] == manifest["tools"][name][field],
                "export changed template metadata for {name}/{field}"
            );
        }
    }
    let definitions: toml::Value =
        toml::from_str(&std::fs::read_to_string(destination.join("tools.toml"))?)?;
    ensure!(
        definitions.get("automation").is_none() && definitions.get("selection").is_none(),
        "export generated authority or activation policy"
    );
    let pressure = &definitions["tools"]["observe_pressure"];
    let source = Path::new(
        pressure["execution"]["source"]
            .as_str()
            .context("payload source")?,
    );
    ensure!(
        source.is_absolute() && source.is_file(),
        "export did not retain the executable reviewed payload"
    );
    ensure!(
        pressure["execution"].get("snapshot").is_none(),
        "export reintroduced a snapshot reference"
    );
    ensure!(
        pressure["input_schema"]["additionalProperties"] == toml::Value::Boolean(false)
            && pressure["input_schema"]["properties"]
                .as_table()
                .is_some_and(toml::Table::is_empty),
        "empty closed PSI domain broadened"
    );
    for absent in ["overlays", "snapshots"] {
        ensure!(
            !destination.join(absent).exists(),
            "export wrote a {absent} directory"
        );
    }
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        std::fs::metadata(&destination)?.permissions().mode() & 0o777 == 0o700,
        "exported policy is group/world accessible"
    );
    ensure!(
        std::fs::metadata(destination.join("catalog-selection.json"))?
            .permissions()
            .mode()
            & 0o777
            == 0o600
    );
    Ok(())
}

#[test]
fn invalid_selection_cannot_clobber_or_leak_private_names() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let destination = directory.path().join("existing");
    std::fs::create_dir(&destination)?;
    std::fs::write(destination.join("sentinel"), "preserve")?;
    let output = invoke(&[
        "export".as_ref(),
        "--tool".as_ref(),
        "observe_pressure".as_ref(),
        "--output".as_ref(),
        destination.as_os_str(),
    ])?;
    ensure!(
        !output.status.success(),
        "existing export directory was replaced"
    );
    ensure!(
        std::fs::read_to_string(destination.join("sentinel"))? == "preserve",
        "existing directory changed"
    );
    let unknown = invoke(&[
        "export".as_ref(),
        "--tool".as_ref(),
        "private-unlisted-tool-identifier".as_ref(),
        "--output".as_ref(),
        directory.path().join("bad").as_os_str(),
    ])?;
    ensure!(
        !unknown.status.success() && !directory.path().join("bad").exists(),
        "invalid selection left a misleading bundle"
    );
    ensure!(
        !String::from_utf8_lossy(&unknown.stderr).contains("private-unlisted-tool-identifier"),
        "catalog rejection disclosed untrusted input"
    );
    Ok(())
}

#[test]
fn global_catalog_options_are_honored_or_rejected_without_reflecting_values() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (export, option) in [false, true].into_iter().flat_map(|export| {
        ["--config", "--ssh", "--ssh-config"]
            .into_iter()
            .map(move |option| (export, option))
    }) {
        let destination = root.path().join("must-not-export");
        let mut command = Command::new(test_binary());
        command
            .arg(option)
            .arg("DO_NOT_REFLECT_OFFLINE")
            .args(["catalog", "--root"])
            .arg(assets())
            .env("ESTUS_CONFIG", "/missing/ambient-config")
            .env("ESTUS_SSH", "/missing/ambient-ssh");
        if export {
            command
                .args(["export", "--tool", "observe_pressure", "--output"])
                .arg(&destination);
        } else {
            command.args(["list", "--json"]);
        }
        let output = command.output()?;
        ensure!(!output.status.success() && output.stdout.is_empty() && !destination.exists());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        ensure!(error["error_code"] == "catalog_option_not_applicable");
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_REFLECT"));
    }
    Ok(())
}

/// A site config enables an installed catalog tool by name, with its own
/// `fixed_args`, and the resulting payload runs through the real stdio server.
#[test]
fn site_config_enables_a_catalog_tool_with_site_fixed_args() -> Result<()> {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("collector-ran");
    let source = root.path().join("payloads/probe/collector.py");
    std::fs::create_dir_all(source.parent().context("payload dir")?)?;
    std::fs::write(
        &source,
        r#"import estus_runtime, json
cfg = estus_runtime.request()[0]
open(cfg["marker"], "w", encoding="utf-8").write(cfg["greeting"])
print(json.dumps({"ok": True}))
"#,
    )?;
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(std::fs::read(&source)?))
    };
    std::fs::write(
        source
            .parent()
            .context("payload dir")?
            .join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1, "protocol": 1, "adapter_version": 1,
            "change_policy": "read_only",
            "source_sha256": digest,
            "max_source_bytes": 1_048_576,
            "argv": [{"kind": "object", "fields": {
                "marker": {"name": "marker"}, "greeting": {"name": "greeting"},
            }}],
            "requirements": {
                "python_min": [3, 8], "modules": ["json"],
                "executables": [], "paths": [],
            },
            "contract": {
                "schema": {"type": "object", "additionalProperties": false,
                    "required": ["target_python", "marker", "greeting"],
                    "properties": {
                        "target_python": {"type": "string"},
                        "marker": {"type": "string"},
                        "greeting": {"type": "string"},
                    }},
                "aliases": {"aliases": {}, "properties": {
                    "target_python": {"aliases": {}, "properties": {}},
                    "marker": {"aliases": {}, "properties": {}},
                    "greeting": {"aliases": {}, "properties": {}},
                }},
                "defaults": {}, "review_required": [],
            },
        }))?,
    )?;
    let site = root.path().join("site.toml");
    std::fs::write(
        &site,
        format!(
            r#"capabilities = {{ named = true }}
[selection]
allow = ["observe_probe"]

[targets.local]
ssh_host = "local"

[automation.targets.local]
destination = "local"
python = "/usr/bin/python3"

[tools.observe_probe]
description = "Bounded probe proving site fixed arguments reach the collector."
revision = "1"
targets = ["local"]
authority = "automation"
effects = ["read"]
execution = {{ kind = "native_payload", source = {source}, no_log = false }}
fixed_args = {{ target_python = "/usr/bin/python3", marker = {marker}, greeting = "site policy" }}
input_map = {{}}
input_schema = {{ type = "object", properties = {{}}, required = [], additionalProperties = false }}
result = {{ kind = "capability_projection", fields = {{ ok = ["ok"] }}, schema = {{ type = "object", properties = {{ ok = {{ type = "boolean" }} }}, required = ["ok"], additionalProperties = false }}, max_bytes = 1024, max_items = 16, max_depth = 3 }}
"#,
            marker = serde_json::to_string(&marker.to_string_lossy())?,
            source = serde_json::to_string(&source.to_string_lossy())?,
        ),
    )?;
    use std::io::{BufRead, BufReader, Write};
    let mut child = Command::new(test_binary())
        .args(["--config"])
        .arg(&site)
        .env_remove("ESTUS_CONFIG")
        .env_remove("ESTUS_SSH")
        .env_remove("ESTUS_SSH_CONFIG")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().context("stdin")?;
    let mut stdout = BufReader::new(child.stdout.take().context("stdout")?);
    for frame in [
        serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}
        }),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ] {
        serde_json::to_writer(&mut stdin, &frame)?;
        stdin.write_all(b"\n")?;
    }
    stdin.flush()?;
    drop(stdin);
    let mut listed = String::new();
    while stdout.read_line(&mut listed)? > 0 {
        if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&listed)
            && frame["id"] == 2
        {
            let tool = frame["result"]["tools"]
                .as_array()
                .context("tools")?
                .iter()
                .find(|tool| tool["name"] == "observe_probe")
                .context("site definition was not advertised")?
                .clone();
            ensure!(
                tool["inputSchema"]["properties"]["host"]["enum"] == serde_json::json!(["local"]),
                "site definition did not restrict hosts: {tool}"
            );
            ensure!(
                std::fs::read_to_string(&marker).is_err(),
                "listing ran the collector"
            );
            let status = child.wait()?;
            ensure!(status.success(), "server exited with {status}");
            return Ok(());
        }
        listed.clear();
    }
    let stderr = child.wait_with_output()?.stderr;
    anyhow::bail!(
        "server never listed the site tool: {}",
        String::from_utf8_lossy(&stderr)
    );
}

/// A collector edited after installation is refused at load, before any target
/// connection: the shipped manifest pins its bytes.
#[test]
fn modified_collector_bytes_are_rejected_before_connecting() -> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("payloads/tampered/collector.py");
    std::fs::create_dir_all(source.parent().context("payload dir")?)?;
    std::fs::write(&source, "print('installed')\n")?;
    let installed_digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(std::fs::read(&source)?))
    };
    std::fs::write(
        source
            .parent()
            .context("payload dir")?
            .join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": 1, "protocol": 1, "adapter_version": 1,
            "change_policy": "read_only",
            "source_sha256": installed_digest,
            "max_source_bytes": 1_048_576,
            "argv": [],
            "requirements": {"python_min": [3, 8], "modules": [], "executables": [], "paths": []},
            "contract": {
                "schema": {"type": "object", "additionalProperties": false, "required": ["target_python"],
                    "properties": {"target_python": {"type": "string"}}},
                "aliases": {"aliases": {}, "properties": {"target_python": {"aliases": {}, "properties": {}}}},
                "defaults": {}, "review_required": [],
            },
        }))?,
    )?;
    std::fs::write(&source, "print('edited after install')\n")?;
    let site = root.path().join("site.toml");
    std::fs::write(
        &site,
        format!(
            r#"capabilities = {{ named = true }}
[selection]
allow = ["observe_probe"]

[targets.local]
ssh_host = "local"

[automation.targets.local]
destination = "local"
python = "/usr/bin/python3"

[tools.observe_probe]
description = "Bounded probe proving a tampered collector is rejected at load."
revision = "1"
targets = ["local"]
authority = "automation"
effects = ["read"]
execution = {{ kind = "native_payload", source = {source}, no_log = false }}
fixed_args = {{ target_python = "/usr/bin/python3" }}
input_map = {{}}
input_schema = {{ type = "object", properties = {{}}, required = [], additionalProperties = false }}
result = {{ kind = "capability_projection", fields = {{ ok = ["ok"] }}, schema = {{ type = "object", properties = {{ ok = {{ type = "boolean" }} }}, required = ["ok"], additionalProperties = false }}, max_bytes = 1024, max_items = 16, max_depth = 3 }}
"#,
            source = serde_json::to_string(&source.to_string_lossy())?,
        ),
    )?;
    let output = Command::new(test_binary())
        .args(["--config"])
        .arg(&site)
        .env_remove("ESTUS_CONFIG")
        .env_remove("ESTUS_SSH")
        .env_remove("ESTUS_SSH_CONFIG")
        .env("ESTUS_SSH", "/missing/ssh-must-not-be-invoked")
        .stdin(std::process::Stdio::null())
        .output()?;
    ensure!(
        !output.status.success(),
        "a collector that no longer matches its manifest was accepted"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    ensure!(
        diagnostic.contains("source_digest") || diagnostic.contains("invalid_config"),
        "rejection did not name the integrity failure: {diagnostic}"
    );
    ensure!(
        !diagnostic.contains("edited after install"),
        "rejection reflected collector contents"
    );
    Ok(())
}

/// Runs `binary`, retrying while the kernel reports it busy. A test that copies
/// an executable and runs it at once can hit ETXTBSY: another test thread's
/// child, between fork and exec, may still hold the copy's write descriptor. It
/// clears within milliseconds, so retry that error only, and only briefly.
fn run_in(binary: &Path, arguments: &[&str]) -> Result<Output> {
    let mut attempts = 0;
    loop {
        let result = Command::new(binary)
            .args(arguments)
            .env_remove("ESTUS_CATALOG_ROOT")
            .env_remove("ESTUS_CONFIG")
            .env_remove("ESTUS_SSH")
            .stdin(std::process::Stdio::null())
            .output();
        match result {
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 100 =>
            {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return Ok(other?),
        }
    }
}

#[test]
fn install_writes_the_bundled_catalog_and_is_idempotent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("share/estus/catalog");
    let target_text = target.to_str().context("target path")?;
    let binary = PathBuf::from(test_binary());

    let first = run_in(&binary, &["catalog", "install", "--dir", target_text])?;
    ensure!(
        first.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&first.stdout)?;
    ensure!(report["ok"] == true && report["installed"] == true);
    ensure!(report["files"].as_u64().is_some_and(|files| files > 100));
    for relative in ["catalog.json", "payloads/observe_cpu/collector.py"] {
        ensure!(
            std::fs::read(target.join(relative))? == std::fs::read(assets().join(relative))?,
            "{relative} was not installed byte for byte"
        );
    }
    // The installed tree is a usable root.
    let listed = run_in(
        &binary,
        &["catalog", "--root", target_text, "list", "--json"],
    )?;
    ensure!(listed.status.success(), "installed catalog does not load");

    // Installing the same catalog again changes nothing.
    let again = run_in(&binary, &["catalog", "install", "--dir", target_text])?;
    ensure!(again.status.success());
    ensure!(serde_json::from_slice::<serde_json::Value>(&again.stdout)?["installed"] == false);

    // A catalog that differs is never overwritten without --replace.
    let manifest = target.join("catalog.json");
    let mut edited = std::fs::read(&manifest)?;
    edited.push(b'\n');
    std::fs::write(&manifest, &edited)?;
    let refused = run_in(&binary, &["catalog", "install", "--dir", target_text])?;
    ensure!(!refused.status.success());
    ensure!(String::from_utf8_lossy(&refused.stderr).contains("catalog_install_exists"));
    ensure!(
        std::fs::read(&manifest)? == edited,
        "a refused install modified the existing catalog"
    );
    let replaced = run_in(
        &binary,
        &["catalog", "install", "--dir", target_text, "--replace"],
    )?;
    ensure!(
        replaced.status.success(),
        "replace failed: {}",
        String::from_utf8_lossy(&replaced.stderr)
    );
    ensure!(std::fs::read(&manifest)? == std::fs::read(assets().join("catalog.json"))?);
    let leftovers: Vec<_> = std::fs::read_dir(target.parent().context("parent")?)?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with(".estus-catalog"))
        .collect();
    ensure!(leftovers.is_empty(), "staging left behind: {leftovers:?}");
    Ok(())
}

#[test]
fn install_refuses_a_symlinked_target_and_a_root_option() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let real = dir.path().join("real");
    std::fs::create_dir(&real)?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link)?;
    let binary = PathBuf::from(test_binary());
    let link_text = link.to_str().context("link path")?;
    let output = run_in(
        &binary,
        &["catalog", "install", "--dir", link_text, "--replace"],
    )?;
    ensure!(!output.status.success());
    ensure!(String::from_utf8_lossy(&output.stderr).contains("catalog_path_unsafe"));
    ensure!(
        std::fs::read_dir(&real)?.next().is_none(),
        "install wrote through a symlink"
    );

    let rooted = run_in(
        &binary,
        &[
            "catalog",
            "--root",
            assets().to_str().context("assets")?,
            "install",
            "--dir",
            dir.path().join("x").to_str().context("x")?,
        ],
    )?;
    ensure!(!rooted.status.success());
    ensure!(String::from_utf8_lossy(&rooted.stderr).contains("catalog_option_not_applicable"));
    Ok(())
}

/// The case this feature exists for: a lone binary, with no packaging around it,
/// installs the catalog next to itself and then works in every mode.
#[test]
fn a_lone_binary_installs_and_then_finds_its_catalog() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin)?;
    let binary = bin.join("estus");
    std::fs::copy(test_binary(), &binary)?;

    // Before installing there is nothing to find, and the error says what to do.
    let missing = run_in(&binary, &["catalog", "list"])?;
    ensure!(!missing.status.success());
    ensure!(String::from_utf8_lossy(&missing.stderr).contains("catalog_not_installed"));

    let installed = run_in(&binary, &["catalog", "install"])?;
    ensure!(
        installed.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    ensure!(
        dir.path()
            .join("share/estus/catalog/catalog.json")
            .is_file()
    );
    let listed = run_in(&binary, &["catalog", "list"])?;
    ensure!(
        listed.status.success(),
        "catalog next to the binary was not found"
    );

    // A headless site config that selects a catalog tool resolves it too.
    let config = dir.path().join("estus.toml");
    std::fs::write(
        &config,
        indoc::indoc! {r#"
            mode = "headless"
            capabilities = { named = true }
            [selection]
            presets = ["linux-health"]
            [targets.web-1]
            ssh_host = "web-1"
            [automation.targets.web-1]
            destination = "web-1"
            python = "/usr/bin/python3"
        "#},
    )?;
    let allowed = run_in(
        &binary,
        &[
            "--config",
            config.to_str().context("config")?,
            "auth",
            "can-i",
            "observe_cpu",
            "web-1",
        ],
    )?;
    ensure!(
        allowed.status.success(),
        "headless config did not find the installed catalog: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    Ok(())
}
