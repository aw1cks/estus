use anyhow::{Context, Result, ensure};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn assets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
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
        .env("ESTUS_ANSIBLE_RUNTIME", "/missing/private-runtime")
        .output()?)
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
    ensure!(
        data["presets"]["linux-health"]
            == serde_json::json!(["cpu_stats", "memory_stats", "pressure_get"]),
        "health preset changed disclosure/effect surface"
    );
    let tools = data["tools"].as_array().context("tools")?;
    let pressure = tools
        .iter()
        .find(|v| v["name"] == "pressure_get")
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
        .find(|v| v["name"] == "nic_features_set")
        .context("tuning template")?;
    ensure!(
        tuning["policy_required"] == true,
        "NIC tuning lost explicit site-policy gate"
    );
    ensure!(
        data["presets"].get("all").is_none() && data["presets"].get("admin").is_none(),
        "blanket privileged preset exposed"
    );
    Ok(())
}

#[test]
fn export_is_inert_private_and_retains_typed_input_overlay() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let destination = directory.path().join("health");
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
    let definitions: toml::Value =
        toml::from_str(&std::fs::read_to_string(destination.join("tools.toml"))?)?;
    ensure!(
        definitions.get("automation").is_none() && definitions.get("enabled_tools").is_none(),
        "export generated authority or activation policy"
    );
    let pressure = &definitions["tools"]["pressure_get"];
    let role = Path::new(
        pressure["execution"]["role_path"]
            .as_str()
            .context("role path")?,
    );
    ensure!(
        role.is_absolute() && role.join("files/collector.py").is_file(),
        "export did not retain the executable reviewed payload"
    );
    let overlay: serde_json::Value = serde_json::from_slice(&std::fs::read(
        destination.join("overlays/pressure_get.json"),
    )?)?;
    ensure!(
        overlay["input_schema"]["additionalProperties"] == false
            && overlay["input_schema"]["properties"] == serde_json::json!({}),
        "empty closed PSI domain broadened"
    );
    ensure!(
        std::fs::read_dir(destination.join("snapshots"))?
            .next()
            .is_none(),
        "export silently approved a snapshot"
    );
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        std::fs::metadata(&destination)?.permissions().mode() & 0o777 == 0o700,
        "private exported policy is group/world accessible"
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
        "pressure_get".as_ref(),
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

fn test_binary() -> std::ffi::OsString {
    std::env::var_os("ESTUS_TEST_BINARY").unwrap_or_else(|| env!("CARGO_BIN_EXE_estus").into())
}

#[test]
fn inspect_honors_explicit_catalog_root_without_ambient_configuration() -> Result<()> {
    let root = tempfile::tempdir()?;
    let site = root.path().join("site.toml");
    let mut text = String::from(
        "profile='actions-only'\ntool_presets=['linux-health']\n[catalog]\nversion='1'\n[targets.one]\nssh_host='private-alias'\n",
    );
    for name in ["cpu_stats", "memory_stats", "pressure_get"] {
        text.push_str(&format!(
            r#"
[tools.{name}]
description="Explicit operator binding"
revision="1"
targets=["one"]
authority="ordinary"
effects=["read"]
execution={{kind="native_argv",program="/usr/bin/id",argv=["--","root"]}}
input_schema={{type="object",properties={{}},required=[],additionalProperties=false}}
result={{kind="command"}}
"#
        ));
    }
    std::fs::write(&site, text)?;
    let output = Command::new(test_binary())
        .args(["catalog", "--root"])
        .arg(assets())
        .args(["inspect", "--site"])
        .arg(&site)
        .env_remove("ESTUS_CATALOG_ROOT")
        .env_remove("ESTUS_CONFIG")
        .env("ESTUS_SSH", env!("CARGO_BIN_EXE_estus"))
        .output()?;
    ensure!(
        output.status.success(),
        "explicit-root inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        report["global_native_execution"] == false,
        "actions-only widened native exposure"
    );
    ensure!(
        report["tools"]
            .as_array()
            .context("resolved tools")?
            .iter()
            .all(|v| v["enabled"] == true && v["targets"][0]["permitted"] == true),
        "inspect did not resolve the requested preset"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preparation_rejects_fifo_ssh_config_without_hanging_or_partial_output() -> Result<()> {
    use std::time::Duration;
    use tokio::process::Command as AsyncCommand;
    let root = tempfile::tempdir()?;
    let export = root.path().join("export");
    let output = invoke(&[
        "export".as_ref(),
        "--tool".as_ref(),
        "pressure_get".as_ref(),
        "--output".as_ref(),
        export.as_os_str(),
    ])?;
    ensure!(output.status.success(), "fixture export failed");
    let fifo = root.path().join("ssh-fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let site = root.path().join("site.toml");
    std::fs::write(
        &site,
        format!(
            "profile='actions-only'\n[ssh]\nconfig_file={fifo:?}\n[targets.server]\nssh_host='private-alias'\n[automation.targets.server]\ndestination='private-alias'\npython='/usr/bin/python3'\n"
        ),
    )?;
    let prepared = root.path().join("prepared");
    let mut child = AsyncCommand::new(test_binary())
        .args(["catalog", "--root"])
        .arg(assets())
        .args(["prepare", "--site"])
        .arg(site)
        .arg("--definitions")
        .arg(export.join("tools.toml"))
        .arg("--output")
        .arg(&prepared)
        .args(["--timeout-secs", "1"])
        .env_remove("ESTUS_CONFIG")
        .env_remove("ESTUS_SSH_CONFIG")
        .env("ESTUS_SSH", env!("CARGO_BIN_EXE_estus"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let status = match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            child.kill().await?;
            anyhow::bail!("preparation hung opening an SSH FIFO after its deadline");
        }
    };
    ensure!(!status.success(), "FIFO was accepted as SSH configuration");
    ensure!(
        !prepared.exists(),
        "failed preparation left an apparently reviewed configuration"
    );
    Ok(())
}
