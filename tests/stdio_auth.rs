use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

fn estus_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_estus"))
}

fn catalog_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog")
}

#[test]
fn auth_explain_and_can_i_enforce_groups_ssh_alias_and_strictest_wins() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("operator.toml");
    let ssh_config_path = dir.path().join("ssh_config");

    std::fs::write(
        &ssh_config_path,
        "\
Host db1
    HostName db1.prod.internal
Host rawbox
    HostName 10.42.0.15
",
    )?;
    std::fs::write(
        &config_path,
        "\
mode = \"workstation\"
default_profile = \"prod\"

[[groups]]
name = \"lab\"
match_hosts = [\"*.lab.internal\", \"lab-*\"]

[[groups]]
name = \"dev\"
match_hosts = [\"eu-*\", \"*.dev.internal\", \"rawbox\"]

[[groups]]
name = \"prod\"
match_hosts = [\"*.prod.internal\", \"*-prd-*\"]
",
    )?;

    // 1. Alias `db1` resolves via `ssh -G` to `db1.prod.internal`, matching group "prod":
    //    `auth can-i exec_command db1` must exit 1 and name the ssh -G hostname + prod profile.
    let deny_exec = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "can-i",
            "exec_command",
            "db1",
        ])
        .output()?;
    ensure!(
        !deny_exec.status.success(),
        "expected exec_command denied on db1 alias resolving to prod"
    );
    let deny_stdout = String::from_utf8(deny_exec.stdout)?;
    ensure!(
        deny_stdout.starts_with("no")
            && deny_stdout.contains("db1.prod.internal")
            && deny_stdout.contains("prod"),
        "unexpected can-i output: {deny_stdout}"
    );

    // 2. Read-only `inspect_file` IS allowed on `db1` (prod max_tier = inspect, file_read = true).
    let allow_read = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "can-i",
            "inspect_file",
            "db1",
        ])
        .output()?;
    ensure!(
        allow_read.status.success(),
        "expected inspect_file allowed on prod db1: {}",
        String::from_utf8_lossy(&allow_read.stdout)
    );

    // 3. `auth explain db1 --json` reports resolved_ssh_hostname + matched group "prod".
    let explain = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "explain",
            "db1",
            "--json",
        ])
        .output()?;
    ensure!(explain.status.success(), "auth explain db1 failed");
    let json: Value = serde_json::from_slice(&explain.stdout)?;
    ensure!(json["allowed"] == true);
    ensure!(json["resolved_ssh_hostname"] == "db1.prod.internal");
    ensure!(json["effective"]["max_tier"] == "inspect");
    ensure!(json["effective"]["require_preview"] == true);
    ensure!(json["matched"][0]["profile"] == "prod");

    // 4. `rawbox` resolves via `ssh -G` to IP literal 10.42.0.15: IP-literal guard rejects
    //    `dev` (allow_ip_literals = false) and falls back to default_profile = "prod".
    let rawbox = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "explain",
            "rawbox",
            "--json",
        ])
        .output()?;
    ensure!(rawbox.status.success());
    let rawbox_json: Value = serde_json::from_slice(&rawbox.stdout)?;
    ensure!(rawbox_json["is_ip_literal"] == true);
    ensure!(rawbox_json["effective"]["max_tier"] == "inspect");
    ensure!(
        rawbox_json["skipped_ip_groups"]
            .as_array()
            .is_some_and(|arr| arr.iter().any(|v| v == "dev")),
        "expected dev skipped for IP literal rawbox: {rawbox_json}"
    );

    // 5. Overlap host `eu-prd-db01` matches BOTH dev and prod -> strictest-wins yields prod.
    let overlap = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "explain",
            "eu-prd-db01",
            "--json",
        ])
        .output()?;
    ensure!(overlap.status.success());
    let overlap_json: Value = serde_json::from_slice(&overlap.stdout)?;
    ensure!(overlap_json["matched"].as_array().map(Vec::len) == Some(2));
    ensure!(overlap_json["effective"]["max_tier"] == "inspect");
    ensure!(overlap_json["effective"]["capabilities"]["exec"] == false);

    // 6. Lab host allows exec_sudo.
    let lab_sudo = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "--ssh-config",
            ssh_config_path.to_str().context("ssh config path")?,
            "auth",
            "can-i",
            "exec_sudo",
            "lab-01",
        ])
        .output()?;
    ensure!(
        lab_sudo.status.success(),
        "expected exec_sudo allowed on lab-01: {}",
        String::from_utf8_lossy(&lab_sudo.stdout)
    );
    Ok(())
}

#[test]
fn yolo_mode_authorizes_all_non_lab_tools_and_blocks_config_combination() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("operator.toml");
    std::fs::write(&config_path, "mode = \"workstation\"\n")?;

    // --yolo + --config must fail closed with exit code 2.
    let conflict = Command::new(estus_binary())
        .args([
            "--yolo",
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "explain",
            "anyhost",
        ])
        .output()?;
    ensure!(
        conflict.status.code() == Some(2),
        "expected exit 2 when combining --yolo and --config, got {:?}",
        conflict.status.code()
    );

    // Standalone --yolo allows exec_sudo and wildcard policy_required mutations like change_systemd_unit.
    let explain = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args(["--yolo", "auth", "explain", "10.0.0.5", "--json"])
        .output()?;
    ensure!(
        explain.status.success(),
        "auth explain under --yolo failed: {}",
        String::from_utf8_lossy(&explain.stderr)
    );
    let json: Value = serde_json::from_slice(&explain.stdout)?;
    ensure!(json["yolo"] == true);
    ensure!(json["allowed"] == true);
    ensure!(json["effective"]["sudo_mode"] == "same-account");
    let total = json["tools"]["total"].as_u64().unwrap_or(0);
    ensure!(
        total >= 90,
        "expected >= 90 permitted tools under --yolo, got {total}"
    );

    for tool in [
        "exec_sudo",
        "change_systemd_unit",
        "change_sysctl_runtime",
        "observe_network",
    ] {
        let out = Command::new(estus_binary())
            .env("ESTUS_CATALOG_ROOT", catalog_root())
            .args(["--yolo", "auth", "can-i", tool, "10.0.0.5"])
            .output()?;
        ensure!(
            out.status.success(),
            "expected {tool} allowed under --yolo: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
    Ok(())
}
