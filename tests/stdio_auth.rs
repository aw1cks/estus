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

#[test]
fn dropin_directories_load_profiles_groups_targets_with_provenance_and_reject_duplicates()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let profiles_dir = dir.path().join("profiles");
    let groups_dir = dir.path().join("groups");
    let targets_dir = dir.path().join("targets");
    std::fs::create_dir_all(&profiles_dir)?;
    std::fs::create_dir_all(&groups_dir)?;
    std::fs::create_dir_all(&targets_dir)?;

    // Single-entry profile drop-in: filename stem "prod-db" becomes profile name.
    std::fs::write(
        profiles_dir.join("prod-db.toml"),
        "extends = \"prod\"\nmax_tier = \"observe\"\n",
    )?;
    // Multi-entry profile drop-in also supported.
    std::fs::write(
        profiles_dir.join("extra.toml"),
        "[profiles.dev-safe]\nextends = \"dev\"\nrequire_preview = true\n",
    )?;
    // Single-entry group drop-in with filename-stem -> name -> profile sugar (`prod.toml`).
    std::fs::write(
        groups_dir.join("prod.toml"),
        "match_hosts = [\"*.prod.internal\"]\n",
    )?;
    // Single-entry group drop-in matching labels -> custom profile `prod-db`.
    std::fs::write(
        groups_dir.join("prod-databases.toml"),
        "profile = \"prod-db\"\nmatch_labels = { env = \"prod\", role = \"db\" }\n",
    )?;
    // Single-entry target drop-in: filename stem "eu-db-01" becomes logical target name.
    std::fs::write(
        targets_dir.join("eu-db-01.toml"),
        "ssh_host = \"eu-db-01.prod.internal\"\nlabels = { env = \"prod\", role = \"db\" }\n",
    )?;
    // Multi-entry target drop-in + non-toml file ignored cleanly.
    std::fs::write(
        targets_dir.join("dev.toml"),
        "[targets.dev-app-01]\nssh_host = \"dev-app-01.dev.internal\"\nprofile = \"dev-safe\"\n",
    )?;
    std::fs::write(targets_dir.join("README.txt"), "ignored\n")?;

    // Symlinked drop-in (Nix / Home Manager style) must work cleanly.
    let nix_target = dir.path().join("nix-store-lab.toml");
    std::fs::write(
        &nix_target,
        "ssh_host = \"lab-01.lab.internal\"\nprofile = \"lab\"\n",
    )?;
    std::os::unix::fs::symlink(&nix_target, targets_dir.join("lab-01.toml"))?;

    let config_path = dir.path().join("estus.toml");
    std::fs::write(
        &config_path,
        "\
mode = \"workstation\"
default_profile = \"deny\"
profiles_dir = \"profiles\"
groups_dir = \"groups\"
targets_dir = \"targets\"
",
    )?;

    // 1. eu-db-01 matches BOTH prod.toml (max_tier=inspect) and prod-databases.toml -> prod-db.toml (max_tier=observe).
    //    Strictest-wins yields observe + provenance for target, groups, and custom profile.
    let explain = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "explain",
            "eu-db-01",
            "--json",
        ])
        .output()?;
    ensure!(
        explain.status.success(),
        "auth explain eu-db-01 failed: {}",
        String::from_utf8_lossy(&explain.stderr)
    );
    let json: Value = serde_json::from_slice(&explain.stdout)?;
    ensure!(json["allowed"] == true);
    ensure!(json["mode"] == "configured");
    ensure!(json["target_source_file"] == "targets/eu-db-01.toml");
    ensure!(json["effective"]["max_tier"] == "observe");
    let matched = json["matched"].as_array().context("matched array")?;
    ensure!(matched.len() == 2, "expected 2 matched groups: {json}");
    ensure!(
        matched
            .iter()
            .any(|m| m["source_file"] == "groups/prod.toml" && m["profile"] == "prod")
    );
    ensure!(matched.iter().any(|m| {
        m["source_file"] == "groups/prod-databases.toml"
            && m["profile"] == "prod-db"
            && m["profile_source_file"] == "profiles/prod-db.toml"
    }));

    // 2. Human-readable output surfaces source file provenance cleanly.
    let explain_text = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "explain",
            "eu-db-01",
        ])
        .output()?;
    ensure!(explain_text.status.success());
    let text = String::from_utf8(explain_text.stdout)?;
    ensure!(
        text.contains("from targets/eu-db-01.toml")
            && text.contains("groups/prod-databases.toml")
            && text.contains("profiles/prod-db.toml"),
        "missing provenance in text output:\n{text}"
    );

    // 3. Symlinked target drop-in lab-01 works and grants lab sudo.
    let lab_sudo = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "can-i",
            "exec_sudo",
            "lab-01",
        ])
        .output()?;
    ensure!(lab_sudo.status.success());

    // 4. Unlisted host is denied because targets_dir closes open mode.
    let unlisted = Command::new(estus_binary())
        .env("ESTUS_CATALOG_ROOT", catalog_root())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "can-i",
            "observe_stat",
            "unlisted.lab.internal",
        ])
        .output()?;
    ensure!(!unlisted.status.success());

    // 5. Duplicate profile across drop-ins fails closed (exit 2).
    std::fs::write(
        profiles_dir.join("dup.toml"),
        "[profiles.prod-db]\nextends = \"dev\"\n",
    )?;
    let dup_err = Command::new(estus_binary())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "explain",
            "eu-db-01",
        ])
        .output()?;
    ensure!(dup_err.status.code() == Some(2));
    std::fs::remove_file(profiles_dir.join("dup.toml"))?;

    // 6. Drop-in attempting to set top-level `mode` or `capabilities` fails closed (exit 2).
    std::fs::write(groups_dir.join("bad.toml"), "mode = \"workstation\"\n")?;
    let bad_err = Command::new(estus_binary())
        .args([
            "--config",
            config_path.to_str().context("config path")?,
            "auth",
            "explain",
            "eu-db-01",
        ])
        .output()?;
    ensure!(bad_err.status.code() == Some(2));
    std::fs::remove_file(groups_dir.join("bad.toml"))?;

    // 7. Missing declared drop-in directory fails startup (never silently skipped).
    let missing_cfg = dir.path().join("missing.toml");
    std::fs::write(
        &missing_cfg,
        "mode = \"workstation\"\ngroups_dir = \"nope\"\n",
    )?;
    let missing_err = Command::new(estus_binary())
        .args([
            "--config",
            missing_cfg.to_str().context("missing path")?,
            "auth",
            "explain",
            "anyhost",
        ])
        .output()?;
    ensure!(missing_err.status.code() == Some(2));

    // 8. Empty targets_dir still closes open mode in workstation config.
    let empty_targets = dir.path().join("empty_targets");
    std::fs::create_dir_all(&empty_targets)?;
    let empty_cfg = dir.path().join("empty_targets.toml");
    std::fs::write(
        &empty_cfg,
        "mode = \"workstation\"\ntargets_dir = \"empty_targets\"\n",
    )?;
    let empty_check = Command::new(estus_binary())
        .args([
            "--config",
            empty_cfg.to_str().context("empty cfg")?,
            "auth",
            "can-i",
            "observe_stat",
            "anyhost",
        ])
        .output()?;
    ensure!(!empty_check.status.success());

    Ok(())
}
