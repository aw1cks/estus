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
        .env("ESTUS_ANSIBLE_RUNTIME", "/missing/private-runtime")
        .output()?)
}

#[test]
fn site_failures_preserve_safe_causes_locations_and_output_cleanup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let exported = root.path().join("exported");
    let output = invoke(&[
        "export".as_ref(),
        "--tool".as_ref(),
        "pressure_get".as_ref(),
        "--output".as_ref(),
        exported.as_os_str(),
    ])?;
    ensure!(output.status.success());
    let site = root.path().join("DO_NOT_REFLECT-site.toml");
    for (index, (text, code, phase, field)) in [
        (
            "[ssh]\nDO_NOT_REFLECT_KEY='DO_NOT_REFLECT_VALUE'",
            "invalid_config",
            "config_validation",
            "ssh",
        ),
        (
            "# DO_NOT_REFLECT_SOURCE\n[ssh]\nexecutable = @",
            "invalid_toml",
            "config_parse",
            "config",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        std::fs::write(&site, text)?;
        for prepare in [false, true] {
            let destination = root.path().join(format!("prepared-{index}"));
            let mut args: Vec<&std::ffi::OsStr> = vec![
                if prepare {
                    "prepare".as_ref()
                } else {
                    "inspect".as_ref()
                },
                "--site".as_ref(),
                site.as_os_str(),
            ];
            let definitions = exported.join("tools.toml");
            if prepare {
                args.extend([
                    "--definitions".as_ref(),
                    definitions.as_os_str(),
                    "--output".as_ref(),
                    destination.as_os_str(),
                ]);
            }
            let output = invoke(&args)?;
            ensure!(
                output.status.code() == Some(2)
                    && output.stdout.is_empty()
                    && !destination.exists()
            );
            let diagnostic: serde_json::Value = serde_json::from_slice(&output.stderr)?;
            ensure!(
                diagnostic["code"] == code
                    && diagnostic["phase"] == phase
                    && diagnostic["schema_path"] == field,
                "catalog discarded safe cause context: {diagnostic}"
            );
            if code == "invalid_toml" {
                ensure!(
                    diagnostic["location"]["line"] == 3 && diagnostic["location"]["column"] == 14
                );
            }
            ensure!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_REFLECT"));
        }
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
    ensure!(data["schema"] == 3 && data["version"] == "7");
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
    for name in [
        "nic_eee_get",
        "nic_eee_set",
        "nic_transceiver_get",
        "nic_fec_get",
        "nic_fec_set",
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
    let selection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(destination.join("catalog-selection.json"))?)?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(assets().join("catalog.json"))?)?;
    ensure!(
        selection["schema"] == 3
            && selection["version"] == manifest["version"]
            && selection["scope"] == "catalog_templates"
    );
    for name in ["cpu_stats", "memory_stats", "pressure_get"] {
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
        definitions.get("automation").is_none() && definitions.get("enabled_tools").is_none(),
        "export generated authority or activation policy"
    );
    let pressure = &definitions["tools"]["pressure_get"];
    let source = Path::new(
        pressure["execution"]["source"]
            .as_str()
            .context("payload source")?,
    );
    ensure!(
        source.is_absolute() && source.is_file(),
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
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(assets().join("catalog.json"))?)?;
    let pin = serde_json::to_string(&manifest["version"])?;
    let mut text = format!(
        "tool_presets=['linux-health']\nenabled_tools=['custom_action','custom_sudo']\n[catalog]\nversion={}\n[targets.one]\nssh_host='private-alias'\n[targets.one.sudo]\nmode='same-account'\nusers=['root']\nprograms=['/usr/bin/id']\n",
        pin
    );
    for name in [
        "cpu_stats",
        "memory_stats",
        "pressure_get",
        "custom_action",
        "custom_sudo",
    ] {
        let authority = if name == "custom_sudo" {
            "{sudo='root'}"
        } else {
            "'ordinary'"
        };
        text.push_str(&format!(
            r#"
[tools.{name}]
description="Explicit operator binding"
revision="1"
targets=["one"]
authority={authority}
effects=["read"]
execution={{kind="native_argv",program="/usr/bin/id",argv=["--","root"]}}
input_schema={{type="object",properties={{}},required=[],additionalProperties=false}}
result={{kind="command"}}
"#
        ));
    }
    for (profile, execution, file_read, file_write, bindings) in [
        (None, false, false, false, true),
        (Some("baseline"), true, true, true, true),
        (Some("read-only-files"), false, true, false, false),
        (Some("files-only"), false, true, true, false),
    ] {
        let selected = profile.map_or_else(
            || text.clone(),
            |profile| format!("profile='{profile}'\n{text}"),
        );
        std::fs::write(&site, selected)?;
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
        let public = String::from_utf8(output.stdout.clone())?;
        for private in [
            "private-alias",
            "/usr/bin/id",
            site.to_str().context("site path")?,
        ] {
            ensure!(
                !public.contains(private),
                "inspection disclosed private binding data"
            );
        }
        ensure!(
            report["deployment_boundary"]
                == serde_json::json!({
                    "mcp": "request_policy",
                    "same_identity_arbitrary_execution": "outside_restriction",
                    "service_account_separation": "operator_managed_not_observed",
                    "sandbox": "not_provided_by_estus"
                })
        );
        ensure!(
            report["global_native_execution"] == execution
                && report["global_native_file_read"] == file_read
                && report["global_native_file_write"] == file_write,
            "inspection disagrees with global exposure for {profile:?}"
        );
        ensure!(
            report["tools"]
                .as_array()
                .context("resolved tools")?
                .iter()
                .all(|v| v["enabled"] == bindings && v["targets"][0]["permitted"] == bindings),
            "inspect did not resolve named authority for {profile:?}"
        );
        ensure!(report["qualification_scope"] == "catalog_template");
        for tool in report["tools"].as_array().context("inspected tools")? {
            ensure!(tool["executor"] == "native_argv");
            ensure!(tool["execution_location"] == "remote");
            ensure!(tool["trusted_controller_code"] == false);
            ensure!(
                tool["restriction_boundary"]
                    == serde_json::json!({
                        "mcp": "request_policy", "os": "service_account_and_remote_identity",
                        "service_account_separation": "operator_managed_not_observed",
                        "sandbox": "not_provided_by_estus"
                    })
            );
            let authority = if tool["name"] == "custom_sudo" {
                serde_json::json!({"sudo":"root"})
            } else {
                serde_json::json!("ordinary")
            };
            ensure!(
                tool["authority"] == authority,
                "inspection changed fixed authority"
            );
            if tool["name"] == "custom_action" || tool["name"] == "custom_sudo" {
                ensure!(
                    tool["catalog_template"] == serde_json::json!({"qualification":"unqualified"})
                );
            } else {
                let name = tool["name"].as_str().context("tool name")?;
                for field in ["qualification", "policy_required", "requires"] {
                    ensure!(
                        tool["catalog_template"][field] == manifest["tools"][name][field],
                        "inspection lost catalog template metadata"
                    );
                }
            }
        }
    }
    let outdated = text.replacen(&format!("\nversion={pin}\n"), "\nversion=\"1\"\n", 1);
    std::fs::write(&site, outdated)?;
    let rejected = Command::new(test_binary())
        .args(["catalog", "--root"])
        .arg(assets())
        .args(["inspect", "--site"])
        .arg(&site)
        .env_remove("ESTUS_CATALOG_ROOT")
        .env_remove("ESTUS_CONFIG")
        .env("ESTUS_SSH", env!("CARGO_BIN_EXE_estus"))
        .output()?;
    ensure!(
        !rejected.status.success(),
        "a previous catalog version pin silently adopted the new inventory"
    );
    Ok(())
}

#[test]
fn global_catalog_options_are_honored_or_rejected_without_reflecting_values() -> Result<()> {
    let root = tempfile::tempdir()?;
    let binary = std::fs::canonicalize(test_binary())?;
    let launch = root.path().join("launch");
    let policy = root.path().join("policy");
    std::fs::create_dir(&launch)?;
    std::fs::create_dir(&policy)?;
    std::os::unix::fs::symlink(&binary, launch.join("cli-ssh"))?;
    std::fs::write(launch.join("cli.conf"), "# selected CLI configuration\n")?;
    let site = policy.join("site.toml");
    std::fs::write(
        &site,
        "[ssh]\nexecutable='missing-site-ssh'\nconfig_file='missing-site.conf'\n[targets]\n",
    )?;
    let base = || {
        let mut command = Command::new(&binary);
        command
            .current_dir(&launch)
            .env("ESTUS_CONFIG", "/missing/ambient-config")
            .env("ESTUS_SSH", "/missing/ambient-ssh")
            .env("ESTUS_SSH_CONFIG", "/missing/ambient-ssh-config");
        command
    };
    // Both placements retain CLI provenance and resolve against launch cwd.
    for trailing in [false, true] {
        let mut command = base();
        if !trailing {
            command.args(["--ssh", "cli-ssh", "--ssh-config", "cli.conf"]);
        }
        command
            .args(["catalog", "--root"])
            .arg(assets())
            .args(["inspect", "--site"])
            .arg(&site);
        if trailing {
            command.args(["--ssh", "cli-ssh", "--ssh-config", "cli.conf"]);
        }
        let output = command.output()?;
        ensure!(
            output.status.success(),
            "CLI overrides did not beat environment/site: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure!(report["tools"] == serde_json::json!([]));
    }
    for invalid_config in [false, true] {
        let output = base()
            .args(["catalog", "--root"])
            .arg(assets())
            .args(["inspect", "--site"])
            .arg(&site)
            .args([
                "--ssh",
                if invalid_config {
                    "cli-ssh"
                } else {
                    "DO_NOT_REFLECT_INVALID_SSH"
                },
                "--ssh-config",
                if invalid_config {
                    "DO_NOT_REFLECT_INVALID_CONFIG"
                } else {
                    "cli.conf"
                },
            ])
            .output()?;
        ensure!(
            !output.status.success() && output.stdout.is_empty(),
            "invalid explicit override fell back"
        );
        ensure!(
            !output.stderr.is_empty(),
            "invalid override produced no diagnostic"
        );
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_REFLECT"));
    }
    for trailing in [false, true] {
        let mut command = base();
        if !trailing {
            command.args(["--config", "DO_NOT_REFLECT_CONFLICT"]);
        }
        command
            .args(["catalog", "--root"])
            .arg(assets())
            .args(["inspect", "--site"])
            .arg(&site);
        if trailing {
            command.args(["--config", "DO_NOT_REFLECT_CONFLICT"]);
        }
        let output = command.output()?;
        ensure!(!output.status.success() && output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr)?;
        ensure!(error["error_code"] == "catalog_config_site_conflict");
        ensure!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_REFLECT"));
    }
    for export in [false, true] {
        for option in ["--config", "--ssh", "--ssh-config"] {
            let destination = root.path().join("must-not-export");
            let mut command = base();
            command
                .args([option, "DO_NOT_REFLECT_OFFLINE"])
                .args(["catalog", "--root"])
                .arg(assets());
            if export {
                command
                    .args(["export", "--tool", "pressure_get", "--output"])
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
    }
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

#[test]
#[ignore = "requires installed ESTUS_TEST_BINARY and shipped ESTUS_TEST_ANSIBLE_RUNTIME; no SSH"]
fn real_prepare_shares_one_reviewed_bundle_and_pins_all_role_paths() -> Result<()> {
    let runtime = std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
        .context("set ESTUS_TEST_ANSIBLE_RUNTIME to the pinned installed runtime")?;
    let root = tempfile::tempdir()?;
    let export = root.path().join("export");
    let output = invoke(&[
        "export".as_ref(),
        "--tool".as_ref(),
        "host_summary".as_ref(),
        "--tool".as_ref(),
        "hardware_system_get".as_ref(),
        "--output".as_ref(),
        export.as_os_str(),
    ])?;
    ensure!(output.status.success(), "fixture export failed");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&workspace)?;
    let site = root.path().join("site.toml");
    let launch = root.path().canonicalize()?;
    let binary = std::fs::canonicalize(test_binary())?;
    std::os::unix::fs::symlink(&binary, launch.join("cli-ssh"))?;
    std::fs::write(
        launch.join("cli.conf"),
        "# prepared effective configuration\n",
    )?;
    std::fs::write(
        &site,
        format!(
            "profile='actions-only'\n[ssh]\nexecutable='missing-site-ssh'\nconfig_file='missing-site.conf'\n[targets.server]\nssh_host='private-alias'\n[automation]\nruntime={runtime:?}\nworkspace_root={workspace:?}\n[automation.targets.server]\ndestination='private-alias'\npython='/usr/bin/python3'\n"
        ),
    )?;
    let valid_site = root.path().join("valid-site.toml");
    let mut valid_document: toml::Value = toml::from_str(&std::fs::read_to_string(&site)?)?;
    valid_document["ssh"]["executable"] = binary.to_str().context("binary UTF8")?.into();
    valid_document["ssh"]["config_file"] = launch
        .join("cli.conf")
        .to_str()
        .context("config UTF8")?
        .into();
    std::fs::write(&valid_site, toml::to_string(&valid_document)?)?;
    let missing_site = root.path().join("DO_NOT_REFLECT-missing-runtime.toml");
    let mut missing_document = valid_document.clone();
    missing_document["automation"]["runtime"] = "/DO_NOT_REFLECT_MISSING_RUNTIME".into();
    std::fs::write(&missing_site, toml::to_string(&missing_document)?)?;
    let failed_output = root.path().join("failed-runtime");
    let rejected = Command::new(&binary)
        .args(["catalog", "--root"])
        .arg(assets())
        .args(["prepare", "--site"])
        .arg(&missing_site)
        .arg("--definitions")
        .arg(export.join("tools.toml"))
        .arg("--output")
        .arg(&failed_output)
        .env_remove("ESTUS_CONFIG")
        .env_remove("ESTUS_SSH")
        .env_remove("ESTUS_SSH_CONFIG")
        .output()?;
    ensure!(
        rejected.status.code() == Some(2) && rejected.stdout.is_empty() && !failed_output.exists()
    );
    let diagnostic: serde_json::Value = serde_json::from_slice(&rejected.stderr)?;
    ensure!(
        diagnostic["code"] == "runtime_unavailable" && diagnostic["phase"] == "runtime_import",
        "catalog swallowed the role authoring failure: {diagnostic}"
    );
    ensure!(!String::from_utf8_lossy(&rejected.stderr).contains("DO_NOT_REFLECT"));
    for invalid_config in [false, true] {
        let rejected_output = root.path().join(if invalid_config {
            "bad-config"
        } else {
            "bad-executable"
        });
        let rejected = Command::new(&binary)
            .current_dir(&launch)
            .args(["catalog", "--root"])
            .arg(assets())
            .args(["prepare", "--site"])
            .arg(&valid_site)
            .arg("--definitions")
            .arg(export.join("tools.toml"))
            .arg("--output")
            .arg(&rejected_output)
            .args([
                "--ssh",
                if invalid_config {
                    "cli-ssh"
                } else {
                    "DO_NOT_REFLECT_BAD_PREPARE_SSH"
                },
                "--ssh-config",
                if invalid_config {
                    "DO_NOT_REFLECT_BAD_PREPARE_CONFIG"
                } else {
                    "cli.conf"
                },
            ])
            .env_remove("ESTUS_CONFIG")
            .env("ESTUS_SSH", &binary)
            .env("ESTUS_SSH_CONFIG", launch.join("cli.conf"))
            .output()?;
        ensure!(
            !rejected.status.success() && !rejected_output.exists(),
            "prepare ignored an invalid explicit override or retained partial output"
        );
        ensure!(!String::from_utf8_lossy(&rejected.stderr).contains("DO_NOT_REFLECT"));
    }
    let prepared = root.path().join("prepared");
    let output = Command::new(&binary)
        .current_dir(&launch)
        .args(["catalog", "--root"])
        .arg(assets())
        .args(["prepare", "--site"])
        .arg(&site)
        .arg("--definitions")
        .arg(export.join("tools.toml"))
        .arg("--output")
        .arg(&prepared)
        .args(["--ssh", "cli-ssh", "--ssh-config", "cli.conf"])
        .env("ESTUS_CONFIG", "/missing/ambient-config")
        .env("ESTUS_SSH_CONFIG", "/missing/ambient-ssh-config")
        .env("ESTUS_SSH", "/missing/ambient-ssh")
        .output()?;
    ensure!(
        output.status.success(),
        "real catalog preparation failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let config: toml::Value =
        toml::from_str(&std::fs::read_to_string(prepared.join("estus.toml"))?)?;
    ensure!(
        config["ssh"]["executable"].as_str() == launch.join("cli-ssh").to_str()
            && config["ssh"]["config_file"].as_str() == launch.join("cli.conf").to_str(),
        "prepared output lost the effective CLI selection or used the wrong path base"
    );
    let inspected = Command::new(&binary)
        .current_dir(&export)
        .args(["catalog", "inspect", "--site"])
        .arg(prepared.join("estus.toml"))
        .env_remove("ESTUS_CONFIG")
        .env_remove("ESTUS_SSH")
        .env_remove("ESTUS_SSH_CONFIG")
        .output()?;
    ensure!(
        inspected.status.success(),
        "prepared SSH selection did not survive a different launch cwd: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let mut approved_root = None;
    for name in ["host_summary", "hardware_system_get"] {
        let snapshot: serde_json::Value = serde_json::from_slice(&std::fs::read(
            prepared.join(format!("snapshots/{name}.json")),
        )?)?;
        ensure!(snapshot["schema"] == 2);
        let bundle =
            std::path::PathBuf::from(snapshot["bundle_root"].as_str().context("bundle root")?);
        if let Some(root) = &approved_root {
            ensure!(
                root == &bundle,
                "catalog preparation duplicated the shared role parent"
            );
        }
        approved_root = Some(bundle.clone());
        ensure!(
            config["tools"][name]["execution"]["role_path"].as_str() == bundle.join(name).to_str()
        );
        ensure!(bundle.join("host_summary/tasks/main.yml").is_file());
        ensure!(bundle.join("hardware_system_get/tasks/main.yml").is_file());
    }
    let bundles = std::fs::read_dir(prepared.join("snapshots"))?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "roles"))
        .count();
    ensure!(
        bundles == 1,
        "catalog preparation copied its role parent more than once"
    );
    Ok(())
}
