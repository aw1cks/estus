#![cfg(unix)]

use estus::internal::catalog_assets as assets;

use assets::Catalog;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn canonical_catalog() -> Catalog {
    Catalog::load(Some(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"))).unwrap()
}

#[test]
fn canonical_catalog_exports_every_operational_definition_and_executor_asset() {
    let catalog = canonical_catalog();
    assert_eq!(
        catalog.manifest().presets["linux-health"],
        ["observe_cpu", "observe_memory", "observe_pressure"]
    );
    assert!(!catalog.manifest().tools.contains_key("app_config"));
    let output = tempfile::tempdir().unwrap();
    let output = output.path().canonicalize().unwrap();
    for name in catalog.manifest().tools.keys() {
        assert!(
            catalog.definition(name).unwrap()["tools"]
                .get(name.as_str())
                .is_some()
        );
        let destination = output.join(name);
        match &catalog.manifest().tools[name].executor {
            assets::Executor::NativePayload { .. } => {
                catalog.copy_assets(name, &destination).unwrap();
                assert!(destination.join("collector.py").is_file(), "{name}");
                assert_eq!(
                    fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                    0o700
                );
            }
            assets::Executor::AnsibleModule { .. } => {
                assert!(catalog.copy_assets(name, &destination).is_err(), "{name}");
            }
        }
    }
    assert!(catalog.definition("../observe_cpu").is_err());
    assert!(catalog.definition("not_a_tool").is_err());
    assert!(
        catalog
            .copy_assets("not_a_tool", &output.join("unknown"))
            .is_err()
    );
    assert!(!output.join("unknown").exists());
}

fn small_catalog(root: &Path) {
    let payload = root.join("payloads/observe_cpu");
    fs::create_dir_all(&payload).unwrap();
    fs::write(root.join("catalog.json"), r#"{"schema":3,"version":"1","presets":{"linux-health":["observe_cpu"]},"tools":{"observe_cpu":{"definition":"observe_cpu.toml","executor":{"kind":"native_payload","path":"payloads/observe_cpu"},"qualification":"site_policy_template","policy_required":false,"requires":["linux"]}}}"#).unwrap();
    fs::write(
        root.join("observe_cpu.toml"),
        "[tools.observe_cpu]\ndescription = 'fixture'\neffects = [\"read\"]\n",
    )
    .unwrap();
    fs::write(payload.join("collector.py"), "raise SystemExit(0)\n").unwrap();
    fs::write(payload.join("manifest.json"), "{}\n").unwrap();
}
#[test]
fn missing_unknown_and_legacy_qualification_formats_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    let path = root.join("catalog.json");
    let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for case in 0..3 {
        let mut manifest = original.clone();
        match case {
            0 => {
                manifest["tools"]["observe_cpu"]
                    .as_object_mut()
                    .unwrap()
                    .remove("qualification");
            }
            1 => {
                manifest["tools"]["observe_cpu"]["qualification"] =
                    serde_json::json!("PRIVATE_UNREVIEWED_QUALIFICATION")
            }
            2 => manifest["schema"] = serde_json::json!(1),
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(
            Catalog::load(Some(&root)).is_err(),
            "accepted qualification case {case}"
        );
    }
}

#[test]
fn payload_export_excludes_installer_generated_python_bytecode() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    let files = root.join("payloads/observe_cpu");
    let collector = files.join("collector.py");
    fs::write(
        &collector,
        "raise RuntimeError('must not execute during byte-compilation')\n",
    )
    .unwrap();
    let python = std::env::var_os("ESTUS_TEST_TARGET_PYTHON").unwrap_or_else(|| "python3".into());
    let compiled = Command::new(python).args(["-I", "-c",
        "import pathlib, py_compile, sys\nsource = pathlib.Path(sys.argv[1])\npy_compile.compile(str(source), doraise=True)\nfor suffix in ('pyc', 'pyo'):\n    py_compile.compile(str(source), cfile=str(source.with_suffix('.' + suffix)), doraise=True)\n",
    ]).arg(&collector).output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let cache = files.join("__pycache__");
    assert!(fs::read_dir(&cache).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "pyc")
    }));
    assert!(files.join("collector.pyc").is_file());
    assert!(files.join("collector.pyo").is_file());
    let output = root.join("export");
    Catalog::load(Some(&root))
        .unwrap()
        .copy_assets("observe_cpu", &output)
        .unwrap();
    assert_eq!(
        fs::read(output.join("collector.py")).unwrap(),
        fs::read(&collector).unwrap()
    );
    assert!(output.join("manifest.json").is_file());
    assert!(!output.join("__pycache__").exists());
    assert!(!output.join("collector.pyc").exists());
    assert!(!output.join("collector.pyo").exists());
}

#[test]
fn catalog_rejects_symlinks_clobber_traversal_and_oversized_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    let catalog = Catalog::load(Some(&root)).unwrap();
    let destination = root.join("existing");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("sentinel"), "keep").unwrap();
    assert!(catalog.copy_assets("observe_cpu", &destination).is_err());
    assert_eq!(
        fs::read_to_string(destination.join("sentinel")).unwrap(),
        "keep"
    );
    let task = root.join("payloads/observe_cpu/collector.py");
    fs::remove_file(&task).unwrap();
    symlink(root.join("observe_cpu.toml"), &task).unwrap();
    assert!(
        catalog
            .copy_assets("observe_cpu", &root.join("existing/../traversal"))
            .is_err()
    );
    assert!(!root.join("traversal").exists());
    assert!(
        catalog
            .copy_assets("observe_cpu", &root.join("symlink-copy"))
            .is_err()
    );
    assert!(!root.join("symlink-copy").exists());
    fs::remove_file(&task).unwrap();
    fs::write(&task, "raise SystemExit(0)\n").unwrap();
    fs::write(root.join("observe_cpu.toml"), vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(catalog.definition("observe_cpu").is_err());
    fs::remove_file(root.join("observe_cpu.toml")).unwrap();
    symlink(&task, root.join("observe_cpu.toml")).unwrap();
    assert!(catalog.definition("observe_cpu").is_err());
    let manifest = root.join("catalog.json");
    let original = fs::read_to_string(&manifest).unwrap();
    for replacement in [
        original.replace("observe_cpu.toml", "../observe_cpu.toml"),
        original.replace("\"schema\":3", "\"schema\":1"),
        original.replace("\"schema\":3", "\"schema\":3,\"schema\":3"),
        original.replace("\"schema\":3", "\"schema\":3,\"unexpected\":true"),
    ] {
        fs::write(&manifest, replacement).unwrap();
        assert!(Catalog::load(Some(&root)).is_err());
    }
    fs::write(&manifest, vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(Catalog::load(Some(&root)).is_err());
    assert!(Catalog::load(Some(&root.join("missing"))).is_err());
}

fn installed_command(binary: &Path, working: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("HOME", working)
        .env("ESTUS_CATALOG_ROOT", working.join("untrusted-missing"))
        .current_dir(working)
        .output()
        .unwrap()
}

#[test]
#[ignore = "requires ESTUS_TEST_BINARY pointing to an installed native wrapper or wheel launcher; no network or automation runtime"]
fn installed_catalog_lists_and_exports_offline_without_checkout_or_runtime() {
    let binary =
        PathBuf::from(std::env::var_os("ESTUS_TEST_BINARY").expect("set ESTUS_TEST_BINARY"));
    assert!(binary.is_absolute());
    let work = tempfile::tempdir().unwrap();
    let work = work.path().canonicalize().unwrap();
    // Both launchers must replace an inherited untrusted asset path.
    let listed = installed_command(&binary, &work, &["catalog", "list", "--json"]);
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listing["schema"], 3);
    assert_eq!(listing["version"], "8");
    let canonical: Value = serde_json::from_slice(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/catalog.json")).unwrap(),
    )
    .unwrap();
    let tools = listing["tools"].as_array().unwrap();
    assert_eq!(tools.len(), canonical["tools"].as_object().unwrap().len());
    let mut names = std::collections::BTreeSet::new();
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        assert!(names.insert(name), "duplicate installed template: {name}");
        assert!(canonical["tools"].get(name).is_some(), "{name}");
        assert!(
            matches!(
                tool["qualification"].as_str(),
                Some("site_policy_template" | "laboratory_only")
            ),
            "{name}: missing or unsupported qualification"
        );
        assert!(tool["policy_required"].is_boolean(), "{name}");
        assert!(tool["requires"].is_array(), "{name}");
        for field in ["qualification", "policy_required", "requires"] {
            assert_eq!(
                tool[field], canonical["tools"][name][field],
                "{name}: {field}"
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
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        assert_eq!(tool["qualification"], "laboratory_only", "{name}");
        assert!(
            tool["requires"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(prerequisite)),
            "{name}: missing {prerequisite}"
        );
    }
    assert_eq!(
        listing["presets"]["linux-health"],
        serde_json::json!(["observe_cpu", "observe_memory", "observe_pressure"])
    );
    let output = work.join("export");
    let exported = installed_command(
        &binary,
        &work,
        &[
            "catalog",
            "export",
            "--preset",
            "linux-health",
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(report["enabled"], false);
    assert_eq!(
        report["tools"],
        serde_json::json!(["observe_cpu", "observe_memory", "observe_pressure"])
    );
    assert_selection_metadata(
        &output,
        &canonical,
        &["observe_cpu", "observe_memory", "observe_pressure"],
    );
    let definitions: toml::Table = fs::read_to_string(output.join("tools.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions["tools"].as_table().unwrap().len(), 3);
    for name in ["observe_cpu", "observe_memory", "observe_pressure"] {
        assert!(
            output
                .join(format!("payloads/{name}/manifest.json"))
                .is_file()
        );
        assert!(
            output
                .join(format!("payloads/{name}/collector.py"))
                .is_file()
        );
        assert_eq!(
            definitions["tools"][name]["execution"]["source"]
                .as_str()
                .unwrap(),
            output
                .join(format!("payloads/{name}/collector.py"))
                .to_str()
                .unwrap()
        );
    }
    // Export writes reviewable inputs only, never generated policy state.
    assert!(!output.join("overlays").exists());
    assert!(!output.join("snapshots").exists());
    let laboratory = work.join("laboratory");
    let exported = installed_command(
        &binary,
        &work,
        &[
            "catalog",
            "export",
            "--tool",
            "observe_nic_eee",
            "--tool",
            "change_nic_eee",
            "--tool",
            "observe_nic_transceiver",
            "--output",
            laboratory.to_str().unwrap(),
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(report["enabled"], false);
    assert_selection_metadata(
        &laboratory,
        &canonical,
        &[
            "observe_nic_eee",
            "change_nic_eee",
            "observe_nic_transceiver",
        ],
    );
    let site = work.join("site.toml");
    fs::write(&site, "").unwrap();
    let inspected = installed_command(
        &binary,
        &work,
        &[
            "--ssh",
            binary.to_str().unwrap(),
            "catalog",
            "inspect",
            "--site",
            site.to_str().unwrap(),
        ],
    );
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let inspection: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(inspection["qualification_scope"], "catalog_template");
    assert_eq!(inspection["tools"], serde_json::json!([]));
    for field in [
        "global_native_execution",
        "global_native_file_read",
        "global_native_file_write",
    ] {
        assert_eq!(inspection[field], false, "{field}");
    }
    assert!(
        !installed_command(
            &binary,
            &work,
            &[
                "catalog",
                "export",
                "--tool",
                "observe_cpu",
                "--output",
                output.to_str().unwrap()
            ]
        )
        .status
        .success()
    );
    assert!(
        !installed_command(
            &binary,
            &work,
            &["catalog", "--root", "/nonexistent", "list", "--json"]
        )
        .status
        .success()
    );
    assert!(
        !installed_command(
            &binary,
            &work,
            &[
                "catalog",
                "export",
                "--tool",
                "../observe_cpu",
                "--output",
                work.join("bad").to_str().unwrap()
            ]
        )
        .status
        .success()
    );
}

fn assert_selection_metadata(output: &Path, canonical: &Value, selected: &[&str]) {
    let path = output.join("catalog-selection.json");
    let selection: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(selection["schema"], 3);
    assert_eq!(selection["version"], "8");
    assert_eq!(selection["scope"], "catalog_templates");
    assert_eq!(selection.as_object().unwrap().len(), 4);
    assert_eq!(
        selection["tools"].as_object().unwrap().len(),
        selected.len()
    );
    for &name in selected {
        assert_eq!(
            selection["tools"][name],
            serde_json::json!({
                "executor": canonical["tools"][name]["executor"],
                "qualification": canonical["tools"][name]["qualification"],
                "policy_required": canonical["tools"][name]["policy_required"],
                "requires": canonical["tools"][name]["requires"],
            }),
            "{name}: exported qualification metadata diverged"
        );
    }
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn all_catalog_tools_satisfy_risk_prefix_effects_invariant_and_mismatches_fail() {
    let catalog = canonical_catalog();
    assert_eq!(catalog.manifest().tools.len(), 120);
    for name in catalog.manifest().tools.keys() {
        let definition = catalog.definition(name).unwrap();
        let effects = definition["tools"][name]["effects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(!effects.is_empty(), "{name}: empty effects");
        if name.starts_with("observe_") {
            assert_eq!(effects, ["read"], "{name}: observe_* must be read-only");
        } else if name.starts_with("inspect_") {
            assert!(
                effects
                    .iter()
                    .all(|e| matches!(*e, "read" | "sensitive_read" | "probe"))
                    && effects
                        .iter()
                        .any(|e| matches!(*e, "sensitive_read" | "probe")),
                "{name}: inspect_* must declare sensitive_read or probe without mutation: {effects:?}"
            );
        } else if name.starts_with("preview_") {
            assert!(
                effects
                    .iter()
                    .all(|e| matches!(*e, "read" | "sensitive_read" | "probe")),
                "{name}: preview_* must not declare mutation: {effects:?}"
            );
        } else if name.starts_with("change_") {
            assert!(
                effects.iter().any(|e| matches!(
                    *e,
                    "runtime_write" | "persistent_write" | "availability" | "unknown"
                )),
                "{name}: change_* must declare a mutating or unknown effect: {effects:?}"
            );
        } else {
            panic!("unexpected catalog tool risk prefix: {name}");
        }
    }

    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    fs::write(
        root.join("observe_cpu.toml"),
        "[tools.observe_cpu]\ndescription = 'fixture'\neffects = [\"read\", \"sensitive_read\"]\n",
    )
    .unwrap();
    assert!(Catalog::load(Some(&root)).is_err());

    let bad_prefix = tempfile::tempdir().unwrap();
    let bad_root = bad_prefix.path().canonicalize().unwrap();
    fs::create_dir_all(bad_root.join("payloads/legacy_tool")).unwrap();
    fs::write(
        bad_root.join("catalog.json"),
        r#"{"schema":3,"version":"1","presets":{},"tools":{"legacy_tool":{"definition":"legacy_tool.toml","executor":{"kind":"native_payload","path":"payloads/legacy_tool"},"qualification":"site_policy_template","policy_required":false,"requires":["linux"]}}}"#,
    )
    .unwrap();
    fs::write(
        bad_root.join("legacy_tool.toml"),
        "[tools.legacy_tool]\ndescription = 'fixture'\neffects = [\"read\"]\n",
    )
    .unwrap();
    fs::write(bad_root.join("payloads/legacy_tool/collector.py"), "").unwrap();
    fs::write(bad_root.join("payloads/legacy_tool/manifest.json"), "{}").unwrap();
    assert!(Catalog::load(Some(&bad_root)).is_err());
}

#[test]
fn all_payload_manifests_pin_modules_executable_candidates_and_python_min() {
    use sha2::{Digest, Sha256};
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
    let catalog = canonical_catalog();
    let py310 = [
        "observe_nic_eee",
        "change_nic_eee",
        "observe_nic_fec",
        "observe_nic_transceiver",
    ];
    for (name, template) in &catalog.manifest().tools {
        let assets::Executor::NativePayload { path } = &template.executor else {
            continue;
        };
        let dir = root.join(path);
        let source = fs::read(dir.join("collector.py")).unwrap();
        let manifest: Value =
            serde_json::from_slice(&fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["source_sha256"].as_str().unwrap(),
            hex::encode(Sha256::digest(&source)),
            "{name}: source_sha256 drift"
        );
        let req = &manifest["requirements"];
        let expected_py = if py310.contains(&name.as_str()) {
            serde_json::json!([3, 10])
        } else {
            serde_json::json!([3, 8])
        };
        assert_eq!(req["python_min"], expected_py, "{name}: python_min");
        assert_eq!(
            req["executables"],
            serde_json::json!([]),
            "{name}: legacy PATH executables must be empty"
        );
        let modules = req["modules"].as_array().unwrap();
        assert!(!modules.is_empty(), "{name}: missing modules");
        if let Some(cands) = req["executable_candidates"].as_object() {
            for (key, candidates) in cands {
                assert!(
                    !candidates.as_array().unwrap().is_empty(),
                    "{name}: {key} has no executable candidates"
                );
            }
        }
    }
}

#[test]
fn payload_export_accepts_subdirectories_and_rejects_unexpected_asset_types() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    let subdir = root.join("payloads/observe_cpu/support");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("helper.py"), "VALUE = 1\n").unwrap();
    assert!(
        Catalog::load(Some(&root))
            .unwrap()
            .copy_assets("observe_cpu", &root.join("out-sub"))
            .is_ok()
    );
    assert!(root.join("out-sub/support/helper.py").is_file());
    fs::remove_dir_all(&subdir).unwrap();

    let bad_ext = root.join("payloads/observe_cpu/extra.sh");
    fs::write(&bad_ext, "#!/bin/sh\n").unwrap();
    assert!(
        Catalog::load(Some(&root))
            .unwrap()
            .copy_assets("observe_cpu", &root.join("out-ext"))
            .is_err()
    );
    fs::remove_file(&bad_ext).unwrap();
    assert!(
        Catalog::load(Some(&root))
            .unwrap()
            .copy_assets("observe_cpu", &root.join("out-clean"))
            .is_ok()
    );
}

#[test]
fn sre_skill_lists_every_published_builtin_and_catalog_tool() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let catalog = Catalog::load(Some(&root.join("catalog"))).unwrap();
    let skill = fs::read_to_string(root.join("skills/estus-sre/SKILL.md")).unwrap();
    let mut blocks = skill.split("```json\n").skip(1);
    let allow_json = blocks.next().unwrap().split("```").next().unwrap();
    let ask_json = blocks.next().unwrap().split("```").next().unwrap();
    let allow: Vec<String> = serde_json::from_str(allow_json).unwrap();
    let ask: Vec<String> = serde_json::from_str(ask_json).unwrap();
    assert!(allow.iter().all(|name| name.starts_with("observe_")));
    assert!(ask.iter().all(|name| !name.starts_with("observe_")));

    let mut actual: std::collections::BTreeSet<String> = allow.into_iter().chain(ask).collect();
    let builtins = [
        "observe_targets",
        "observe_stat",
        "inspect_file",
        "inspect_directory",
        "inspect_output",
        "change_file_write",
        "change_file_replace",
        "change_mkdir",
        "change_rename",
        "change_file_remove",
        "change_directory_remove",
        "change_target_quarantine_clear",
        "exec_command",
        "exec_argv",
        "exec_sudo",
    ];
    let mut expected: std::collections::BTreeSet<String> =
        builtins.into_iter().map(str::to_owned).collect();
    expected.extend(catalog.manifest().tools.keys().cloned());
    assert_eq!(actual, expected);
    actual.clear();
}

#[test]
fn python_sources_pass_ast_and_dangerous_call_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            r#"
import ast, pathlib, sys
root = pathlib.Path(sys.argv[1])
guarded = [root / "src/native_payload/prestate.py", root / "python/estus/__init__.py", root / "setup.py"]
guarded.extend(sorted((root / "catalog/payloads").glob("*/collector.py")))
for path in guarded:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                raise SystemExit(f"forbidden {node.func.id}() in {path}")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    raise SystemExit(f"forbidden shell=True in {path}")
ast.parse((root / "src/native_payload/bootstrap.py").read_text(encoding="utf-8"))
"#,
        ])
        .arg(root)
        .status()
        .unwrap();
    assert!(status.success());
}
