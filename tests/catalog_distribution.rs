#![cfg(unix)]

#[allow(dead_code)]
#[path = "../src/catalog_assets.rs"]
mod catalog_assets;

use catalog_assets::Catalog;
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn canonical_catalog() -> Catalog {
    Catalog::load(Some(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"),
    ))
    .unwrap()
}

#[test]
fn canonical_catalog_exports_every_operational_definition_and_role() {
    let catalog = canonical_catalog();
    assert_eq!(
        catalog.manifest().presets["linux-health"],
        ["cpu_stats", "memory_stats", "pressure_get"]
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
        catalog.copy_role(name, &destination).unwrap();
        assert!(destination.join("tasks/main.yml").is_file(), "{name}");
        assert_eq!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    assert!(catalog.definition("../cpu_stats").is_err());
    assert!(catalog.definition("not_a_tool").is_err());
    assert!(
        catalog
            .copy_role("not_a_tool", &output.join("unknown"))
            .is_err()
    );
    assert!(!output.join("unknown").exists());
}

fn small_catalog(root: &Path) {
    fs::create_dir_all(root.join("roles/cpu_stats/tasks")).unwrap();
    fs::write(root.join("catalog.json"), r#"{"schema":2,"version":"1","presets":{"linux-health":["cpu_stats"]},"tools":{"cpu_stats":{"definition":"cpu_stats.toml","role":"roles/cpu_stats","qualification":"site_policy_template","policy_required":false,"requires":["linux"]}}}"#).unwrap();
    fs::write(
        root.join("cpu_stats.toml"),
        "[tools.cpu_stats]\ndescription = 'fixture'\n",
    )
    .unwrap();
    fs::write(root.join("roles/cpu_stats/tasks/main.yml"), "---\n[]\n").unwrap();
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
                manifest["tools"]["cpu_stats"]
                    .as_object_mut()
                    .unwrap()
                    .remove("qualification");
            }
            1 => {
                manifest["tools"]["cpu_stats"]["qualification"] =
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
fn role_export_excludes_installer_generated_python_bytecode() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    small_catalog(&root);
    let files = root.join("roles/cpu_stats/files");
    fs::create_dir(&files).unwrap();
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
        .copy_role("cpu_stats", &output)
        .unwrap();
    assert_eq!(
        fs::read(output.join("files/collector.py")).unwrap(),
        fs::read(&collector).unwrap()
    );
    assert!(!output.join("files/__pycache__").exists());
    assert!(!output.join("files/collector.pyc").exists());
    assert!(!output.join("files/collector.pyo").exists());
    assert!(output.join("tasks/main.yml").is_file());
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
    assert!(catalog.copy_role("cpu_stats", &destination).is_err());
    assert_eq!(
        fs::read_to_string(destination.join("sentinel")).unwrap(),
        "keep"
    );
    let task = root.join("roles/cpu_stats/tasks/main.yml");
    fs::remove_file(&task).unwrap();
    symlink(root.join("cpu_stats.toml"), &task).unwrap();
    assert!(
        catalog
            .copy_role("cpu_stats", &root.join("existing/../traversal"))
            .is_err()
    );
    assert!(!root.join("traversal").exists());
    assert!(
        catalog
            .copy_role("cpu_stats", &root.join("symlink-copy"))
            .is_err()
    );
    assert!(!root.join("symlink-copy").exists());
    fs::remove_file(&task).unwrap();
    fs::write(&task, "---\n[]\n").unwrap();
    fs::write(root.join("cpu_stats.toml"), vec![b' '; 256 * 1024 + 1]).unwrap();
    assert!(catalog.definition("cpu_stats").is_err());
    fs::remove_file(root.join("cpu_stats.toml")).unwrap();
    symlink(&task, root.join("cpu_stats.toml")).unwrap();
    assert!(catalog.definition("cpu_stats").is_err());
    let manifest = root.join("catalog.json");
    let original = fs::read_to_string(&manifest).unwrap();
    for replacement in [
        original.replace("cpu_stats.toml", "../cpu_stats.toml"),
        original.replace("\"schema\":2", "\"schema\":1"),
        original.replace("\"schema\":2", "\"schema\":2,\"schema\":2"),
        original.replace("\"schema\":2", "\"schema\":2,\"unexpected\":true"),
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
    assert_eq!(listing["schema"], 2);
    assert_eq!(listing["version"], "6");
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
        ("nic_eee_get", "estus_nic_model"),
        ("nic_eee_set", "estus_nic_model"),
        ("nic_transceiver_get", "estus_nic_model"),
        ("nic_fec_get", "netdevsim"),
        ("nic_fec_set", "netdevsim"),
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
        serde_json::json!(["cpu_stats", "memory_stats", "pressure_get"])
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
        serde_json::json!(["cpu_stats", "memory_stats", "pressure_get"])
    );
    assert_selection_metadata(
        &output,
        &canonical,
        &["cpu_stats", "memory_stats", "pressure_get"],
    );
    let definitions: toml::Table = fs::read_to_string(output.join("tools.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(definitions.len(), 1);
    assert_eq!(definitions["tools"].as_table().unwrap().len(), 3);
    for name in ["cpu_stats", "memory_stats", "pressure_get"] {
        assert!(
            output
                .join(format!("roles/{name}/tasks/main.yml"))
                .is_file()
        );
        assert!(
            output
                .join(format!("roles/{name}/files/collector.py"))
                .is_file()
        );
        let overlay: Value = serde_json::from_slice(
            &fs::read(output.join(format!("overlays/{name}.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(overlay.as_object().unwrap().len(), 3);
        assert!(overlay["input_schema"].is_object());
        assert_eq!(
            definitions["tools"][name]["execution"]["role_path"]
                .as_str()
                .unwrap(),
            output.join(format!("roles/{name}")).to_str().unwrap()
        );
    }
    assert!(output.join("snapshots").is_dir());
    assert!(
        fs::read_dir(output.join("snapshots"))
            .unwrap()
            .next()
            .is_none()
    );
    let laboratory = work.join("laboratory");
    let exported = installed_command(
        &binary,
        &work,
        &[
            "catalog",
            "export",
            "--tool",
            "nic_eee_get",
            "--tool",
            "nic_eee_set",
            "--tool",
            "nic_transceiver_get",
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
        &["nic_eee_get", "nic_eee_set", "nic_transceiver_get"],
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
                "cpu_stats",
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
                "../cpu_stats",
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
    assert_eq!(selection["schema"], 2);
    assert_eq!(selection["version"], "6");
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
