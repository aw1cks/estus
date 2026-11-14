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
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples"),
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
    fs::write(root.join("catalog.json"), r#"{"schema":1,"version":"1","presets":{"linux-health":["cpu_stats"]},"tools":{"cpu_stats":{"definition":"cpu_stats.toml","role":"roles/cpu_stats","policy_required":false,"requires":["linux"]}}}"#).unwrap();
    fs::write(
        root.join("cpu_stats.toml"),
        "[tools.cpu_stats]\ndescription = 'fixture'\n",
    )
    .unwrap();
    fs::write(root.join("roles/cpu_stats/tasks/main.yml"), "---\n[]\n").unwrap();
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
        original.replace("\"schema\":1", "\"schema\":2"),
        original.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
        original.replace("\"schema\":1", "\"schema\":1,\"unexpected\":true"),
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
    assert_eq!(listing["schema"], 1);
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
