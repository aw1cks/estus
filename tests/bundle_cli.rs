//! Offline AnsiballZ bundle CLI acceptance: verification never needs Python or SSH,
//! and building is delegated to an explicitly selected external interpreter.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn binary() -> PathBuf {
    std::env::var_os("ESTUS_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_estus")))
}

fn invoke(arguments: &[&std::ffi::OsStr], extra: &[(&str, &std::ffi::OsStr)]) -> Result<Output> {
    // Diagnostics still resolve a private site configuration, so pin an existing
    // absolute SSH executable rather than depending on the caller's PATH.
    let home = tempfile::tempdir()?;
    let mut command = Command::new(binary());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ESTUS_") {
            command.env_remove(name);
        }
    }
    command
        .args(arguments)
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("TMPDIR", home.path())
        .env("ESTUS_SSH", "/bin/sh");
    for (name, value) in extra {
        command.env(name, value);
    }
    Ok(command.output()?)
}

fn report(output: &Output) -> Result<Value> {
    ensure!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count() == 1,
        "bundle CLI must emit exactly one JSON report: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn inspect_rejects_a_missing_pack_without_python_or_ssh() -> Result<()> {
    let work = tempfile::tempdir()?;
    let missing = work.path().join("absent");
    let output = invoke(
        &[
            "bundle".as_ref(),
            "inspect".as_ref(),
            "--bundle".as_ref(),
            missing.as_os_str(),
        ],
        &[],
    )?;
    ensure!(output.status.code() == Some(1));
    let parsed = report(&output)?;
    ensure!(parsed["status"] == "failed");
    ensure!(parsed["error_code"] == "bundle_unavailable");
    ensure!(parsed["module_count"].is_null());
    // A relative configured reference is never interpreted against the caller's cwd.
    let relative = invoke(
        &["bundle".as_ref(), "inspect".as_ref()],
        &[(
            "ESTUS_ANSIBLE_BUNDLE",
            Path::new("relative-private-bundle").as_os_str(),
        )],
    )?;
    ensure!(relative.status.code() == Some(1));
    ensure!(report(&relative)?["status"] == "failed");
    Ok(())
}

#[test]
fn inspect_rejects_missing_tampered_and_oversized_bundle_entries() -> Result<()> {
    let work = tempfile::tempdir()?;
    for (label, case) in [
        ("missing", None),
        ("manifest", Some("{}")),
        ("empty-modules", Some("{\"schema\":1}")),
    ] {
        let root = work.path().join(label);
        fs::create_dir(&root)?;
        if let Some(manifest) = case {
            fs::write(root.join("bundle.json"), manifest)?;
        }
        let output = invoke(
            &[
                "bundle".as_ref(),
                "inspect".as_ref(),
                "--bundle".as_ref(),
                root.as_os_str(),
            ],
            &[],
        )?;
        ensure!(output.status.code() == Some(1), "{label}");
        let report = report(&output)?;
        ensure!(report["status"] == "failed", "{label}: {report}");
        ensure!(
            report["error_code"].as_str() == Some("invalid_bundle_manifest")
                || report["error_code"].as_str() == Some("bundle_unavailable"),
            "{label}: unexpected cause {report}"
        );
    }
    let oversized = work.path().join("oversized");
    fs::create_dir(&oversized)?;
    fs::write(
        oversized.join("bundle.json"),
        vec![b' '; 2 * 1024 * 1024 + 1],
    )?;
    let output = invoke(
        &[
            "bundle".as_ref(),
            "inspect".as_ref(),
            "--bundle".as_ref(),
            oversized.as_os_str(),
        ],
        &[],
    )?;
    ensure!(output.status.code() == Some(1));
    ensure!(report(&output)?["error_code"] == "bundle_size_exceeded");
    Ok(())
}

#[test]
fn build_rejects_relative_missing_python_and_existing_output_before_spawning() -> Result<()> {
    let work = tempfile::tempdir()?;
    for (label, python, expected) in [
        (
            "relative",
            PathBuf::from("python3"),
            "invalid_python_executable",
        ),
        (
            "missing",
            PathBuf::from("/nonexistent/private-python"),
            "invalid_python_executable",
        ),
    ] {
        let output_dir = work.path().join(format!("out-{label}"));
        let output = invoke(
            &[
                "bundle".as_ref(),
                "build".as_ref(),
                "--python".as_ref(),
                python.as_os_str(),
                "--output".as_ref(),
                output_dir.as_os_str(),
                "--module".as_ref(),
                "ansible.builtin.ping".as_ref(),
                "--timeout-secs".as_ref(),
                "5".as_ref(),
            ],
            &[],
        )?;
        ensure!(output.status.code() == Some(1), "{label}");
        let report = report(&output)?;
        ensure!(report["ok"] == false, "{label}: {report}");
        ensure!(report["phase"] == "bundle_build", "{label}: {report}");
        ensure!(report["error_code"] == expected, "{label}: {report}");
        ensure!(!output_dir.exists(), "{label}: retained a partial bundle");
    }

    // An existing output path is never replaced, even when the interpreter is valid.
    let python = std::env::var_os("ESTUS_TEST_ANSIBLE_PYTHON")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute());
    let Some(python) = python else {
        return Ok(());
    };
    let output_dir = work.path().join("out-existing");
    fs::create_dir(&output_dir)?;
    fs::write(output_dir.join("sentinel"), b"keep")?;
    let output = invoke(
        &[
            "bundle".as_ref(),
            "build".as_ref(),
            "--python".as_ref(),
            python.as_os_str(),
            "--output".as_ref(),
            output_dir.as_os_str(),
            "--module".as_ref(),
            "ansible.builtin.ping".as_ref(),
            "--timeout-secs".as_ref(),
            "5".as_ref(),
        ],
        &[],
    )?;
    ensure!(output.status.code() == Some(1));
    ensure!(report(&output)?["error_code"] == "bundle_output_exists");
    ensure!(
        fs::read(output_dir.join("sentinel"))? == b"keep",
        "existing output was modified"
    );
    Ok(())
}

#[test]
fn build_and_inspect_round_trip_with_the_selected_external_interpreter() -> Result<()> {
    let Some(python) = std::env::var_os("ESTUS_TEST_ANSIBLE_PYTHON") else {
        return Ok(());
    };
    let python = PathBuf::from(python);
    ensure!(
        python.is_absolute() && python.is_file(),
        "ESTUS_TEST_ANSIBLE_PYTHON must name an absolute interpreter"
    );
    let work = tempfile::tempdir()?;
    let bundle = work.path().join("bundle");
    let build = invoke(
        &[
            "bundle".as_ref(),
            "build".as_ref(),
            "--python".as_ref(),
            python.as_os_str(),
            "--output".as_ref(),
            bundle.as_os_str(),
            "--module".as_ref(),
            "ansible.builtin.ping".as_ref(),
            "--module".as_ref(),
            "ansible.builtin.command".as_ref(),
            "--module".as_ref(),
            "ansible.posix.sysctl".as_ref(),
            "--module".as_ref(),
            "ansible.builtin.apt".as_ref(),
        ],
        &[],
    )?;
    ensure!(
        build.status.success(),
        "bundle build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let built = report(&build)?;
    ensure!(built["ok"] == true);
    ensure!(
        built["ansible_core_version"]
            .as_str()
            .is_some_and(|version| !version.is_empty())
    );
    ensure!(
        built["bundle_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    for module in [
        "ansible.builtin.ping",
        "ansible.builtin.command",
        "ansible.posix.sysctl",
    ] {
        ensure!(
            built["modules"]
                .as_array()
                .context("built modules")?
                .iter()
                .any(|value| value == module),
            "built bundle omitted {module}: {built}"
        );
    }
    ensure!(
        built["routers"]
            .as_array()
            .context("built routers")?
            .iter()
            .any(|value| value == "ansible.builtin.package"),
        "built bundle omitted the generic package router: {built}"
    );

    // Verification must be independent of the interpreter that produced the pack.
    let inspected = invoke(
        &[
            "bundle".as_ref(),
            "inspect".as_ref(),
            "--bundle".as_ref(),
            bundle.as_os_str(),
        ],
        &[],
    )?;
    ensure!(inspected.status.success());
    let inspection = report(&inspected)?;
    ensure!(inspection["status"] == "passed", "{inspection}");
    ensure!(
        inspection["ansible_core_version"] == built["ansible_core_version"]
            && inspection["bundle_sha256"] == built["bundle_sha256"]
            && inspection["module_count"].as_u64()
                == built["modules"]
                    .as_array()
                    .map(|modules| modules.len() as u64),
        "inspect disagreed with build output: {inspection} vs {built}"
    );

    fs::write(bundle.join("wrapper.py"), b"tampered\n")?;
    let tampered = invoke(
        &[
            "bundle".as_ref(),
            "inspect".as_ref(),
            "--bundle".as_ref(),
            bundle.as_os_str(),
        ],
        &[],
    )?;
    ensure!(tampered.status.code() == Some(1));
    ensure!(report(&tampered)?["error_code"] == "bundle_wrapper_drift");
    Ok(())
}

#[test]
fn doctor_reports_bundle_health_only_from_the_configured_pack() -> Result<()> {
    let missing = invoke(
        &["doctor".as_ref(), "--runtime".as_ref(), "ansible".as_ref()],
        &[(
            "ESTUS_ANSIBLE_BUNDLE",
            Path::new("/nonexistent/bundle").as_os_str(),
        )],
    )?;
    ensure!(!missing.status.success());
    let report: Value = serde_json::from_slice(&missing.stdout)?;
    ensure!(report["ok"] == false);
    ensure!(report["runtime"]["status"] == "failed");
    ensure!(
        report["runtime"]["phase"] == "runtime_check",
        "doctor omitted the bundle phase: {report}"
    );
    ensure!(
        report["runtime"]["error_code"]
            .as_str()
            .is_some_and(|code| code.starts_with("bundle_") || code == "runtime_unavailable"),
        "doctor leaked an unexpected bundle cause: {report}"
    );
    Ok(())
}
