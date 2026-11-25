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

/// A stub interpreter, so the failure path is exercised without Ansible.
fn stub_interpreter(directory: &Path, name: &str, body: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn build_with(python: &Path, output_dir: &Path) -> Result<Output> {
    invoke(
        &[
            "bundle".as_ref(),
            "build".as_ref(),
            "--python".as_ref(),
            python.as_os_str(),
            "--output".as_ref(),
            output_dir.as_os_str(),
            "--timeout-secs".as_ref(),
            "30".as_ref(),
        ],
        &[],
    )
}

#[test]
fn a_failed_build_reports_what_the_builder_said() -> Result<()> {
    let work = tempfile::tempdir()?;
    let failing = stub_interpreter(
        work.path(),
        "failing",
        "echo 'WARNING: community.general.zypper was not found' >&2\n\
         echo 'Missing ansible-doc specification for community.general.apk' >&2\n\
         exit 3",
    )?;
    let output_dir = work.path().join("out-failing");
    let output = build_with(&failing, &output_dir)?;
    ensure!(output.status.code() == Some(1));
    let failed = report(&output)?;
    ensure!(
        failed["ok"] == false && failed["phase"] == "bundle_build",
        "{failed}"
    );
    ensure!(failed["error_code"] == "builder_failed", "{failed}");
    let detail = failed["detail"].as_str().context("detail")?;
    ensure!(
        detail.contains("Missing ansible-doc specification for community.general.apk"),
        "detail lost the builder's message: {detail}"
    );
    ensure!(!output_dir.exists(), "retained a partial bundle");

    // A builder that writes far more than a pipe holds must neither deadlock nor
    // flood the report: only the last lines survive, and never a cut-off line.
    let chatty = stub_interpreter(
        work.path(),
        "chatty",
        "i=0\n\
         while [ \"$i\" -lt 3000 ]; do echo \"noise line $i padding padding padding padding\" >&2; i=$((i+1)); done\n\
         echo 'the real cause' >&2\n\
         exit 1",
    )?;
    let output = build_with(&chatty, &work.path().join("out-chatty"))?;
    ensure!(output.status.code() == Some(1));
    let chatty_report = report(&output)?;
    ensure!(
        chatty_report["error_code"] == "builder_failed",
        "{chatty_report}"
    );
    let detail = chatty_report["detail"].as_str().context("detail")?;
    ensure!(
        detail.len() <= 2048,
        "detail is unbounded: {} bytes",
        detail.len()
    );
    ensure!(detail.ends_with("the real cause"), "{detail}");
    ensure!(
        detail.starts_with("noise line"),
        "detail begins mid-line: {detail}"
    );

    // Nothing said means no detail, not an empty one.
    let silent = stub_interpreter(work.path(), "silent", "exit 1")?;
    let output = build_with(&silent, &work.path().join("out-silent"))?;
    let silent_report = report(&output)?;
    ensure!(
        silent_report["error_code"] == "builder_failed",
        "{silent_report}"
    );
    ensure!(silent_report.get("detail").is_none(), "{silent_report}");
    Ok(())
}
