//! Explicit portable wheel payload compatibility audit.
#![cfg(unix)]

#[allow(dead_code)]
mod support;

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};
use support::find_program;
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

const SETUP: Duration = Duration::from_secs(900);

fn input(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).with_context(|| format!("set {name}"))?);
    ensure!(
        path.is_absolute() && path.is_file(),
        "{name} must name an absolute existing file"
    );
    Ok(path)
}

// Downloads and existing compiled suites need a longer deadline than short fixture helpers.
// Drain both pipes concurrently and kill/reap the actual child on timeout.
async fn checked(command: &mut Command) -> Result<Output> {
    let description = format!("{command:?}");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("acceptance stdout")?;
    let mut stderr = child.stderr.take().context("acceptance stderr")?;
    let out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match timeout(SETUP, child.wait()).await {
        Ok(status) => status?,
        Err(error) => {
            child.kill().await?;
            out.abort();
            err.abort();
            return Err(error)
                .with_context(|| format!("acceptance command timed out: {description}"));
        }
    };
    let output = Output {
        status,
        stdout: timeout(support::CLEANUP, out).await???,
        stderr: timeout(support::CLEANUP, err).await???,
    };
    ensure!(
        output.status.success(),
        "command failed: {description}\nstatus: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn baseline_version(value: &str) -> Result<[u32; 3]> {
    let mut version = [0; 3];
    for (index, part) in value.split('.').enumerate() {
        ensure!(
            index < version.len() && !part.is_empty(),
            "unrecognized ABI version: {value}"
        );
        version[index] = part
            .parse()
            .with_context(|| format!("unrecognized ABI version: {value}"))?;
    }
    Ok(version)
}

#[tokio::test]
#[ignore = "requires SSH_MCP_TEST_WHEEL, unzip and pinned llvm-otool (Darwin) or llvm-readelf (Linux); no network"]
async fn wheel_payload_matches_declared_baseline() -> Result<()> {
    let wheel = input("SSH_MCP_TEST_WHEEL")?;
    let root = tempfile::Builder::new()
        .prefix("ssh-mcp-audit-")
        .tempdir_in("/tmp")?;
    let path = std::env::var_os("PATH").context("PATH prerequisite")?;
    let command = |program: &Path| {
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("PATH", &path)
            .env("LC_ALL", "C")
            .env("HOME", root.path())
            .env("TMPDIR", root.path())
            .current_dir(root.path())
            .kill_on_drop(true);
        command
    };
    let unzip = find_program("unzip")?;
    let listing = checked(command(&unzip).arg("-Z1").arg(&wheel)).await?;
    let listing = std::str::from_utf8(&listing.stdout)?;
    let payload_member = "ssh_mcp/_bin/ssh-mcp";
    ensure!(
        listing
            .lines()
            .filter(|line| *line == payload_member)
            .count()
            == 1,
        "wheel must contain exactly one native payload"
    );
    let mut metadata_members = listing.lines().filter(|line| {
        line.strip_suffix("/WHEEL").is_some_and(|parent| {
            parent.starts_with("ssh_mcp-")
                && parent.ends_with(".dist-info")
                && !parent.contains('/')
                && !parent.contains('\\')
        })
    });
    let metadata_member = metadata_members
        .next()
        .context("missing ssh_mcp dist-info/WHEEL")?;
    ensure!(
        metadata_members.next().is_none(),
        "ambiguous wheel metadata"
    );
    checked(
        command(&unzip)
            .arg("-q")
            .arg(&wheel)
            .args([payload_member, metadata_member])
            .arg("-d")
            .arg(root.path()),
    )
    .await?;
    for member in [payload_member, metadata_member] {
        let selected = root.path().join(member);
        ensure!(
            fs::symlink_metadata(&selected)?.is_file()
                && fs::canonicalize(&selected)?.starts_with(fs::canonicalize(root.path())?),
            "selected wheel asset must be a regular owned extracted file: {member}"
        );
    }
    let payload = root.path().join(payload_member);
    let metadata = fs::read_to_string(root.path().join(metadata_member))?;
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "macosx_11_0_arm64",
        ("linux", "aarch64") => "manylinux_2_17_aarch64",
        ("linux", "x86_64") => "manylinux_2_17_x86_64",
        other => anyhow::bail!("unsupported wheel audit platform: {other:?}"),
    };
    ensure!(
        wheel
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(&format!("-{platform}.whl"))),
        "wheel filename does not declare the required {platform} baseline"
    );
    let mut tags = metadata
        .lines()
        .filter_map(|line| line.strip_prefix("Tag: "));
    let first = tags.next().context("WHEEL has no compatibility tag")?;
    for tag in std::iter::once(first).chain(tags) {
        ensure!(
            tag.rsplit_once('-')
                .is_some_and(|(_, value)| value == platform),
            "wheel metadata declares an unexpected platform: {tag}"
        );
    }

    if cfg!(target_os = "macos") {
        let otool = find_program("llvm-otool")?;
        let header = checked(command(&otool).arg("-hv").arg(&payload)).await?;
        let header = std::str::from_utf8(&header.stdout)?;
        let mut architectures = header
            .lines()
            .filter(|line| line.trim_start().starts_with("MH_MAGIC"));
        let architecture = architectures
            .next()
            .context("missing Mach-O architecture")?;
        ensure!(
            architecture.split_whitespace().nth(1) == Some("ARM64")
                && architectures.next().is_none(),
            "wheel payload is not a single arm64 Mach-O: {header}"
        );
        let loads = checked(command(&otool).arg("-l").arg(&payload)).await?;
        let loads = std::str::from_utf8(&loads.stdout)?;
        ensure!(
            !loads.contains("/nix/store/"),
            "Mach-O load commands retain a Nix store reference: {loads}"
        );
        let mut current = "";
        let mut minimum_seen = false;
        let mut platform_seen = false;
        for line in loads.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("cmd ") {
                current = value;
            } else if current == "LC_BUILD_VERSION" {
                if let Some(value) = line.strip_prefix("platform ") {
                    ensure!(
                        value == "1" || value.eq_ignore_ascii_case("macos"),
                        "Mach-O declares a non-macOS platform: {value}"
                    );
                    platform_seen = true;
                } else if let Some(value) = line.strip_prefix("minos ") {
                    ensure!(
                        baseline_version(value)? <= [11, 0, 0],
                        "wheel advertises macOS 11.0 but payload requires macOS {value}"
                    );
                    minimum_seen = true;
                }
            } else if current == "LC_VERSION_MIN_MACOSX"
                && let Some(value) = line.strip_prefix("version ")
            {
                ensure!(
                    baseline_version(value)? <= [11, 0, 0],
                    "wheel advertises macOS 11.0 but payload requires macOS {value}"
                );
                minimum_seen = true;
                platform_seen = true;
            }
        }
        ensure!(
            minimum_seen && platform_seen,
            "Mach-O does not declare an auditable macOS minimum"
        );
        let libraries = checked(command(&otool).arg("-L").arg(&payload)).await?;
        let libraries = std::str::from_utf8(&libraries.stdout)?;
        let mut system_library_seen = false;
        for line in libraries
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
        {
            let library = line
                .trim()
                .split_once(" (")
                .context("unrecognized Mach-O dylib entry")?
                .0;
            ensure!(
                library.starts_with("/usr/lib/") || library.starts_with("/System/Library/"),
                "non-system Mach-O dependency: {library}"
            );
            system_library_seen = true;
        }
        ensure!(
            system_library_seen,
            "missing Mach-O system dependency evidence"
        );
    } else {
        let readelf = find_program("llvm-readelf")?;
        let inspected = checked(
            command(&readelf)
                .args([
                    "--file-header",
                    "--program-headers",
                    "--dynamic-table",
                    "--version-info",
                ])
                .arg(&payload),
        )
        .await?;
        let inspected = std::str::from_utf8(&inspected.stdout)?;
        ensure!(
            !inspected.contains("/nix/store/"),
            "ELF loader/dynamic metadata retains a Nix store reference: {inspected}"
        );
        let (machine, interpreter) = match std::env::consts::ARCH {
            "aarch64" => ("AArch64", "/lib/ld-linux-aarch64.so.1"),
            "x86_64" => (
                "Advanced Micro Devices X86-64",
                "/lib64/ld-linux-x86-64.so.2",
            ),
            other => anyhow::bail!("unsupported ELF architecture: {other}"),
        };
        let actual_machine = inspected
            .lines()
            .find_map(|line| line.trim().strip_prefix("Machine:"))
            .context("missing ELF machine")?
            .trim();
        ensure!(
            actual_machine == machine,
            "ELF architecture disagrees with wheel tag: {actual_machine}"
        );
        let mut interpreters = inspected.lines().filter_map(|line| {
            line.split_once("Requesting program interpreter: ")
                .map(|(_, value)| value.trim_end_matches(']').trim())
        });
        ensure!(
            interpreters.next() == Some(interpreter) && interpreters.next().is_none(),
            "ELF must use the architecture's FHS program interpreter {interpreter}"
        );
        let mut needed_seen = false;
        let mut glibc_seen = false;
        for line in inspected.lines() {
            if line.contains("(NEEDED)") {
                let library = line
                    .split_once('[')
                    .and_then(|(_, value)| value.split_once(']'))
                    .context("unrecognized ELF DT_NEEDED entry")?
                    .0;
                ensure!(
                    matches!(
                        library,
                        "libc.so.6"
                            | "libgcc_s.so.1"
                            | "libm.so.6"
                            | "libpthread.so.0"
                            | "librt.so.1"
                            | "libdl.so.2"
                    ),
                    "nonportable ELF dependency outside the system C runtime: {library}"
                );
                needed_seen = true;
            }
            for token in line.split_whitespace() {
                if let Some((_, requirement)) = token.split_once("GLIBC_") {
                    let requirement = requirement.trim_end_matches([')', ']', ',']);
                    ensure!(
                        baseline_version(requirement)? <= [2, 17, 0],
                        "wheel advertises glibc 2.17 but payload requires GLIBC_{requirement}"
                    );
                    glibc_seen = true;
                }
            }
        }
        ensure!(
            needed_seen && glibc_seen,
            "missing dynamic ELF/glibc requirement evidence"
        );
    }
    let owned = root.path().to_owned();
    root.close()?;
    ensure!(
        !owned.exists(),
        "owned artifact audit workspace survived cleanup"
    );
    Ok(())
}
