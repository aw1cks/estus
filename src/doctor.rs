//! Operator-only ordinary SSH/SFTP negotiation; never a model-callable capability.
//! Only checks with a cause include a fixed phase; successful and unattempted checks
//! without a cause keep their existing shape. Backend diagnostics remain private.
//! Effective SSH policy inspection runs `ssh -G -- <destination>`, which can evaluate
//! `Match exec` stanzas from the configured or user SSH config.
use crate::bundle::{self, BundleCheck};
use crate::{
    config::{Config, DoctorArgs, IdentityRole},
    filesystem::operations::{self, FileContext},
    ssh::Pool,
};
use serde::Serialize;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

const MAX_TARGETS: usize = 32;
const MAX_REPORT_BYTES: usize = 65_536;
const OUTPUT_GRACE: Duration = Duration::from_secs(1);
const POLICY_BYTES: usize = 65_536;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Passed,
    Failed,
    NotTested,
}

#[derive(Serialize)]
struct Check {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<&'static str>,
}

impl Check {
    fn passed() -> Self {
        Self {
            status: Status::Passed,
            error_code: None,
            phase: None,
        }
    }
    fn failed(code: &'static str, phase: &'static str) -> Self {
        Self {
            status: Status::Failed,
            error_code: Some(code),
            phase: Some(phase),
        }
    }
    fn untested(code: Option<&'static str>, phase: &'static str) -> Self {
        Self {
            status: Status::NotTested,
            error_code: code,
            phase: code.map(|_| phase),
        }
    }
}

#[derive(Serialize)]
struct SshEffectivePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    strict_host_key_checking: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_host_keys: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_mode: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<&'static str>,
}

#[derive(Serialize)]
struct TargetReport {
    target: String,
    ssh: Check,
    sftp: Check,
    sudo: Check,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_ssh_policy: Option<SshEffectivePolicy>,
}
#[derive(Serialize)]
struct RuntimeReport {
    #[serde(flatten)]
    check: BundleCheck,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<&'static str>,
}

#[derive(Serialize)]
pub(crate) struct Report {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_executable: Option<PathBuf>,
    targets: Vec<TargetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<RuntimeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<&'static str>,
    #[serde(skip)]
    exit: u8,
}

impl Report {
    fn invalid(code: &'static str) -> Self {
        Self {
            ok: false,
            ssh_executable: None,
            targets: Vec::new(),
            runtime: None,
            error_code: Some(code),
            phase: Some("doctor_validation"),
            exit: 2,
        }
    }
    fn encode(&self) -> (Vec<u8>, u8) {
        struct Limited(Vec<u8>);
        impl Write for Limited {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if bytes.len() > (MAX_REPORT_BYTES - 1).saturating_sub(self.0.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "report byte bound",
                    ));
                }
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut encoded = Limited(Vec::new());
        let exit = if serde_json::to_writer(&mut encoded, self).is_ok() {
            encoded.0.push(b'\n');
            self.exit
        } else {
            encoded.0.clear();
            encoded.0.extend_from_slice(
                b"{\"ok\":false,\"targets\":[],\"error_code\":\"diagnostic_report_limit\",\"phase\":\"doctor_output\"}\n",
            );
            1
        };
        (encoded.0, exit)
    }

    /// All owned pools have been finalized before this bounded output stage starts.
    pub(crate) async fn publish(self) -> u8 {
        let (encoded, exit) = self.encode();
        let output = async {
            let mut stdout = tokio::io::stdout();
            stdout.write_all(&encoded).await?;
            stdout.flush().await
        };
        match tokio::time::timeout(OUTPUT_GRACE, output).await {
            Ok(Ok(())) => exit,
            _ => {
                crate::audit::emit(
                    &serde_json::json!({"event":"error","code":"doctor_output_failed","phase":"doctor_output"}),
                );
                1
            }
        }
    }
}

fn stopped(shutdown: &CancellationToken, deadline: tokio::time::Instant) -> Option<&'static str> {
    if shutdown.is_cancelled() {
        Some("cancelled")
    } else if tokio::time::Instant::now() >= deadline {
        Some("timeout")
    } else {
        None
    }
}
async fn effective_ssh_policy(
    executable: &Path,
    config: Option<&Path>,
    destination: &str,
    deadline: tokio::time::Instant,
    shutdown: &CancellationToken,
) -> Option<SshEffectivePolicy> {
    if shutdown.is_cancelled() || tokio::time::Instant::now() >= deadline {
        return None;
    }
    let mut command = Command::new(executable);
    command.arg("-G");
    if let Some(config) = config {
        command.arg("-F").arg(config);
    }
    command
        .arg("--")
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let read = async {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let n = stdout.read(&mut chunk).await.ok()?;
            if n == 0 {
                break;
            }
            let take = n.min(POLICY_BYTES.saturating_sub(buffer.len()));
            buffer.extend_from_slice(&chunk[..take]);
            if buffer.len() >= POLICY_BYTES {
                break;
            }
        }
        let status = child.wait().await.ok()?;
        status.success().then_some(buffer)
    };
    let bytes = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return None,
        _ = tokio::time::sleep_until(deadline) => return None,
        bytes = read => bytes?,
    };
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut strict_host_key_checking = None;
    let mut update_host_keys = None;
    let mut batch_mode = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value.len() > 64 || value.bytes().any(|b| b.is_ascii_control()) {
            continue;
        }
        if key.eq_ignore_ascii_case("stricthostkeychecking") {
            strict_host_key_checking = Some(value.to_ascii_lowercase());
        } else if key.eq_ignore_ascii_case("updatehostkeys") {
            update_host_keys = Some(value.to_ascii_lowercase());
        } else if key.eq_ignore_ascii_case("batchmode") {
            batch_mode = Some(value.to_ascii_lowercase());
        }
    }
    let mut warnings = Vec::new();
    if matches!(
        strict_host_key_checking.as_deref(),
        Some("no" | "off" | "false")
    ) {
        warnings.push("strict_host_key_checking_disabled");
    }
    if config.is_none() {
        warnings.push("ambient_ssh_config_in_use");
    }
    Some(SshEffectivePolicy {
        strict_host_key_checking,
        update_host_keys,
        batch_mode,
        warnings,
    })
}

pub(crate) async fn run(config: Config, args: DoctorArgs, shutdown: CancellationToken) -> Report {
    let mut selected = args.targets;
    if (selected.is_empty() && args.runtime.is_none()) || selected.len() > MAX_TARGETS {
        return Report::invalid("invalid_target_selection");
    }
    selected.sort_unstable();
    if selected.windows(2).any(|pair| pair[0] == pair[1])
        || selected
            .iter()
            .any(|name| config.doctor_target(name).is_err())
    {
        return Report::invalid("invalid_target_selection");
    }
    let duration = match config.timeout(args.timeout_secs) {
        Ok(duration) => duration,
        Err(_) => return Report::invalid("invalid_timeout"),
    };
    let Some(deadline) = tokio::time::Instant::now().checked_add(duration) else {
        return Report::invalid("invalid_timeout");
    };
    let runtime = if let Some(kind) = args.runtime {
        let check = match kind {
            crate::config::RuntimeKind::Ansible => {
                if let Some(code) = stopped(&shutdown, deadline) {
                    BundleCheck::not_tested(code)
                } else {
                    match config.automation_runtime() {
                        Ok(reference) => bundle::check(reference),
                        Err(_) => BundleCheck::failed("runtime_unavailable"),
                    }
                }
            }
        };
        let phase = (!check.is_passed()).then_some("runtime_check");
        Some(RuntimeReport { check, phase })
    } else {
        None
    };
    let mut targets = Vec::with_capacity(selected.len());
    let mut ok = runtime
        .as_ref()
        .is_none_or(|runtime| runtime.check.is_passed());
    for name in selected {
        if let Some(code) = stopped(&shutdown, deadline) {
            ok = false;
            targets.push(TargetReport {
                target: name,
                ssh: Check::untested(Some(code), "ssh_connect"),
                sftp: Check::untested(Some(code), "sftp_probe"),
                sudo: Check::untested(None, "sudo_probe"),
                effective_ssh_policy: None,
            });
            continue;
        }
        let target = config
            .doctor_target(&name)
            .expect("validated immutable configured target");
        // `ssh -G` only evaluates the configuration, so ask it first: a connection
        // that uses up the deadline must not take the policy and its warnings with
        // it, since a timeout is when they matter most.
        let effective_ssh_policy = effective_ssh_policy(
            config.ssh_executable(),
            config.ssh_config(),
            target.destination,
            deadline,
            &shutdown,
        )
        .await;
        // One pool per selected target: finalize before advancing, without retaining
        // idle masters or resetting the original whole-run deadline.
        let pool = Pool::diagnostic(
            config.ssh_executable().to_path_buf(),
            config.ssh_config().map(ToOwned::to_owned),
            Duration::from_secs(config.limits().connect_timeout_secs),
            shutdown.clone(),
        );
        let (ssh, sftp) = match pool
            .acquire(
                target.name,
                target.destination,
                IdentityRole::Ordinary,
                deadline,
                &shutdown,
            )
            .await
        {
            Ok(lease) => {
                let outcome = operations::probe(
                    lease.session(),
                    FileContext {
                        deadline,
                        ct: &shutdown,
                        shutdown: &shutdown,
                        progress: crate::progress::Reporter::default(),
                    },
                )
                .await;
                let sftp = match outcome.reply.error() {
                    Some(error) => {
                        ok = false;
                        Check::failed(error.code().as_str(), "sftp_probe")
                    }
                    None => Check::passed(),
                };
                (Check::passed(), sftp)
            }
            Err(error) => {
                ok = false;
                (
                    Check::failed(error.code().as_str(), "ssh_connect"),
                    Check::untested(None, "sftp_probe"),
                )
            }
        };
        pool.shutdown().await;
        targets.push(TargetReport {
            target: name,
            ssh,
            sftp,
            sudo: Check::untested(None, "sudo_probe"),
            effective_ssh_policy,
        });
    }
    Report {
        ok,
        ssh_executable: Some(config.ssh_executable().to_path_buf()),
        targets,
        runtime,
        error_code: None,
        phase: None,
        exit: if ok { 0 } else { 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_report_bound_includes_json_escaping_and_newline() {
        let mut report = Report {
            ok: true,
            ssh_executable: None,
            error_code: None,
            phase: None,
            runtime: None,
            exit: 0,
            targets: vec![TargetReport {
                target: "site-\"\\\n☃".into(),
                ssh: Check::passed(),
                sftp: Check::passed(),
                sudo: Check::untested(None, "sudo_probe"),
                effective_ssh_policy: None,
            }],
        };
        let base = serde_json::to_vec(&report).unwrap().len() + 1;
        report.targets[0]
            .target
            .push_str(&"x".repeat(MAX_REPORT_BYTES - base));
        let (exact, exit) = report.encode();
        assert_eq!(exit, 0);
        assert_eq!(exact.len(), MAX_REPORT_BYTES);
        assert_eq!(exact.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&exact).unwrap();
        assert_eq!(value["targets"][0]["target"], report.targets[0].target);
        assert_eq!(value["targets"][0]["sudo"]["status"], "not_tested");
        report.targets[0].target.push('x');
        let (oversize, exit) = report.encode();
        assert_eq!(exit, 1);
        let value: serde_json::Value = serde_json::from_slice(&oversize).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "ok": false, "targets": [], "error_code": "diagnostic_report_limit",
                "phase": "doctor_output",
            })
        );
    }
}
