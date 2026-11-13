//! Operator-only ordinary SSH/SFTP negotiation; never a model-callable capability.
use std::io::{self, Write};
use std::time::Duration;

use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::automation::{self, RuntimeCheck, RuntimeContext};
use crate::{
    config::{Config, DoctorArgs, IdentityRole},
    files::{self, FileContext},
    ssh::Pool,
};

const MAX_TARGETS: usize = 32;
const MAX_REPORT_BYTES: usize = 65_536;
const OUTPUT_GRACE: Duration = Duration::from_secs(1);

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
}

impl Check {
    fn passed() -> Self {
        Self {
            status: Status::Passed,
            error_code: None,
        }
    }
    fn failed(code: &'static str) -> Self {
        Self {
            status: Status::Failed,
            error_code: Some(code),
        }
    }
    fn untested(code: Option<&'static str>) -> Self {
        Self {
            status: Status::NotTested,
            error_code: code,
        }
    }
}

#[derive(Serialize)]
struct TargetReport {
    target: String,
    ssh: Check,
    sftp: Check,
    sudo: Check,
}

#[derive(Serialize)]
pub(crate) struct Report {
    ok: bool,
    targets: Vec<TargetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<RuntimeCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip)]
    exit: u8,
}

impl Report {
    fn invalid(code: &'static str) -> Self {
        Self {
            ok: false,
            targets: Vec::new(),
            runtime: None,
            error_code: Some(code),
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
                b"{\"ok\":false,\"targets\":[],\"error_code\":\"diagnostic_report_limit\"}\n",
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
                    &serde_json::json!({"event":"error","code":"doctor_output_failed"}),
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
        Some(match kind {
            crate::config::RuntimeKind::Ansible => {
                if let Some(code) = stopped(&shutdown, deadline) {
                    RuntimeCheck::not_tested(code)
                } else {
                    match config.automation_runtime() {
                        Ok(reference) => {
                            automation::check(
                                reference,
                                RuntimeContext {
                                    deadline,
                                    ct: &shutdown,
                                    shutdown: &shutdown,
                                },
                            )
                            .await
                        }
                        Err(_) => RuntimeCheck::failed("runtime_unavailable"),
                    }
                }
            }
        })
    } else {
        None
    };
    let mut targets = Vec::with_capacity(selected.len());
    let mut ok = runtime.as_ref().is_none_or(RuntimeCheck::is_passed);
    for name in selected {
        if let Some(code) = stopped(&shutdown, deadline) {
            ok = false;
            targets.push(TargetReport {
                target: name,
                ssh: Check::untested(Some(code)),
                sftp: Check::untested(Some(code)),
                sudo: Check::untested(None),
            });
            continue;
        }
        let target = config
            .doctor_target(&name)
            .expect("validated immutable configured target");
        // One pool per selected target: finalize before advancing, without retaining
        // idle masters or resetting the original whole-run deadline.
        let pool = Pool::diagnostic(
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
                let outcome = files::probe(
                    lease.session(),
                    FileContext {
                        deadline,
                        ct: &shutdown,
                        shutdown: &shutdown,
                    },
                )
                .await;
                let sftp = match outcome.reply.error {
                    Some(error) => {
                        ok = false;
                        Check::failed(error.code)
                    }
                    None => Check::passed(),
                };
                (Check::passed(), sftp)
            }
            Err(error) => {
                ok = false;
                (Check::failed(error.code), Check::untested(None))
            }
        };
        pool.shutdown().await;
        targets.push(TargetReport {
            target: name,
            ssh,
            sftp,
            sudo: Check::untested(None),
        });
    }
    Report {
        ok,
        targets,
        runtime,
        error_code: None,
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
            error_code: None,
            runtime: None,
            exit: 0,
            targets: vec![TargetReport {
                target: "site-\"\\\n☃".into(),
                ssh: Check::passed(),
                sftp: Check::passed(),
                sudo: Check::untested(None),
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
            })
        );
    }
}
