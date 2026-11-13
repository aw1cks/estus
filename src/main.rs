mod audit;
mod automation;
mod automation_exec;
mod bindings;
mod capture;
mod command;
mod config;
mod controller;
mod doctor;
mod exec;
mod filedata;
mod filemeta;
mod files;
mod module_schema;
mod process;
mod reply;
mod schema_import;
mod server;
mod ssh;
mod wire;

use std::{
    pin::Pin,
    process::ExitCode,
    task::{Context, Poll},
};

use clap::Parser;
use rmcp::ServiceExt;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new(process::ANCHOR_ARG))
        && arguments.next().is_none()
    {
        return match process::anchor() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    let mut cli = config::Cli::parse();
    let command = cli.command.take();
    let diagnostic = command.is_some();
    let config = match config::Config::load(cli) {
        Ok(config) => config,
        Err(error) => {
            let status = invalid_config(&error);
            return if diagnostic {
                ExitCode::from(2)
            } else {
                status
            };
        }
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let status = runtime.block_on(run(config, command));
            // Tokio's blocking stdin reader cannot be cancelled while stdin stays open.
            runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            status
        }
        Err(_) => fail("runtime_start_failed"),
    }
}

async fn run(mut config: config::Config, command: Option<config::CliCommand>) -> ExitCode {
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        return fail("signal_setup_failed");
    };
    if let Some(command) = command {
        let shutdown = CancellationToken::new();
        let operation = async {
            match command {
                config::CliCommand::Doctor(args) => {
                    doctor::run(config, args, shutdown.clone())
                        .await
                        .publish()
                        .await
                }
                config::CliCommand::Schema(args) => {
                    schema_import::run(config, args, shutdown.clone())
                        .await
                        .publish()
                        .await
                }
            }
        };
        tokio::pin!(operation);
        let report = tokio::select! {
            report = &mut operation => report,
            _ = interrupt.recv() => {
                shutdown.cancel();
                operation.as_mut().await
            },
            _ = terminate.recv() => {
                shutdown.cancel();
                operation.as_mut().await
            },
        };
        return ExitCode::from(report);
    }
    let shutdown = CancellationToken::new();
    let activated = {
        let activation = config.activate_automation(&shutdown);
        tokio::pin!(activation);
        tokio::select! {
            result = &mut activation => result,
            _ = interrupt.recv() => {
                shutdown.cancel();
                activation.as_mut().await
            },
            _ = terminate.recv() => {
                shutdown.cancel();
                activation.as_mut().await
            },
        }
    };
    let activated = match activated {
        Ok(activated) if !shutdown.is_cancelled() => activated,
        _ => return fail("automation_runtime_unavailable"),
    };
    if config.automation_required() && !activated {
        let shutdown = CancellationToken::new();
        let duration = match config.timeout(None) {
            Ok(duration) => duration,
            Err(_) => return fail("automation_runtime_unavailable"),
        };
        let Some(deadline) = tokio::time::Instant::now().checked_add(duration) else {
            return fail("automation_runtime_unavailable");
        };
        let verification = async {
            match config.automation_runtime() {
                Ok(reference) => {
                    automation::check(
                        reference,
                        automation::RuntimeContext {
                            deadline,
                            ct: &shutdown,
                            shutdown: &shutdown,
                        },
                    )
                    .await
                }
                Err(_) => automation::RuntimeCheck::failed("runtime_unavailable"),
            }
        };
        tokio::pin!(verification);
        let health = tokio::select! {
            health = &mut verification => health,
            _ = interrupt.recv() => {
                shutdown.cancel();
                verification.as_mut().await
            },
            _ = terminate.recv() => {
                shutdown.cancel();
                verification.as_mut().await
            },
        };
        if !health.is_passed() {
            return fail("automation_runtime_unavailable");
        }
    }
    let application = match server::SshMcp::new(config) {
        Ok(application) => application,
        Err(error) => return invalid_config(&error),
    };
    let result = run_session(&application, &mut interrupt, &mut terminate).await;
    application.shutdown().await;
    result
}

fn invalid_config(error: &config::ConfigError) -> ExitCode {
    audit::emit(&serde_json::json!({
        "event": "error",
        "code": "invalid_config",
        "message": error.to_string(),
    }));
    ExitCode::FAILURE
}

async fn run_session(
    application: &server::SshMcp,
    interrupt: &mut tokio::signal::unix::Signal,
    terminate: &mut tokio::signal::unix::Signal,
) -> ExitCode {
    let shutdown = application.shutdown_token();
    let (input, output) = rmcp::transport::stdio();
    let input = EofStdin {
        inner: input,
        shutdown: shutdown.clone(),
    };
    let transport = wire::BoundedTransport(rmcp::transport::async_rw::AsyncRwTransport::<
        rmcp::RoleServer,
        _,
        _,
    >::new(input, output));
    let service = tokio::select! {
        result = application.clone().serve(transport) => match result {
            Ok(service) => service,
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => {
                return ExitCode::SUCCESS;
            },
            Err(_) => return fail("mcp_initialize_failed"),
        },
        _ = interrupt.recv() => return ExitCode::SUCCESS,
        _ = terminate.recv() => return ExitCode::SUCCESS,
    };
    let cancellation = service.cancellation_token();
    let waiting = service.waiting();
    tokio::pin!(waiting);
    tokio::select! {
        result = &mut waiting => return if result.is_ok() {
            ExitCode::SUCCESS
        } else {
            fail("mcp_session_failed")
        },
        _ = interrupt.recv() => {},
        _ = terminate.recv() => {},
    }
    shutdown.cancel();
    cancellation.cancel();
    match tokio::time::timeout(std::time::Duration::from_secs(2), waiting).await {
        Ok(Ok(_)) => ExitCode::SUCCESS,
        _ => fail("mcp_shutdown_failed"),
    }
}

// RMCP drains pending responses on EOF before it cancels handler tokens. Stop
// remote work immediately on actual stdin EOF, while preserving that reply drain.
struct EofStdin {
    inner: tokio::io::Stdin,
    shutdown: CancellationToken,
}

impl AsyncRead for EofStdin {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let has_capacity = buffer.remaining() > 0;
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Err(_)))
            || (has_capacity
                && matches!(&result, Poll::Ready(Ok(())))
                && buffer.filled().len() == before)
        {
            self.shutdown.cancel();
        }
        result
    }
}

fn fail(code: &str) -> ExitCode {
    audit::emit(&serde_json::json!({ "event": "error", "code": code }));
    ExitCode::FAILURE
}
