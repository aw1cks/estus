mod audit;
mod auth;
mod bindings;
mod bundle;
mod capture;
mod catalog;
mod command;
mod config;
mod contracts;
mod controller;
mod doctor;
mod exec;
mod filesystem;
mod native_payload;
mod output;
mod process;
mod progress;
mod reply;
mod server;
mod ssh;
mod strict_json;
mod wire;

#[doc(hidden)]
pub mod internal {
    pub mod wire {
        pub use crate::wire::{MAX_RESPONSE_BYTES, ReplyBudget};
    }

    pub mod reply {
        pub use crate::reply::{
            CommandData, ErrorCode, GroupCleanup, Termination, ToolError, ToolReply,
        };
    }

    pub mod command {
        pub use crate::command::{
            ExecRequest, Invocation, MAX_COMMAND_BYTES, RunRequest, Shell, SudoRequest,
            shell_script,
        };
    }

    pub mod strict_json {
        pub use crate::strict_json::parse;
    }

    pub mod contracts {
        pub mod module_schema {
            pub use crate::contracts::module_schema::{
                CapabilityBinding, bounded, compile_binding, import_document,
                import_explicit_schema, validate_input_shape, validate_overlay,
            };
        }

        pub mod projection {
            pub use crate::contracts::projection::{Plan, compile};
        }
    }

    pub mod bundle {
        pub use crate::bundle::BundlePack;
    }
    pub mod filesystem_data {
        pub use crate::filesystem::data::{
            Encoding, RawRead, ReadData, ReadRequest, ReadSpec, WriteData, WriteRequest, WriteSpec,
            encode,
        };
    }

    pub mod filesystem_metadata {
        pub use crate::filesystem::metadata::{FileKind, ListEntry, StatData, metadata_data};
    }

    pub mod catalog_assets {
        pub use crate::catalog::assets::{
            Catalog, CatalogError, Executor, Manifest, Qualification, Template,
        };
    }
}

use std::{
    pin::Pin,
    process::ExitCode,
    task::{Context, Poll},
};

use clap::{CommandFactory, FromArgMatches};
use rmcp::ServiceExt;
use tokio::io::{AsyncRead, ReadBuf};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;

enum Diagnostic {
    Doctor(config::DoctorArgs),
    Bundle(bundle::BundleArgs),
}

/// Runs `operation` until it completes or SIGINT/SIGTERM arrives. On a signal
/// the shared shutdown token is cancelled first, then the operation is given a
/// chance to finish before the process exits.
#[cfg(unix)]
struct Signals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(windows)]
struct Signals;

impl Signals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self)
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.interrupt.recv() => {}
                _ = self.terminate.recv() => {}
            }
        }
        #[cfg(windows)]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

async fn run_cancellable<T>(
    signals: &mut Signals,
    shutdown: &CancellationToken,
    operation: impl Future<Output = T>,
) -> T {
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => result,
        () = signals.recv() => {
            shutdown.cancel();
            operation.as_mut().await
        },
    }
}

pub fn run_cli() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new(process::ANCHOR_ARG))
        && arguments.next().is_none()
    {
        return match process::anchor() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    let Ok(_diagnostics) = audit::start() else {
        return ExitCode::FAILURE;
    };
    let mut matches = match config::Cli::command()
        .mut_args(|argument| argument.hide_env_values(true))
        .try_get_matches()
    {
        Ok(matches) => matches,
        Err(error) => return cli_error(error),
    };
    let explicit_config =
        matches.value_source("config") == Some(clap::parser::ValueSource::CommandLine);
    let explicit_ssh = ["ssh", "ssh_config"]
        .into_iter()
        .any(|name| matches.value_source(name) == Some(clap::parser::ValueSource::CommandLine));
    let mut cli = match config::Cli::from_arg_matches_mut(&mut matches) {
        Ok(cli) => cli,
        Err(error) => return cli_error(error),
    };
    drop(matches);
    let mut auth_args = None;
    let command = match cli.command.take() {
        Some(config::CliCommand::Catalog(args)) => {
            return standalone_catalog(args, cli, explicit_config, explicit_ssh);
        }
        Some(config::CliCommand::Auth(args)) => {
            auth_args = Some(args);
            None
        }
        Some(config::CliCommand::Doctor(args)) => Some(Diagnostic::Doctor(args)),
        Some(config::CliCommand::Bundle(args)) => Some(Diagnostic::Bundle(args)),
        None => None,
    };
    let diagnostic = command.is_some() || auth_args.is_some();
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
    if let Some(args) = auth_args {
        return auth::run(&config, args);
    }
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

fn standalone_catalog(
    args: catalog::cli::CatalogArgs,
    cli: config::Cli,
    explicit_config: bool,
    explicit_ssh: bool,
) -> ExitCode {
    if let Err(code) = args.validate_global_options(explicit_config, explicit_ssh) {
        audit::emit(&serde_json::json!({"ok":false,"error_code":code}));
        return ExitCode::from(2);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return fail("runtime_start_failed"),
    };
    let status = runtime.block_on(async {
        let Ok(mut signals) = Signals::new() else {
            return fail("signal_setup_failed");
        };
        let shutdown = CancellationToken::new();
        let operation = catalog::cli::run(args, cli, shutdown.clone());
        let status = run_cancellable(&mut signals, &shutdown, operation).await;
        ExitCode::from(status)
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    status
}

async fn run(mut config: config::Config, command: Option<Diagnostic>) -> ExitCode {
    let Ok(mut signals) = Signals::new() else {
        return fail("signal_setup_failed");
    };
    if let Some(command) = command {
        let shutdown = CancellationToken::new();
        let operation = async {
            match command {
                Diagnostic::Doctor(args) => {
                    doctor::run(config, args, shutdown.clone())
                        .await
                        .publish()
                        .await
                }
                Diagnostic::Bundle(args) => {
                    let configured = config.automation_runtime().ok().flatten();
                    bundle::run_cli(args, configured, shutdown.clone()).await
                }
            }
        };
        let report = run_cancellable(&mut signals, &shutdown, operation).await;
        return ExitCode::from(report);
    }
    let shutdown = CancellationToken::new();
    let activated = run_cancellable(
        &mut signals,
        &shutdown,
        config.activate_automation(&shutdown),
    )
    .await;
    let activated = match activated {
        Ok(activated) if !shutdown.is_cancelled() => activated,
        Ok(_) => return fail_phase("cancelled", "activation", "automation"),
        Err(error) => return invalid_config(&error),
    };
    if config.automation_required() && !activated {
        let reference = match config.automation_runtime() {
            Ok(reference) => reference,
            Err(error) => {
                return invalid_config(
                    &error.with_cause("runtime_unavailable", "runtime_selection"),
                );
            }
        };
        let health = bundle::check(reference);
        if !health.is_passed() {
            return fail_phase(
                health.error_code().unwrap_or("runtime_unavailable"),
                "runtime_verification",
                "automation.bundle",
            );
        }
    }
    let application = match server::Estus::new(config) {
        Ok(application) => application,
        Err(error) => return invalid_config(&error),
    };
    let result = run_session(&application, &mut signals).await;
    application.shutdown().await;
    result
}

fn invalid_config(error: &config::ConfigError) -> ExitCode {
    audit::emit(&error.record());
    ExitCode::FAILURE
}

async fn run_session(application: &server::Estus, signals: &mut Signals) -> ExitCode {
    let shutdown = application.shutdown_token();
    let pending = application.pending_replies();
    let overload = pending.overload_token();
    let (input, output) = rmcp::transport::stdio();
    let input = EofStdin {
        inner: input,
        shutdown: shutdown.clone(),
    };
    let transport = progress::BoundedTransport::with_pending(
        rmcp::transport::async_rw::AsyncRwTransport::<rmcp::RoleServer, _, _>::new(input, output),
        pending,
    );
    let service = tokio::select! {
        biased;
        _ = overload.cancelled() => return fail("mcp_session_overloaded"),
        result = application.clone().serve(transport) => match result {
            Ok(service) => service,
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => {
                if overload.is_cancelled() {
                    return fail("mcp_session_overloaded");
                }
                return ExitCode::SUCCESS;
            },
            Err(_) => {
                if overload.is_cancelled() {
                    return fail("mcp_session_overloaded");
                }
                return fail("mcp_initialize_failed");
            }
        },
        () = signals.recv() => return ExitCode::SUCCESS,
    };
    let cancellation = service.cancellation_token();
    let waiting = service.waiting();
    tokio::pin!(waiting);
    tokio::select! {
        biased;
        _ = overload.cancelled() => {},
        result = &mut waiting => {
            if overload.is_cancelled() {
                return fail("mcp_session_overloaded");
            }
            return if result.is_ok() {
                ExitCode::SUCCESS
            } else {
                fail("mcp_session_failed")
            };
        },
        () = signals.recv() => {},
    }
    shutdown.cancel();
    cancellation.cancel();
    let finished = tokio::time::timeout(std::time::Duration::from_secs(2), waiting).await;
    if overload.is_cancelled() {
        return fail("mcp_session_overloaded");
    }
    match finished {
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

fn cli_error(error: clap::Error) -> ExitCode {
    if matches!(
        error.kind(),
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
    ) {
        return if error.print().is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(2)
        };
    }
    audit::emit(&serde_json::json!({
        "event":"error", "code":"invalid_cli_arguments",
        "phase":"cli_parse", "schema_path":"cli",
    }));
    ExitCode::from(2)
}

fn fail_phase(code: &'static str, phase: &'static str, schema_path: &'static str) -> ExitCode {
    audit::emit(&serde_json::json!({
        "event":"error", "code":code, "phase":phase, "schema_path":schema_path,
    }));
    ExitCode::FAILURE
}

fn fail(code: &str) -> ExitCode {
    audit::emit(&serde_json::json!({ "event": "error", "code": code }));
    ExitCode::FAILURE
}
