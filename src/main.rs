mod audit;
mod bindings;
mod command;
mod config;
mod exec;
mod filedata;
mod filemeta;
mod files;
mod reply;
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
    let config = match config::Config::load(config::Cli::parse()) {
        Ok(config) => config,
        Err(error) => return invalid_config(&error),
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let status = runtime.block_on(run(config));
            // Tokio's blocking stdin reader cannot be cancelled while stdin stays open.
            runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            status
        }
        Err(_) => fail("runtime_start_failed"),
    }
}

async fn run(config: config::Config) -> ExitCode {
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        return fail("signal_setup_failed");
    };
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
