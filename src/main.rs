mod server;

use std::process::ExitCode;

use clap::Parser;
use rmcp::ServiceExt;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() -> ExitCode {
    Cli::parse();
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let status = runtime.block_on(run());
            // Tokio's blocking stdin reader cannot be cancelled while stdin stays open.
            runtime.shutdown_timeout(std::time::Duration::from_secs(2));
            status
        }
        Err(_) => fail("runtime_start_failed"),
    }
}

async fn run() -> ExitCode {
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        return fail("signal_setup_failed");
    };
    let service = tokio::select! {
        result = server::SshMcp::new().serve(rmcp::transport::stdio()) => match result {
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
    cancellation.cancel();
    match tokio::time::timeout(std::time::Duration::from_secs(2), waiting).await {
        Ok(Ok(_)) => ExitCode::SUCCESS,
        _ => fail("mcp_shutdown_failed"),
    }
}

fn fail(code: &str) -> ExitCode {
    eprintln!("{}", serde_json::json!({ "event": "error", "code": code }));
    ExitCode::FAILURE
}
