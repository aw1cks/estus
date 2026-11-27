//! Windows stub for controller script tools (rejected at config validation).
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use crate::bindings::PreparedController;
use crate::config::CleanupDiagnostics;
use crate::progress::Reporter;
use crate::reply::{
    ControllerData, ControllerError, ControllerReply, ControllerTermination, ErrorCode,
    GroupCleanup,
};

pub(crate) const QUARANTINE_CAPACITY: usize = 32;

#[derive(Default)]
pub(crate) struct CleanupQuarantine;

impl CleanupQuarantine {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn snapshot(&self) -> CleanupDiagnostics {
        CleanupDiagnostics {
            capacity: 0,
            child_reap: 0,
            workspace_remove: 0,
        }
    }

    pub(crate) fn try_reserve(self: &Arc<Self>) -> Option<CleanupReservation> {
        Some(CleanupReservation)
    }
}

pub(crate) struct CleanupReservation;

pub(crate) struct ControllerContext<'a> {
    #[allow(dead_code)]
    pub deadline: tokio::time::Instant,
    #[allow(dead_code)]
    pub ct: &'a CancellationToken,
    #[allow(dead_code)]
    pub shutdown: &'a CancellationToken,
    pub started: Instant,
    #[allow(dead_code)]
    pub capture_limit: u64,
    #[allow(dead_code)]
    pub retention: Option<crate::output::Session>,
    #[allow(dead_code)]
    pub progress: Reporter,
}

pub(crate) struct ControllerRun {
    pub reply: ControllerReply,
    pub pending: Option<PendingCleanup>,
}

pub(crate) struct PendingCleanup;

impl PendingCleanup {
    pub(crate) async fn finish_with(
        self,
        _permit: Option<OwnedSemaphorePermit>,
        _slot: Option<CleanupReservation>,
    ) {
    }
}

pub(crate) async fn run(
    _prepared: PreparedController,
    context: ControllerContext<'_>,
) -> ControllerRun {
    let duration_ms = context.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let reply = ControllerReply::with_optional_error(
        ControllerData {
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_lossy: false,
            stderr_lossy: false,
            exit_code: None,
            signal: None,
            termination: ControllerTermination::IoError,
            duration_ms,
            owned_group_cleanup: GroupCleanup::NotStarted,
            output: None,
        },
        Some(ControllerError::new(
            ErrorCode::Unsupported,
            "Controller script tools are not supported on Windows",
        )),
    );
    ControllerRun {
        reply,
        pending: None,
    }
}
