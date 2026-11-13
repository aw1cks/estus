//! Runtime ownership for the private Runner adapter.
use std::sync::atomic::{AtomicU64, Ordering};

use crate::automation_protocol::{self, Completion};
use crate::bindings::PreparedController;
use crate::controller::{self, ControllerContext, PendingCleanup};
use crate::reply::{AutomationData, GroupCleanup, ToolReply};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn invocation_id() -> String {
    // Uniqueness within this process, not synchronization or a security token.
    format!(
        "{:016x}{:016x}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    )
}

pub(crate) struct PreparedAutomation {
    pub controller: PreparedController,
    pub host: String,
    pub projection: Option<std::sync::Arc<crate::projection::Plan>>,
}

pub(crate) struct AutomationRun {
    pub reply: ToolReply<AutomationData>,
    pub pending: Option<PendingCleanup>,
}

pub(crate) async fn run(
    prepared: PreparedAutomation,
    context: ControllerContext<'_>,
) -> AutomationRun {
    let started = context.started;
    let run = controller::run(prepared.controller, context).await;
    let error = run.reply.error.as_ref().map(|e| e.code);
    let group_cleanup = run
        .reply
        .data
        .as_ref()
        .map(|d| d.owned_group_cleanup)
        .unwrap_or(GroupCleanup::NotStarted);
    let local = Completion {
        started_child: group_cleanup != GroupCleanup::NotStarted
            && !matches!(error, Some("spawn_failed" | "resource_unavailable")),
        error,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        group_cleanup,
    };
    AutomationRun {
        reply: automation_protocol::reduce(
            run.automation,
            prepared.host,
            prepared.projection.as_deref(),
            local,
        ),
        pending: run.pending,
    }
}

#[cfg(test)]
mod spawn_failures {
    use super::*;
    use crate::reply::AutomationStatus;
    use std::{
        borrow::Cow,
        collections::BTreeMap,
        sync::Arc,
        time::{Duration, Instant},
    };

    #[tokio::test]
    async fn adapter_spawn_failure_is_not_remote_execution() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-interpreter");
        let prepared = PreparedAutomation {
            host: "logical".into(),
            projection: None,
            controller: PreparedController {
                plan: Arc::new(crate::bindings::ControllerPlan {
                    source: Cow::Borrowed(""),
                    interpreter: missing.to_str().unwrap().to_owned(),
                    interpreter_argv: Vec::new(),
                    cwd: None,
                    environment: BTreeMap::new(),
                    workspace_root: Arc::from(root.path()),
                }),
                input_json: b"{}".to_vec(),
                duration: Duration::from_secs(5),
                max_output_bytes: 1024,
                supervision: controller::ControllerSupervision::Automation {
                    invocation_id: invocation_id(),
                    mode: crate::automation_protocol::ExecutionMode::Module,
                    scratch_bytes: 65536,
                    scratch_files: 32,
                },
            },
        };
        let cancellation = tokio_util::sync::CancellationToken::new();
        let run = run(
            prepared,
            ControllerContext {
                deadline: tokio::time::Instant::now() + Duration::from_secs(5),
                ct: &cancellation,
                shutdown: &cancellation,
                started: Instant::now(),
                capture_limit: 1024,
                retention: None,
                progress: crate::progress::Reporter::default(),
            },
        )
        .await;
        if let Some(pending) = run.pending {
            pending.finish().await;
        }
        let error = run.reply.error.unwrap();
        assert_eq!(error.code, "unsupported");
        assert!(!error.remote_state_unknown);
        assert_eq!(run.reply.data.unwrap().status, AutomationStatus::NotStarted);
        assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
    }
}
