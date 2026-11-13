//! The private Runner protocol carries bounded evidence, never raw module results.
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;

use crate::bindings::PreparedController;
use crate::controller::{self, ControllerContext, PendingCleanup};
use crate::reply::{
    AutomationData, AutomationStatus, AutomationTasks, GroupCleanup, ToolError, ToolReply,
};

const FRAME_LIMIT: usize = 8192;
const STREAM_LIMIT: usize = 65_536;
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
}

pub(crate) struct AutomationRun {
    pub reply: ToolReply<AutomationData>,
    pub pending: Option<PendingCleanup>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TaskOutcome {
    Ok,
    Failed,
    Unreachable,
    Skipped,
}

impl TaskOutcome {
    fn tasks(self) -> AutomationTasks {
        let mut tasks = AutomationTasks::default();
        match self {
            Self::Ok => tasks.ok = 1,
            Self::Failed => tasks.failed = 1,
            Self::Unreachable => tasks.unreachable = 1,
            Self::Skipped => tasks.skipped = 1,
        }
        tasks
    }
}

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    Ready {
        schema: u32,
        id: String,
    },
    Task {
        schema: u32,
        id: String,
        outcome: TaskOutcome,
        #[serde(deserialize_with = "nullable")]
        changed: Option<bool>,
        censored: bool,
    },
    Terminal {
        schema: u32,
        id: String,
        status: AutomationStatus,
        #[serde(deserialize_with = "nullable")]
        rc: Option<i32>,
        #[serde(deserialize_with = "nullable")]
        changed: Option<bool>,
        tasks: AutomationTasks,
        censored: bool,
        complete: bool,
    },
}

struct Task {
    tasks: AutomationTasks,
    changed: Option<bool>,
    censored: bool,
}

struct Terminal {
    status: AutomationStatus,
    rc: Option<i32>,
    task: Task,
    complete: bool,
}

pub(crate) struct Evidence {
    id: String,
    line: Vec<u8>,
    bytes: usize,
    ready: bool,
    task: Option<Task>,
    terminal: Option<Terminal>,
    invalid: bool,
    resource: bool,
    completed_before_stop: bool,
}

impl Evidence {
    pub(crate) fn new(id: String) -> Self {
        Self {
            id,
            line: Vec::new(),
            bytes: 0,
            ready: false,
            task: None,
            terminal: None,
            invalid: false,
            resource: false,
            completed_before_stop: false,
        }
    }

    pub(crate) fn failed(&self) -> bool {
        self.invalid || self.resource
    }
    pub(crate) fn resource_limited(&self) -> bool {
        self.resource
    }

    pub(crate) fn stop(&mut self) {
        self.completed_before_stop = self.terminal.as_ref().is_some_and(|t| t.complete);
    }

    pub(crate) fn finish(&mut self) {
        if !self.line.is_empty() {
            self.invalid = true;
        }
    }

    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        if self.failed() {
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes.len());
        if self.bytes > STREAM_LIMIT {
            self.resource = true;
            return;
        }
        for &byte in bytes {
            if self.terminal.is_some() {
                self.invalid = true;
                return;
            }
            if self.line.len() >= FRAME_LIMIT - 1 {
                self.resource = true;
                return;
            }
            if byte == b'\n' {
                let frame = serde_json::from_slice::<Frame>(&self.line);
                self.line.clear();
                match frame {
                    Ok(frame) => self.frame(frame),
                    Err(_) => self.invalid = true,
                }
                if self.failed() {
                    return;
                }
            } else {
                self.line.push(byte);
            }
        }
    }

    fn frame(&mut self, frame: Frame) {
        let (schema, id) = match &frame {
            Frame::Ready { schema, id }
            | Frame::Task { schema, id, .. }
            | Frame::Terminal { schema, id, .. } => (*schema, id),
        };
        if schema != 1 || id != &self.id {
            self.invalid = true;
            return;
        }
        match frame {
            Frame::Ready { .. } => {
                if self.ready || self.task.is_some() {
                    self.invalid = true;
                }
                self.ready = true;
            }
            Frame::Task {
                outcome,
                changed,
                censored,
                ..
            } => {
                if !self.ready
                    || self.task.is_some()
                    || (matches!(outcome, TaskOutcome::Unreachable | TaskOutcome::Skipped)
                        && changed == Some(true))
                {
                    self.invalid = true;
                    return;
                }
                self.task = Some(Task {
                    tasks: outcome.tasks(),
                    changed,
                    censored,
                });
            }
            Frame::Terminal {
                status,
                rc,
                changed,
                tasks,
                censored,
                complete,
                ..
            } => {
                let total = u64::from(tasks.ok)
                    + u64::from(tasks.failed)
                    + u64::from(tasks.unreachable)
                    + u64::from(tasks.skipped);
                if total > 1
                    || (complete && (!self.ready || total != 1))
                    || self.task.as_ref().is_some_and(|task| {
                        task.tasks != tasks
                            || task.censored != censored
                            || (task.changed.is_some() && task.changed != changed)
                            || (censored && changed.is_some())
                    })
                    || (self.task.is_none() && total != 0)
                {
                    self.invalid = true;
                    return;
                }
                let coherent = match status {
                    AutomationStatus::Successful => complete && rc == Some(0) && tasks.ok == 1,
                    AutomationStatus::Failed => {
                        complete && rc.is_some_and(|rc| rc != 0) && tasks.failed == 1
                    }
                    AutomationStatus::Unreachable => {
                        complete && rc.is_some_and(|rc| rc != 0) && tasks.unreachable == 1
                    }
                    AutomationStatus::Cancelled
                    | AutomationStatus::Timeout
                    | AutomationStatus::InvalidResult
                    | AutomationStatus::ResourceLimit => !complete,
                    AutomationStatus::NotStarted | AutomationStatus::WorkerLost => false,
                };
                if !coherent {
                    self.invalid = true;
                    return;
                }
                self.terminal = Some(Terminal {
                    status,
                    rc,
                    task: Task {
                        tasks,
                        changed,
                        censored,
                    },
                    complete,
                });
            }
        }
    }
}

pub(crate) async fn run(
    prepared: PreparedAutomation,
    context: ControllerContext<'_>,
) -> AutomationRun {
    let started = context.started;
    let run = controller::run(prepared.controller, context).await;
    let evidence = run.automation;
    let complete = evidence
        .as_ref()
        .and_then(|e| e.terminal.as_ref())
        .is_some_and(|t| t.complete);
    let local_error = run.reply.error.as_ref().map(|e| e.code);
    let started_child = run
        .reply
        .data
        .as_ref()
        .is_some_and(|d| d.owned_group_cleanup != GroupCleanup::NotStarted)
        && !matches!(local_error, Some("spawn_failed" | "resource_unavailable"));
    let unknown = started_child && !complete;
    let terminal = evidence.as_ref().and_then(|e| e.terminal.as_ref());
    let observed = terminal
        .map(|t| &t.task)
        .or_else(|| evidence.as_ref().and_then(|e| e.task.as_ref()));
    let invalid = evidence.as_ref().is_none_or(|e| e.invalid);
    let resource = evidence.as_ref().is_some_and(|e| e.resource);
    let preserve = evidence.as_ref().is_some_and(|e| e.completed_before_stop);
    let (status, error) = if resource || local_error == Some("resource_limit") {
        (
            AutomationStatus::ResourceLimit,
            Some(ToolError::new(
                "resource_limit",
                "Automation scratch or protocol budget exceeded",
                unknown,
            )),
        )
    } else if matches!(local_error, Some("timeout" | "cancelled")) && !preserve {
        if local_error == Some("timeout") {
            (
                AutomationStatus::Timeout,
                Some(ToolError::new(
                    "timeout",
                    "Automation deadline exceeded; remote work may continue",
                    unknown,
                )),
            )
        } else {
            (
                AutomationStatus::Cancelled,
                Some(ToolError::new(
                    "cancelled",
                    "Automation cancelled; remote work may continue",
                    unknown,
                )),
            )
        }
    } else if invalid {
        (
            AutomationStatus::InvalidResult,
            Some(ToolError::new(
                "invalid_result",
                "Automation adapter contract was violated",
                unknown,
            )),
        )
    } else if let Some(terminal) = terminal {
        let error = match terminal.status {
            AutomationStatus::Successful => local_error
                .filter(|code| !preserve || !matches!(*code, "timeout" | "cancelled"))
                .map(|_| {
                    ToolError::new(
                        "cleanup_incomplete",
                        "Automation local cleanup is incomplete",
                        false,
                    )
                }),
            AutomationStatus::Failed | AutomationStatus::Unreachable => Some(ToolError::new(
                "automation_failed",
                "Automation module failed or was unreachable",
                unknown,
            )),
            AutomationStatus::Cancelled => Some(ToolError::new(
                "cancelled",
                "Automation cancelled; remote work may continue",
                unknown,
            )),
            AutomationStatus::Timeout => Some(ToolError::new(
                "timeout",
                "Automation deadline exceeded; remote work may continue",
                unknown,
            )),
            AutomationStatus::ResourceLimit => Some(ToolError::new(
                "resource_limit",
                "Automation scratch budget exceeded",
                unknown,
            )),
            _ => Some(ToolError::new(
                "invalid_result",
                "Automation did not establish a valid result",
                unknown,
            )),
        };
        (terminal.status, error)
    } else if !started_child {
        (
            AutomationStatus::NotStarted,
            Some(ToolError::new(
                "unsupported",
                "Automation runtime could not start",
                false,
            )),
        )
    } else {
        (
            AutomationStatus::WorkerLost,
            Some(ToolError::new(
                "invalid_result",
                "Automation worker exited without terminal evidence",
                true,
            )),
        )
    };
    let data = AutomationData {
        host: prepared.host,
        status,
        runner_rc: terminal.and_then(|t| t.rc),
        changed: observed.and_then(|t| t.changed),
        tasks: observed.map(|t| t.tasks).unwrap_or_default(),
        censored: observed.is_some_and(|t| t.censored),
        complete,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        owned_group_cleanup: run
            .reply
            .data
            .map(|d| d.owned_group_cleanup)
            .unwrap_or(GroupCleanup::NotStarted),
    };
    AutomationRun {
        reply: ToolReply {
            data: Some(data),
            error,
        },
        pending: run.pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn frame(kind: &str) -> Value {
        json!({"schema":1,"id":"test","kind":kind})
    }
    fn send(e: &mut Evidence, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        e.feed(&bytes);
    }
    fn completed() -> Evidence {
        let mut e = Evidence::new("test".into());
        send(&mut e, frame("ready"));
        let mut task = frame("task");
        task["outcome"] = json!("ok");
        task["changed"] = json!(false);
        task["censored"] = json!(false);
        send(&mut e, task);
        let mut t = frame("terminal");
        t["status"] = json!("successful");
        t["rc"] = json!(0);
        t["changed"] = json!(false);
        t["tasks"] = json!({"ok":1,"failed":0,"unreachable":0,"skipped":0});
        t["censored"] = json!(false);
        t["complete"] = json!(true);
        send(&mut e, t);
        e
    }

    #[test]
    fn terminal_requires_singleton_task_and_reconciled_status() {
        let valid = completed();
        assert!(!valid.failed());
        assert!(valid.terminal.unwrap().complete);
        for patch in [
            json!({"rc":2}),
            json!({"tasks":{"ok":0,"failed":0,"unreachable":0,"skipped":0}}),
            json!({"status":"failed"}),
            json!({"changed":true}),
            json!({"complete":false}),
        ] {
            let mut e = completed();
            e.terminal = None;
            let mut terminal = frame("terminal");
            terminal["status"] = json!("successful");
            terminal["rc"] = json!(0);
            terminal["changed"] = json!(false);
            terminal["tasks"] = json!({"ok":1,"failed":0,"unreachable":0,"skipped":0});
            terminal["censored"] = json!(false);
            terminal["complete"] = json!(true);
            terminal
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            send(&mut e, terminal);
            assert!(e.failed());
        }
        let mut missing = Evidence::new("test".into());
        send(&mut missing, frame("ready"));
        let mut terminal = frame("terminal");
        terminal["status"] = json!("successful");
        terminal["rc"] = json!(0);
        terminal["changed"] = Value::Null;
        terminal["tasks"] = json!({"ok":1,"failed":0,"unreachable":0,"skipped":0});
        terminal["censored"] = json!(false);
        terminal["complete"] = json!(true);
        send(&mut missing, terminal);
        assert!(missing.failed());
    }

    #[test]
    fn authoritative_stats_can_refine_omitted_large_event_change_evidence() {
        let mut evidence = Evidence::new("test".into());
        send(&mut evidence, frame("ready"));
        let mut task = frame("task");
        task["outcome"] = json!("ok");
        task["changed"] = Value::Null;
        task["censored"] = json!(false);
        send(&mut evidence, task);
        let mut terminal = frame("terminal");
        terminal["status"] = json!("successful");
        terminal["rc"] = json!(0);
        terminal["changed"] = json!(true);
        terminal["tasks"] = json!({"ok":1,"failed":0,"unreachable":0,"skipped":0});
        terminal["censored"] = json!(false);
        terminal["complete"] = json!(true);
        send(&mut evidence, terminal);
        assert!(!evidence.failed());
        let terminal = evidence.terminal.unwrap();
        assert!(terminal.complete);
        assert_eq!(terminal.task.changed, Some(true));
    }

    #[test]
    fn framing_identity_bounds_and_post_terminal_corruption_fail_closed() {
        for bytes in [
            b"{\"kind\":\"ready\",\"schema\":2,\"id\":\"test\"}\n".as_slice(),
            b"{\"kind\":\"ready\",\"schema\":1,\"id\":\"other\"}\n",
            b"not-json\n",
        ] {
            let mut e = Evidence::new("test".into());
            e.feed(bytes);
            assert!(e.failed());
        }
        let mut partial = Evidence::new("test".into());
        partial.feed(b"{\"kind\":");
        partial.finish();
        assert!(partial.failed());
        let mut oversized = Evidence::new("test".into());
        oversized.feed(&vec![b'x'; FRAME_LIMIT]);
        assert!(oversized.resource_limited());
        let mut completed = completed();
        completed.stop();
        completed.feed(b"garbage\n");
        assert!(completed.failed());
        assert!(completed.terminal.unwrap().complete);
        assert!(completed.completed_before_stop);
    }

    #[test]
    fn repeated_or_unready_task_observations_are_not_completion() {
        let mut ready = Evidence::new("test".into());
        send(&mut ready, frame("ready"));
        send(&mut ready, frame("ready"));
        assert!(ready.failed());
        let mut e = Evidence::new("test".into());
        let mut task = frame("task");
        task["outcome"] = json!("ok");
        task["changed"] = json!(false);
        task["censored"] = json!(false);
        send(&mut e, task);
        assert!(e.failed());
        let mut e = completed();
        e.terminal = None;
        let mut task = frame("task");
        task["outcome"] = json!("ok");
        task["changed"] = json!(false);
        task["censored"] = json!(false);
        send(&mut e, task);
        assert!(e.failed());
    }
}

#[cfg(test)]
mod spawn_failures {
    use super::*;
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

#[cfg(test)]
mod required_protocol_fields {
    use super::*;

    #[test]
    fn nullable_evidence_is_not_an_optional_protocol_field() {
        let mut evidence = Evidence::new("test".into());
        evidence.feed(b"{\"schema\":1,\"id\":\"test\",\"kind\":\"ready\"}\n");
        evidence.feed(b"{\"schema\":1,\"id\":\"test\",\"kind\":\"task\",\"outcome\":\"ok\",\"censored\":false}\n");
        assert!(
            evidence.failed(),
            "missing changed is not explicit unknown evidence"
        );
    }
}
