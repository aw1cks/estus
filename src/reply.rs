use schemars::JsonSchema;
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ToolReply<T> {
    pub(crate) data: Option<T>,
    pub(crate) error: Option<ToolError>,
}

impl<T> ToolReply<T> {
    pub(crate) fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }
    pub(crate) fn failure(error: ToolError) -> Self {
        Self {
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ToolError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) remote_state_unknown: bool,
}

impl ToolError {
    pub(crate) const SSH_CONNECT_FAILED: Self = Self::new(
        "ssh_connect_failed",
        "SSH connection failed; verify the configured alias, authentication and known hosts with your SSH client outside MCP",
        false,
    );

    pub(crate) const fn new(
        code: &'static str,
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self {
            code,
            message,
            remote_state_unknown,
        }
    }
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Termination {
    Exited,
    Timeout,
    Cancelled,
    ConnectionLost,
}

#[derive(Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum OutputReceipt {
    Ready {
        handle: String,
        expires_in_secs: u64,
        stdout: StreamInfo,
        stderr: StreamInfo,
    },
    Unavailable {
        reason: &'static str,
    },
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct StreamInfo {
    pub bytes_retained: u64,
    pub total_bytes: u64,
    pub truncated: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct CommandData {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_lossy: bool,
    pub stderr_lossy: bool,
    pub exit_code: Option<i32>,
    pub termination: Termination,
    pub duration_ms: u64,
    pub remote_may_still_be_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputReceipt>,
}

/// Sanitized local failure; controller errors never describe remote state.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ControllerError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
}

impl ControllerError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ControllerReply {
    pub(crate) data: Option<ControllerData>,
    pub(crate) error: Option<ControllerError>,
}

impl ControllerReply {
    pub(crate) fn success(data: ControllerData) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }

    pub(crate) fn failure(error: ControllerError) -> Self {
        Self {
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControllerTermination {
    Exited,
    Signalled,
    Timeout,
    Cancelled,
    IoError,
}

/// Evidence about the anchored group signal and the two directly owned children.
///
/// `SignalledAndReaped` does not claim descendant containment, disappearance,
/// rollback of effects, or reaping of descendants not directly owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GroupCleanup {
    /// This executor creates no per-request controller process group.
    NotApplicable,
    NotStarted,
    SignalledAndReaped,
    Incomplete,
}

/// Local output and observed cleanup evidence, not a rollback guarantee.
///
/// Interrupted execution may already have produced effects. Cleanup describes
/// only the owned anchored process group and directly owned children.

#[derive(Serialize, JsonSchema)]
pub(crate) struct ControllerData {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_lossy: bool,
    pub stderr_lossy: bool,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub termination: ControllerTermination,
    pub duration_ms: u64,
    pub owned_group_cleanup: GroupCleanup,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputReceipt>,
}

/// Bounded execution evidence and optional explicitly selected module data.
#[derive(Serialize, JsonSchema)]
pub(crate) struct AutomationData {
    pub host: String,
    pub status: AutomationStatus,
    pub runner_rc: Option<i32>,
    pub changed: Option<bool>,
    pub tasks: AutomationTasks,
    pub censored: bool,
    pub complete: bool,
    pub duration_ms: u64,
    pub owned_group_cleanup: GroupCleanup,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<ModuleProjection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AutomationStatus {
    NotStarted,
    Successful,
    Failed,
    Unreachable,
    Cancelled,
    Timeout,
    InvalidResult,
    ResourceLimit,
    WorkerLost,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, serde::Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutomationTasks {
    pub ok: u32,
    pub failed: u32,
    pub unreachable: u32,
    pub skipped: u32,
    #[serde(default, skip_serializing_if = "zero_count")]
    pub rescued: u32,
    #[serde(default, skip_serializing_if = "zero_count")]
    pub ignored: u32,
}

fn zero_count(value: &u32) -> bool {
    *value == 0
}

/// Projection availability is independent of authoritative workflow completion.
#[derive(Debug, Serialize, serde::Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ModuleProjection {
    Complete { value: serde_json::Value },
    Truncated { value: serde_json::Value },
    Censored,
    Invalid,
    Unavailable,
}
