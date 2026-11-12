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
}
