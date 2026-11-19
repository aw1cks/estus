use std::borrow::Cow;

use schemars::JsonSchema;
use serde::{Serialize, ser::SerializeStruct};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ErrorCode {
    AlreadyExists,
    AutomationFailed,
    Cancelled,
    ChecksumMismatch,
    CleanupIncomplete,
    CommandFailed,
    ConnectionLost,
    ControllerResourceLimit,
    #[cfg(test)]
    ControllerTimeout,
    DiscoveryFailed,
    InvalidArgument,
    InvalidEncoding,
    InvalidProjection,
    InvalidResult,
    IoError,
    NotFound,
    PayloadFailed,
    PayloadRejected,
    PermissionDenied,
    PolicyDenied,
    PreviewRequired,
    ResourceLimit,
    ResourceUnavailable,
    Shutdown,
    SpawnFailed,
    SshConnectFailed,
    SshSpawnFailed,
    TargetQuarantined,
    Timeout,
    Unsupported,
    UnsupportedWorkspaceEntry,
}

impl ErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyExists => "already_exists",
            Self::AutomationFailed => "automation_failed",
            Self::Cancelled => "cancelled",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::CleanupIncomplete => "cleanup_incomplete",
            Self::CommandFailed => "command_failed",
            Self::ConnectionLost => "connection_lost",
            Self::ControllerResourceLimit => "controller_resource_limit",
            #[cfg(test)]
            Self::ControllerTimeout => "controller_timeout",
            Self::DiscoveryFailed => "discovery_failed",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidProjection => "invalid_projection",
            Self::InvalidResult => "invalid_result",
            Self::IoError => "io_error",
            Self::NotFound => "not_found",
            Self::PayloadFailed => "payload_failed",
            Self::PayloadRejected => "payload_rejected",
            Self::PermissionDenied => "permission_denied",
            Self::PolicyDenied => "policy_denied",
            Self::PreviewRequired => "preview_required",
            Self::ResourceLimit => "resource_limit",
            Self::ResourceUnavailable => "resource_unavailable",
            Self::Shutdown => "shutdown",
            Self::SpawnFailed => "spawn_failed",
            Self::SshConnectFailed => "ssh_connect_failed",
            Self::SshSpawnFailed => "ssh_spawn_failed",
            Self::TargetQuarantined => "target_quarantined",
            Self::Timeout => "timeout",
            Self::Unsupported => "unsupported",
            Self::UnsupportedWorkspaceEntry => "unsupported_workspace_entry",
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl JsonSchema for ErrorCode {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        <&str>::schema_name()
    }

    fn schema_id() -> Cow<'static, str> {
        <&str>::schema_id()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <&str>::json_schema(generator)
    }
}

#[derive(Clone, Debug)]
enum ReplyOutcome<T, E = ToolError> {
    Success(T),
    Failure(E),
    Partial { data: T, error: E },
}

impl<T, E> ReplyOutcome<T, E> {
    fn data(&self) -> Option<&T> {
        match self {
            Self::Success(data) | Self::Partial { data, .. } => Some(data),
            Self::Failure(_) => None,
        }
    }

    fn data_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Success(data) | Self::Partial { data, .. } => Some(data),
            Self::Failure(_) => None,
        }
    }

    fn error(&self) -> Option<&E> {
        match self {
            Self::Failure(error) | Self::Partial { error, .. } => Some(error),
            Self::Success(_) => None,
        }
    }

    fn error_mut(&mut self) -> Option<&mut E> {
        match self {
            Self::Failure(error) | Self::Partial { error, .. } => Some(error),
            Self::Success(_) => None,
        }
    }
}

fn serialize_reply<S: serde::Serializer, T: Serialize, E: Serialize>(
    name: &'static str,
    outcome: &ReplyOutcome<T, E>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut state = serializer.serialize_struct(name, 2)?;
    state.serialize_field("data", &outcome.data())?;
    state.serialize_field("error", &outcome.error())?;
    state.end()
}

pub struct ToolReply<T> {
    outcome: ReplyOutcome<T>,
}

#[derive(JsonSchema)]
#[allow(dead_code)]
struct ToolReplySchema<T> {
    data: Option<T>,
    error: Option<ToolError>,
}

impl<T: Serialize> Serialize for ToolReply<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_reply("ToolReply", &self.outcome, serializer)
    }
}

impl<T: JsonSchema> JsonSchema for ToolReply<T> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Owned(format!("ToolReply_for_{}", T::schema_name()))
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Owned(format!("{}::ToolReply<{}>", module_path!(), T::schema_id()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        ToolReplySchema::<T>::json_schema(generator)
    }
}

impl<T> ToolReply<T> {
    pub fn success(data: T) -> Self {
        Self {
            outcome: ReplyOutcome::Success(data),
        }
    }

    pub fn failure(error: ToolError) -> Self {
        Self {
            outcome: ReplyOutcome::Failure(error),
        }
    }

    pub fn partial(data: T, error: ToolError) -> Self {
        Self {
            outcome: ReplyOutcome::Partial { data, error },
        }
    }

    pub(crate) fn with_optional_error(data: T, error: Option<ToolError>) -> Self {
        match error {
            Some(error) => Self::partial(data, error),
            None => Self::success(data),
        }
    }

    pub fn data(&self) -> Option<&T> {
        self.outcome.data()
    }

    pub fn data_mut(&mut self) -> Option<&mut T> {
        self.outcome.data_mut()
    }

    pub fn error(&self) -> Option<&ToolError> {
        self.outcome.error()
    }

    pub(crate) fn error_mut(&mut self) -> Option<&mut ToolError> {
        self.outcome.error_mut()
    }

    pub(crate) fn set_error(&mut self, error: ToolError) {
        let placeholder = ReplyOutcome::Failure(ToolError::io_error("", false));
        let current = std::mem::replace(&mut self.outcome, placeholder);
        self.outcome = match current {
            ReplyOutcome::Success(data) | ReplyOutcome::Partial { data, .. } => {
                ReplyOutcome::Partial { data, error }
            }
            ReplyOutcome::Failure(_) => ReplyOutcome::Failure(error),
        };
    }

    pub(crate) fn map_ok<U>(self, f: impl FnOnce(T) -> Result<U, ToolError>) -> ToolReply<U> {
        match self.outcome {
            ReplyOutcome::Success(data) => match f(data) {
                Ok(mapped) => ToolReply::success(mapped),
                Err(error) => ToolReply::failure(error),
            },
            ReplyOutcome::Failure(error) => ToolReply::failure(error),
            ReplyOutcome::Partial { data, error } => match f(data) {
                Ok(mapped) => ToolReply::partial(mapped, error),
                Err(mapped_err) => ToolReply::failure(mapped_err),
            },
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ToolError {
    code: ErrorCode,
    pub message: Cow<'static, str>,
    pub remote_state_unknown: bool,
}

impl ToolError {
    pub const SSH_CONNECT_FAILED: Self = Self::new(
        ErrorCode::SshConnectFailed,
        "SSH connection failed; run `estus doctor --target <host>` outside MCP to diagnose alias, authentication and known hosts",
        false,
    );

    const fn new(code: ErrorCode, message: &'static str, remote_state_unknown: bool) -> Self {
        Self {
            code,
            message: Cow::Borrowed(message),
            remote_state_unknown,
        }
    }

    pub const fn code(&self) -> &'static str {
        self.code.as_str()
    }

    pub(crate) const fn already_exists(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::AlreadyExists, message, remote_state_unknown)
    }

    pub(crate) const fn automation_failed(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::AutomationFailed, message, remote_state_unknown)
    }

    pub(crate) const fn cancelled(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::Cancelled, message, remote_state_unknown)
    }

    pub(crate) const fn checksum_mismatch(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::ChecksumMismatch, message, remote_state_unknown)
    }

    pub(crate) const fn cleanup_incomplete(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::CleanupIncomplete, message, remote_state_unknown)
    }

    pub(crate) const fn command_failed(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::CommandFailed, message, remote_state_unknown)
    }

    pub const fn connection_lost(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::ConnectionLost, message, remote_state_unknown)
    }

    pub(crate) const fn discovery_failed(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::DiscoveryFailed, message, remote_state_unknown)
    }

    pub(crate) const fn invalid_argument(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::InvalidArgument, message, remote_state_unknown)
    }

    pub(crate) fn invalid_argument_owned(message: String) -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
            message: Cow::Owned(message),
            remote_state_unknown: false,
        }
    }

    pub(crate) const fn invalid_encoding(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::InvalidEncoding, message, remote_state_unknown)
    }

    pub(crate) const fn invalid_projection(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::InvalidProjection, message, remote_state_unknown)
    }

    pub(crate) const fn invalid_result(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::InvalidResult, message, remote_state_unknown)
    }

    pub(crate) const fn io_error(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::IoError, message, remote_state_unknown)
    }

    pub(crate) const fn not_found(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::NotFound, message, remote_state_unknown)
    }

    pub(crate) const fn payload_failed(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::PayloadFailed, message, remote_state_unknown)
    }

    pub(crate) const fn payload_rejected(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::PayloadRejected, message, remote_state_unknown)
    }

    pub(crate) const fn permission_denied(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::PermissionDenied, message, remote_state_unknown)
    }

    pub(crate) const fn policy_denied(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::PolicyDenied, message, remote_state_unknown)
    }

    pub(crate) const fn preview_required(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::PreviewRequired, message, remote_state_unknown)
    }

    pub(crate) const fn resource_limit(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::ResourceLimit, message, remote_state_unknown)
    }

    pub(crate) const fn shutdown(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::Shutdown, message, remote_state_unknown)
    }

    pub(crate) const fn ssh_spawn_failed(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::SshSpawnFailed, message, remote_state_unknown)
    }

    pub(crate) const fn target_quarantined(
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self::new(ErrorCode::TargetQuarantined, message, remote_state_unknown)
    }

    pub(crate) const fn timeout(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::Timeout, message, remote_state_unknown)
    }

    pub(crate) const fn unsupported(message: &'static str, remote_state_unknown: bool) -> Self {
        Self::new(ErrorCode::Unsupported, message, remote_state_unknown)
    }
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Exited,
    Timeout,
    Cancelled,
    ConnectionLost,
}

#[derive(Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OutputReceipt {
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
pub struct StreamInfo {
    pub bytes_retained: u64,
    pub total_bytes: u64,
    pub truncated: bool,
}

#[derive(Serialize, JsonSchema)]
pub struct CommandData {
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
    code: ErrorCode,
    pub(crate) message: &'static str,
}

impl ControllerError {
    const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code.as_str()
    }

    pub(crate) const fn cancelled(message: &'static str) -> Self {
        Self::new(ErrorCode::Cancelled, message)
    }

    pub(crate) const fn cleanup_incomplete(message: &'static str) -> Self {
        Self::new(ErrorCode::CleanupIncomplete, message)
    }

    pub(crate) const fn command_failed(message: &'static str) -> Self {
        Self::new(ErrorCode::CommandFailed, message)
    }

    pub(crate) const fn controller_resource_limit(message: &'static str) -> Self {
        Self::new(ErrorCode::ControllerResourceLimit, message)
    }

    #[cfg(test)]
    pub(crate) const fn controller_timeout(message: &'static str) -> Self {
        Self::new(ErrorCode::ControllerTimeout, message)
    }

    pub(crate) const fn invalid_argument(message: &'static str) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    pub(crate) const fn invalid_result(message: &'static str) -> Self {
        Self::new(ErrorCode::InvalidResult, message)
    }

    pub(crate) const fn io_error(message: &'static str) -> Self {
        Self::new(ErrorCode::IoError, message)
    }

    pub(crate) const fn policy_denied(message: &'static str) -> Self {
        Self::new(ErrorCode::PolicyDenied, message)
    }

    pub(crate) const fn resource_limit(message: &'static str) -> Self {
        Self::new(ErrorCode::ResourceLimit, message)
    }

    pub(crate) const fn resource_unavailable(message: &'static str) -> Self {
        Self::new(ErrorCode::ResourceUnavailable, message)
    }

    pub(crate) const fn spawn_failed(message: &'static str) -> Self {
        Self::new(ErrorCode::SpawnFailed, message)
    }

    pub(crate) const fn timeout(message: &'static str) -> Self {
        Self::new(ErrorCode::Timeout, message)
    }

    pub(crate) const fn unsupported_workspace_entry(message: &'static str) -> Self {
        Self::new(ErrorCode::UnsupportedWorkspaceEntry, message)
    }
}

pub(crate) struct ControllerReply {
    outcome: ReplyOutcome<ControllerData, ControllerError>,
}

#[derive(JsonSchema)]
#[allow(dead_code)]
struct ControllerReplySchema {
    data: Option<ControllerData>,
    error: Option<ControllerError>,
}

impl Serialize for ControllerReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_reply("ControllerReply", &self.outcome, serializer)
    }
}

impl JsonSchema for ControllerReply {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ControllerReply")
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Owned(format!("{}::ControllerReply", module_path!()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        ControllerReplySchema::json_schema(generator)
    }
}

impl ControllerReply {
    pub(crate) fn success(data: ControllerData) -> Self {
        Self {
            outcome: ReplyOutcome::Success(data),
        }
    }

    pub(crate) fn failure(error: ControllerError) -> Self {
        Self {
            outcome: ReplyOutcome::Failure(error),
        }
    }

    pub(crate) fn partial(data: ControllerData, error: ControllerError) -> Self {
        Self {
            outcome: ReplyOutcome::Partial { data, error },
        }
    }

    pub(crate) fn with_optional_error(
        data: ControllerData,
        error: Option<ControllerError>,
    ) -> Self {
        match error {
            Some(error) => Self::partial(data, error),
            None => Self::success(data),
        }
    }

    pub(crate) fn data(&self) -> Option<&ControllerData> {
        self.outcome.data()
    }

    pub(crate) fn into_parts(self) -> (Option<ControllerData>, Option<ControllerError>) {
        match self.outcome {
            ReplyOutcome::Success(data) => (Some(data), None),
            ReplyOutcome::Failure(error) => (None, Some(error)),
            ReplyOutcome::Partial { data, error } => (Some(data), Some(error)),
        }
    }

    pub(crate) fn data_mut(&mut self) -> Option<&mut ControllerData> {
        self.outcome.data_mut()
    }

    pub(crate) fn error(&self) -> Option<&ControllerError> {
        self.outcome.error()
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
pub enum GroupCleanup {
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
pub struct AutomationData {
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
pub enum AutomationStatus {
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
pub struct AutomationTasks {
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
pub enum ModuleProjection {
    Complete { value: serde_json::Value },
    Truncated { value: serde_json::Value },
    Censored,
    Invalid,
    Unavailable,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ClearTargetQuarantineData {
    pub cleared: bool,
    pub was_quarantined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_cause: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn reply_outcome_states_and_schemas_match_wire_contract() {
        let success = serde_json::to_value(ToolReply::success("ok")).unwrap();
        assert_eq!(success, json!({"data": "ok", "error": null}));

        let failure =
            serde_json::to_value(ToolReply::<&str>::failure(ToolError::SSH_CONNECT_FAILED))
                .unwrap();
        assert_eq!(
            failure,
            json!({
                "data": null,
                "error": {
                    "code": "ssh_connect_failed",
                    "message": ToolError::SSH_CONNECT_FAILED.message.as_ref(),
                    "remote_state_unknown": false,
                }
            })
        );

        let mut partial_reply = ToolReply::success("partial");
        partial_reply.set_error(ToolError::timeout("deadline exceeded", true));
        let partial = serde_json::to_value(partial_reply).unwrap();
        assert_eq!(
            partial,
            json!({
                "data": "partial",
                "error": {
                    "code": "timeout",
                    "message": "deadline exceeded",
                    "remote_state_unknown": true,
                }
            })
        );

        let controller_data = || ControllerData {
            stdout: String::from("out"),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_lossy: false,
            stderr_lossy: false,
            exit_code: Some(0),
            signal: None,
            termination: ControllerTermination::Exited,
            duration_ms: 1,
            owned_group_cleanup: GroupCleanup::SignalledAndReaped,
            output: None,
        };
        assert!(
            serde_json::to_value(ControllerReply::success(controller_data())).unwrap()["error"]
                .is_null()
        );
        assert!(
            serde_json::to_value(ControllerReply::failure(ControllerError::cancelled(
                "stopped"
            )))
            .unwrap()["data"]
                .is_null()
        );
        let c_partial = serde_json::to_value(ControllerReply::partial(
            controller_data(),
            ControllerError::cleanup_incomplete("dirty"),
        ))
        .unwrap();
        assert_eq!(c_partial["data"]["stdout"], "out");
        assert_eq!(c_partial["error"]["code"], "cleanup_incomplete");

        let generator = schemars::generate::SchemaSettings::draft2020_12()
            .for_serialize()
            .with(|s| s.inline_subschemas = true);
        let actual_schema: Value = serde_json::to_value(
            generator
                .clone()
                .into_generator()
                .into_root_schema_for::<ToolReply<CommandData>>(),
        )
        .unwrap();
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct LegacyToolReply<T> {
            data: Option<T>,
            error: Option<ToolError>,
        }
        let mut expected_schema: Value = serde_json::to_value(
            generator
                .into_generator()
                .into_root_schema_for::<LegacyToolReply<CommandData>>(),
        )
        .unwrap();
        expected_schema["title"] = json!("ToolReply_for_CommandData");
        assert_eq!(actual_schema, expected_schema);
    }

    #[test]
    fn every_error_code_serializes_with_exact_snake_case_name() {
        let tool_cases = [
            ("already_exists", ToolError::already_exists("m", false)),
            (
                "automation_failed",
                ToolError::automation_failed("m", false),
            ),
            ("cancelled", ToolError::cancelled("m", true)),
            (
                "checksum_mismatch",
                ToolError::checksum_mismatch("m", false),
            ),
            (
                "cleanup_incomplete",
                ToolError::cleanup_incomplete("m", false),
            ),
            ("command_failed", ToolError::command_failed("m", false)),
            ("connection_lost", ToolError::connection_lost("m", true)),
            ("discovery_failed", ToolError::discovery_failed("m", false)),
            ("invalid_argument", ToolError::invalid_argument("m", false)),
            (
                "invalid_argument",
                ToolError::invalid_argument_owned("m".into()),
            ),
            ("invalid_encoding", ToolError::invalid_encoding("m", false)),
            (
                "invalid_projection",
                ToolError::invalid_projection("m", false),
            ),
            ("invalid_result", ToolError::invalid_result("m", true)),
            ("io_error", ToolError::io_error("m", false)),
            ("not_found", ToolError::not_found("m", false)),
            ("payload_failed", ToolError::payload_failed("m", false)),
            ("payload_rejected", ToolError::payload_rejected("m", false)),
            (
                "permission_denied",
                ToolError::permission_denied("m", false),
            ),
            ("policy_denied", ToolError::policy_denied("m", false)),
            ("preview_required", ToolError::preview_required("m", false)),
            ("resource_limit", ToolError::resource_limit("m", false)),
            ("shutdown", ToolError::shutdown("m", false)),
            ("ssh_connect_failed", ToolError::SSH_CONNECT_FAILED),
            ("ssh_spawn_failed", ToolError::ssh_spawn_failed("m", false)),
            (
                "target_quarantined",
                ToolError::target_quarantined("m", false),
            ),
            ("timeout", ToolError::timeout("m", true)),
            ("unsupported", ToolError::unsupported("m", false)),
        ];
        for (expected, err) in &tool_cases {
            assert_eq!(err.code(), *expected);
            let serialized = serde_json::to_value(err).unwrap();
            assert_eq!(serialized["code"], *expected);
            assert!(serialized["message"].is_string());
            assert_eq!(serialized["remote_state_unknown"], err.remote_state_unknown);
        }

        let controller_cases = [
            ("cancelled", ControllerError::cancelled("m")),
            (
                "cleanup_incomplete",
                ControllerError::cleanup_incomplete("m"),
            ),
            ("command_failed", ControllerError::command_failed("m")),
            (
                "controller_resource_limit",
                ControllerError::controller_resource_limit("m"),
            ),
            (
                "controller_timeout",
                ControllerError::controller_timeout("m"),
            ),
            ("invalid_argument", ControllerError::invalid_argument("m")),
            ("invalid_result", ControllerError::invalid_result("m")),
            ("io_error", ControllerError::io_error("m")),
            ("policy_denied", ControllerError::policy_denied("m")),
            ("resource_limit", ControllerError::resource_limit("m")),
            (
                "resource_unavailable",
                ControllerError::resource_unavailable("m"),
            ),
            ("spawn_failed", ControllerError::spawn_failed("m")),
            ("timeout", ControllerError::timeout("m")),
            (
                "unsupported_workspace_entry",
                ControllerError::unsupported_workspace_entry("m"),
            ),
        ];
        for (expected, err) in &controller_cases {
            assert_eq!(err.code(), *expected);
            let serialized = serde_json::to_value(err).unwrap();
            assert_eq!(serialized["code"], *expected);
            assert!(serialized["message"].is_string());
            assert!(serialized.get("remote_state_unknown").is_none());
        }
    }
}
