use std::borrow::Cow;

use schemars::JsonSchema;
use serde::{Serialize, ser::SerializeStruct};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
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
}

impl ErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
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
        }
    }
}

/// Every production error code, ordered by its snake_case wire string.
///
/// Test-only codes such as `ControllerTimeout` stay out of the public schema.
const ALL_PUBLIC: &[ErrorCode] = &[
    ErrorCode::AlreadyExists,
    ErrorCode::AutomationFailed,
    ErrorCode::Cancelled,
    ErrorCode::ChecksumMismatch,
    ErrorCode::CleanupIncomplete,
    ErrorCode::CommandFailed,
    ErrorCode::ConnectionLost,
    ErrorCode::ControllerResourceLimit,
    ErrorCode::InvalidArgument,
    ErrorCode::InvalidEncoding,
    ErrorCode::InvalidProjection,
    ErrorCode::InvalidResult,
    ErrorCode::IoError,
    ErrorCode::NotFound,
    ErrorCode::PayloadFailed,
    ErrorCode::PayloadRejected,
    ErrorCode::PermissionDenied,
    ErrorCode::PolicyDenied,
    ErrorCode::PreviewRequired,
    ErrorCode::ResourceLimit,
    ErrorCode::ResourceUnavailable,
    ErrorCode::Shutdown,
    ErrorCode::SpawnFailed,
    ErrorCode::SshConnectFailed,
    ErrorCode::SshSpawnFailed,
    ErrorCode::TargetQuarantined,
    ErrorCode::Timeout,
    ErrorCode::Unsupported,
];

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
        // A closed set: callers can branch on the exact wire strings.
        let mut schema = <&str>::json_schema(generator);
        let values = ALL_PUBLIC
            .iter()
            .map(|code| serde_json::Value::String(code.as_str().to_owned()))
            .collect();
        schema
            .ensure_object()
            .insert("enum".to_owned(), serde_json::Value::Array(values));
        schema
    }
}

#[derive(Clone, Debug)]
enum Outcome<T, E> {
    Success(T),
    Failure(E),
    Partial { data: T, error: E },
}

fn serialize_reply<S: serde::Serializer, T: Serialize, E: Serialize>(
    name: &'static str,
    outcome: &Outcome<T, E>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let (data, error) = match outcome {
        Outcome::Success(data) => (Some(data), None),
        Outcome::Failure(error) => (None, Some(error)),
        Outcome::Partial { data, error } => (Some(data), Some(error)),
    };
    let mut state = serializer.serialize_struct(name, 2)?;
    state.serialize_field("data", &data)?;
    state.serialize_field("error", &error)?;
    state.end()
}

/// The one reply envelope for tool and controller calls: data, error, or both
/// (partial). The wire shape is always `{"data": …, "error": …}` with nulls.
#[derive(Clone, Debug)]
pub struct Reply<T, E = ToolError> {
    outcome: Outcome<T, E>,
}

/// Tool replies are generic over their execution evidence.
pub type ToolReply<T> = Reply<T, ToolError>;

#[derive(JsonSchema)]
#[allow(dead_code)]
struct ReplySchema<T, E> {
    data: Option<T>,
    error: Option<E>,
}

impl<T: Serialize, E: Serialize> Serialize for Reply<T, E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_reply("ToolReply", &self.outcome, serializer)
    }
}

impl<T: JsonSchema> JsonSchema for Reply<T, ToolError> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Owned(format!("ToolReply_for_{}", T::schema_name()))
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Owned(format!("{}::ToolReply<{}>", module_path!(), T::schema_id()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        ReplySchema::<T, ToolError>::json_schema(generator)
    }
}

/// The controller's published output schema keeps its historical identity.
impl<T: JsonSchema> JsonSchema for Reply<T, ControllerError> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ControllerReply")
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Owned(format!("{}::ControllerReply", module_path!()))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        ReplySchema::<T, ControllerError>::json_schema(generator)
    }
}

impl<T, E> Reply<T, E> {
    pub const fn success(data: T) -> Self {
        Self {
            outcome: Outcome::Success(data),
        }
    }

    pub const fn failure(error: E) -> Self {
        Self {
            outcome: Outcome::Failure(error),
        }
    }

    pub const fn partial(data: T, error: E) -> Self {
        Self {
            outcome: Outcome::Partial { data, error },
        }
    }

    pub(crate) fn with_optional_error(data: T, error: Option<E>) -> Self {
        match error {
            Some(error) => Self::partial(data, error),
            None => Self::success(data),
        }
    }

    pub fn data(&self) -> Option<&T> {
        match &self.outcome {
            Outcome::Success(data) | Outcome::Partial { data, .. } => Some(data),
            Outcome::Failure(_) => None,
        }
    }

    pub fn data_mut(&mut self) -> Option<&mut T> {
        match &mut self.outcome {
            Outcome::Success(data) | Outcome::Partial { data, .. } => Some(data),
            Outcome::Failure(_) => None,
        }
    }

    pub fn error(&self) -> Option<&E> {
        match &self.outcome {
            Outcome::Failure(error) | Outcome::Partial { error, .. } => Some(error),
            Outcome::Success(_) => None,
        }
    }

    pub(crate) fn error_mut(&mut self) -> Option<&mut E> {
        match &mut self.outcome {
            Outcome::Failure(error) | Outcome::Partial { error, .. } => Some(error),
            Outcome::Success(_) => None,
        }
    }

    pub(crate) fn set_error(&mut self, error: E)
    where
        E: Clone,
    {
        let placeholder = Outcome::Failure(error.clone());
        let current = std::mem::replace(&mut self.outcome, placeholder);
        self.outcome = match current {
            Outcome::Success(data) | Outcome::Partial { data, .. } => {
                Outcome::Partial { data, error }
            }
            Outcome::Failure(_) => Outcome::Failure(error),
        };
    }

    pub(crate) fn map_ok<U>(self, f: impl FnOnce(T) -> Result<U, E>) -> Reply<U, E> {
        match self.outcome {
            Outcome::Success(data) => match f(data) {
                Ok(mapped) => Reply::success(mapped),
                Err(error) => Reply::failure(error),
            },
            Outcome::Failure(error) => Reply::failure(error),
            Outcome::Partial { data, error } => match f(data) {
                Ok(mapped) => Reply::partial(mapped, error),
                Err(mapped_err) => Reply::failure(mapped_err),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFailureReason {
    UnsupportedPlatform,
    PolicyViolation,
    TargetNotFound,
    PermissionDenied,
    DependencyUnavailable,
    Timeout,
    OutputBoundExceeded,
    PreconditionFailed,
    VerificationFailed,
}

impl PayloadFailureReason {
    pub(crate) fn from_code(code: &str) -> Option<Self> {
        match code {
            "unsupported_platform" => Some(Self::UnsupportedPlatform),
            "policy_violation" => Some(Self::PolicyViolation),
            "target_not_found" => Some(Self::TargetNotFound),
            "permission_denied" => Some(Self::PermissionDenied),
            "dependency_unavailable" => Some(Self::DependencyUnavailable),
            "timeout" => Some(Self::Timeout),
            "output_bound_exceeded" => Some(Self::OutputBoundExceeded),
            "precondition_failed" => Some(Self::PreconditionFailed),
            "verification_failed" => Some(Self::VerificationFailed),
            _ => None,
        }
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "Payload operation failed: unsupported target platform",
            Self::PolicyViolation => "Payload operation failed: input violates collector policy",
            Self::TargetNotFound => {
                "Payload operation failed: requested target resource was not found"
            }
            Self::PermissionDenied => "Payload operation failed: target permission denied",
            Self::DependencyUnavailable => {
                "Payload operation failed: required target subsystem or utility failed"
            }
            Self::Timeout => "Payload operation failed: collector subprocess timed out",
            Self::OutputBoundExceeded => {
                "Payload operation failed: collector source or output exceeded safety bound"
            }
            Self::PreconditionFailed => "Payload operation failed: target precondition was not met",
            Self::VerificationFailed => {
                "Payload operation failed: post-mutation verification failed"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ToolError {
    code: ErrorCode,
    pub message: Cow<'static, str>,
    pub remote_state_unknown: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<PayloadFailureReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint: Option<&'static str>,
}

impl ToolError {
    pub const SSH_CONNECT_FAILED: Self = Self::new(
        ErrorCode::SshConnectFailed,
        "SSH connection failed; run `estus doctor --target <host>` outside MCP to diagnose alias, authentication and known hosts",
        false,
    );

    pub const fn new(code: ErrorCode, message: &'static str, remote_state_unknown: bool) -> Self {
        Self {
            code,
            message: Cow::Borrowed(message),
            remote_state_unknown,
            reason: None,
            schema_path: None,
            constraint: None,
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub(crate) fn invalid_argument_owned(message: String) -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
            message: Cow::Owned(message),
            remote_state_unknown: false,
            reason: None,
            schema_path: None,
            constraint: None,
        }
    }

    pub(crate) fn invalid_projection_at(schema_path: String, constraint: &'static str) -> Self {
        let mut trimmed = schema_path;
        if trimmed.len() > 96 {
            trimmed.truncate(96);
        }
        let message =
            format!("Payload output violates approved projection at {trimmed} ({constraint})");
        Self {
            code: ErrorCode::InvalidProjection,
            message: Cow::Owned(message),
            remote_state_unknown: false,
            reason: None,
            schema_path: Some(trimmed),
            constraint: Some(constraint),
        }
    }

    pub(crate) const fn payload_failed_with_reason(
        reason: PayloadFailureReason,
        remote_state_unknown: bool,
    ) -> Self {
        Self {
            code: ErrorCode::PayloadFailed,
            message: Cow::Borrowed(reason.message()),
            remote_state_unknown,
            reason: Some(reason),
            schema_path: None,
            constraint: None,
        }
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
    pub const fn new(code: ErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code.as_str()
    }
}

/// Controller replies share the tool reply envelope; their evidence and error
/// types differ, so this is the one non-alias over the generic `Reply`.
pub(crate) type ControllerReply = Reply<ControllerData, ControllerError>;

#[cfg_attr(windows, allow(dead_code))]
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
        partial_reply.set_error(ToolError::new(
            ErrorCode::Timeout,
            "deadline exceeded",
            true,
        ));
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
            serde_json::to_value(ControllerReply::failure(ControllerError::new(
                ErrorCode::Cancelled,
                "stopped"
            )))
            .unwrap()["data"]
                .is_null()
        );
        let c_partial = serde_json::to_value(ControllerReply::partial(
            controller_data(),
            ControllerError::new(ErrorCode::CleanupIncomplete, "dirty"),
        ))
        .unwrap();
        assert_eq!(c_partial["data"]["stdout"], "out");
        assert_eq!(c_partial["error"]["code"], "cleanup_incomplete");

        // The controller's published output schema keeps its historical title.
        let controller_schema: Value = serde_json::to_value(
            schemars::generate::SchemaSettings::draft2020_12()
                .for_serialize()
                .with(|s| s.inline_subschemas = true)
                .into_generator()
                .into_root_schema_for::<ControllerReply>(),
        )
        .unwrap();
        assert_eq!(controller_schema["title"], "ControllerReply");

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
    fn public_error_code_schema_is_the_exact_sorted_closed_enum() {
        let mut names: Vec<&str> = ALL_PUBLIC.iter().map(|code| code.as_str()).collect();
        let sorted = {
            let mut copy = names.clone();
            copy.sort_unstable();
            copy
        };
        assert_eq!(names, sorted, "ALL_PUBLIC must stay sorted by wire string");
        names.dedup();
        assert_eq!(
            names.len(),
            ALL_PUBLIC.len(),
            "ALL_PUBLIC must not repeat a code"
        );

        // Every non-test variant must be published exactly once.
        let production = [
            ErrorCode::AlreadyExists,
            ErrorCode::AutomationFailed,
            ErrorCode::Cancelled,
            ErrorCode::ChecksumMismatch,
            ErrorCode::CleanupIncomplete,
            ErrorCode::CommandFailed,
            ErrorCode::ConnectionLost,
            ErrorCode::ControllerResourceLimit,
            ErrorCode::InvalidArgument,
            ErrorCode::InvalidEncoding,
            ErrorCode::InvalidProjection,
            ErrorCode::InvalidResult,
            ErrorCode::IoError,
            ErrorCode::NotFound,
            ErrorCode::PayloadFailed,
            ErrorCode::PayloadRejected,
            ErrorCode::PermissionDenied,
            ErrorCode::PolicyDenied,
            ErrorCode::PreviewRequired,
            ErrorCode::ResourceLimit,
            ErrorCode::ResourceUnavailable,
            ErrorCode::Shutdown,
            ErrorCode::SpawnFailed,
            ErrorCode::SshConnectFailed,
            ErrorCode::SshSpawnFailed,
            ErrorCode::TargetQuarantined,
            ErrorCode::Timeout,
            ErrorCode::Unsupported,
        ];
        assert_eq!(production.len(), ALL_PUBLIC.len());
        for code in production {
            assert!(
                ALL_PUBLIC.contains(&code),
                "{} is missing from ALL_PUBLIC",
                code.as_str()
            );
        }
        assert!(!ALL_PUBLIC.contains(&ErrorCode::ControllerTimeout));

        // The published outputSchema enum is exactly the wire strings.
        let schema: Value = serde_json::to_value(
            schemars::generate::SchemaSettings::draft2020_12()
                .for_serialize()
                .with(|s| s.inline_subschemas = true)
                .into_generator()
                .into_root_schema_for::<ToolError>(),
        )
        .unwrap();
        let published: Vec<String> = schema["properties"]["code"]["enum"]
            .as_array()
            .expect("ToolError.code must publish an enum")
            .iter()
            .map(|value| value.as_str().expect("enum entries are strings").to_owned())
            .collect();
        assert_eq!(
            published,
            ALL_PUBLIC
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect::<Vec<_>>()
        );
        assert!(
            !published.iter().any(|code| code == "controller_timeout"),
            "test-only code leaked into the public schema"
        );
    }

    #[test]
    fn every_error_code_serializes_with_exact_snake_case_name() {
        let tool_cases = [
            (
                "already_exists",
                ToolError::new(ErrorCode::AlreadyExists, "m", false),
            ),
            (
                "automation_failed",
                ToolError::new(ErrorCode::AutomationFailed, "m", false),
            ),
            ("cancelled", ToolError::new(ErrorCode::Cancelled, "m", true)),
            (
                "checksum_mismatch",
                ToolError::new(ErrorCode::ChecksumMismatch, "m", false),
            ),
            (
                "command_failed",
                ToolError::new(ErrorCode::CommandFailed, "m", false),
            ),
            (
                "connection_lost",
                ToolError::new(ErrorCode::ConnectionLost, "m", true),
            ),
            (
                "invalid_argument",
                ToolError::new(ErrorCode::InvalidArgument, "m", false),
            ),
            (
                "invalid_argument",
                ToolError::invalid_argument_owned("m".into()),
            ),
            (
                "invalid_encoding",
                ToolError::new(ErrorCode::InvalidEncoding, "m", false),
            ),
            (
                "invalid_projection",
                ToolError::new(ErrorCode::InvalidProjection, "m", false),
            ),
            (
                "invalid_result",
                ToolError::new(ErrorCode::InvalidResult, "m", true),
            ),
            ("io_error", ToolError::new(ErrorCode::IoError, "m", false)),
            ("not_found", ToolError::new(ErrorCode::NotFound, "m", false)),
            (
                "payload_failed",
                ToolError::new(ErrorCode::PayloadFailed, "m", false),
            ),
            (
                "payload_rejected",
                ToolError::new(ErrorCode::PayloadRejected, "m", false),
            ),
            (
                "permission_denied",
                ToolError::new(ErrorCode::PermissionDenied, "m", false),
            ),
            (
                "policy_denied",
                ToolError::new(ErrorCode::PolicyDenied, "m", false),
            ),
            (
                "preview_required",
                ToolError::new(ErrorCode::PreviewRequired, "m", false),
            ),
            (
                "resource_limit",
                ToolError::new(ErrorCode::ResourceLimit, "m", false),
            ),
            ("shutdown", ToolError::new(ErrorCode::Shutdown, "m", false)),
            ("ssh_connect_failed", ToolError::SSH_CONNECT_FAILED),
            (
                "ssh_spawn_failed",
                ToolError::new(ErrorCode::SshSpawnFailed, "m", false),
            ),
            (
                "target_quarantined",
                ToolError::new(ErrorCode::TargetQuarantined, "m", false),
            ),
            ("timeout", ToolError::new(ErrorCode::Timeout, "m", true)),
            (
                "unsupported",
                ToolError::new(ErrorCode::Unsupported, "m", false),
            ),
        ];
        for (expected, err) in &tool_cases {
            assert_eq!(err.code().as_str(), *expected);
            let serialized = serde_json::to_value(err).unwrap();
            assert_eq!(serialized["code"], *expected);
            assert!(serialized["message"].is_string());
            assert_eq!(serialized["remote_state_unknown"], err.remote_state_unknown);
        }

        let controller_cases = [
            ("cancelled", ControllerError::new(ErrorCode::Cancelled, "m")),
            (
                "cleanup_incomplete",
                ControllerError::new(ErrorCode::CleanupIncomplete, "m"),
            ),
            (
                "command_failed",
                ControllerError::new(ErrorCode::CommandFailed, "m"),
            ),
            (
                "controller_resource_limit",
                ControllerError::new(ErrorCode::ControllerResourceLimit, "m"),
            ),
            (
                "controller_timeout",
                ControllerError::new(ErrorCode::ControllerTimeout, "m"),
            ),
            (
                "invalid_argument",
                ControllerError::new(ErrorCode::InvalidArgument, "m"),
            ),
            ("io_error", ControllerError::new(ErrorCode::IoError, "m")),
            (
                "policy_denied",
                ControllerError::new(ErrorCode::PolicyDenied, "m"),
            ),
            (
                "resource_limit",
                ControllerError::new(ErrorCode::ResourceLimit, "m"),
            ),
            (
                "resource_unavailable",
                ControllerError::new(ErrorCode::ResourceUnavailable, "m"),
            ),
            (
                "spawn_failed",
                ControllerError::new(ErrorCode::SpawnFailed, "m"),
            ),
            ("timeout", ControllerError::new(ErrorCode::Timeout, "m")),
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
