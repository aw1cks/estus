use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rmcp::model::RequestId;
use serde::Serialize;

use crate::{
    config::{IdentityRole, SudoMode},
    server::ToolError,
};

/// Best-effort JSON diagnostics; stderr failure must never interrupt cleanup.
pub(crate) fn emit(record: &impl Serialize) {
    use std::io::Write;

    // Serialize before locking stderr, so a failed serialization cannot leave a
    // partial record or hold the output lock while invoking Serialize code.
    let line = serde_json::to_string(record);
    let line = line
        .as_deref()
        .unwrap_or(r#"{"event":"diagnostic_error","error_code":"serialization_failed"}"#);
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

#[derive(Clone, Copy)]
pub(crate) struct Metadata<'a> {
    pub(crate) request_id: &'a RequestId,
    pub(crate) tool: &'a str,
    pub(crate) host: Option<&'a str>,
    pub(crate) identity_role: IdentityRole,
    pub(crate) sudo_mode: Option<SudoMode>,
    pub(crate) user: Option<&'a str>,
    pub(crate) program: Option<&'a str>,
}

#[derive(Serialize)]
struct Record<'a> {
    event: &'static str,
    timestamp_ms: u64,
    request_id: &'a RequestId,
    tool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    identity_role: IdentityRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    sudo_mode: Option<SudoMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_state_unknown: Option<bool>,
}

impl Metadata<'_> {
    fn emit(
        self,
        event: &'static str,
        duration_ms: Option<u64>,
        exit_code: Option<i32>,
        error: Option<&ToolError>,
    ) {
        let record = Record {
            event,
            timestamp_ms: millis(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
            request_id: self.request_id,
            tool: self.tool,
            host: self.host,
            identity_role: self.identity_role,
            sudo_mode: self.sudo_mode,
            user: self.user,
            program: self.program,
            duration_ms,
            exit_code,
            error_code: error.map(|error| error.code),
            remote_state_unknown: duration_ms
                .map(|_| error.is_some_and(|error| error.remote_state_unknown)),
        };
        emit(&record);
    }

    pub(crate) fn reject(self, started: Instant, error: &ToolError) {
        self.emit("reject", Some(millis(started.elapsed())), None, Some(error));
    }
}

pub(crate) struct Audit<'a> {
    metadata: Metadata<'a>,
    started: Instant,
    finished: bool,
}

impl<'a> Audit<'a> {
    pub(crate) fn start(metadata: Metadata<'a>, started: Instant) -> Self {
        metadata.emit("start", None, None, None);
        Self {
            metadata,
            started,
            finished: false,
        }
    }

    pub(crate) fn finish(mut self, exit_code: Option<i32>, error: Option<&ToolError>) {
        self.metadata.emit(
            "finish",
            Some(millis(self.started.elapsed())),
            exit_code,
            error,
        );
        self.finished = true;
    }
}

impl Drop for Audit<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.metadata.emit(
                "finish",
                Some(millis(self.started.elapsed())),
                None,
                Some(&ToolError::new(
                    "cancelled",
                    "Request cleanup interrupted",
                    true,
                )),
            );
        }
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
