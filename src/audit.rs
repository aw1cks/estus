use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rmcp::model::RequestId;
use serde::Serialize;

use crate::{
    config::{IdentityRole, SudoMode},
    reply::{ControllerError, ControllerReply, GroupCleanup, ToolError},
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
    pub(crate) binding_revision: Option<&'a str>,
    pub(crate) executor: Option<&'static str>,
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
    binding_revision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executor: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_state_unknown: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owned_group_cleanup: Option<GroupCleanup>,
}

impl<'a> Metadata<'a> {
    fn emit(
        self,
        event: &'static str,
        duration_ms: Option<u64>,
        exit_code: Option<i32>,
        error: Option<&ToolError>,
    ) {
        emit(&self.record(
            event,
            duration_ms,
            exit_code,
            error.map(|error| error.code),
            duration_ms.map(|_| error.is_some_and(|error| error.remote_state_unknown)),
            None,
        ));
    }

    fn record(
        self,
        event: &'static str,
        duration_ms: Option<u64>,
        exit_code: Option<i32>,
        error_code: Option<&'static str>,
        remote_state_unknown: Option<bool>,
        owned_group_cleanup: Option<GroupCleanup>,
    ) -> Record<'a> {
        let controller = matches!(self.identity_role, IdentityRole::Controller);
        Record {
            event,
            timestamp_ms: millis(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
            request_id: self.request_id,
            tool: self.tool,
            host: if controller { None } else { self.host },
            identity_role: self.identity_role,
            sudo_mode: if controller { None } else { self.sudo_mode },
            user: if controller { None } else { self.user },
            program: if controller { None } else { self.program },
            binding_revision: self.binding_revision,
            executor: self.executor,
            duration_ms,
            exit_code,
            error_code,
            remote_state_unknown: if controller {
                None
            } else {
                remote_state_unknown
            },
            owned_group_cleanup: if controller {
                owned_group_cleanup
            } else {
                None
            },
        }
    }

    pub(crate) fn reject_controller(self, started: Instant, error: &ControllerError) {
        emit(&self.record(
            "reject",
            Some(millis(started.elapsed())),
            None,
            Some(error.code),
            None,
            None,
        ));
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

    pub(crate) fn finish_controller(mut self, reply: &ControllerReply) {
        emit(&self.metadata.record(
            "finish",
            Some(millis(self.started.elapsed())),
            reply.data.as_ref().and_then(|data| data.exit_code),
            reply.error.as_ref().map(|error| error.code),
            None,
            reply.data.as_ref().map(|data| data.owned_group_cleanup),
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_records_exclude_remote_and_private_identity_even_on_drop_path() {
        let id = RequestId::Number(7);
        let metadata = Metadata {
            request_id: &id,
            tool: "observe_controller",
            host: Some("private-host"),
            identity_role: IdentityRole::Controller,
            sudo_mode: None,
            user: Some("private-user"),
            program: Some("/private/interpreter"),
            binding_revision: Some("1"),
            executor: Some("controller_script"),
        };
        for (event, remote, cleanup) in [
            ("start", None, None),
            ("reject", Some(false), None),
            ("finish", Some(true), Some(GroupCleanup::Incomplete)),
        ] {
            // Drop/panic passes native uncertainty to this constructor too.
            let record = metadata.record(event, Some(1), None, Some("cancelled"), remote, cleanup);
            let value = serde_json::to_value(record).unwrap();
            for forbidden in [
                "host",
                "sudo_mode",
                "user",
                "program",
                "remote_state_unknown",
            ] {
                assert!(value.get(forbidden).is_none(), "{event}: {forbidden}");
            }
            assert_eq!(value["identity_role"], "controller");
            assert_eq!(value["tool"], "observe_controller");
            if cleanup.is_some() {
                assert_eq!(value["owned_group_cleanup"], "incomplete");
            } else {
                assert!(value.get("owned_group_cleanup").is_none());
            }
        }
    }
}
