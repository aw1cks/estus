use std::{
    io::{self, Write},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rmcp::model::RequestId;
use serde::Serialize;

use crate::{
    config::{IdentityRole, SudoMode},
    reply::{ControllerError, ControllerReply, GroupCleanup, ToolError},
};

// These bounds include serialization, queued records and the in-flight write:
// at most 64 records, each retaining at most 4096 bytes (256 KiB total).
const MAX_RECORDS: usize = 64;
const MAX_RECORD_BYTES: usize = 4096;
const SHUTDOWN_GRACE: Duration = Duration::from_millis(100);
static DIAGNOSTICS: OnceLock<Diagnostics> = OnceLock::new();

#[derive(Default)]
struct Delivery {
    retained: AtomicUsize,
    dropped: AtomicU64,
    closing: AtomicBool,
}

impl Delivery {
    fn lost(&self) {
        let _ = self
            .dropped
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }
}

struct PendingRecord {
    line: Vec<u8>,
    delivery: Arc<Delivery>,
}

impl Write for PendingRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Leave space for the newline in this record's fixed allocation.
        if bytes.len() > MAX_RECORD_BYTES - 1 - self.line.len() {
            return Err(io::Error::other("diagnostic record limit"));
        }
        self.line.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PendingRecord {
    fn drop(&mut self) {
        self.delivery.retained.fetch_sub(1, Ordering::Relaxed);
    }
}

enum Message {
    Record(PendingRecord),
    Wake,
}

struct Diagnostics {
    sender: SyncSender<Message>,
    delivery: Arc<Delivery>,
}

impl Diagnostics {
    fn emit(&self, record: &impl Serialize) {
        if self.delivery.closing.load(Ordering::Acquire) {
            return;
        }
        if self
            .delivery
            .retained
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < MAX_RECORDS).then_some(n + 1)
            })
            .is_err()
        {
            self.delivery.lost();
            return;
        }
        let mut pending = PendingRecord {
            line: Vec::with_capacity(MAX_RECORD_BYTES),
            delivery: Arc::clone(&self.delivery),
        };
        if serde_json::to_writer(&mut pending, record).is_err() {
            self.delivery.lost();
            // Wake an idle writer to report serialization/size loss as well.
            let _ = self.sender.try_send(Message::Wake);
            return;
        }
        pending.line.push(b'\n');
        if self.sender.try_send(Message::Record(pending)).is_err() {
            self.delivery.lost();
        }
    }
}

/// Owns only diagnostics, never requests, admission permits or cleanup work.
pub(crate) struct Writer {
    done: Receiver<()>,
    thread: Option<JoinHandle<()>>,
}

/// Initialize once, before any application diagnostics or async work.
pub(crate) fn start() -> io::Result<Writer> {
    let (sender, receiver) = mpsc::sync_channel(MAX_RECORDS);
    let (finished, done) = mpsc::sync_channel(1);
    let delivery = Arc::new(Delivery::default());
    let writer_delivery = Arc::clone(&delivery);
    let thread = std::thread::Builder::new()
        .name("estus-diagnostics".into())
        .spawn(move || {
            let stderr = io::stderr();
            let mut next = receiver.recv().ok();
            while let Some(message) = next {
                // Lock only while writing: CLI parsing may also use stderr.
                let result = (|| -> io::Result<()> {
                    let mut output = stderr.lock();
                    if let Message::Record(record) = message {
                        output.write_all(&record.line)?;
                    }
                    let dropped = writer_delivery.dropped.swap(0, Ordering::Relaxed);
                    if dropped != 0 {
                        writeln!(
                            output,
                            "{{\"event\":\"diagnostic_loss\",\"dropped_records\":{dropped}}}"
                        )?;
                    }
                    Ok(())
                })();
                if result.is_err() {
                    // A closed/broken sink is terminal; never retry or block callers.
                    break;
                }
                next = if writer_delivery.closing.load(Ordering::Acquire) {
                    receiver.try_recv().ok()
                } else {
                    receiver.recv().ok()
                };
            }
            let _ = finished.send(());
        })?;
    let _ = DIAGNOSTICS.set(Diagnostics { sender, delivery });
    Ok(Writer {
        done,
        thread: Some(thread),
    })
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some(diagnostics) = DIAGNOSTICS.get() {
            diagnostics.delivery.closing.store(true, Ordering::Release);
            // A full queue already wakes the writer; an empty queue needs this.
            let _ = diagnostics.sender.try_send(Message::Wake);
        }
        if self.done.recv_timeout(SHUTDOWN_GRACE).is_ok()
            && let Some(thread) = self.thread.take()
        {
            let _ = thread.join();
        }
        // A blocked OS write cannot be cancelled safely. Detach after the grace;
        // process exit terminates this diagnostic-only thread.
    }
}

/// Best-effort JSON diagnostics; never wait for stderr or queue capacity.
pub(crate) fn emit(record: &impl Serialize) {
    if let Some(diagnostics) = DIAGNOSTICS.get() {
        diagnostics.emit(record);
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<crate::reply::AutomationStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete: Option<bool>,
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
        // Even validated/configured identifiers belong only to execution
        // records. No rejection path may disclose caller sudo user/program.
        let execution_identity = !controller && event != "reject";
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
            user: if execution_identity { self.user } else { None },
            program: if execution_identity {
                self.program
            } else {
                None
            },
            binding_revision: self.binding_revision,
            executor: self.executor,
            status: None,
            complete: None,
            duration_ms,
            exit_code,
            error_code,
            remote_state_unknown: if controller {
                None
            } else {
                remote_state_unknown
            },
            owned_group_cleanup: if controller || self.executor == Some("ansible_module") {
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

    pub(crate) fn finish_automation(
        mut self,
        reply: &crate::reply::ToolReply<crate::reply::AutomationData>,
    ) {
        let mut record = self.metadata.record(
            "finish",
            Some(millis(self.started.elapsed())),
            reply.data.as_ref().and_then(|data| data.runner_rc),
            reply.error.as_ref().map(|error| error.code),
            Some(
                reply
                    .error
                    .as_ref()
                    .is_some_and(|error| error.remote_state_unknown),
            ),
            reply.data.as_ref().map(|data| data.owned_group_cleanup),
        );
        record.status = reply.data.as_ref().map(|data| data.status);
        record.complete = reply.data.as_ref().map(|data| data.complete);
        emit(&record);
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
    fn oversized_diagnostics_are_dropped_whole_and_capacity_recovers() {
        let (sender, receiver) = mpsc::sync_channel(MAX_RECORDS);
        let delivery = Arc::new(Delivery::default());
        let diagnostics = Diagnostics {
            sender,
            delivery: Arc::clone(&delivery),
        };
        diagnostics.emit(&serde_json::json!({"private": "\n".repeat(MAX_RECORD_BYTES)}));
        assert!(matches!(receiver.try_recv(), Ok(Message::Wake)));
        assert_eq!(delivery.retained.load(Ordering::Relaxed), 0);
        assert_eq!(delivery.dropped.load(Ordering::Relaxed), 1);
        for sequence in 0..MAX_RECORDS {
            diagnostics.emit(&serde_json::json!({"sequence": sequence}));
        }
        diagnostics.emit(&serde_json::json!({"overflow": true}));
        assert_eq!(delivery.dropped.load(Ordering::Relaxed), 2);
        for sequence in 0..MAX_RECORDS {
            let Message::Record(record) = receiver.try_recv().unwrap() else {
                panic!("expected a complete diagnostic");
            };
            assert!(record.line.len() <= MAX_RECORD_BYTES);
            assert_eq!(record.line.last(), Some(&b'\n'));
            let value: serde_json::Value = serde_json::from_slice(&record.line).unwrap();
            assert_eq!(value["sequence"], sequence);
        }
        assert_eq!(delivery.retained.load(Ordering::Relaxed), 0);
        diagnostics.emit(&serde_json::json!({"recovered": true}));
        let Message::Record(record) = receiver.try_recv().unwrap() else {
            panic!("expected recovered delivery");
        };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&record.line).unwrap()["recovered"],
            true
        );
    }

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
