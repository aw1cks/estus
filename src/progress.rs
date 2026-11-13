//! Advisory request-scoped observations; never part of execution or cleanup ownership.
use std::{
    collections::HashSet,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crate::wire::{frame_fits, size_error};
use rmcp::{
    RoleServer,
    model::{
        ClientJsonRpcMessage, ProgressNotification, ProgressNotificationParam, ProgressToken,
        ServerNotification,
    },
    service::RequestContext,
};
use rmcp::{model::ServerJsonRpcMessage, transport::Transport};
use std::io;
use tokio::{sync::watch, task::AbortHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_ACTIVE: usize = 16;
const MAX_TOKEN_BYTES: usize = 256;
const INTERVAL: Duration = Duration::from_millis(250);
const SEND_WAIT: Duration = Duration::from_millis(100);
// MCP progress is f64. Stop increasing before integers cease to be exact.
const MAX_VALUE: u64 = (1 << 53) - 1;

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    SftpOpened,
    SftpReady,
    SftpAcknowledged,
    RunnerStarted,
    RunnerReady,
    RunnerTask,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::SftpOpened => "SFTP channel opened",
            Self::SftpReady => "SFTP session ready",
            Self::SftpAcknowledged => "SFTP operation acknowledged",
            Self::RunnerStarted => "Runner started",
            Self::RunnerReady => "Runner ready",
            Self::RunnerTask => "Runner task observed",
        }
    }
}

/// This extension is local-only. A queued stale update must not start a wire write.
#[derive(Clone)]
pub(crate) struct Gate {
    stopped: CancellationToken,
    request: CancellationToken,
    shutdown: CancellationToken,
}

impl Gate {
    pub(crate) fn active(&self) -> bool {
        !self.stopped.is_cancelled()
            && !self.request.is_cancelled()
            && !self.shutdown.is_cancelled()
    }

    async fn cancelled(&self) {
        tokio::select! {
            () = self.stopped.cancelled() => {},
            () = self.request.cancelled() => {},
            () = self.shutdown.cancelled() => {},
        }
    }
}

#[derive(Clone, Copy)]
enum Update {
    Bytes(u64),
    Milestone(u64, Stage),
}

impl Update {
    fn value(self) -> u64 {
        match self {
            Self::Bytes(value) | Self::Milestone(value, _) => value,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Bytes(_) => "Command output bytes received",
            Self::Milestone(_, stage) => stage.message(),
        }
    }
}

struct Shared {
    latest: watch::Sender<Option<Update>>,
    gate: Gate,
}

/// Disabled reporters allocate nothing; producers only replace one bounded snapshot.
#[derive(Clone, Default)]
pub(crate) struct Reporter(Option<Arc<Shared>>);

impl Reporter {
    pub(crate) fn from_context(context: &RequestContext<RoleServer>) -> Self {
        context
            .extensions
            .get::<Self>()
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn output_started(&self) {
        if let Some(shared) = &self.0
            && shared.gate.active()
        {
            shared.latest.send_if_modified(|latest| {
                if latest.is_some() {
                    return false;
                }
                *latest = Some(Update::Bytes(0));
                true
            });
        }
    }

    pub(crate) fn bytes(&self, count: usize) {
        if count == 0 {
            return;
        }
        if let Some(shared) = &self.0
            && shared.gate.active()
        {
            shared.latest.send_if_modified(|latest| {
                let previous = match *latest {
                    Some(Update::Bytes(value)) => value,
                    None => 0,
                    Some(Update::Milestone(..)) => return false,
                };
                let value = previous.saturating_add(count as u64).min(MAX_VALUE);
                if value == previous {
                    return false;
                }
                *latest = Some(Update::Bytes(value));
                true
            });
        }
    }

    pub(crate) fn stage(&self, stage: Stage) {
        if let Some(shared) = &self.0
            && shared.gate.active()
        {
            shared.latest.send_if_modified(|latest| {
                let previous = match *latest {
                    Some(Update::Milestone(value, _)) => value,
                    None => 0,
                    Some(Update::Bytes(_)) => return false,
                };
                if previous == MAX_VALUE {
                    return false;
                }
                *latest = Some(Update::Milestone(previous + 1, stage));
                true
            });
        }
    }

    pub(crate) fn stop(&self) {
        if let Some(shared) = &self.0 {
            shared.gate.stopped.cancel();
        }
    }
}

#[derive(Default)]
pub(crate) struct Registry(Arc<Mutex<HashSet<ProgressToken>>>);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Registration {
    active: Arc<Mutex<HashSet<ProgressToken>>>,
    token: ProgressToken,
    gate: Gate,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.gate.stopped.cancel();
        lock(&self.active).remove(&self.token);
    }
}

pub(crate) struct Scope {
    pub(crate) reporter: Reporter,
    task: AbortHandle,
    _registration: Registration,
}

impl Drop for Scope {
    fn drop(&mut self) {
        // A cancelled/dropped handler must not leave a producer or publisher alive.
        self.reporter.stop();
        self.task.abort();
    }
}

impl Registry {
    pub(crate) fn start(
        &self,
        context: &RequestContext<RoleServer>,
        shutdown: &CancellationToken,
        tasks: &TaskTracker,
    ) -> Option<Scope> {
        let value = context.meta.get("progressToken")?;
        if !(value.is_i64()
            || value.is_u64()
            || value
                .as_str()
                .is_some_and(|value| value.len() <= MAX_TOKEN_BYTES))
            || context.ct.is_cancelled()
            || shutdown.is_cancelled()
        {
            return None;
        }
        let token = context.meta.get_progress_token()?;
        {
            let mut active = lock(&self.0);
            if active.len() >= MAX_ACTIVE || !active.insert(token.clone()) {
                return None;
            }
        }
        let gate = Gate {
            stopped: CancellationToken::new(),
            request: context.ct.clone(),
            shutdown: shutdown.clone(),
        };
        let registration = Registration {
            active: self.0.clone(),
            token: token.clone(),
            gate: gate.clone(),
        };
        let (latest, receiver) = watch::channel(None);
        let reporter = Reporter(Some(Arc::new(Shared {
            latest,
            gate: gate.clone(),
        })));
        let peer = context.peer.clone();
        let task = tasks.spawn(async move {
            let _stop = gate.stopped.clone().drop_guard();
            publish(peer, receiver, token, gate).await;
        });
        Some(Scope {
            reporter,
            task: task.abort_handle(),
            _registration: registration,
        })
    }
}

async fn publish(
    peer: rmcp::service::Peer<RoleServer>,
    mut receiver: watch::Receiver<Option<Update>>,
    token: ProgressToken,
    gate: Gate,
) {
    let mut last_value = None;
    let mut next_send = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            () = gate.cancelled() => return,
            result = receiver.changed() => if result.is_err() { return; },
        }
        tokio::select! {
            biased;
            () = gate.cancelled() => return,
            () = tokio::time::sleep_until(next_send) => {},
        }
        let Some(update) = *receiver.borrow_and_update() else {
            continue;
        };
        if last_value.is_some_and(|value| value >= update.value()) {
            continue;
        }
        let params = ProgressNotificationParam::new(token.clone(), update.value() as f64)
            .with_message(update.message());
        let mut notification = ProgressNotification::new(params);
        notification.extensions.insert(gate.clone());
        // Cancelling this peer wait does NOT cancel a started transport frame.
        // BoundedTransport independently owns that write through completion.
        let sent = tokio::select! {
            biased;
            () = gate.cancelled() => return,
            result = tokio::time::timeout(SEND_WAIT, peer.send_notification(
                ServerNotification::ProgressNotification(notification)
            )) => result,
        };
        if !matches!(sent, Ok(Ok(()))) {
            return;
        }
        last_value = Some(update.value());
        next_send = tokio::time::Instant::now() + INTERVAL;
    }
}

pub(crate) struct BoundedTransport<T> {
    inner: T,
    writer: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl<T> BoundedTransport<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner,
            writer: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

impl<T: Transport<RoleServer, Error = io::Error>> Transport<RoleServer> for BoundedTransport<T> {
    type Error = io::Error;

    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        // Validate the actual SDK message, including protocol errors and any
        // version-specific fields, before its encoder allocates the wire frame.
        let fits = frame_fits(&message);
        let gate = match &message {
            ServerJsonRpcMessage::Notification(notification) => {
                use rmcp::model::GetExtensions;
                notification
                    .notification
                    .extensions()
                    .get::<crate::progress::Gate>()
                    .cloned()
            }
            _ => None,
        };
        // Never queue advisory progress behind a blocked frame. Once a frame
        // starts, however, it MUST finish: RMCP's FramedWrite is not cancel-safe.
        let progress = gate
            .as_ref()
            .map(|_| self.writer.clone().try_lock_owned().ok());
        let writer = self.writer.clone();
        let send = fits.then(|| self.inner.send(message));
        async move {
            let Some(send) = send else {
                return Err(size_error());
            };
            let _writer = match progress {
                Some(Some(permit)) if gate.as_ref().is_some_and(|gate| gate.active()) => permit,
                Some(_) => return Ok(()),
                None => writer.lock_owned().await,
            };
            // A scope may have stopped while RMCP queued this send task.
            if gate.as_ref().is_some_and(|gate| !gate.active()) {
                return Ok(());
            }
            send.await
        }
    }

    fn receive(&mut self) -> impl Future<Output = Option<ClientJsonRpcMessage>> + Send {
        self.inner.receive()
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::{model::ServerJsonRpcMessage, transport::Transport};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};

    fn gate() -> Gate {
        Gate {
            stopped: CancellationToken::new(),
            request: CancellationToken::new(),
            shutdown: CancellationToken::new(),
        }
    }

    fn notification(gate: Gate) -> ServerJsonRpcMessage {
        let mut notification = ProgressNotification::new(
            ProgressNotificationParam::new(
                ProgressToken(rmcp::model::NumberOrString::Number(7)),
                1.0,
            )
            .with_message("Command output bytes received"),
        );
        notification.extensions.insert(gate);
        ServerJsonRpcMessage::notification(ServerNotification::ProgressNotification(notification))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_active_tokens_remain_reserved_after_the_publisher_stops() {
        use rmcp::ServiceExt;
        struct PeerHandshake;
        impl rmcp::ServerHandler for PeerHandshake {}
        tokio::time::timeout(Duration::from_secs(5), async {
            // Real SDK handshake supplies a peer; no synthetic tool or operation.
            let (server_io, client_io) = tokio::io::duplex(4096);
            let connecting = tokio::spawn(async { PeerHandshake.serve(server_io).await.unwrap() });
            let client: rmcp::service::RunningService<rmcp::RoleClient, ()> =
                ().serve(client_io).await.unwrap();
            let server: rmcp::service::RunningService<RoleServer, PeerHandshake> =
                connecting.await.unwrap();
            let mut context =
                RequestContext::new(rmcp::model::RequestId::Number(1), server.peer().clone());
            context.meta.insert(
                "progressToken".into(),
                serde_json::json!("same-active-token"),
            );
            let registry = Registry::default();
            let shutdown = CancellationToken::new();
            let tasks = TaskTracker::new();
            let scope = registry.start(&context, &shutdown, &tasks).unwrap();
            scope.reporter.stop();
            tasks.close();
            tasks.wait().await;
            assert!(
                registry.start(&context, &shutdown, &tasks).is_none(),
                "publisher termination released a still-active request token"
            );
            drop(scope);
            let next = registry
                .start(&context, &shutdown, &tasks)
                .expect("request completion must permit safe token reuse");
            drop(next);
            tasks.wait().await;
            client.cancel().await.unwrap();
            server.cancel().await.unwrap();
        })
        .await
        .expect("token lifetime regression handshake or publisher stalled");
    }

    #[test]
    fn byte_counts_stay_exact_and_stop_without_mixing_units() {
        let (latest, receiver) = watch::channel(None);
        let reporter = Reporter(Some(Arc::new(Shared {
            latest,
            gate: gate(),
        })));
        reporter.output_started();
        reporter.bytes(8192);
        reporter.bytes(8192);
        reporter.stage(Stage::SftpOpened);
        assert!(matches!(*receiver.borrow(), Some(Update::Bytes(16384))));
        reporter.stop();
        reporter.bytes(8192);
        assert!(matches!(*receiver.borrow(), Some(Update::Bytes(16384))));
    }

    #[test]
    fn byte_counts_saturate_before_f64_loses_integer_precision() {
        let (latest, receiver) = watch::channel(None);
        let reporter = Reporter(Some(Arc::new(Shared {
            latest,
            gate: gate(),
        })));
        reporter
            .0
            .as_ref()
            .unwrap()
            .latest
            .send_replace(Some(Update::Bytes(MAX_VALUE - 1)));
        reporter.bytes(2);
        assert!(matches!(*receiver.borrow(), Some(Update::Bytes(MAX_VALUE))));
        reporter.bytes(1);
        assert!(matches!(*receiver.borrow(), Some(Update::Bytes(MAX_VALUE))));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_started_frame_finishes_before_reply_while_busy_and_stale_progress_drop() {
        tokio::time::timeout(Duration::from_secs(3), async {
            // One byte capacity forces a real partially-written JSON frame.
            let (writer, mut reader) = tokio::io::duplex(1);
            let mut transport =
                BoundedTransport::new(rmcp::transport::async_rw::AsyncRwTransport::<
                    RoleServer,
                    _,
                    _,
                >::new(tokio::io::empty(), writer));
            let first_gate = gate();
            let first = tokio::spawn(transport.send(notification(first_gate.clone())));
            let initial = reader.read_u8().await.unwrap();
            assert_eq!(initial, b'{');
            first_gate.stopped.cancel();
            // Dropping busy progress must not poll the underlying FramedWrite.
            transport.send(notification(gate())).await.unwrap();
            let stale = gate();
            stale.request.cancel();
            transport.send(notification(stale)).await.unwrap();
            let reply: ServerJsonRpcMessage = serde_json::from_value(serde_json::json!({
                "jsonrpc":"2.0", "id":9, "result":{"tools":[]}
            }))
            .unwrap();
            let final_write = tokio::spawn(transport.send(reply));
            let mut reader = tokio::io::BufReader::new(reader);
            let mut line = vec![initial];
            reader.read_until(b'\n', &mut line).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value["method"], "notifications/progress");
            assert_eq!(value["params"]["progressToken"], 7);
            line.clear();
            reader.read_until(b'\n', &mut line).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
            assert_eq!(value["id"], 9);
            first.await.unwrap().unwrap();
            final_write.await.unwrap().unwrap();
            transport.close().await.unwrap();
            line.clear();
            assert_eq!(reader.read_until(b'\n', &mut line).await.unwrap(), 0);
        })
        .await
        .expect("a blocked progress frame stalled or corrupted the final reply");
    }
}
