//! Advisory request-scoped observations; never part of execution or cleanup ownership.
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use crate::wire::{frame_fits, frame_len, size_error};
use rmcp::{
    RoleServer,
    model::{
        ClientJsonRpcMessage, ProgressNotification, ProgressNotificationParam, ProgressToken,
        RequestId, ServerJsonRpcMessage, ServerNotification,
    },
    service::RequestContext,
    transport::Transport,
};
use std::io;
use tokio::{sync::watch, task::AbortHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const MAX_ACTIVE: usize = 16;
const MAX_IN_FLIGHT: usize = 64;
// Aggregate serialized reply bytes allowed behind a stalled stdout consumer.
const MAX_BLOCKED_BYTES: usize = 32 * 1024 * 1024;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 256;
const INTERVAL: Duration = Duration::from_millis(250);
const SEND_WAIT: Duration = Duration::from_millis(100);
// MCP progress is f64. Stop increasing before integers cease to be exact.
const MAX_VALUE: u64 = (1 << 53) - 1;

#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum Stage {
    SftpOpened,
    SftpReady,
    SftpAcknowledged,
}

impl Stage {
    fn message(self) -> &'static str {
        match self {
            Self::SftpOpened => "SFTP channel opened",
            Self::SftpReady => "SFTP session ready",
            Self::SftpAcknowledged => "SFTP operation acknowledged",
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreditState {
    Dispatched,
    InHandler { cancelled: bool },
    CompletedAwaitingRmcp,
    Sending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReserveOutcome {
    Admitted,
    Busy,
    Overloaded,
}

struct PendingState {
    entries: HashMap<RequestId, CreditState>,
    // Serialized bytes of every frame that has entered `CreditState::Sending`
    // and has not yet finished its wire write.
    queued_bytes: usize,
    overloaded: bool,
}

pub(crate) struct PendingReplies {
    state: Mutex<PendingState>,
    shutdown: CancellationToken,
    overload: CancellationToken,
}

impl PendingReplies {
    pub(crate) fn new(shutdown: CancellationToken, overload: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(PendingState {
                entries: HashMap::new(),
                queued_bytes: 0,
                overloaded: false,
            }),
            shutdown,
            overload,
        })
    }

    pub(crate) fn overload_token(&self) -> CancellationToken {
        self.overload.clone()
    }

    fn is_overloaded(&self) -> bool {
        lock(&self.state).overloaded
    }

    fn trip_overload(&self) {
        lock(&self.state).overloaded = true;
        self.shutdown.cancel();
        self.overload.cancel();
    }

    fn reserve(&self, id: &RequestId, writer_blocked: bool) -> ReserveOutcome {
        let outcome = {
            let mut state = lock(&self.state);
            if state.overloaded
                || state.entries.contains_key(id)
                || (writer_blocked
                    && (state.entries.len() >= MAX_ACTIVE
                        || state.queued_bytes >= MAX_BLOCKED_BYTES))
            {
                state.overloaded = true;
                ReserveOutcome::Overloaded
            } else if state.entries.len() >= MAX_IN_FLIGHT
                || state.queued_bytes >= MAX_BLOCKED_BYTES
            {
                ReserveOutcome::Busy
            } else {
                state.entries.insert(id.clone(), CreditState::Dispatched);
                ReserveOutcome::Admitted
            }
        };
        if matches!(outcome, ReserveOutcome::Overloaded) {
            self.shutdown.cancel();
            self.overload.cancel();
        }
        outcome
    }

    /// Charge the frame's serialized size so the matching drop refunds exactly
    /// those bytes. Every frame that reaches the wire owes its bytes, tracked
    /// reply or untracked error frame alike.
    fn mark_sending(self: &Arc<Self>, id: &RequestId, bytes: usize) -> ReplyCredit {
        let (tracked, trip) = {
            let mut state = lock(&self.state);
            let tracked = if state.entries.contains_key(id) {
                state.entries.insert(id.clone(), CreditState::Sending);
                true
            } else {
                false
            };
            state.queued_bytes = state.queued_bytes.saturating_add(bytes);
            let trip = state.queued_bytes > MAX_PENDING_BYTES && !state.overloaded;
            if trip {
                state.overloaded = true;
            }
            (tracked, trip)
        };
        if trip {
            self.shutdown.cancel();
            self.overload.cancel();
        }
        ReplyCredit {
            pending: Arc::clone(self),
            id: tracked.then(|| id.clone()),
            bytes,
        }
    }

    fn mark_cancelled(&self, id: &RequestId) {
        let mut state = lock(&self.state);
        match state.entries.get_mut(id) {
            // A completed reply is already produced and heading to `send()`;
            // dropping it here would skip its `queued_bytes` accounting.
            Some(CreditState::Dispatched) => {
                state.entries.remove(id);
            }
            Some(CreditState::InHandler { cancelled }) => {
                *cancelled = true;
            }
            Some(CreditState::CompletedAwaitingRmcp) | Some(CreditState::Sending) | None => {}
        }
    }

    pub(crate) fn enter_handler(self: &Arc<Self>, id: &RequestId) -> HandlerCredit {
        let mut state = lock(&self.state);
        let Some(slot) = state.entries.get_mut(id) else {
            return HandlerCredit::default();
        };
        if matches!(slot, CreditState::Dispatched) {
            *slot = CreditState::InHandler { cancelled: false };
        }
        HandlerCredit(Some(Arc::new(CreditGuard {
            pending: Arc::clone(self),
            id: id.clone(),
        })))
    }
}

struct CreditGuard {
    pending: Arc<PendingReplies>,
    id: RequestId,
}

impl Drop for CreditGuard {
    fn drop(&mut self) {
        let mut state = lock(&self.pending.state);
        match state.entries.get_mut(&self.id) {
            Some(CreditState::InHandler { cancelled: true }) => {
                state.entries.remove(&self.id);
            }
            Some(slot @ CreditState::InHandler { cancelled: false }) => {
                *slot = CreditState::CompletedAwaitingRmcp;
            }
            _ => {}
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct HandlerCredit(#[allow(dead_code)] Option<Arc<CreditGuard>>);
impl HandlerCredit {
    pub(crate) fn from_context(context: &RequestContext<RoleServer>) -> Self {
        context
            .extensions
            .get::<Self>()
            .cloned()
            .unwrap_or_default()
    }
}

pub(crate) struct ReplyCredit {
    pending: Arc<PendingReplies>,
    id: Option<RequestId>,
    // Exact bytes this credit charged to `PendingState::queued_bytes`.
    bytes: usize,
}

impl Drop for ReplyCredit {
    fn drop(&mut self) {
        let mut state = lock(&self.pending.state);
        if let Some(id) = self.id.take() {
            state.entries.remove(&id);
        }
        state.queued_bytes = state.queued_bytes.saturating_sub(self.bytes);
    }
}

pub(crate) struct BoundedTransport<T> {
    inner: T,
    writer: Arc<tokio::sync::Mutex<()>>,
    pending: Arc<PendingReplies>,
}

impl<T> BoundedTransport<T> {
    #[cfg(test)]
    pub(crate) fn new(inner: T) -> Self {
        Self::with_control(inner, CancellationToken::new(), CancellationToken::new())
    }

    #[cfg(test)]
    pub(crate) fn with_control(
        inner: T,
        shutdown: CancellationToken,
        overload: CancellationToken,
    ) -> Self {
        Self::with_pending(inner, PendingReplies::new(shutdown, overload))
    }

    pub(crate) fn with_pending(inner: T, pending: Arc<PendingReplies>) -> Self {
        Self {
            inner,
            writer: Arc::new(tokio::sync::Mutex::new(())),
            pending,
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
        // Measure once: the same length gates the write and charges the budget.
        let frame = frame_len(&message);
        let release_id = match &message {
            ServerJsonRpcMessage::Response(response) => Some(response.id.clone()),
            ServerJsonRpcMessage::Error(error) => error.id.clone(),
            ServerJsonRpcMessage::Notification(_) | ServerJsonRpcMessage::Request(_) => None,
        };
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
        // An oversized frame never queues, so it charges nothing, yet every
        // frame that reaches the wire charges and refunds its exact bytes.
        let credit = release_id.map(|id| self.pending.mark_sending(&id, frame.unwrap_or(0)));
        let send = frame.map(|_| self.inner.send(message));
        async move {
            let _credit = credit;
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

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            if self.pending.is_overloaded() {
                return None;
            }
            let message = self.inner.receive().await?;
            match &message {
                ClientJsonRpcMessage::Request(request) => {
                    let writer_guard = self.writer.clone().try_lock_owned().ok();
                    match self.pending.reserve(&request.id, writer_guard.is_none()) {
                        ReserveOutcome::Admitted => return Some(message),
                        ReserveOutcome::Overloaded => return None,
                        ReserveOutcome::Busy => {
                            let Some(_writer) = writer_guard else {
                                self.pending.trip_overload();
                                return None;
                            };
                            let busy = ServerJsonRpcMessage::error(
                                rmcp::ErrorData::new(
                                    rmcp::model::ErrorCode(-32000),
                                    "Server busy: concurrent request limit reached",
                                    None,
                                ),
                                Some(request.id.clone()),
                            );
                            if !frame_fits(&busy) {
                                self.pending.trip_overload();
                                return None;
                            }
                            // `T::send` builds a `Send + 'static` future without
                            // awaiting, so the write completes in a spawned task
                            // and `receive()` never awaits `FramedWrite` inside
                            // RMCP's cancelable `select!`.
                            let send = self.inner.send(busy);
                            let pending = Arc::clone(&self.pending);
                            tokio::spawn(async move {
                                let _writer = _writer;
                                if send.await.is_err() {
                                    pending.trip_overload();
                                }
                            });
                        }
                    }
                }
                ClientJsonRpcMessage::Notification(notif) => {
                    if let rmcp::model::ClientNotification::CancelledNotification(cancelled) =
                        &notif.notification
                        && let Some(id) = &cancelled.params.request_id
                    {
                        self.pending.mark_cancelled(id);
                    }
                    return Some(message);
                }
                _ => return Some(message),
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let pending = Arc::clone(&self.pending);
        let close = self.inner.close();
        async move {
            let result = close.await;
            let mut state = lock(&pending.state);
            state.entries.clear();
            state.queued_bytes = 0;
            result
        }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_requests_hold_credits_while_active_and_reclaim_after_cleanup() {
        use rmcp::{
            ErrorData,
            handler::server::ServerHandler,
            model::{
                CallToolRequestParams, CallToolResponse, CallToolResult, InitializeResult,
                ServerCapabilities,
            },
            service::ServiceExt,
        };
        use tokio::io::AsyncWriteExt;

        struct HoldUntilRelease {
            pending: Arc<PendingReplies>,
            started: Arc<tokio::sync::Mutex<Vec<RequestId>>>,
            cleanup_gate: CancellationToken,
        }
        impl ServerHandler for HoldUntilRelease {
            fn get_info(&self) -> InitializeResult {
                InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            }
            async fn call_tool(
                &self,
                request: CallToolRequestParams,
                context: RequestContext<RoleServer>,
            ) -> Result<CallToolResponse, ErrorData> {
                let _call_credit = self.pending.enter_handler(&context.id);
                let cleanup_credit = _call_credit.clone();
                self.started.lock().await.push(context.id.clone());
                if request.name == "echo" {
                    return Ok(CallToolResult::structured(serde_json::json!({"ok": true})).into());
                }
                let gate = self.cleanup_gate.clone();
                // Simulate detached cleanup task retaining HandlerCredit after handler cancel.
                let cleanup = tokio::spawn(async move {
                    let _credit = cleanup_credit;
                    gate.cancelled().await;
                });
                context.ct.cancelled().await;
                let _ = cleanup.await;
                Err(ErrorData::internal_error("cancelled", None))
            }
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            let (server_in, mut client_in) = tokio::io::duplex(4096);
            let (client_out, server_out) = tokio::io::duplex(4096);
            let shutdown = CancellationToken::new();
            let overload = CancellationToken::new();
            let pending = PendingReplies::new(shutdown.clone(), overload.clone());
            let transport = BoundedTransport::with_pending(
                rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new(
                    server_in, server_out,
                ),
                Arc::clone(&pending),
            );
            let started = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let cleanup_gate = CancellationToken::new();
            let handler = HoldUntilRelease {
                pending: Arc::clone(&pending),
                started: Arc::clone(&started),
                cleanup_gate: cleanup_gate.clone(),
            };
            let server_task = tokio::spawn(async move {
                let service = handler.serve(transport).await.unwrap();
                let _ = service.waiting().await;
            });
            let mut reader = tokio::io::BufReader::new(client_out);
            client_in
                .write_all(
                    br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
                )
                .await
                .unwrap();
            client_in.write_all(b"\n").await.unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("\"id\":1"));
            client_in
                .write_all(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .await
                .unwrap();
            client_in.write_all(b"\n").await.unwrap();

            // Release cleanup immediately and cancel 20 sequential requests (> MAX_ACTIVE = 16).
            cleanup_gate.cancel();
            for id in 2..=21_u64 {
                let call = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {"name": "noop", "arguments": {}}
                });
                client_in
                    .write_all(&serde_json::to_vec(&call).unwrap())
                    .await
                    .unwrap();
                client_in.write_all(b"\n").await.unwrap();
                loop {
                    if started
                        .lock()
                        .await
                        .contains(&RequestId::Number(id as i64))
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                let cancel = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": id, "reason": "test"}
                });
                client_in
                    .write_all(&serde_json::to_vec(&cancel).unwrap())
                    .await
                    .unwrap();
                client_in.write_all(b"\n").await.unwrap();
                // Wait until CreditGuard releases the cancelled slot.
                while lock(&pending.state)
                    .entries
                    .contains_key(&RequestId::Number(id as i64))
                {
                    tokio::task::yield_now().await;
                }
            }
            assert!(!overload.is_cancelled());
            assert!(!shutdown.is_cancelled());

            // 21st tool call succeeds cleanly without session overload.
            let verify = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {}}
            });
            client_in
                .write_all(&serde_json::to_vec(&verify).unwrap())
                .await
                .unwrap();
            client_in.write_all(b"\n").await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.contains("\"id\":99"), "unexpected reply: {line}");
            drop(client_in);
            server_task.await.unwrap();
        })
        .await
        .expect("sequential cancel reclamation test stalled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_live_request_id_triggers_overload() {
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(Duration::from_secs(3), async {
            let (server_in, mut client_in) = tokio::io::duplex(4096);
            let (_client_out, server_out) = tokio::io::duplex(4096);
            let shutdown = CancellationToken::new();
            let overload = CancellationToken::new();
            let mut transport = BoundedTransport::with_control(
                rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new(
                    server_in, server_out,
                ),
                shutdown.clone(),
                overload.clone(),
            );
            for _ in 0..2 {
                client_in
                    .write_all(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#)
                    .await
                    .unwrap();
                client_in.write_all(b"\n").await.unwrap();
            }
            assert!(transport.receive().await.is_some());
            assert!(transport.receive().await.is_none());
            assert!(overload.is_cancelled());
            assert!(shutdown.is_cancelled());
            transport.close().await.unwrap();
        })
        .await
        .expect("duplicate id overload test stalled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn healthy_consumer_burst_above_in_flight_limit_returns_busy_without_overload() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        tokio::time::timeout(Duration::from_secs(3), async {
            let (server_in, mut client_in) = tokio::io::duplex(16384);
            let (client_out, server_out) = tokio::io::duplex(16384);
            let shutdown = CancellationToken::new();
            let overload = CancellationToken::new();
            let mut transport = BoundedTransport::with_control(
                rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new(
                    server_in, server_out,
                ),
                shutdown.clone(),
                overload.clone(),
            );
            for id in 1..=(MAX_IN_FLIGHT + 1) {
                let req = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#);
                client_in.write_all(req.as_bytes()).await.unwrap();
                client_in.write_all(b"\n").await.unwrap();
            }
            for _ in 0..MAX_IN_FLIGHT {
                assert!(transport.receive().await.is_some());
            }
            let mut reader = tokio::io::BufReader::new(client_out);
            let recv_task = tokio::spawn(async move { (transport.receive().await, transport) });
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let busy: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(busy["id"], (MAX_IN_FLIGHT + 1) as u64);
            assert_eq!(busy["error"]["code"], -32000);
            assert!(!overload.is_cancelled());
            assert!(!shutdown.is_cancelled());
            drop(client_in);
            let (next, mut transport) = recv_task.await.unwrap();
            assert!(next.is_none());
            assert!(!overload.is_cancelled());
            assert!(!shutdown.is_cancelled());
            transport.close().await.unwrap();
        })
        .await
        .expect("healthy burst busy-reply test stalled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_bytes_charge_on_send_and_refund_after_the_write_completes() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        tokio::time::timeout(Duration::from_secs(3), async {
            // One byte of capacity keeps the frame resident in the writer.
            let (writer, reader) = tokio::io::duplex(1);
            let mut transport =
                BoundedTransport::new(rmcp::transport::async_rw::AsyncRwTransport::<
                    RoleServer,
                    _,
                    _,
                >::new(tokio::io::empty(), writer));
            let reply: ServerJsonRpcMessage = serde_json::from_value(serde_json::json!({
                "jsonrpc":"2.0", "id":41, "result":{"tools":[]}
            }))
            .unwrap();
            let expected = crate::wire::frame_len(&reply).expect("frame fits");
            assert!(expected > 0);
            let pending = Arc::clone(&transport.pending);
            lock(&pending.state)
                .entries
                .insert(RequestId::Number(41), CreditState::CompletedAwaitingRmcp);

            let send = tokio::spawn(transport.send(reply));
            let mut reader = tokio::io::BufReader::new(reader);
            while reader.read_u8().await.unwrap() != b'{' {}
            // The frame is mid-write: the full serialized size stays charged.
            assert_eq!(lock(&pending.state).queued_bytes, expected);

            // The leading `{` was consumed above; read the rest of the frame.
            let mut rest = Vec::new();
            reader.read_until(b'\n', &mut rest).await.unwrap();
            assert!(rest.ends_with(b"\n"));
            assert!(String::from_utf8_lossy(&rest).contains("\"id\":41"));
            send.await.unwrap().unwrap();
            assert_eq!(lock(&pending.state).queued_bytes, 0);
            assert!(
                !lock(&pending.state)
                    .entries
                    .contains_key(&RequestId::Number(41))
            );
        })
        .await
        .expect("queued byte accounting stalled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_writer_above_blocked_bytes_trips_overload_below_active_limit() {
        use tokio::io::AsyncWriteExt;
        tokio::time::timeout(Duration::from_secs(3), async {
            let (server_in, mut client_in) = tokio::io::duplex(4096);
            let (client_out, server_out) = tokio::io::duplex(4096);
            let shutdown = CancellationToken::new();
            let overload = CancellationToken::new();
            let pending = PendingReplies::new(shutdown.clone(), overload.clone());
            let mut transport = BoundedTransport::with_pending(
                rmcp::transport::async_rw::AsyncRwTransport::<RoleServer, _, _>::new(
                    server_in, server_out,
                ),
                Arc::clone(&pending),
            );

            // Hold the writer so every later frame queues as `Sending`.
            let writer_guard = transport.writer.clone().lock_owned().await;
            let first = RequestId::Number(100);
            assert_eq!(pending.reserve(&first, true), ReserveOutcome::Admitted);
            let credit = pending.mark_sending(&first, MAX_BLOCKED_BYTES);
            assert_eq!(lock(&pending.state).queued_bytes, MAX_BLOCKED_BYTES);
            // Fewer than MAX_ACTIVE entries are queued, yet the byte bound trips.
            assert!(lock(&pending.state).entries.len() < MAX_ACTIVE);
            assert!(!overload.is_cancelled());

            client_in
                .write_all(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#)
                .await
                .unwrap();
            client_in.write_all(b"\n").await.unwrap();
            assert!(transport.receive().await.is_none());
            assert!(overload.is_cancelled());
            assert!(shutdown.is_cancelled());
            assert!(lock(&pending.state).overloaded);
            drop(credit);
            drop(writer_guard);
            transport.close().await.unwrap();
            drop(client_out);
            client_in.shutdown().await.unwrap();
        })
        .await
        .expect("blocked-byte overload test stalled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_completed_reply_still_charges_and_refunds_its_bytes() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        tokio::time::timeout(Duration::from_secs(3), async {
            let (writer, reader) = tokio::io::duplex(1);
            let mut transport =
                BoundedTransport::new(rmcp::transport::async_rw::AsyncRwTransport::<
                    RoleServer,
                    _,
                    _,
                >::new(tokio::io::empty(), writer));
            let reply: ServerJsonRpcMessage = serde_json::from_value(serde_json::json!({
                "jsonrpc":"2.0", "id":42, "result":{"tools":[]}
            }))
            .unwrap();
            let expected = crate::wire::frame_len(&reply).expect("frame fits");
            let id = RequestId::Number(42);
            let pending = Arc::clone(&transport.pending);
            lock(&pending.state)
                .entries
                .insert(id.clone(), CreditState::CompletedAwaitingRmcp);

            // Cancellation must not drop a reply whose response already exists.
            pending.mark_cancelled(&id);
            assert_eq!(
                lock(&pending.state).entries.get(&id),
                Some(&CreditState::CompletedAwaitingRmcp)
            );

            let send = tokio::spawn(transport.send(reply));
            let mut reader = tokio::io::BufReader::new(reader);
            while reader.read_u8().await.unwrap() != b'{' {}
            assert_eq!(lock(&pending.state).queued_bytes, expected);
            let mut rest = Vec::new();
            reader.read_until(b'\n', &mut rest).await.unwrap();
            assert!(String::from_utf8_lossy(&rest).contains("\"id\":42"));
            send.await.unwrap().unwrap();
            assert_eq!(lock(&pending.state).queued_bytes, 0);
            assert!(!lock(&pending.state).entries.contains_key(&id));
        })
        .await
        .expect("cancelled completed reply lost its byte accounting");
    }

    #[test]
    fn untracked_frames_still_charge_and_refund_their_bytes() {
        let pending = PendingReplies::new(CancellationToken::new(), CancellationToken::new());
        let id = RequestId::Number(7);
        let credit = pending.mark_sending(&id, 4096);
        assert_eq!(lock(&pending.state).queued_bytes, 4096);
        assert!(lock(&pending.state).entries.is_empty());
        drop(credit);
        assert_eq!(lock(&pending.state).queued_bytes, 0);
    }
}
