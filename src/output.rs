//! Request-owned, bounded local output capabilities. Nothing is created until finish.
use std::{
    collections::HashMap,
    fs::{File, OpenOptions, Permissions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use schemars::JsonSchema;
use serde::Deserialize;
use tempfile::TempDir;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    filesystem::data::{self, Encoding, RawRead, ReadData},
    reply::{OutputReceipt, StreamInfo, ToolError, ToolReply},
    wire::ReplyBudget,
};

const FINALIZE_GRACE: Duration = Duration::from_millis(250);
const READ_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub enabled: bool,
    pub per_stream_bytes: u64,
    pub total_bytes: u64,
    pub max_handles: usize,
    pub ttl_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            enabled: true,
            per_stream_bytes: 1_048_576,
            total_bytes: 16_777_216,
            max_handles: 8,
            ttl_secs: 300,
        }
    }
}

impl Limits {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if !(1..=4_194_304).contains(&self.per_stream_bytes) {
            return Err("output.per_stream_bytes must be between 1 and 4194304");
        }
        if self.total_bytes < 2 * self.per_stream_bytes || self.total_bytes > 67_108_864 {
            return Err("output.total_bytes must be between twice per_stream_bytes and 67108864");
        }
        if !(1..=64).contains(&self.max_handles) {
            return Err("output.max_handles must be between 1 and 64");
        }
        if !(1..=3600).contains(&self.ttl_secs) {
            return Err("output.ttl_secs must be between 1 and 3600");
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct RetainedBytes {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub truncated: bool,
}

impl RetainedBytes {
    fn info(&self) -> StreamInfo {
        StreamInfo {
            bytes_retained: self.bytes.len() as u64,
            total_bytes: self.total_bytes.max(self.bytes.len() as u64),
            truncated: self.truncated || self.total_bytes > self.bytes.len() as u64,
        }
    }
}

#[derive(Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputStream {
    Stdout,
    Stderr,
}

impl OutputStream {
    fn basename(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReadOutputRequest {
    #[schemars(length(equal = 32), pattern(r"^[0-9a-f]{32}$"))]
    pub handle: String,
    pub stream: OutputStream,
    pub offset: Option<u64>,
    #[schemars(range(min = 1))]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub encoding: Encoding,
}

#[derive(Clone)]
pub(crate) struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    limits: Limits,
    stop: CancellationToken,
    ready: Mutex<HashMap<String, Entry>>,
    usage: Mutex<Usage>,
    workers: TaskTracker,
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    handles: usize,
    readers: usize,
}

struct Entry {
    artifact: Arc<Artifact>,
    expires: Instant,
    timer: CancellationToken,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.timer.cancel();
    }
}

struct Artifact {
    directory: Option<TempDir>,
    lengths: [u64; 2],
    quota: Option<Quota>,
    workers: TaskTracker,
    runtime: tokio::runtime::Handle,
}

impl Artifact {
    fn directory(&self) -> &TempDir {
        // Only Drop takes this field, after all references have gone away.
        self.directory
            .as_ref()
            .expect("live artifact owns its directory")
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        let directory = self.directory.take();
        let quota = self.quota.take();
        // The handle/bytes still belong to this cleanup job, even if unlink
        // blocks past shutdown's grace. Never run filesystem destruction on
        // the async caller which released the final read/publication lease.
        self.workers.spawn_blocking_on(
            move || {
                drop(directory);
                drop(quota);
            },
            &self.runtime,
        );
    }
}

// The resource owner, never the async waiter, releases credits. Weak avoids the
// ready map -> artifact -> quota -> store cycle, including detached blocking IO.
struct Quota {
    store: Weak<Inner>,
    bytes: u64,
    handles: usize,
    readers: usize,
}

impl Drop for Quota {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            let mut usage = lock(&store.usage);
            usage.bytes -= self.bytes;
            usage.handles -= self.handles;
            usage.readers -= self.readers;
        }
    }
}

impl Quota {
    fn shrink(&mut self, bytes: u64) {
        if let Some(store) = self.store.upgrade() {
            lock(&store.usage).bytes -= self.bytes - bytes;
        }
        self.bytes = bytes;
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(crate) struct Session {
    store: Weak<Inner>,
    quota: Option<Quota>,
    reason: &'static str,
    limit: u64,
}

impl Store {
    pub(crate) fn new(limits: Limits, shutdown: CancellationToken) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                stop: shutdown.child_token(),
                ready: Mutex::new(HashMap::new()),
                usage: Mutex::new(Usage::default()),
                workers: TaskTracker::new(),
            }),
        }
    }

    pub(crate) fn reserve(&self) -> Session {
        self.inner.expire();
        let limits = self.inner.limits;
        let mut session = Session {
            store: Arc::downgrade(&self.inner),
            quota: None,
            reason: "resource_limit",
            limit: 0,
        };
        if self.inner.stop.is_cancelled() {
            session.reason = "shutdown";
        } else if !limits.enabled {
            session.reason = "retention_disabled";
        } else if let Some(bytes) = limits.per_stream_bytes.checked_mul(2) {
            let mut usage = lock(&self.inner.usage);
            if usage.handles < limits.max_handles
                && usage
                    .bytes
                    .checked_add(bytes)
                    .is_some_and(|n| n <= limits.total_bytes)
            {
                usage.bytes += bytes;
                usage.handles += 1;
                session.limit = limits.per_stream_bytes;
                session.quota = Some(Quota {
                    store: session.store.clone(),
                    bytes,
                    handles: 1,
                    readers: 0,
                });
            }
        }
        session
    }

    pub(crate) async fn shutdown(&self) {
        self.inner.stop.cancel();
        let entries = std::mem::take(&mut *lock(&self.inner.ready));
        // Readers and blocking writers retain their own owners until they end.
        drop(entries);
        self.inner.workers.close();
        // This is a bounded wait, not cancellation of uninterruptible OS IO.
        let _ = tokio::time::timeout(FINALIZE_GRACE, self.inner.workers.wait()).await;
    }

    pub(crate) async fn read(
        &self,
        request: ReadOutputRequest,
        max_file_bytes: u64,
        budget: ReplyBudget,
    ) -> ToolReply<ReadData> {
        let max_bytes = match data::validate_read_range(
            request.max_bytes,
            request.encoding,
            max_file_bytes,
            budget,
        ) {
            Ok(value) => value,
            Err(error) => return ToolReply::failure(error),
        };
        if request.handle.len() != 32
            || !request
                .handle
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return ToolReply::failure(local_error(
                "invalid_argument",
                "handle must contain 32 lowercase hexadecimal characters",
            ));
        }
        self.inner.expire();
        let artifact = {
            let ready = lock(&self.inner.ready);
            if self.inner.stop.is_cancelled() {
                None
            } else {
                ready
                    .get(&request.handle)
                    .map(|entry| entry.artifact.clone())
            }
        };
        let Some(artifact) = artifact else {
            return ToolReply::failure(not_found());
        };
        let offset = request.offset.unwrap_or(0);
        let available = artifact.lengths[request.stream.index()].saturating_sub(offset);
        let count = available.min(max_bytes as u64 + 1);
        let quota = {
            let mut usage = lock(&self.inner.usage);
            // Reader memory is independently bounded by max_handles workers,
            // each reading at most one per_stream_bytes artifact. A full
            // storage reservation must not make its own artifacts unreadable.
            if usage.readers >= self.inner.limits.max_handles {
                return ToolReply::failure(local_error(
                    "resource_limit",
                    "Output read resource limit reached",
                ));
            }
            usage.readers += 1;
            Quota {
                store: Arc::downgrade(&self.inner),
                bytes: 0,
                handles: 0,
                readers: 1,
            }
        };
        let cancel = self.inner.stop.child_token();
        let _guard = cancel.clone().drop_guard();
        let worker_cancel = cancel.clone();
        let worker = self.inner.workers.spawn_blocking(move || {
            let _quota = quota;
            let _artifact = artifact;
            if worker_cancel.is_cancelled() {
                return Err(local_error("shutdown", "Output read cancelled"));
            }
            let mut bytes = BytesMut::zeroed(count as usize);
            if count != 0 {
                let mut file =
                    File::open(_artifact.directory().path().join(request.stream.basename()))
                        .map_err(|_| io_error())?;
                file.seek(SeekFrom::Start(offset)).map_err(|_| io_error())?;
                file.read_exact(&mut bytes).map_err(|_| io_error())?;
            }
            if worker_cancel.is_cancelled() {
                return Err(local_error("shutdown", "Output read cancelled"));
            }
            data::encode_range(
                RawRead {
                    bytes,
                    eof: available <= max_bytes as u64,
                },
                offset,
                max_bytes,
                request.encoding,
                None,
            )
        });
        tokio::select! {
            biased;
            _ = self.inner.stop.cancelled() => ToolReply::failure(local_error("shutdown", "Output read cancelled")),
            result = tokio::time::timeout(READ_GRACE, worker) => match result {
                Ok(Ok(Ok(data))) => ToolReply::success(data),
                Ok(Ok(Err(error))) => ToolReply::failure(error),
                Ok(Err(_)) => ToolReply::failure(io_error()),
                Err(_) => ToolReply::failure(local_error("timeout", "Output read timed out")),
            }
        }
    }
}

impl Inner {
    fn expire(&self) {
        let expired = {
            let mut ready = lock(&self.ready);
            let now = Instant::now();
            let keys: Vec<_> = ready
                .iter()
                .filter(|(_, entry)| entry.expires <= now)
                .map(|(key, _)| key.clone())
                .collect();
            keys.into_iter()
                .filter_map(|key| ready.remove(&key))
                .collect::<Vec<_>>()
        };
        drop(expired);
    }
}

impl Session {
    pub(crate) fn capture_limit(&self) -> u64 {
        self.limit
    }

    pub(crate) async fn finish(
        mut self,
        stdout: RetainedBytes,
        stderr: RetainedBytes,
        request_ct: &CancellationToken,
    ) -> Option<OutputReceipt> {
        if request_ct.is_cancelled() {
            return None;
        }
        let Some(quota) = self.quota.take() else {
            return Some(unavailable(self.reason));
        };
        let Some(store) = self.store.upgrade() else {
            return Some(unavailable("shutdown"));
        };
        if store.stop.is_cancelled() {
            return Some(unavailable("shutdown"));
        }
        // Defend the private ownership boundary even if an internal caller errs.
        if stdout.bytes.len() as u64 > self.limit
            || stderr.bytes.len() as u64 > self.limit
            || stdout.bytes.capacity() as u64 > self.limit
            || stderr.bytes.capacity() as u64 > self.limit
        {
            return Some(unavailable("resource_limit"));
        }
        let stdout_info = stdout.info();
        let stderr_info = stderr.info();
        let cancel = store.stop.child_token();
        let _guard = cancel.clone().drop_guard();
        let worker_cancel = cancel.clone();
        let request_cancel = request_ct.clone();
        let deadline = Instant::now() + FINALIZE_GRACE;
        let workers = store.workers.clone();
        let worker = store.workers.spawn_blocking(move || {
            write_artifact(
                stdout,
                stderr,
                quota,
                &worker_cancel,
                &request_cancel,
                workers,
            )
        });
        let artifact = tokio::select! {
            biased;
            _ = store.stop.cancelled() => return Some(unavailable("shutdown")),
            _ = request_ct.cancelled() => return None,
            result = tokio::time::timeout(FINALIZE_GRACE, worker) => match result {
                Ok(Ok(Ok(artifact))) => artifact,
                Ok(_) => return Some(unavailable("io_error")),
                Err(_) => return Some(unavailable("timeout")),
            }
        };
        let mut random = [0u8; 16];
        if getrandom::fill(&mut random).is_err() {
            return Some(unavailable("io_error"));
        }
        let handle = hex::encode(random);
        let ttl = store.limits.ttl_secs;
        let expires = Instant::now() + Duration::from_secs(ttl);
        let timer = store.stop.child_token();
        {
            let mut ready = lock(&store.ready);
            if store.stop.is_cancelled() {
                return Some(unavailable("shutdown"));
            }
            if request_ct.is_cancelled() {
                return None;
            }
            if Instant::now() >= deadline {
                return Some(unavailable("timeout"));
            }
            if ready.contains_key(&handle) {
                return Some(unavailable("io_error"));
            }
            ready.insert(
                handle.clone(),
                Entry {
                    artifact: Arc::new(artifact),
                    expires,
                    timer: timer.clone(),
                },
            );
        }
        let weak = Arc::downgrade(&store);
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = timer.cancelled() => {},
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(expires)) => {
                    if let Some(store) = weak.upgrade() { store.expire(); }
                }
            }
        });
        Some(OutputReceipt::Ready {
            handle,
            expires_in_secs: ttl,
            stdout: stdout_info,
            stderr: stderr_info,
        })
    }
}

fn write_artifact(
    stdout: RetainedBytes,
    stderr: RetainedBytes,
    mut quota: Quota,
    cancel: &CancellationToken,
    request_cancel: &CancellationToken,
    workers: TaskTracker,
) -> io::Result<Artifact> {
    let cancelled = || cancel.is_cancelled() || request_cancel.is_cancelled();
    if cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    let directory = tempfile::Builder::new()
        .prefix("estus-output-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir()?;
    let lengths = [stdout.bytes.len() as u64, stderr.bytes.len() as u64];
    for (name, bytes) in [("stdout", stdout.bytes), ("stderr", stderr.bytes)] {
        if cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.path().join(name))?;
        file.write_all(&bytes)?;
        // Closing before returning is essential: only closed artifacts publish.
        drop(file);
    }
    if cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
    }
    quota.shrink(lengths[0] + lengths[1]);
    Ok(Artifact {
        directory: Some(directory),
        lengths,
        quota: Some(quota),
        workers,
        runtime: tokio::runtime::Handle::current(),
    })
}

fn unavailable(reason: &'static str) -> OutputReceipt {
    OutputReceipt::Unavailable { reason }
}
fn local_error(code: &'static str, message: &'static str) -> ToolError {
    ToolError::new(code, message, false)
}
fn io_error() -> ToolError {
    local_error("io_error", "Unable to read retained output")
}
fn not_found() -> ToolError {
    local_error("not_found", "Retained output not found")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            per_stream_bytes: 16,
            total_bytes: 32,
            max_handles: 1,
            ttl_secs: 1,
            ..Limits::default()
        }
    }

    fn retained(bytes: &[u8]) -> RetainedBytes {
        RetainedBytes {
            bytes: bytes.to_vec(),
            total_bytes: bytes.len() as u64,
            truncated: false,
        }
    }

    #[test]
    fn pending_ownership_holds_both_stream_credits_until_drop() {
        let store = Store::new(limits(), CancellationToken::new());
        let session = store.reserve();
        assert_eq!(session.capture_limit(), 16);
        assert_eq!(store.reserve().capture_limit(), 0);
        assert_eq!(lock(&store.inner.usage).bytes, 32);
        drop(session);
        assert_eq!(store.reserve().capture_limit(), 16);
    }

    #[tokio::test]
    async fn expiry_unpublishes_but_read_owner_keeps_private_files_and_quota() {
        let store = Store::new(limits(), CancellationToken::new());
        let receipt = store
            .reserve()
            .finish(
                retained(b"abc"),
                retained(b"err"),
                &CancellationToken::new(),
            )
            .await
            .expect("retention receipt");
        let OutputReceipt::Ready { handle, .. } = receipt else {
            panic!("publication failed");
        };
        let artifact = {
            let mut ready = lock(&store.inner.ready);
            let entry = ready.get_mut(&handle).unwrap();
            entry.expires = Instant::now();
            entry.artifact.clone()
        };
        let path = artifact.directory().path().to_owned();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in ["stdout", "stderr"] {
            assert_eq!(
                std::fs::metadata(path.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        store.inner.expire();
        assert!(lock(&store.inner.ready).is_empty());
        assert!(path.exists());
        assert_eq!(lock(&store.inner.usage).bytes, 6);
        assert_eq!(store.reserve().capture_limit(), 0);
        drop(artifact);
        store.inner.workers.close();
        tokio::time::timeout(Duration::from_secs(2), store.inner.workers.wait())
            .await
            .unwrap();
        assert!(!path.exists());
        assert_eq!(store.reserve().capture_limit(), 16);
    }

    #[tokio::test]
    async fn shutdown_revokes_capabilities_and_cleans_artifacts() {
        let store = Store::new(limits(), CancellationToken::new());
        let receipt = store
            .reserve()
            .finish(
                retained(b"data"),
                RetainedBytes::default(),
                &CancellationToken::new(),
            )
            .await
            .expect("retention receipt");
        let OutputReceipt::Ready { handle, .. } = receipt else {
            panic!("publication failed");
        };
        let path = lock(&store.inner.ready)[&handle]
            .artifact
            .directory()
            .path()
            .to_owned();
        store.shutdown().await;
        assert!(!path.exists());
        assert_eq!(store.reserve().capture_limit(), 0);
        assert!(matches!(
            store
                .reserve()
                .finish(
                    RetainedBytes::default(),
                    RetainedBytes::default(),
                    &CancellationToken::new()
                )
                .await,
            Some(OutputReceipt::Unavailable { reason: "shutdown" })
        ));
    }

    #[tokio::test]
    async fn full_artifact_storage_still_allows_bounded_reads() {
        let store = Store::new(limits(), CancellationToken::new());
        let receipt = store
            .reserve()
            .finish(
                retained(b"0123456789abcdef"),
                retained(b"fedcba9876543210"),
                &CancellationToken::new(),
            )
            .await
            .expect("retention receipt");
        let OutputReceipt::Ready { handle, .. } = receipt else {
            panic!("publication failed");
        };
        assert_eq!(lock(&store.inner.usage).bytes, 32);
        assert_eq!(store.reserve().capture_limit(), 0);
        let budget = ReplyBudget::new(&rmcp::model::RequestId::Number(1)).unwrap();
        let reply = store
            .read(
                ReadOutputRequest {
                    handle,
                    stream: OutputStream::Stdout,
                    offset: None,
                    max_bytes: Some(16),
                    encoding: Encoding::Utf8,
                },
                16,
                budget,
            )
            .await;
        assert!(reply.error.is_none());
        let data = reply.data.unwrap();
        assert_eq!(data.content, "0123456789abcdef");
        assert!(data.eof);
        assert_eq!(lock(&store.inner.usage).bytes, 32);
        assert_eq!(lock(&store.inner.usage).readers, 0);
        store.shutdown().await;
    }

    #[tokio::test]
    async fn foreign_handle_is_not_found_and_ranges_are_lossless() {
        let store = Store::new(limits(), CancellationToken::new());
        let receipt = store
            .reserve()
            .finish(
                retained(b"a\0\xffz"),
                RetainedBytes::default(),
                &CancellationToken::new(),
            )
            .await
            .expect("retention receipt");
        let OutputReceipt::Ready { handle, .. } = receipt else {
            panic!("publication failed");
        };
        let budget = ReplyBudget::new(&rmcp::model::RequestId::Number(1)).unwrap();
        let foreign = Store::new(limits(), CancellationToken::new());
        let request = || ReadOutputRequest {
            handle: handle.clone(),
            stream: OutputStream::Stdout,
            offset: Some(1),
            max_bytes: Some(2),
            encoding: Encoding::Base64,
        };
        let error = foreign.read(request(), 16, budget).await.error.unwrap();
        assert_eq!(error.code, "not_found");
        assert!(!error.remote_state_unknown);
        let data = store.read(request(), 16, budget).await.data.unwrap();
        assert_eq!(data.content, "AP8=");
        assert_eq!(data.bytes_read, 2);
        assert_eq!(data.next_offset, 3);
        assert!(!data.eof);
        let error = store
            .read(
                ReadOutputRequest {
                    encoding: Encoding::Utf8,
                    ..request()
                },
                16,
                budget,
            )
            .await
            .error
            .unwrap();
        assert_eq!(error.code, "invalid_encoding");
        store.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_finish_reclaims_quota_and_normal_post_return_cancel_keeps_entry() {
        let store = Store::new(limits(), CancellationToken::new());
        let pre_cancelled = CancellationToken::new();
        pre_cancelled.cancel();
        assert!(
            store
                .reserve()
                .finish(retained(b"abc"), RetainedBytes::default(), &pre_cancelled)
                .await
                .is_none()
        );
        assert_eq!(lock(&store.inner.usage).handles, 0);
        assert_eq!(lock(&store.inner.usage).bytes, 0);

        let post_return = CancellationToken::new();
        let receipt = store
            .reserve()
            .finish(retained(b"ok"), RetainedBytes::default(), &post_return)
            .await;
        let Some(OutputReceipt::Ready { handle, .. }) = receipt else {
            panic!("expected ready receipt");
        };
        // RMCP cancels the request token after the handler returns; published output must survive.
        post_return.cancel();
        tokio::task::yield_now().await;
        assert!(lock(&store.inner.ready).contains_key(&handle));
        store.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_before_ready_insert_drops_artifact_and_reclaims_quota() {
        let store = Store::new(limits(), CancellationToken::new());
        let session = store.reserve();
        let ct = CancellationToken::new();
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let inner = Arc::clone(&store.inner);
        let holder = std::thread::spawn(move || {
            let _guard = lock(&inner.ready);
            let _ = locked_tx.send(());
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        let ct_for_task = ct.clone();
        let task = tokio::spawn(async move {
            session
                .finish(retained(b"race"), RetainedBytes::default(), &ct_for_task)
                .await
        });
        // Give write_artifact time to finish and park on lock(&store.inner.ready).
        tokio::time::sleep(Duration::from_millis(50)).await;
        ct.cancel();
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        assert!(task.await.unwrap().is_none());
        assert!(lock(&store.inner.ready).is_empty());
        let deadline = Instant::now() + Duration::from_secs(2);
        while lock(&store.inner.usage).handles != 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(lock(&store.inner.usage).handles, 0);
        assert_eq!(lock(&store.inner.usage).bytes, 0);
        assert_eq!(store.reserve().capture_limit(), 16);
        store.shutdown().await;
    }
}
