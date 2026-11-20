//! Surviving-task launch for handlers: keeps cleanup, audit and reply delivery
//! alive even when RMCP suppresses a cancelled reply and drops the handler's
//! future. The task body receives the oneshot sender and decides when to
//! deliver the result (for example before a pending cleanup finishes).

use tokio_util::task::TaskTracker;

/// Runs `body` on a tracked task and awaits the reply the body sends. The task
/// owns any permits or leases it captures, so dropping the handler's future
/// cannot skip cleanup. Returns `None` if the task was cancelled or panicked
/// before it sent a reply.
pub(super) async fn spawn_surviving<R, B, Body>(tracker: &TaskTracker, body: Body) -> Option<R>
where
    R: Send + 'static,
    B: Future<Output = ()> + Send + 'static,
    Body: Send + 'static + FnOnce(tokio::sync::oneshot::Sender<R>) -> B,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tracker.spawn(async move {
        body(sender).await;
    });
    receiver.await.ok()
}
