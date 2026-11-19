use super::{Estus, preparation::request_deadline};
use crate::{
    audit::{Audit, Metadata},
    bindings::{AutomationRequest, BindingId},
    reply::{AutomationData, ToolError, ToolReply},
    wire::ReplyBudget,
};
use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
impl Estus {
    pub(super) async fn payload_binding(
        &self,
        id: BindingId,
        activated: Arc<crate::bindings::ActivatedPayload>,
        request: AutomationRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered binding exists");
        budget.automation_reserve(&request.host, Some(activated.projection.max_bytes))?;
        let identity_role = activated.authority.identity_role();
        let authority = activated.authority.label().into_owned();
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .permits_host(&request.host)
                .then_some(request.host.as_str()),
            identity_role,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some("native_payload"),
        };
        let reject = |error: ToolError| {
            metadata.reject(started, &error);
            budget.result(ToolReply::<AutomationData>::failure(error))
        };
        if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
            return reject(ToolError::new(
                "cancelled",
                "Request cancelled before dispatch",
                false,
            ));
        }
        let prepared = match binding.prepare_activated_payload(
            &activated,
            &request,
            self.state.config.limits(),
        ) {
            Ok(prepared) => prepared,
            Err(error) => return reject(error),
        };
        let deadline = match request_deadline(started, prepared.duration) {
            Ok(deadline) => deadline,
            Err(error) => return reject(error),
        };
        if let Err(error) = self.state.config.automation_target(id, &request.host) {
            return reject(error);
        }
        if matches!(
            crate::config::risk_tier_for_binding(binding),
            crate::config::RiskTier::Change | crate::config::RiskTier::Exec
        ) && self.state.config.requires_preview(&request.host)
        {
            return reject(ToolError::new(
                "preview_required",
                "Operation has no qualified preview path under require_preview policy",
                false,
            ));
        }
        let shared_read = binding.is_shared_read();
        let revision = binding.revision.clone();
        let argv = prepared.argv;
        let output_limit = prepared.output_limit;
        let Ok(operation) = Arc::clone(&self.state.operations).try_acquire_owned() else {
            return reject(ToolError::new(
                "resource_limit",
                "Tool operation limit reached",
                false,
            ));
        };
        let Ok(runtime) = Arc::clone(&self.state.automation).try_acquire_owned() else {
            return reject(ToolError::new(
                "resource_limit",
                "Automation operation limit reached",
                false,
            ));
        };
        let state = Arc::clone(&self.state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            // Dropping an MCP handler never relinquishes execution/admission ownership.
            let _permits = (operation, runtime);
            let metadata = Metadata {
                request_id: &context.id,
                tool: state.binding_name(id),
                host: Some(&request.host),
                identity_role,
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: Some(&revision),
                executor: Some("native_payload"),
            };
            let mut target_lease = match state
                .admission
                .acquire(
                    &request.host,
                    shared_read,
                    deadline,
                    &context.ct,
                    &state.shutdown,
                )
                .await
            {
                Ok(lease) => lease,
                Err(error) => {
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::failure(error));
                    return;
                }
            };
            let target = state
                .config
                .automation_target(id, &request.host)
                .expect("payload target already authorized");
            let audit = Audit::start(metadata, started);
            target_lease.mark_dispatched(request.host.clone(), authority.clone(), "native_payload");
            let reply = state
                .payload
                .run(crate::native_payload::PayloadRun {
                    plan: &activated.plan,
                    host: &request.host,
                    authority: &authority,
                    target,
                    argv,
                    output_limit,
                    connect_timeout: Duration::from_secs(
                        state.config.limits().connect_timeout_secs,
                    ),
                    deadline,
                    ct: &context.ct,
                    started,
                })
                .await;
            target_lease.finish(
                reply.error.as_ref().is_some_and(|e| e.remote_state_unknown),
                reply.error.as_ref().map_or("unknown", |e| e.code),
            );
            audit.finish_automation(&reply);
            let _ = sender.send(reply);
        });
        let reply = receiver.await.unwrap_or_else(|_| {
            ToolReply::failure(ToolError::new(
                "io_error",
                "Native payload worker lost; remote state is unknown",
                true,
            ))
        });
        budget.result(reply)
    }
}
