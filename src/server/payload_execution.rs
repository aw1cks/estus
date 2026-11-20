use super::{Estus, preparation::request_deadline};
use crate::{
    audit::{Audit, Metadata},
    bindings::{AutomationRequest, BindingId},
    reply::{AutomationData, ErrorCode, ToolError, ToolReply},
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
            return reject(ToolError::cancelled(
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
        // Authorize the target up front; the resolved value is re-read at each use.
        if let Err(error) = self.state.config.automation_target(id, &request.host) {
            return reject(error);
        }
        let risk_tier = crate::config::risk_tier_for_binding(binding);
        let is_preview = risk_tier == crate::config::RiskTier::Preview;
        let requires_preview = matches!(
            risk_tier,
            crate::config::RiskTier::Change | crate::config::RiskTier::Exec
        ) && self.state.config.requires_preview(&request.host);
        let preview_meta = if is_preview || requires_preview {
            match super::preview::PreviewSpec::for_payload(
                &binding.name,
                is_preview,
                &prepared.merged_args,
            ) {
                Some(spec) => Some(spec),
                None if requires_preview => {
                    return reject(ToolError::preview_required(
                        "Operation has no qualified preview path under require_preview policy",
                        false,
                    ));
                }
                None => None,
            }
        } else {
            None
        };
        let admission_mode = if binding.is_shared_read() {
            super::admission::AdmissionMode::SharedRead
        } else if binding.is_probe_only() {
            super::admission::AdmissionMode::ExclusiveProbe
        } else {
            super::admission::AdmissionMode::ExclusiveWrite
        };
        let revision = binding.revision.clone();
        let payload_request = prepared.request;
        let output_limit = prepared.output_limit;
        let operation = match self
            .state
            .acquire_permit(&self.state.operations, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => return reject(error),
        };
        let runtime = match self
            .state
            .acquire_permit(&self.state.automation, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => return reject(error),
        };
        let state = Arc::clone(&self.state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            // Dropping an MCP handler never relinquishes execution/admission ownership.
            let _credit = crate::progress::HandlerCredit::from_context(&context);
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
                    admission_mode,
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
            if requires_preview {
                let spec = preview_meta
                    .as_ref()
                    .expect("preview spec checked before spawn");
                let pre_state_digest = match state
                    .payload
                    .observe_preview_prestate(crate::native_payload::PreviewPrestateRequest {
                        host: &request.host,
                        authority: &authority,
                        target: &target,
                        module: spec.prestate_module,
                        arguments: &spec.prestate_args,
                        connect_timeout: Duration::from_secs(
                            state.config.limits().connect_timeout_secs,
                        ),
                        deadline,
                        ct: &context.ct,
                    })
                    .await
                {
                    Ok(digest) => digest,
                    Err(error) => {
                        let error =
                            if matches!(error.code(), ErrorCode::Cancelled | ErrorCode::Timeout) {
                                error
                            } else {
                                ToolError::preview_required(
                                    "Independent pre-state digest could not be obtained",
                                    false,
                                )
                            };
                        target_lease.finish(false, Some(error.code()));
                        metadata.reject(started, &error);
                        let _ = sender.send(ToolReply::failure(error));
                        return;
                    }
                };
                let key = super::preview::PreviewKey {
                    target: request.host.clone(),
                    authority: identity_role,
                    domain: spec.domain,
                    intent_digest: spec.intent_digest,
                    pre_state_digest,
                };
                if !state.previews.consume(&key) {
                    let error = ToolError::preview_required(
                        "A matching non-expired preview is required before apply",
                        false,
                    );
                    target_lease.finish(false, Some(error.code()));
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::failure(error));
                    return;
                }
            }
            let audit = Audit::start(metadata, started);
            target_lease.mark_dispatched(request.host.clone(), authority.clone(), "native_payload");
            let reply = state
                .payload
                .run(crate::native_payload::PayloadRun {
                    plan: &activated.plan,
                    host: &request.host,
                    authority: &authority,
                    target,
                    request: payload_request,
                    output_limit,
                    connect_timeout: Duration::from_secs(
                        state.config.limits().connect_timeout_secs,
                    ),
                    deadline,
                    ct: &context.ct,
                    started,
                })
                .await;
            if is_preview
                && reply.error().is_none()
                && reply.data().is_some_and(|d| {
                    d.complete && d.status == crate::reply::AutomationStatus::Successful
                })
                && let Some(spec) = preview_meta
                && let Ok(pre_state_digest) = state
                    .payload
                    .observe_preview_prestate(crate::native_payload::PreviewPrestateRequest {
                        host: &request.host,
                        authority: &authority,
                        target: &state
                            .config
                            .automation_target(id, &request.host)
                            .expect("payload target already authorized"),
                        module: spec.prestate_module,
                        arguments: &spec.prestate_args,
                        connect_timeout: Duration::from_secs(
                            state.config.limits().connect_timeout_secs,
                        ),
                        deadline,
                        ct: &context.ct,
                    })
                    .await
            {
                // Record the key from the preview's own pre-state observation.
                state.previews.insert(super::preview::PreviewKey {
                    target: request.host.clone(),
                    authority: identity_role,
                    domain: spec.domain,
                    intent_digest: spec.intent_digest,
                    pre_state_digest,
                });
            }
            target_lease.finish(
                reply.error().is_some_and(|e| e.remote_state_unknown),
                reply.error().map(|error| error.code()),
            );
            audit.finish_automation(&reply);
            let _ = sender.send(reply);
        });
        let reply = receiver.await.unwrap_or_else(|_| {
            ToolReply::failure(ToolError::io_error(
                "Native payload worker lost; remote state is unknown",
                true,
            ))
        });
        budget.result(reply)
    }
}
