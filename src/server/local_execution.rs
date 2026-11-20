use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};

use crate::{
    audit::{Audit, Metadata},
    bindings::{self, BindingId, ControllerRequest},
    reply::{ControllerError, ControllerReply, ErrorCode, ToolError, ToolReply},
    wire::ReplyBudget,
};

use super::{Estus, preparation::request_deadline};

impl Estus {
    pub(super) async fn automation_binding(
        &self,
        id: BindingId,
        activated: Arc<bindings::ActivatedAutomation>,
        request: bindings::AutomationRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::reply::AutomationData;
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        // Resolved once at dispatch (see Estus::binding).
        let binding = super::preparation::Operation::binding(id, &self.state.config);
        budget.automation_reserve(
            &request.host,
            activated.projection.as_ref().map(|plan| plan.max_bytes),
        )?;
        let authority_role = activated.authority.identity_role();
        let authority_label = activated.authority.label().into_owned();
        let executor = binding.executor_kind();
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .permits_host(&request.host)
                .then_some(request.host.as_str()),
            identity_role: authority_role,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some(executor),
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
        // Authorize the target up front; the resolved value is re-read at each use.
        if let Err(error) = self.state.config.automation_target(id, &request.host) {
            return reject(error);
        }
        let prepared = match binding.prepare_activated_automation(
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
        let is_preview = activated.check_mode;
        let requires_preview = !is_preview
            && matches!(
                crate::config::risk_tier_for_binding(binding),
                crate::config::RiskTier::Change | crate::config::RiskTier::Exec
            )
            && self.state.config.requires_preview(&request.host);
        let preview_meta = if is_preview || requires_preview {
            if requires_preview && !super::preview::is_qualified_module(&activated.module) {
                return reject(ToolError::preview_required(
                    "Operation has no qualified preview path under require_preview policy",
                    false,
                ));
            }
            let Some(spec) =
                super::preview::PreviewSpec::for_ansible(&activated.module, &prepared.arguments)
            else {
                return reject(ToolError::preview_required(
                    "Operation has no qualified preview path under require_preview policy",
                    false,
                ));
            };
            Some(spec)
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
        let state = self.state.clone();
        let revision = binding.revision.clone();
        let reply =
            super::launch::spawn_surviving(&self.state.local_tasks, move |sender| async move {
                let _credit = crate::progress::HandlerCredit::from_context(&context);
                let _permits = (operation, runtime);
                let metadata = Metadata {
                    request_id: &context.id,
                    tool: state.binding_name(id),
                    host: Some(&request.host),
                    identity_role: authority_role,
                    sudo_mode: None,
                    user: None,
                    program: None,
                    binding_revision: Some(&revision),
                    executor: Some(executor),
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
                    .expect("automation target already authorized");
                if requires_preview {
                    let spec = preview_meta
                        .as_ref()
                        .expect("preview spec checked before spawn");
                    let pre_state_digest = match state
                        .payload
                        .observe_preview_prestate(crate::native_payload::PreviewPrestateRequest {
                            host: &request.host,
                            authority: &authority_label,
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
                            let error = if matches!(
                                error.code(),
                                ErrorCode::Cancelled | ErrorCode::Timeout
                            ) {
                                error
                            } else {
                                ToolError::preview_required(
                                    "Independent pre-state digest could not be obtained",
                                    false,
                                )
                            };
                            target_lease.finish(false, Some(error.code())).await;
                            metadata.reject(started, &error);
                            let _ = sender.send(ToolReply::failure(error));
                            return;
                        }
                    };
                    let key = super::preview::PreviewKey {
                        target: request.host.clone(),
                        authority: authority_role,
                        domain: spec.domain,
                        intent_digest: spec.intent_digest,
                        pre_state_digest,
                    };
                    if !state.previews.consume(&key) {
                        let error = ToolError::preview_required(
                            "A matching non-expired preview is required before apply",
                            false,
                        );
                        target_lease.finish(false, Some(error.code())).await;
                        metadata.reject(started, &error);
                        let _ = sender.send(ToolReply::failure(error));
                        return;
                    }
                }
                let audit = Audit::start(metadata, started);
                target_lease.mark_dispatched(
                    request.host.clone(),
                    authority_label.clone(),
                    executor,
                );
                let mut reply = state
                    .payload
                    .run_bundle(crate::native_payload::BundleRun {
                        pack: &activated.pack,
                        module: &activated.module,
                        arguments: &prepared.arguments,
                        no_log: activated.no_log,
                        check_mode: activated.check_mode,
                        diff: activated.diff,
                        projection: activated.projection.as_deref(),
                        host: &request.host,
                        authority: &authority_label,
                        target,
                        connect_timeout: Duration::from_secs(
                            state.config.limits().connect_timeout_secs,
                        ),
                        output_limit: prepared.output_limit,
                        deadline,
                        ct: &context.ct,
                        started,
                    })
                    .await;
                if is_preview {
                    let valid_observation = reply.error().is_none()
                        && reply.data().is_some_and(|d| {
                            d.complete
                                && d.status == crate::reply::AutomationStatus::Successful
                                && d.tasks.ok == 1
                                && d.tasks.skipped == 0
                        });
                    if valid_observation {
                        if let Some(spec) = preview_meta
                            && let Ok(pre_state_digest) = state
                                .payload
                                .observe_preview_prestate(
                                    crate::native_payload::PreviewPrestateRequest {
                                        host: &request.host,
                                        authority: &authority_label,
                                        target: &state
                                            .config
                                            .automation_target(id, &request.host)
                                            .expect("automation target already authorized"),
                                        module: spec.prestate_module,
                                        arguments: &spec.prestate_args,
                                        connect_timeout: Duration::from_secs(
                                            state.config.limits().connect_timeout_secs,
                                        ),
                                        deadline,
                                        ct: &context.ct,
                                    },
                                )
                                .await
                        {
                            // Record the key from the preview's own pre-state observation.
                            state.previews.insert(super::preview::PreviewKey {
                                target: request.host.clone(),
                                authority: authority_role,
                                domain: spec.domain,
                                intent_digest: spec.intent_digest,
                                pre_state_digest,
                            });
                        }
                    } else if reply.error().is_none()
                        && reply.data().is_some_and(|d| d.tasks.skipped > 0)
                    {
                        reply.set_error(ToolError::invalid_result(
                            "Preview was skipped; no target observation was produced",
                            false,
                        ));
                    }
                }
                target_lease
                    .finish(
                        reply.error().is_some_and(|e| e.remote_state_unknown),
                        reply.error().map(|error| error.code()),
                    )
                    .await;
                audit.finish_automation(&reply);
                let _ = sender.send(reply);
            })
            .await
            .unwrap_or_else(|| {
                ToolReply::failure(ToolError::io_error(
                    "Automation operation could not complete; remote state is unknown",
                    true,
                ))
            });
        budget.result(reply)
    }

    pub(super) async fn controller_binding(
        &self,
        id: BindingId,
        plan: Arc<bindings::ControllerPlan>,
        request: ControllerRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        // Resolved once at dispatch (see Estus::binding).
        let binding = super::preparation::Operation::binding(id, &self.state.config);
        let metadata = self.state.controller_metadata(id, binding, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.controller_capture_limit(request.retain_output) {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject_controller(
                    started,
                    &ControllerError::invalid_argument("Insufficient controller response budget"),
                );
                return Err(error);
            }
        };
        let prepared = (|| {
            if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
                return Err(ControllerError::cancelled(
                    "Controller request cancelled before dispatch",
                ));
            }
            if !self.state.config.controller_enabled(id) {
                return Err(ControllerError::policy_denied(
                    "Controller operation is not authorized",
                ));
            }
            let prepared = binding.prepare_activated_controller(
                &plan,
                &request,
                self.state.config.limits(),
            )?;
            let deadline = request_deadline(started, prepared.duration).map_err(|_| {
                ControllerError::invalid_argument("Controller request deadline expired")
            })?;
            Ok((prepared, deadline))
        })();
        let (prepared, deadline) = match prepared {
            Ok(value) => value,
            Err(error) => {
                metadata.reject_controller(started, &error);
                return budget.controller_result(ControllerReply::failure(error));
            }
        };
        let Some(cleanup_slot) = self.state.cleanup_quarantine.try_reserve() else {
            let error =
                ControllerError::resource_limit("Controller cleanup quarantine limit reached");
            metadata.reject_controller(started, &error);
            return budget.controller_result(ControllerReply::failure(error));
        };
        let permit = match self
            .state
            .acquire_permit(&self.state.operations, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                let ctrl_err = if error.code() == ErrorCode::Timeout {
                    ControllerError::timeout(
                        "Controller operation deadline expired waiting for slot",
                    )
                } else {
                    ControllerError::cancelled("Controller request cancelled before dispatch")
                };
                metadata.reject_controller(started, &ctrl_err);
                return budget.controller_result(ControllerReply::failure(ctrl_err));
            }
        };
        let state = Arc::clone(&self.state);
        let reply =
            super::launch::spawn_surviving(&self.state.local_tasks, move |sender| async move {
                let _credit = crate::progress::HandlerCredit::from_context(&context);
                let permit = permit;
                let metadata = state.controller_metadata(
                    id,
                    super::preparation::Operation::binding(id, &state.config),
                    &context.id,
                );
                let audit = Audit::start(metadata, started);
                let retention = request.retain_output.then(|| state.outputs.reserve());
                let run = crate::controller::run(
                    prepared,
                    crate::controller::ControllerContext {
                        deadline,
                        ct: &context.ct,
                        shutdown: &state.shutdown,
                        started,
                        capture_limit,
                        retention,
                        progress: crate::progress::Reporter::from_context(&context),
                    },
                )
                .await;
                audit.finish_controller(&run.reply);
                let _ = sender.send(run.reply);
                if let Some(pending) = run.pending {
                    pending.finish_with(Some(permit), Some(cleanup_slot)).await;
                }
            })
            .await
            .unwrap_or_else(|| {
                ControllerReply::failure(ControllerError::io_error(
                    "Controller operation could not complete; effects may be incomplete",
                ))
            });
        budget.controller_result(reply)
    }
}
