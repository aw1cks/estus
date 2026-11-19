use std::{sync::Arc, time::Instant};

use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};

use crate::{
    audit::{Audit, Metadata},
    bindings::{self, BindingId, ControllerRequest},
    reply::{ControllerError, ControllerReply, ToolError, ToolReply},
    wire::ReplyBudget,
};

use super::{Estus, preparation::request_deadline};

impl Estus {
    pub(super) async fn automation_binding(
        &self,
        id: BindingId,
        request: bindings::AutomationRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::reply::AutomationData;
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered module binding");
        budget.automation_reserve(
            &request.host,
            binding.projection().map(|plan| plan.max_bytes),
        )?;
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .targets
                .iter()
                .find(|host| **host == request.host)
                .map(String::as_str),
            identity_role: binding
                .automation_authority()
                .expect("automation binding")
                .identity_role(),
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some(binding.executor_kind()),
        };
        let reject = |code, message| {
            let error = ToolError::new(code, message, false);
            metadata.reject(started, &error);
            budget.result(ToolReply::<AutomationData>::failure(error))
        };
        if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
            return reject("cancelled", "Request cancelled before dispatch");
        }
        let target = match self.state.config.automation_target(id, &request.host) {
            Ok(target) => target,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<AutomationData>::failure(error));
            }
        };
        let is_preview = binding.is_preview_check_mode();
        let requires_preview = !is_preview
            && matches!(
                crate::config::risk_tier_for_binding(binding),
                crate::config::RiskTier::Change | crate::config::RiskTier::Exec
            )
            && self.state.config.requires_preview(&request.host);
        let Some(authority_label) = binding
            .automation_authority()
            .map(|a| a.label().into_owned())
        else {
            return reject("policy_denied", "Operation is not authorized");
        };
        let authority_identity = if is_preview || requires_preview {
            let Ok(digest) = super::preview::authority_identity_digest(&authority_label, &target)
            else {
                return reject("preview_required", "Invalid preview authority identity");
            };
            Some(digest)
        } else {
            None
        };
        let (bytes, files) = self.state.config.automation_scratch();
        let mut prepared = match binding.prepare_automation(
            &request,
            self.state.config.limits(),
            bindings::AutomationTransport {
                authority: target,
                scratch_bytes: bytes,
                scratch_files: files,
                started,
            },
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<AutomationData>::failure(error));
            }
        };
        if requires_preview
            && !prepared
                .module_name
                .as_deref()
                .is_some_and(super::preview::is_qualified_module)
        {
            return reject(
                "preview_required",
                "Operation has no qualified preview path under require_preview policy",
            );
        }
        let deadline = match request_deadline(started, prepared.controller.duration) {
            Ok(deadline) => deadline,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<AutomationData>::failure(error));
            }
        };
        let preview_meta = if is_preview || requires_preview {
            let (Some(module_name), Some(args), Some(reviewed), Some(authority_identity)) = (
                prepared.module_name.take(),
                prepared.arguments.take(),
                binding.automation_reviewed(),
                authority_identity,
            ) else {
                return reject(
                    "preview_required",
                    "Operation has no qualified preview path under require_preview policy",
                );
            };
            let Ok(catalog_revision) = super::preview::catalog_revision_digest(
                self.state.config.catalog_version(),
                reviewed,
            ) else {
                return reject("preview_required", "Invalid preview catalog revision");
            };
            let Ok(canonical_arguments) = super::preview::canonical_json_sha256(&args) else {
                return reject("preview_required", "Invalid preview arguments");
            };
            Some((
                module_name,
                args,
                authority_identity,
                catalog_revision,
                binding.revision.clone(),
                canonical_arguments,
            ))
        } else {
            None
        };
        let shared_read = binding.is_shared_read();
        let Ok(operation) = self.state.operations.clone().try_acquire_owned() else {
            return reject("resource_limit", "Tool operation limit reached");
        };
        let Ok(runtime) = self.state.automation.clone().try_acquire_owned() else {
            return reject("resource_limit", "Automation operation limit reached");
        };
        let state = self.state.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            let _permits = (operation, runtime);
            let binding = state
                .config
                .bindings()
                .get(id)
                .expect("registered module binding");
            let executor = binding.executor_kind();
            let metadata = Metadata {
                request_id: &context.id,
                tool: state.binding_name(id),
                host: Some(&request.host),
                identity_role: binding
                    .automation_authority()
                    .expect("automation binding")
                    .identity_role(),
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: Some(&binding.revision),
                executor: Some(executor),
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
            if requires_preview {
                let Some((
                    ref module_name,
                    ref args,
                    authority_identity,
                    catalog_revision,
                    ref binding_revision,
                    canonical_arguments,
                )) = preview_meta
                else {
                    let error = ToolError::new(
                        "preview_required",
                        "Operation has no qualified preview path under require_preview policy",
                        false,
                    );
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::failure(error));
                    return;
                };
                let resolved = state
                    .config
                    .automation_target(id, &request.host)
                    .expect("automation target already authorized");
                let pre_state_digest = match state
                    .payload
                    .observe_preview_prestate(crate::native_payload::PreviewPrestateRequest {
                        host: &request.host,
                        authority: &authority_label,
                        target: &resolved,
                        module: module_name,
                        arguments: args,
                        connect_timeout: std::time::Duration::from_secs(
                            state.config.limits().connect_timeout_secs,
                        ),
                        deadline,
                        ct: &context.ct,
                    })
                    .await
                {
                    Ok(digest) => digest,
                    Err(error) => {
                        let error = if error.code == "cancelled" || error.code == "timeout" {
                            error
                        } else {
                            ToolError::new(
                                "preview_required",
                                "Independent pre-state digest could not be obtained",
                                false,
                            )
                        };
                        target_lease.finish(false, error.code);
                        metadata.reject(started, &error);
                        let _ = sender.send(ToolReply::failure(error));
                        return;
                    }
                };
                let key = super::preview::PreviewKey {
                    target: request.host.clone(),
                    authority_identity,
                    catalog_revision,
                    binding_revision: binding_revision.clone(),
                    canonical_arguments,
                    pre_state_digest,
                };
                if !state.previews.consume(&key) {
                    let error = ToolError::new(
                        "preview_required",
                        "A matching non-expired preview is required before apply",
                        false,
                    );
                    target_lease.finish(false, error.code);
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::failure(error));
                    return;
                }
            }
            let audit = Audit::start(metadata, started);
            target_lease.mark_dispatched(request.host.clone(), authority_label.clone(), executor);
            let mut run = crate::automation::execution::run(
                prepared,
                crate::controller::ControllerContext {
                    deadline,
                    ct: &context.ct,
                    shutdown: &state.shutdown,
                    started,
                    capture_limit: 65_536,
                    retention: None,
                    progress: crate::progress::Reporter::from_context(&context),
                },
            )
            .await;
            if is_preview {
                let valid_observation = run.reply.error.is_none()
                    && run.reply.data.as_ref().is_some_and(|d| {
                        d.complete
                            && d.status == crate::reply::AutomationStatus::Successful
                            && d.tasks.ok == 1
                            && d.tasks.skipped == 0
                    });
                if valid_observation {
                    if let Some((
                        module_name,
                        args,
                        authority_identity,
                        catalog_revision,
                        binding_revision,
                        canonical_arguments,
                    )) = preview_meta
                    {
                        let resolved = state
                            .config
                            .automation_target(id, &request.host)
                            .expect("automation target already authorized");
                        if let Ok(pre_state_digest) = state
                            .payload
                            .observe_preview_prestate(
                                crate::native_payload::PreviewPrestateRequest {
                                    host: &request.host,
                                    authority: &authority_label,
                                    target: &resolved,
                                    module: &module_name,
                                    arguments: &args,
                                    connect_timeout: std::time::Duration::from_secs(
                                        state.config.limits().connect_timeout_secs,
                                    ),
                                    deadline,
                                    ct: &context.ct,
                                },
                            )
                            .await
                        {
                            state.previews.insert(super::preview::PreviewKey {
                                target: request.host.clone(),
                                authority_identity,
                                catalog_revision,
                                binding_revision,
                                canonical_arguments,
                                pre_state_digest,
                            });
                        }
                    }
                } else if run.reply.error.is_none()
                    && run.reply.data.as_ref().is_some_and(|d| d.tasks.skipped > 0)
                {
                    run.reply.error = Some(ToolError::new(
                        "invalid_result",
                        "Preview was skipped; no target observation was produced",
                        false,
                    ));
                }
            }
            target_lease.finish(
                run.reply
                    .error
                    .as_ref()
                    .is_some_and(|e| e.remote_state_unknown),
                run.reply.error.as_ref().map_or("unknown", |e| e.code),
            );
            audit.finish_automation(&run.reply);
            let _ = sender.send(run.reply);
            if let Some(pending) = run.pending {
                pending.finish().await;
            }
        });
        let reply = receiver.await.unwrap_or_else(|_| {
            ToolReply::failure(ToolError::new(
                "io_error",
                "Automation operation could not complete; remote state is unknown",
                true,
            ))
        });
        budget.result(reply)
    }

    pub(super) async fn controller_binding(
        &self,
        id: BindingId,
        request: ControllerRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let metadata = self.state.controller_metadata(id, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.controller_capture_limit(request.retain_output) {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject_controller(
                    started,
                    &ControllerError::new(
                        "invalid_argument",
                        "Insufficient controller response budget",
                    ),
                );
                return Err(error);
            }
        };
        let prepared = (|| {
            if self.state.shutdown.is_cancelled() || context.ct.is_cancelled() {
                return Err(ControllerError::new(
                    "cancelled",
                    "Controller request cancelled before dispatch",
                ));
            }
            if !self.state.config.controller_enabled(id) {
                return Err(ControllerError::new(
                    "policy_denied",
                    "Controller operation is not authorized",
                ));
            }
            let binding = self
                .state
                .config
                .bindings()
                .get(id)
                .expect("registered controller binding exists");
            let prepared = binding.prepare_controller(&request, self.state.config.limits())?;
            let deadline = request_deadline(started, prepared.duration).map_err(|error| {
                ControllerError::new(error.code, "Controller request deadline expired")
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
            let error = ControllerError::new(
                "resource_limit",
                "Controller cleanup quarantine limit reached",
            );
            metadata.reject_controller(started, &error);
            return budget.controller_result(ControllerReply::failure(error));
        };
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ControllerError::new("resource_limit", "Tool operation limit reached");
                metadata.reject_controller(started, &error);
                return budget.controller_result(ControllerReply::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            // Receiver cancellation cannot drop admission, files, or child ownership.
            let permit = permit;
            let metadata = state.controller_metadata(id, &context.id);
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
        });
        match receiver.await {
            Ok(reply) => budget.controller_result(reply),
            Err(_) => budget.controller_result(ControllerReply::failure(ControllerError::new(
                "io_error",
                "Controller operation could not complete; effects may be incomplete",
            ))),
        }
    }
}
