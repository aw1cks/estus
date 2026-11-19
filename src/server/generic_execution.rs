//! Generic tools share normal Runner ownership, authority and host admission.
use super::{Estus, preparation::request_deadline};
use crate::{
    audit::{Audit, Metadata},
    automation::generic::Request,
    bindings::{self, BindingId},
    reply::{ToolError, ToolReply},
    wire::ReplyBudget,
};
use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};
use serde_json::{Value, json};
use std::time::Instant;
impl Estus {
    pub(super) async fn generic_binding(
        &self,
        id: BindingId,
        request: Request,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered generic binding");
        let policy = binding.generic_policy().expect("registered generic policy");
        budget.automation_reserve(request.host(), policy.projection().map(|p| p.max_bytes))?;
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .targets
                .iter()
                .find(|h| h.as_str() == request.host())
                .map(String::as_str),
            identity_role: binding
                .automation_authority()
                .expect("generic authority")
                .identity_role(),
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some(binding.executor_kind()),
        };
        let reject = |error: ToolError| {
            metadata.reject(started, &error);
            budget.result(ToolReply::<Value>::failure(error))
        };
        if let Err(error) = self.state.config.automation_target(id, request.host()) {
            return reject(error);
        }
        if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
            return reject(ToolError::new(
                "cancelled",
                "Request cancelled before dispatch",
                false,
            ));
        }
        let Ok(operation) = self.state.operations.clone().try_acquire_owned() else {
            return reject(ToolError::new(
                "resource_limit",
                "Tool operation limit reached",
                false,
            ));
        };
        let policy_permits = match policy.admit(request.host()) {
            Ok(p) => p,
            Err(e) => return reject(e),
        };
        if !matches!(request, Request::Call { .. }) {
            let _permits = (operation, policy_permits);
            return match policy.discover(&request) {
                Ok(value) => budget.result(ToolReply::success(value)),
                Err(error) => reject(error),
            };
        }
        let Some(authority_label) = binding
            .automation_authority()
            .map(|a| a.label().into_owned())
        else {
            return reject(ToolError::new(
                "policy_denied",
                "Operation is not authorized",
                false,
            ));
        };
        let prepared = {
            let authority = match self.state.config.automation_target(id, request.host()) {
                Ok(authority) => authority,
                Err(error) => return reject(error),
            };
            let (scratch_bytes, scratch_files) = self.state.config.automation_scratch();
            match binding.prepare_generic(
                &request,
                self.state.config.limits(),
                bindings::AutomationTransport {
                    authority,
                    scratch_bytes,
                    scratch_files,
                    started,
                },
            ) {
                Ok(prepared) => prepared,
                Err(error) => return reject(error),
            }
        };
        let deadline = match request_deadline(started, prepared.controller.duration) {
            Ok(deadline) => deadline,
            Err(error) => return reject(error),
        };
        let Ok(runtime) = self.state.automation.clone().try_acquire_owned() else {
            return reject(ToolError::new(
                "resource_limit",
                "Automation operation limit reached",
                false,
            ));
        };
        let state = self.state.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            let _permits = (operation, runtime, policy_permits);
            let binding = state
                .config
                .bindings()
                .get(id)
                .expect("registered generic binding");
            let policy = binding.generic_policy().expect("registered generic policy");
            let executor = binding.executor_kind();
            let metadata = Metadata {
                request_id: &context.id,
                tool: state.binding_name(id),
                host: Some(request.host()),
                identity_role: binding
                    .automation_authority()
                    .expect("generic authority")
                    .identity_role(),
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: Some(&binding.revision),
                executor: Some(executor),
            };
            let mut target_lease = match state
                .admission
                .acquire_write(request.host(), deadline, &context.ct, &state.shutdown)
                .await
            {
                Ok(lease) => lease,
                Err(error) => {
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::<Value>::failure(error));
                    return;
                }
            };
            let audit = Audit::start(metadata, started);
            target_lease.mark_dispatched(request.host().to_owned(), authority_label, executor);
            let run = crate::automation::execution::run(
                prepared,
                crate::controller::ControllerContext {
                    deadline,
                    ct: &context.ct,
                    shutdown: &state.shutdown,
                    started,
                    capture_limit: 65536,
                    retention: None,
                    progress: crate::progress::Reporter::from_context(&context),
                },
            )
            .await;
            target_lease.finish(
                run.reply
                    .error
                    .as_ref()
                    .is_some_and(|e| e.remote_state_unknown),
                run.reply.error.as_ref().map_or("unknown", |e| e.code),
            );
            audit.finish_automation(&run.reply);
            let mut data = run
                .reply
                .data
                .map(|data| serde_json::to_value(data).expect("serializable automation result"));
            if let Some(data) = data.as_mut() {
                data["generic"] = policy.call_metadata(&request);
                data["generic"]["authority"] = json!(binding.automation_authority());
            }
            let mut reply = ToolReply {
                data,
                error: run.reply.error,
            };
            let receipt = policy.retain(
                request.host(),
                serde_json::to_value(&reply).expect("serializable generic result"),
            );
            if let Some(data) = reply.data.as_mut() {
                data["receipt"] = json!(receipt);
            }
            let _ = sender.send(reply);
            if let Some(pending) = run.pending {
                pending.finish().await;
            }
        });
        let reply = receiver.await.unwrap_or_else(|_| {
            ToolReply::<Value>::failure(ToolError::new(
                "io_error",
                "Automation operation could not complete; remote state is unknown",
                true,
            ))
        });
        budget.result(reply)
    }
}
