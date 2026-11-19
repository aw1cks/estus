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
            .expect("registered payload binding");
        budget.automation_reserve(&request.host, binding.projection().map(|p| p.max_bytes))?;
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .targets
                .iter()
                .find(|h| **h == request.host)
                .map(String::as_str),
            identity_role: binding
                .automation_authority()
                .expect("payload authority")
                .identity_role(),
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
        if let Err(error) = self.state.config.automation_target(id, &request.host) {
            return reject(error);
        }
        let Some(target) = self.state.automation_targets.get(&request.host) else {
            return reject(ToolError::new(
                "policy_denied",
                "Operation is not authorized",
                false,
            ));
        };
        // Keep identical host serialization for native and Ansible mutations.
        let Ok(target) = Arc::clone(target).try_acquire_owned() else {
            return reject(ToolError::new(
                "resource_limit",
                "Automation target operation limit reached",
                false,
            ));
        };
        let state = Arc::clone(&self.state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            // Dropping an MCP handler never relinquishes execution/admission ownership.
            let _permits = (operation, runtime, target);
            let binding = state
                .config
                .bindings()
                .get(id)
                .expect("registered payload binding");
            let metadata = Metadata {
                request_id: &context.id,
                tool: state.binding_name(id),
                host: Some(&request.host),
                identity_role: binding
                    .automation_authority()
                    .expect("payload authority")
                    .identity_role(),
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: Some(&binding.revision),
                executor: Some("native_payload"),
            };
            let prepared = (|| {
                if context.ct.is_cancelled() || state.shutdown.is_cancelled() {
                    return Err(ToolError::new(
                        "cancelled",
                        "Request cancelled before dispatch",
                        false,
                    ));
                }
                let prepared = binding.prepare_payload(&request, state.config.limits())?;
                let deadline = request_deadline(started, prepared.duration)?;
                let target = state.config.automation_target(id, &request.host)?;
                let authority = serde_json::to_value(binding.automation_authority())
                    .map_err(|_| {
                        ToolError::new("policy_denied", "Invalid payload authority", false)
                    })?
                    .as_str()
                    .ok_or_else(|| {
                        ToolError::new("policy_denied", "Invalid payload authority", false)
                    })?
                    .to_owned();
                Ok((prepared, deadline, target, authority))
            })();
            let (prepared, deadline, target, authority) = match prepared {
                Ok(p) => p,
                Err(error) => {
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::<AutomationData>::failure(error));
                    return;
                }
            };
            let audit = Audit::start(metadata, started);
            let reply = state
                .payload
                .run(crate::native_payload::PayloadRun {
                    plan: prepared.plan,
                    host: &request.host,
                    authority: &authority,
                    target,
                    argv: prepared.argv,
                    connect_timeout: Duration::from_secs(
                        state.config.limits().connect_timeout_secs,
                    ),
                    output_limit: prepared.output_limit,
                    deadline,
                    ct: &context.ct,
                    started,
                })
                .await;
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
