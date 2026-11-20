use std::{sync::Arc, time::Instant};

use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};

use crate::{
    audit::{Audit, Metadata},
    command::Invocation,
    exec::{self, RunContext},
    reply::{CommandData, Termination, ToolError, ToolReply},
    ssh::MasterHealth,
    wire::ReplyBudget,
};

use super::{
    Estus, State,
    preparation::{Operation, PreparedCommand, request_deadline},
};

impl Estus {
    pub(super) async fn command(
        &self,
        request: Operation,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let metadata = request.metadata(&self.state, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.command_capture_limit(request.retain_output()) {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject(
                    started,
                    &ToolError::invalid_argument("Insufficient response budget", false),
                );
                return Err(error);
            }
        };
        if self.state.shutdown.is_cancelled() || context.ct.is_cancelled() {
            let error = ToolError::cancelled("Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return budget.result(ToolReply::<CommandData>::failure(error));
        }
        let deadline = match request
            .prepare(&self.state.config)
            .and_then(|prepared| request_deadline(started, prepared.duration))
        {
            Ok(deadline) => deadline,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<CommandData>::failure(error));
            }
        };
        let permit = match self
            .state
            .acquire_permit(&self.state.operations, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<CommandData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        // Keep cleanup/audit alive even if RMCP suppresses the cancelled reply and
        // drops this handler's JoinHandle. Admission above bounds these tasks.
        let task = self.state.tasks.spawn(async move {
            let reply = state
                .command(request, context, started, capture_limit)
                .await;
            (permit, reply)
        });
        match task.await {
            Ok((_permit, reply)) => budget.command_result(reply),
            Err(_) => budget.result(ToolReply::<CommandData>::failure(ToolError::io_error(
                "Command task could not complete; remote state is unknown",
                true,
            ))),
        }
    }
}

impl State {
    pub(super) async fn command(
        &self,
        request: Operation,
        context: RequestContext<RoleServer>,
        started: Instant,
        capture_limit: u64,
    ) -> ToolReply<CommandData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = request.metadata(self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::cancelled("Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.prepare(&self.config).and_then(|prepared| {
            request_deadline(started, prepared.duration).map(|deadline| (prepared, deadline))
        });
        let (
            PreparedCommand {
                target,
                invocation,
                stdin,
                max_output_bytes,
                ..
            },
            deadline,
        ) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let (admission_mode, admission_executor, admission_authority) =
            request.admission_policy(&self.config);
        let mut target_lease = match self
            .admission
            .acquire(target.name, admission_mode, deadline, &ct, &self.shutdown)
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let metadata = match (&request, &invocation) {
            (Operation::Sudo(_), Invocation::Sudo { user, argv }) => Metadata {
                user: Some(user),
                program: argv.first().map(String::as_str),
                ..metadata
            },
            _ => metadata,
        };
        let audit = Audit::start(metadata, started);
        let retention = request.retain_output().then(|| self.outputs.reserve());
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                target_lease.mark_dispatched(
                    target.name.to_owned(),
                    admission_authority,
                    admission_executor,
                );
                let reply = exec::run(
                    lease.session(),
                    invocation,
                    stdin,
                    RunContext {
                        max_output_bytes: max_output_bytes.min(capture_limit),
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        started,
                        retention,
                        progress,
                    },
                )
                .await;
                target_lease.finish(
                    reply.error().is_some_and(|e| e.remote_state_unknown),
                    reply.error().map_or("ok", ToolError::code),
                );
                if matches!(
                    reply.data().map(|data| &data.termination),
                    Some(Termination::ConnectionLost)
                ) && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                reply
            }
            Err(error) => {
                target_lease.finish(false, error.code());
                ToolReply::failure(error)
            }
        };
        audit.finish(reply.data().and_then(|data| data.exit_code), reply.error());
        reply
    }
}
