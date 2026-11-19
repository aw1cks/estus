use std::{sync::Arc, time::Instant};

use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};
use serde::Serialize;

use crate::{
    audit::Audit,
    config::ToolId,
    filesystem::{
        data::{
            ListData, ListRequest, MkdirRequest, ReadRequest, RemoveDirectoryRequest,
            RemoveFileRequest, RenameRequest, ReplaceRequest, StatRequest, WriteRequest,
        },
        operations::{self, FileContext, FileOutcome},
    },
    reply::{ToolError, ToolReply},
    ssh::MasterHealth,
    wire::ReplyBudget,
};

use super::{
    Estus, State,
    preparation::{file_metadata, request_deadline},
};

impl Estus {
    async fn dispatch_file_op<T, V, F, Fut>(
        &self,
        host: String,
        tool: ToolId,
        context: RequestContext<RoleServer>,
        validate: impl FnOnce(&str, ReplyBudget) -> Result<(V, Option<u64>), ToolError>,
        run: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        T: Serialize + Send + 'static,
        F: FnOnce(
            Arc<State>,
            String,
            V,
            RequestContext<RoleServer>,
            Instant,
            tokio::time::Instant,
            ReplyBudget,
        ) -> Fut,
        Fut: Future<Output = ToolReply<T>> + Send + 'static,
    {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let (validated, deadline) = match (|| {
            if self.state.shutdown.is_cancelled() || context.ct.is_cancelled() {
                return Err(ToolError::new(
                    "cancelled",
                    "Request cancelled before dispatch",
                    false,
                ));
            }
            let (validated, timeout_secs) = validate(&host, budget)?;
            self.state.config.resolve(&host, tool)?;
            let deadline = request_deadline(started, self.state.config.timeout(timeout_secs)?)?;
            Ok((validated, deadline))
        })() {
            Ok(pair) => pair,
            Err(error) => {
                file_metadata(&host, tool, &self.state, &context.id).reject(started, &error);
                return budget.result(ToolReply::<T>::failure(error));
            }
        };
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                file_metadata(&host, tool, &self.state, &context.id).reject(started, &error);
                return budget.result(ToolReply::<T>::failure(error));
            }
        };
        let fut = run(
            Arc::clone(&self.state),
            host,
            validated,
            context,
            started,
            deadline,
            budget,
        );
        let task = self.state.tasks.spawn(async move {
            let reply = fut.await;
            (permit, reply)
        });
        match task.await {
            Ok((_permit, reply)) => budget.result(reply),
            Err(_) => budget.result(ToolReply::<T>::failure(ToolError::new(
                "io_error",
                "File operation task could not complete; remote state is unknown",
                true,
            ))),
        }
    }

    pub(super) async fn read_file(
        &self,
        mut request: ReadRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        let max_file_bytes = self.state.config.limits().max_file_bytes;
        self.dispatch_file_op(
            host,
            ToolId::ReadFile,
            context,
            |_, budget| {
                request.validate(max_file_bytes, budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::ReadFile, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(state.config.limits().max_file_bytes, budget)
                            .expect("read request already validated");
                        let outcome = operations::read(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn stat_file(
        &self,
        mut request: StatRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::Stat,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::Stat, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(budget)
                            .expect("stat request already validated");
                        let outcome = operations::stat(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn list_directory(
        &self,
        mut request: ListRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::ListDirectory,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                state
                    .list_directory(&host, request, context, started, deadline, budget)
                    .await
            },
        )
        .await
    }

    pub(super) async fn write_file(
        &self,
        mut request: WriteRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        let max_file_bytes = self.state.config.limits().max_file_bytes;
        self.dispatch_file_op(
            host,
            ToolId::WriteFile,
            context,
            |_, budget| {
                let (path, content, overwrite, timeout_secs) =
                    request.take_validated(max_file_bytes, budget)?;
                Ok(((path, content, overwrite), timeout_secs))
            },
            |state, host, (path, content, overwrite), context, started, deadline, _| async move {
                match state
                    .acquire_sftp(&host, ToolId::WriteFile, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let outcome = operations::write(
                            lease.session(),
                            crate::filesystem::data::WriteSpec {
                                path: &path,
                                content: std::borrow::Cow::Borrowed(&content),
                                overwrite,
                            },
                            file_ctx,
                        )
                        .await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn mkdir(
        &self,
        mut request: MkdirRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::Mkdir,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::Mkdir, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(budget)
                            .expect("mkdir request already validated");
                        let outcome = operations::mkdir(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn rename(
        &self,
        mut request: RenameRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::Rename,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::Rename, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(budget)
                            .expect("rename request already validated");
                        let outcome = operations::rename(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn remove_file(
        &self,
        mut request: RemoveFileRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::RemoveFile,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::RemoveFile, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(budget)
                            .expect("remove_file request already validated");
                        let outcome =
                            operations::remove_file(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn remove_directory(
        &self,
        mut request: RemoveDirectoryRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        self.dispatch_file_op(
            host,
            ToolId::RemoveDirectory,
            context,
            |_, budget| {
                request.validate(budget)?;
                let timeout_secs = request.timeout_secs;
                Ok((request, timeout_secs))
            },
            |state, host, request, context, started, deadline, budget| async move {
                match state
                    .acquire_sftp(&host, ToolId::RemoveDirectory, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let spec = request
                            .validate(budget)
                            .expect("remove_directory request already validated");
                        let outcome =
                            operations::remove_directory(lease.session(), spec, file_ctx).await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }

    pub(super) async fn replace_file(
        &self,
        mut request: ReplaceRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let host = std::mem::take(&mut request.host);
        let max_file_bytes = self.state.config.limits().max_file_bytes;
        self.dispatch_file_op(
            host,
            ToolId::ReplaceFile,
            context,
            |_, budget| {
                let (path, content, timeout_secs) =
                    request.take_validated(max_file_bytes, budget)?;
                Ok(((path, content), timeout_secs))
            },
            |state, host, (path, content), context, started, deadline, _| async move {
                match state
                    .acquire_sftp(&host, ToolId::ReplaceFile, &context, started, deadline)
                    .await
                {
                    Ok((audit, lease, file_ctx)) => {
                        let outcome = operations::replace_file(
                            lease.session(),
                            crate::filesystem::data::ReplaceSpec {
                                path: &path,
                                content: std::borrow::Cow::Borrowed(&content),
                            },
                            file_ctx,
                        )
                        .await;
                        State::finish_sftp(audit, lease, outcome).await
                    }
                    Err(reply) => reply,
                }
            },
        )
        .await
    }
}

impl State {
    async fn acquire_sftp<'a, T>(
        &'a self,
        host: &'a str,
        tool: ToolId,
        context: &'a RequestContext<RoleServer>,
        started: Instant,
        deadline: tokio::time::Instant,
    ) -> Result<(Audit<'a>, crate::ssh::Lease, FileContext<'a>), ToolReply<T>> {
        let progress = crate::progress::Reporter::from_context(context);
        let metadata = file_metadata(host, tool, self, &context.id);
        if self.shutdown.is_cancelled() || context.ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return Err(ToolReply::failure(error));
        }
        let target = match self.config.resolve(host, tool) {
            Ok(target) => target,
            Err(error) => {
                metadata.reject(started, &error);
                return Err(ToolReply::failure(error));
            }
        };
        let audit = Audit::start(metadata, started);
        let lease = match self
            .pool
            .acquire(
                target.name,
                target.destination,
                target.role,
                deadline,
                &context.ct,
            )
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                audit.finish(None, Some(&error));
                return Err(ToolReply::failure(error));
            }
        };
        Ok((
            audit,
            lease,
            FileContext {
                deadline,
                ct: &context.ct,
                shutdown: &self.shutdown,
                progress,
            },
        ))
    }

    async fn finish_sftp<T>(
        audit: Audit<'_>,
        lease: crate::ssh::Lease,
        outcome: FileOutcome<T>,
    ) -> ToolReply<T> {
        if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost) {
            lease.invalidate();
        }
        audit.finish(None, outcome.reply.error.as_ref());
        outcome.reply
    }

    async fn list_directory(
        &self,
        host: &str,
        request: ListRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        deadline: tokio::time::Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ListData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(host, ToolId::ListDirectory, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let (spec, target) = match request
            .validate(budget)
            .and_then(|spec| Ok((spec, self.config.resolve(host, ToolId::ListDirectory)?)))
        {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = self
            .directories
            .as_ref()
            .expect("published directory listing owns its bounded store")
            .page(
                &self.pool,
                target,
                spec,
                request.continuation.as_deref(),
                FileContext {
                    deadline,
                    ct: &ct,
                    shutdown: &self.shutdown,
                    progress,
                },
            )
            .await;
        audit.finish(None, reply.error.as_ref());
        reply
    }
}
