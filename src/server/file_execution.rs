use std::{sync::Arc, time::Instant};

use rmcp::{ErrorData, RoleServer, model::CallToolResult, service::RequestContext};
use serde::Serialize;

use crate::{
    audit::Audit,
    config::ToolId,
    filesystem::{
        data::{ListData, ListRequest, MkdirData, MkdirRequest, ReadData, ReadRequest,
            RemoveDirectoryData, RemoveDirectoryRequest, RemoveFileData, RemoveFileRequest,
            RenameData, RenameRequest, ReplaceData, ReplaceRequest, StatRequest, WriteData, WriteRequest},
        metadata::StatData,
        operations::{self, FileContext},
    },
    reply::{ToolError, ToolReply},
    ssh::MasterHealth,
    wire::ReplyBudget,
};

use super::{Estus, State, preparation::{file_metadata, request_deadline}};

impl Estus {
    pub(super) async fn read_file(
        &self,
        request: ReadRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::ReadFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ReadData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.read_file(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn stat_file(
        &self,
        request: StatRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::Stat, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<StatData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.stat_file(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn list_directory(
        &self,
        request: ListRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(
            &request.host,
            ToolId::ListDirectory,
            &self.state,
            &context.id,
        );
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ListData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .list_directory(request, context, started, budget)
                .await
        })
        .await
    }

    pub(super) async fn write_file(
        &self,
        request: WriteRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::WriteFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<WriteData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.write_file(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn mkdir(
        &self,
        request: MkdirRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::Mkdir, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<MkdirData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.mkdir(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn rename(
        &self,
        request: RenameRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::Rename, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<RenameData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.rename(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn remove_file(
        &self,
        request: RemoveFileRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::RemoveFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<RemoveFileData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.remove_file(request, context, started, budget).await
        })
        .await
    }

    pub(super) async fn remove_directory(
        &self,
        request: RemoveDirectoryRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(
            &request.host,
            ToolId::RemoveDirectory,
            &self.state,
            &context.id,
        );
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<RemoveDirectoryData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .remove_directory(request, context, started, budget)
                .await
        })
        .await
    }

    pub(super) async fn replace_file(
        &self,
        request: ReplaceRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::ReplaceFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ReplaceData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state.replace_file(request, context, started, budget).await
        })
        .await
    }

    async fn file_result<T: Serialize + Send + 'static>(
        &self,
        budget: ReplyBudget,
        permit: tokio::sync::OwnedSemaphorePermit,
        operation: impl Future<Output = ToolReply<T>> + Send + 'static,
    ) -> Result<CallToolResult, ErrorData> {
        // A dropped RMCP request never drops the bounded SFTP cleanup owner.
        let task = self
            .state
            .tasks
            .spawn(async move { (permit, operation.await) });
        match task.await {
            Ok((_permit, reply)) => budget.result(reply),
            Err(_) => budget.result(ToolReply::<T>::failure(ToolError::new(
                "io_error",
                "File operation task could not complete; remote state is unknown",
                true,
            ))),
        }
    }
}

impl State {
    pub(super) async fn read_file(
        &self,
        request: ReadRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ReadData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::ReadFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(self.config.limits().max_file_bytes, budget)
            .and_then(|spec| {
                let target = self.config.resolve(&request.host, ToolId::ReadFile)?;
                let deadline =
                    request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
                Ok((spec, target, deadline))
            });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::read(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn stat_file(
        &self,
        request: StatRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<StatData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::Stat, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::Stat)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::stat(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn list_directory(
        &self,
        request: ListRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ListData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::ListDirectory, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::ListDirectory)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
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

    pub(super) async fn write_file(
        &self,
        request: WriteRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<WriteData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::WriteFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(self.config.limits().max_file_bytes, budget)
            .and_then(|spec| {
                let target = self.config.resolve(&request.host, ToolId::WriteFile)?;
                let deadline =
                    request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
                Ok((spec, target, deadline))
            });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::write(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn mkdir(
        &self,
        request: MkdirRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<MkdirData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::Mkdir, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::Mkdir)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::mkdir(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn rename(
        &self,
        request: RenameRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<RenameData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::Rename, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::Rename)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::rename(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn remove_file(
        &self,
        request: RemoveFileRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<RemoveFileData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::RemoveFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::RemoveFile)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::remove_file(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn remove_directory(
        &self,
        request: RemoveDirectoryRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<RemoveDirectoryData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::RemoveDirectory, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self
                .config
                .resolve(&request.host, ToolId::RemoveDirectory)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::remove_directory(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    pub(super) async fn replace_file(
        &self,
        request: ReplaceRequest,
        context: RequestContext<RoleServer>,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ReplaceData> {
        let progress = crate::progress::Reporter::from_context(&context);
        let request_id = context.id;
        let ct = context.ct;
        let metadata = file_metadata(&request.host, ToolId::ReplaceFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(self.config.limits().max_file_bytes, budget)
            .and_then(|spec| {
                let target = self.config.resolve(&request.host, ToolId::ReplaceFile)?;
                let deadline =
                    request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
                Ok((spec, target, deadline))
            });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = operations::replace_file(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                        progress,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }
}
