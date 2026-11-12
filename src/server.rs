use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant},
};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{
        common::FromContextPart,
        router::tool::{IntoToolRoute, ToolRoute, ToolRouter},
        tool::{ToolCallContext, schema_for_type},
    },
    model::{
        CallToolResult, JsonObject, RequestId, ServerCapabilities, ServerConfig, Tool,
        ToolAnnotations,
    },
    service::RequestContext,
    tool, tool_handler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    audit::{Audit, Metadata},
    bindings::{self, BindingId, BindingRequest},
    command::{ExecRequest, Invocation, RunRequest, SudoRequest},
    config::{
        Config, ConfigError, IdentityRole, ResolvedTarget, SudoMode, TargetDiscovery, ToolCatalog,
        ToolEntry, ToolId, ToolKey,
    },
    exec::{self, RunContext},
    filedata::{
        ListData, ListRequest, ReadData, ReadRequest, StatRequest, WriteData, WriteRequest,
    },
    filemeta::StatData,
    files::{self, FileContext},
    reply::{CommandData, Termination, ToolError, ToolReply},
    ssh::{MasterHealth, Pool},
    wire::ReplyBudget,
};

#[derive(Clone)]
pub(crate) struct SshMcp {
    tool_router: ToolRouter<Self>,
    state: Arc<State>,
}

struct State {
    config: Config,
    tools: ToolCatalog,
    sudo_name: Cow<'static, str>,
    pool: Arc<Pool>,
    shutdown: CancellationToken,
    operations: Arc<Semaphore>,
    tasks: TaskTracker,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}

// RMCP 3.9 converts its Parameters extractor's errors into tool results. This
// extractor keeps argument-shape failures at the protocol boundary and never
// reflects malformed input values or field names in diagnostics.
struct Arguments<T>(T);

impl<T: DeserializeOwned> FromContextPart<ToolCallContext<'_, SshMcp>> for Arguments<T> {
    fn from_context_part(context: &mut ToolCallContext<'_, SshMcp>) -> Result<Self, ErrorData> {
        serde_json::from_value(serde_json::Value::Object(
            context.arguments.take().unwrap_or_default(),
        ))
        .map(Self)
        .map_err(|_| {
            let error = ToolError::new(
                "invalid_argument",
                "Arguments do not match the tool input schema",
                false,
            );
            let metadata = Metadata {
                request_id: &context.request_context.id,
                tool: &context.name,
                host: None,
                identity_role: if context.name == context.service.state.sudo_name {
                    IdentityRole::Elevated
                } else {
                    IdentityRole::Ordinary
                },
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: None,
                executor: None,
            };
            metadata.reject(Instant::now(), &error);
            ErrorData::invalid_params(error.message, None)
        })
    }
}

impl SshMcp {
    pub(crate) fn new(config: Config) -> Result<Self, ConfigError> {
        // This is the explicit publication inventory. Each entry binds native
        // SDK metadata and its callable handler to a target-policy identity.
        let routes: [(ToolId, ToolRoute<Self>); 8] = [
            (
                ToolId::Targets,
                (Self::ssh_targets_tool_attr(), Self::ssh_targets).into_tool_route(),
            ),
            (
                ToolId::Exec,
                (Self::ssh_exec_tool_attr(), Self::ssh_exec).into_tool_route(),
            ),
            (
                ToolId::Run,
                (Self::ssh_run_tool_attr(), Self::ssh_run).into_tool_route(),
            ),
            (
                ToolId::ReadFile,
                (Self::ssh_read_file_tool_attr(), Self::ssh_read_file).into_tool_route(),
            ),
            (
                ToolId::WriteFile,
                (Self::ssh_write_file_tool_attr(), Self::ssh_write_file).into_tool_route(),
            ),
            (
                ToolId::Stat,
                (Self::ssh_stat_tool_attr(), Self::ssh_stat).into_tool_route(),
            ),
            (
                ToolId::ListDirectory,
                (
                    Self::ssh_list_directory_tool_attr(),
                    Self::ssh_list_directory,
                )
                    .into_tool_route(),
            ),
            (
                ToolId::Sudo,
                (Self::ssh_sudo_tool_attr(), Self::ssh_sudo).into_tool_route(),
            ),
        ];
        let command_output_schema = routes
            .iter()
            .find(|(id, _)| *id == ToolId::Exec)
            .and_then(|(_, route)| route.attr.output_schema.as_ref())
            .expect("command registration has its output contract")
            .clone();
        let binding_routes = config.bindings().entries().map(|(id, binding)| {
            let annotations = ToolAnnotations::new()
                .read_only(binding.read_only())
                .destructive(!binding.read_only())
                .idempotent(false);
            let metadata = Tool::new(
                binding.name.clone(),
                format!("{} Fixed ordinary execution on declared targets; typed values fill whole arguments, not templates. Effects are operator-reviewed, not a sandbox or remote authorization. Cancellation may leave remote work running; operations are never replayed.", binding.description),
                Arc::clone(&binding.input_schema),
            )
            .with_raw_output_schema(Arc::clone(&command_output_schema))
            .with_annotations(annotations)
            .with_meta(rmcp::model::MetaObject(JsonObject::from_iter([
                ("revision".into(), serde_json::json!(binding.revision)),
                ("result".into(), serde_json::json!(bindings::RESULT_KIND)),
                ("effects".into(), serde_json::json!(binding.effects())),
                ("executor".into(), serde_json::json!(bindings::EXECUTOR_KIND)),
            ])));
            let route = ToolRoute::new_dyn(metadata, move |context: ToolCallContext<'_, Self>| {
                Box::pin(async move {
                    context.service.binding(
                        id,
                        context.arguments.unwrap_or_default(),
                        context.request_context,
                    ).await.map(Into::into)
                })
            });
            (ToolKey::Binding(id), route)
        });
        let routes: Vec<_> = routes
            .into_iter()
            .map(|(id, route)| (ToolKey::Builtin(id), route))
            .chain(binding_routes)
            .collect();
        // Validate the full inventory before filtering: even a disabled route
        // must not hide duplicate IDs or names from the programmer.
        let mut tools = ToolCatalog::new(
            routes
                .iter()
                .map(|(id, route)| ToolEntry {
                    id: *id,
                    name: route.attr.name.clone(),
                })
                .collect(),
        )?;
        let sudo_name = routes
            .iter()
            .find(|(id, _)| *id == ToolKey::Builtin(ToolId::Sudo))
            .expect("native registration inventory includes sudo")
            .1
            .attr
            .name
            .clone();
        tools.retain(|id| match id {
            ToolKey::Builtin(id) => config.tool_enabled(id),
            ToolKey::Binding(id) => config.binding_enabled(id),
        });
        let mut tool_router = ToolRouter::new();
        for (id, route) in routes {
            if tools.contains(id) {
                tool_router.add_route(route);
            }
        }
        let shutdown = CancellationToken::new();
        let pool = Pool::new(
            config.ssh_config().map(std::path::Path::to_path_buf),
            Duration::from_secs(config.limits().connect_timeout_secs),
            shutdown.clone(),
        );
        Ok(Self {
            tool_router,
            state: Arc::new(State {
                config,
                tools,
                sudo_name,
                pool,
                shutdown,
                operations: Arc::new(Semaphore::new(16)),
                tasks: TaskTracker::new(),
            }),
        })
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.state.shutdown.clone()
    }

    pub(crate) async fn shutdown(&self) {
        self.state.shutdown.cancel();
        self.state.tasks.close();
        let _ = tokio::time::timeout(Duration::from_secs(3), self.state.tasks.wait()).await;
        self.state.pool.shutdown().await;
    }

    async fn command(
        &self,
        request: Operation,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let metadata = request.metadata(&self.state, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.command_capture_limit() {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject(
                    started,
                    &ToolError::new("invalid_argument", "Insufficient response budget", false),
                );
                return Err(error);
            }
        };
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<CommandData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        // Keep cleanup/audit alive even if RMCP suppresses the cancelled reply and
        // drops this handler's JoinHandle. Admission above bounds these tasks.
        let task = self.state.tasks.spawn(async move {
            let reply = state
                .command(request, context.id, context.ct, started, capture_limit)
                .await;
            (permit, reply)
        });
        match task.await {
            Ok((_permit, reply)) => budget.command_result(reply),
            Err(_) => budget.result(ToolReply::<CommandData>::failure(ToolError::new(
                "io_error",
                "Command task could not complete; remote state is unknown",
                true,
            ))),
        }
    }

    async fn binding(
        &self,
        id: BindingId,
        arguments: JsonObject,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered binding exists");
        match binding.parse_request(arguments) {
            Ok(request) => {
                self.command(Operation::Binding { id, request }, context)
                    .await
            }
            Err(error) => {
                Metadata {
                    request_id: &context.id,
                    tool: self.state.binding_name(id),
                    host: None,
                    identity_role: IdentityRole::Ordinary,
                    sudo_mode: None,
                    user: None,
                    program: None,
                    binding_revision: Some(&binding.revision),
                    executor: Some(bindings::EXECUTOR_KIND),
                }
                .reject(
                    Instant::now(),
                    &ToolError::new(
                        "invalid_argument",
                        "Invalid named tool argument shape",
                        false,
                    ),
                );
                Err(error)
            }
        }
    }

    async fn read_file(
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
            state
                .read_file(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn stat_file(
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
            state
                .stat_file(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn list_directory(
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
                .list_directory(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn write_file(
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
            state
                .write_file(request, context.id, context.ct, started, budget)
                .await
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

impl SshMcp {
    #[tool(
        name = "ssh_targets",
        description = "Discover configured logical targets, public advisory descriptions/labels, startup-permitted operations and resolved policy limits without connecting or probing. Permitted operations do not imply remote support or authorization; observed capabilities remain unknown. Limits are ceilings, further constrained by per-request escaping, request IDs and the response-wire budget. Open mode returns no target inventory and never enumerates SSH configuration. Backend aliases, credential/config paths and authentication state are not returned.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<Empty>(),
        output_schema = schema_for_type::<ToolReply<TargetDiscovery<'static>>>()
    )]
    fn ssh_targets(
        &self,
        Arguments(_): Arguments<Empty>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.tool_name(ToolId::Targets),
            host: None,
            identity_role: IdentityRole::Ordinary,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: None,
            executor: None,
        };
        let _permit = match self.state.operations.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<TargetDiscovery<'_>>::failure(error));
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = ToolReply::success(self.state.config.targets(&self.state.tools));
        audit.finish(None, None);
        budget.result(reply)
    }

    #[tool(
        name = "ssh_exec",
        description = "Execute a stateless noninteractive remote shell script (/bin/sh by default; Bash is opt-in). Potentially destructive; not idempotent. Timeout/cancellation closes only this channel: remote work may continue, and operations are never replayed. Ordinary shell authority can bypass same-account sudo approval separation. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<ExecRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_exec(
        &self,
        Arguments(request): Arguments<ExecRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Exec(request), context).await
    }

    #[tool(
        name = "ssh_run",
        description = "Execute an explicit argv on the ordinary SSH identity, with optional absolute cwd and bounded stdin. Executables may be paths or remote-PATH names. Argument boundaries are preserved, but the remote POSIX login shell still participates: this is not remote execve or a sandbox. Use ssh_exec for shell syntax/builtins. Potentially destructive and non-idempotent; ordinary authority can bypass same-account sudo approval separation. Timeout/cancellation closes only this channel, remote work may continue, and operations are never replayed. Output may be truncated within the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RunRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_run(
        &self,
        Arguments(request): Arguments<RunRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Run(request), context).await
    }

    #[tool(
        name = "ssh_read_file",
        description = "Read a bounded range through an independent ordinary-identity SFTP channel. Paths are literal: no shell, tilde, environment or wildcard expansion, and no path sandbox. UTF-8 is strict, including split codepoints; use base64 for arbitrary bytes. content_sha256 is lowercase SHA-256 of returned raw bytes, excluding lookahead and before encoding. Optional expected_content_sha256 must be 64 hex characters; mismatch returns checksum_mismatch without content. This verifies only that range, not a whole-file snapshot. Reads follow server symlink semantics. No sudo, shell/SCP fallback, remote hash helper, installation or automatic retries/replay. Timeout/cancellation disconnects only this channel; remote completion is not guaranteed. The requested lossless range must fit both the configured file cap and fixed 16 MiB reply limit.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ReadRequest>(),
        output_schema = schema_for_type::<ToolReply<ReadData>>()
    )]
    async fn ssh_read_file(
        &self,
        Arguments(request): Arguments<ReadRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.read_file(request, context).await
    }

    #[tool(
        name = "ssh_stat",
        description = "Query ordinary-identity SFTP metadata for a literal UTF-8 path. Default lstat reports a final symlink itself; follow_symlinks=true queries its target. Intermediate symlinks follow server semantics. No path sandbox, race-free no-follow guarantee, shell/SCP fallback, sudo or automatic retry. Missing attributes remain null and missing type is unknown; permissions contain only mode bits. Each call owns an independent SFTP channel under the original timeout.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<StatRequest>(),
        output_schema = schema_for_type::<ToolReply<StatData>>()
    )]
    async fn ssh_stat(
        &self,
        Arguments(request): Arguments<StatRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.stat_file(request, context).await
    }

    #[tool(
        name = "ssh_list_directory",
        description = "List a literal UTF-8 directory path over an independent ordinary SFTP channel. max_entries defaults to 200 (1–1000); the complete 16 MiB reply budget can shorten it further. Entries retain server order, omit dot/dot-dot, and use server-provided metadata without following each symlink. name_base64 always preserves raw filename bytes; name is null for non-UTF-8 names, which UTF-8 path tools cannot address directly. truncated means another entry was observed, not a continuation cursor or snapshot. No sorting, recursion, path sandbox, shell/SCP fallback, sudo or automatic retries. Timeout/cancellation closes only this channel; remote completion is not guaranteed.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ListRequest>(),
        output_schema = schema_for_type::<ToolReply<ListData>>()
    )]
    async fn ssh_list_directory(
        &self,
        Arguments(request): Arguments<ListRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.list_directory(request, context).await
    }

    #[tool(
        name = "ssh_write_file",
        description = "Write bounded content through an independent ordinary SFTP channel. Default exclusive create refuses an existing destination, including symlinks. overwrite=true directly creates or truncates and follows server symlink semantics: a later failure can leave partial, empty or completed changes. Success requires write and close acknowledgements, not atomic replacement or durable fsync. Paths are literal UTF-8, without shell expansion or a path sandbox. Content is UTF-8 by default (NUL allowed), or canonical padded standard base64; decoded bytes must fit the configured file cap before connecting. No append, parent creation, sudo, fallback, retries, replay or rollback. Failures after a mutating OPEN is dispatched report remote_state_unknown=true and null data. Timeout/cancellation closes only this channel; remote work may continue. SFTP v3 can report concurrent exclusive-create conflicts as io_error.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<WriteRequest>(),
        output_schema = schema_for_type::<ToolReply<WriteData>>()
    )]
    async fn ssh_write_file(
        &self,
        Arguments(request): Arguments<WriteRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write_file(request, context).await
    }

    #[tool(
        name = "ssh_sudo",
        description = "Execute an authorized absolute executable via sudo -n -k with the target's configured identity/user/program policy. argv is not a shell script. Requires remote passwordless sudo; no passwords, PTY, environment preservation, or retries. Potentially destructive and not idempotent. Cancellation cannot guarantee remote termination. Permitted executables may themselves grant shell-like authority; sudoers remains authoritative. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<SudoRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_sudo(
        &self,
        Arguments(request): Arguments<SudoRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Sudo(request), context).await
    }
}

enum Operation {
    Exec(ExecRequest),
    Run(RunRequest),
    Sudo(SudoRequest),
    Binding {
        id: BindingId,
        request: BindingRequest,
    },
}

struct PreparedCommand<'a> {
    target: ResolvedTarget<'a>,
    duration: Duration,
    invocation: Invocation<'a>,
    stdin: Option<&'a str>,
    max_output_bytes: u64,
}

impl Operation {
    fn metadata<'a>(&'a self, state: &'a State, request_id: &'a RequestId) -> Metadata<'a> {
        let (tool, host, user, program, revision, executor) = match self {
            Self::Exec(request) => (
                ToolKey::Builtin(ToolId::Exec),
                Some(request.host.as_str()),
                None,
                None,
                None,
                None,
            ),
            Self::Run(request) => (
                ToolKey::Builtin(ToolId::Run),
                Some(request.host.as_str()),
                None,
                None,
                None,
                None,
            ),
            Self::Sudo(request) => (
                ToolKey::Builtin(ToolId::Sudo),
                Some(request.host.as_str()),
                Some(request.user.as_str()),
                request.argv.first().map(String::as_str),
                None,
                None,
            ),
            Self::Binding { id, request } => {
                let binding = state
                    .config
                    .bindings()
                    .get(*id)
                    .expect("registered binding exists");
                let host = binding
                    .targets
                    .contains(&request.host)
                    .then_some(request.host.as_str());
                (
                    ToolKey::Binding(*id),
                    host,
                    None,
                    None,
                    Some(binding.revision.as_str()),
                    Some(bindings::EXECUTOR_KIND),
                )
            }
        };
        let mode = host.map(|host| state.config.sudo_mode(host));
        Metadata {
            request_id,
            tool: state
                .tools
                .name(tool)
                .expect("executing tool is registered"),
            host,
            user,
            program,
            binding_revision: revision,
            executor,
            sudo_mode: mode,
            identity_role: if matches!(self, Self::Sudo(_)) && mode != Some(SudoMode::SameAccount) {
                IdentityRole::Elevated
            } else {
                IdentityRole::Ordinary
            },
        }
    }

    fn prepare<'a>(&'a self, config: &'a Config) -> Result<PreparedCommand<'a>, ToolError> {
        let (target, invocation, stdin, seconds) = match self {
            Self::Exec(request) => {
                request.validate(config.limits().max_file_bytes)?;
                (
                    config.resolve(&request.host, ToolId::Exec)?,
                    Invocation::Shell {
                        command: &request.command,
                        shell: request.shell,
                        cwd: request.cwd.as_deref(),
                    },
                    request.stdin.as_deref(),
                    request.timeout_secs,
                )
            }
            Self::Run(request) => {
                request.validate(config.limits().max_file_bytes)?;
                (
                    config.resolve(&request.host, ToolId::Run)?,
                    Invocation::Argv {
                        argv: &request.argv,
                        cwd: request.cwd.as_deref(),
                    },
                    request.stdin.as_deref(),
                    request.timeout_secs,
                )
            }
            Self::Sudo(request) => {
                request.validate(config.limits().max_file_bytes)?;
                (
                    config.resolve_sudo(&request.host, &request.user, &request.argv[0])?,
                    Invocation::Sudo {
                        argv: &request.argv,
                        user: &request.user,
                    },
                    request.stdin.as_deref(),
                    request.timeout_secs,
                )
            }
            Self::Binding { id, request } => {
                let target = config.resolve_binding(&request.host, *id)?;
                let binding = config
                    .bindings()
                    .get(*id)
                    .expect("registered binding exists");
                let prepared = binding.prepare(request, config.limits())?;
                return Ok(PreparedCommand {
                    target,
                    duration: prepared.duration,
                    invocation: prepared.invocation,
                    stdin: None,
                    max_output_bytes: prepared.max_output_bytes,
                });
            }
        };
        Ok(PreparedCommand {
            target,
            duration: config.timeout(seconds)?,
            invocation,
            stdin,
            max_output_bytes: config.limits().max_output_bytes,
        })
    }
}

fn file_metadata<'a>(
    host: &'a str,
    tool: ToolId,
    state: &'a State,
    request_id: &'a RequestId,
) -> Metadata<'a> {
    Metadata {
        request_id,
        tool: state.tool_name(tool),
        host: Some(host),
        identity_role: IdentityRole::Ordinary,
        sudo_mode: Some(state.config.sudo_mode(host)),
        user: None,
        program: None,
        binding_revision: None,
        executor: None,
    }
}

fn request_deadline(
    started: Instant,
    duration: Duration,
) -> Result<tokio::time::Instant, ToolError> {
    tokio::time::Instant::from_std(started)
        .checked_add(duration)
        .ok_or_else(|| {
            ToolError::new(
                "invalid_argument",
                "timeout_secs exceeds the supported clock range",
                false,
            )
        })
}

impl State {
    fn tool_name(&self, id: ToolId) -> &str {
        self.tools
            .name(ToolKey::Builtin(id))
            .expect("executing tool is registered")
    }

    fn binding_name(&self, id: BindingId) -> &str {
        self.tools
            .name(ToolKey::Binding(id))
            .expect("executing binding is registered")
    }

    async fn command(
        &self,
        request: Operation,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        capture_limit: u64,
    ) -> ToolReply<CommandData> {
        let metadata = request.metadata(self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
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
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
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
                    },
                )
                .await;
                if matches!(
                    reply.data.as_ref().map(|data| &data.termination),
                    Some(Termination::ConnectionLost)
                ) && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(
            reply.data.as_ref().and_then(|data| data.exit_code),
            reply.error.as_ref(),
        );
        reply
    }

    async fn read_file(
        &self,
        request: ReadRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ReadData> {
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
                let outcome = files::read(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
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

    async fn stat_file(
        &self,
        request: StatRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<StatData> {
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
                let outcome = files::stat(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
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

    async fn list_directory(
        &self,
        request: ListRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ListData> {
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
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = files::list(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
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

    async fn write_file(
        &self,
        request: WriteRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<WriteData> {
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
                let outcome = files::write(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
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

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            rmcp::model::Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        if !self.tool_router.has_route(&request.name) {
            let sudo = request.name == self.state.sudo_name;
            Metadata {
                request_id: &context.id,
                tool: if sudo {
                    &self.state.sudo_name
                } else {
                    "unknown"
                },
                host: None,
                identity_role: if sudo {
                    IdentityRole::Elevated
                } else {
                    IdentityRole::Ordinary
                },
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: None,
                executor: None,
            }
            .reject(
                Instant::now(),
                &ToolError::new("invalid_argument", "Tool is not registered", false),
            );
            return Err(ErrorData::invalid_params("Tool is not registered", None));
        }
        self.tool_router
            .call(ToolCallContext::new(self, request, context))
            .await
    }
}
