use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{
        common::FromContextPart,
        router::tool::ToolRouter,
        tool::{ToolCallContext, schema_for_type},
    },
    model::{CallToolResult, RequestId, ServerCapabilities, ServerConfig},
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    audit::{Audit, Metadata},
    config::{Config, IdentityRole, ResolvedTarget, SudoMode, TargetDiscovery},
    exec::{self, CommandData, ExecRequest, Invocation, RunContext, SudoRequest, Termination},
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
    pool: Arc<Pool>,
    shutdown: CancellationToken,
    operations: Arc<Semaphore>,
    tasks: TaskTracker,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Serialize, JsonSchema)]
pub(crate) struct ToolReply<T> {
    pub(crate) data: Option<T>,
    pub(crate) error: Option<ToolError>,
}

impl<T> ToolReply<T> {
    pub(crate) fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
        }
    }
    pub(crate) fn failure(error: ToolError) -> Self {
        Self {
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ToolError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) remote_state_unknown: bool,
}

impl ToolError {
    pub(crate) const SSH_CONNECT_FAILED: Self = Self::new(
        "ssh_connect_failed",
        "SSH connection failed; verify the configured alias, authentication and known hosts with your SSH client outside MCP",
        false,
    );

    pub(crate) const fn new(
        code: &'static str,
        message: &'static str,
        remote_state_unknown: bool,
    ) -> Self {
        Self {
            code,
            message,
            remote_state_unknown,
        }
    }
}

// RMCP 3.9 converts its Parameters extractor's errors into tool results. This
// extractor keeps argument-shape failures at the protocol boundary and never
// reflects malformed input values or field names in diagnostics.
struct Arguments<T>(T);

impl<S, T: DeserializeOwned> FromContextPart<ToolCallContext<'_, S>> for Arguments<T> {
    fn from_context_part(context: &mut ToolCallContext<'_, S>) -> Result<Self, ErrorData> {
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
                identity_role: if context.name == "ssh_sudo" {
                    IdentityRole::Elevated
                } else {
                    IdentityRole::Ordinary
                },
                sudo_mode: None,
                user: None,
                program: None,
            };
            metadata.reject(Instant::now(), &error);
            ErrorData::invalid_params(error.message, None)
        })
    }
}

impl SshMcp {
    pub(crate) fn new(config: Config) -> Self {
        let shutdown = CancellationToken::new();
        let pool = Pool::new(
            config.ssh_config().map(std::path::Path::to_path_buf),
            Duration::from_secs(config.limits().connect_timeout_secs),
            shutdown.clone(),
        );
        let mut tool_router = Self::tool_router();
        if !config.has_sudo() {
            tool_router.remove_route("ssh_sudo");
        }
        Self {
            tool_router,
            state: Arc::new(State {
                config,
                pool,
                shutdown,
                operations: Arc::new(Semaphore::new(16)),
                tasks: TaskTracker::new(),
            }),
        }
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
        let metadata = request.metadata(&self.state.config, &context.id);
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
}

#[tool_router]
impl SshMcp {
    #[tool(
        description = "List configured logical targets without connecting. Open mode does not enumerate SSH configuration.",
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
            tool: "ssh_targets",
            host: None,
            identity_role: IdentityRole::Ordinary,
            sudo_mode: None,
            user: None,
            program: None,
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
        let reply = ToolReply::success(self.state.config.targets());
        audit.finish(None, None);
        budget.result(reply)
    }

    #[tool(
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
    Sudo(SudoRequest),
}

impl Operation {
    fn metadata<'a>(&'a self, config: &Config, request_id: &'a RequestId) -> Metadata<'a> {
        let (tool, host, user, program) = match self {
            Self::Exec(request) => ("ssh_exec", request.host.as_str(), None, None),
            Self::Sudo(request) => (
                "ssh_sudo",
                request.host.as_str(),
                Some(request.user.as_str()),
                request.argv.first().map(String::as_str),
            ),
        };
        let mode = config.sudo_mode(host);
        Metadata {
            request_id,
            tool,
            host: Some(host),
            user,
            program,
            sudo_mode: Some(mode),
            identity_role: if matches!(self, Self::Sudo(_)) && mode != SudoMode::SameAccount {
                IdentityRole::Elevated
            } else {
                IdentityRole::Ordinary
            },
        }
    }

    fn validate<'a>(
        &'a self,
        config: &'a Config,
    ) -> Result<(ResolvedTarget<'a>, Duration), ToolError> {
        let (target, seconds) = match self {
            Self::Exec(request) => {
                request.validate(config.limits().max_file_bytes)?;
                (config.resolve(&request.host)?, request.timeout_secs)
            }
            Self::Sudo(request) => {
                request.validate(config.limits().max_file_bytes)?;
                (
                    config.resolve_sudo(&request.host, &request.user, &request.argv[0])?,
                    request.timeout_secs,
                )
            }
        };
        Ok((target, config.timeout(seconds)?))
    }

    fn invocation(&self) -> (Invocation<'_>, Option<&str>) {
        match self {
            Self::Exec(request) => (
                Invocation::Shell {
                    command: &request.command,
                    shell: request.shell,
                    cwd: request.cwd.as_deref(),
                },
                request.stdin.as_deref(),
            ),
            Self::Sudo(request) => (
                Invocation::Sudo {
                    argv: &request.argv,
                    user: &request.user,
                },
                request.stdin.as_deref(),
            ),
        }
    }
}

impl State {
    async fn command(
        &self,
        request: Operation,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        capture_limit: u64,
    ) -> ToolReply<CommandData> {
        let metadata = request.metadata(&self.config, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(&self.config)
            .and_then(|(target, duration)| {
                tokio::time::Instant::from_std(started)
                    .checked_add(duration)
                    .map(|deadline| (target, deadline))
                    .ok_or_else(|| {
                        ToolError::new(
                            "invalid_argument",
                            "timeout_secs exceeds the supported clock range",
                            false,
                        )
                    })
            });
        let (target, deadline) = match validated {
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
                let (invocation, input) = request.invocation();
                let reply = exec::run(
                    lease.session(),
                    invocation,
                    input,
                    RunContext {
                        max_output_bytes: self.config.limits().max_output_bytes.min(capture_limit),
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
            let sudo = request.name == "ssh_sudo";
            Metadata {
                request_id: &context.id,
                tool: if sudo { "ssh_sudo" } else { "unknown" },
                host: None,
                identity_role: if sudo {
                    IdentityRole::Elevated
                } else {
                    IdentityRole::Ordinary
                },
                sudo_mode: None,
                user: None,
                program: None,
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
