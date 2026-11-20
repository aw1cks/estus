use std::{sync::Arc, time::Instant};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{
        common::FromContextPart,
        tool::{ToolCallContext, schema_for_type},
    },
    model::{CallToolResult, JsonObject, ServerCapabilities, ServerConfig},
    service::RequestContext,
    tool, tool_handler,
};
use schemars::JsonSchema;
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    audit::{Audit, Metadata},
    bindings::{ActivatedCall, ActivatedExecution, BindingId},
    command::{ExecRequest, RunRequest, SudoRequest},
    config::{IdentityRole, SudoMode, TargetDiscovery, ToolId},
    filesystem::{
        data::{
            ListData, ListRequest, MkdirData, MkdirRequest, ReadData, ReadRequest,
            RemoveDirectoryData, RemoveDirectoryRequest, RemoveFileData, RemoveFileRequest,
            RenameData, RenameRequest, ReplaceData, ReplaceRequest, StatRequest, WriteData,
            WriteRequest,
        },
        metadata::StatData,
    },
    output::ReadOutputRequest,
    reply::{ClearTargetQuarantineData, CommandData, ControllerError, ToolError, ToolReply},
    wire::ReplyBudget,
};

use super::{Estus, preparation::Operation};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Empty {}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ClearTargetQuarantineRequest {
    host: String,
    acknowledge_remote_state_reconciled: bool,
}

// RMCP 3.9 converts its Parameters extractor's errors into tool results. This
// extractor keeps argument-shape failures at the protocol boundary and uses the
// registered schema to identify only declared paths and constraint kinds.
pub(super) struct Arguments<T>(T);

fn diagnose_schema_error(
    route: Option<&super::registration::RouteSchema>,
    value: &serde_json::Value,
) -> (String, &'static str) {
    let Some(route) = route else {
        return ("arguments".to_owned(), "invalid_type");
    };
    route
        .validator
        .iter_errors(value)
        .map(|error| {
            (
                crate::contracts::schema::safe_path(&route.schema, &error, "arguments"),
                crate::contracts::schema::classify_error(&error, "invalid_type"),
            )
        })
        .min()
        .unwrap_or_else(|| ("arguments".to_owned(), "invalid_type"))
}

fn shape_error(
    route: Option<&super::registration::RouteSchema>,
    value: &serde_json::Value,
) -> ErrorData {
    let (schema_path, constraint) = diagnose_schema_error(route, value);
    ErrorData::invalid_params(
        "Arguments do not match the tool input schema",
        Some(serde_json::json!({
            "code": "invalid_argument",
            "phase": "argument_shape",
            "schema_path": schema_path,
            "constraint": constraint,
        })),
    )
}

impl<T: DeserializeOwned> FromContextPart<ToolCallContext<'_, Estus>> for Arguments<T> {
    fn from_context_part(context: &mut ToolCallContext<'_, Estus>) -> Result<Self, ErrorData> {
        let value = serde_json::Value::Object(context.arguments.take().unwrap_or_default());
        T::deserialize(&value).map(Self).map_err(|_| {
            let error =
                ToolError::invalid_argument("Arguments do not match the tool input schema", false);
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
            shape_error(
                context
                    .service
                    .state
                    .input_schemas
                    .get(context.name.as_ref()),
                &value,
            )
        })
    }
}

impl Estus {
    pub(super) async fn binding(
        &self,
        id: BindingId,
        activated: ActivatedExecution,
        arguments: JsonObject,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        // Verify the binding exists once at dispatch; handlers below reuse this
        // resolved reference instead of re-deriving it.
        let binding = super::preparation::Operation::binding(id, &self.state.config);
        let mode = arguments
            .get("host")
            .and_then(serde_json::Value::as_str)
            .filter(|host| binding.targets.iter().any(|allowed| allowed == host))
            .map(|host| self.state.config.sudo_mode(host));
        match binding.parse_activated_call(&activated, &arguments) {
            Ok(ActivatedCall::Remote(request)) => {
                self.command(Operation::Binding { id, request }, context)
                    .await
            }
            Ok(ActivatedCall::Controller { plan, request }) => {
                self.controller_binding(id, plan, request, context).await
            }
            Ok(ActivatedCall::Automation { activated, request }) => {
                self.automation_binding(id, activated, request, context)
                    .await
            }
            Ok(ActivatedCall::Payload { activated, request }) => {
                self.payload_binding(id, activated, request, context).await
            }
            Err(_) => {
                let value = serde_json::Value::Object(arguments);
                let error = shape_error(
                    self.state.input_schemas.get(self.state.binding_name(id)),
                    &value,
                );
                if binding.is_controller() {
                    self.state
                        .controller_metadata(id, binding, &context.id)
                        .reject_controller(
                            Instant::now(),
                            &ControllerError::invalid_argument(
                                "Invalid controller tool argument shape",
                            ),
                        );
                    return Err(error);
                }
                Metadata {
                    request_id: &context.id,
                    tool: self.state.binding_name(id),
                    host: None,
                    identity_role: if let Some(authority) = binding.automation_authority() {
                        authority.identity_role()
                    } else if binding.sudo().is_some() && mode != Some(SudoMode::SameAccount) {
                        IdentityRole::Elevated
                    } else {
                        IdentityRole::Ordinary
                    },
                    sudo_mode: if binding.automation_authority().is_some() {
                        None
                    } else {
                        mode
                    },
                    user: binding.sudo().map(|(user, _)| user),
                    program: None,
                    binding_revision: Some(&binding.revision),
                    executor: Some(binding.executor_kind()),
                }
                .reject(
                    Instant::now(),
                    &ToolError::invalid_argument("Invalid named tool argument shape", false),
                );
                Err(error)
            }
        }
    }
}

impl Estus {
    #[tool(
        name = "observe_targets",
        description = "List configured logical targets with advisory descriptions, permitted operations and resolved policy limits. Connects to nothing, so permitted operations do not prove remote support.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<Empty>(),
        output_schema = schema_for_type::<ToolReply<TargetDiscovery<'static>>>()
    )]
    pub(super) async fn observe_targets(
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
        let deadline = match super::preparation::request_deadline(
            started,
            std::time::Duration::from_secs(self.state.config.limits().operation_timeout_secs),
        ) {
            Ok(deadline) => deadline,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<TargetDiscovery<'_>>::failure(error));
            }
        };
        let _permit = match self
            .state
            .acquire_permit(&self.state.operations, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<TargetDiscovery<'_>>::failure(error));
            }
        };
        let audit = Audit::start(metadata, started);
        let mut discovery = self.state.config.targets(&self.state.tools);
        discovery.cleanup_quarantine = self.state.cleanup_quarantine.snapshot();
        let reply = ToolReply::success(discovery);
        audit.finish(None, None);
        budget.result(reply)
    }

    #[tool(
        name = "inspect_output",
        description = "Read a bounded raw-byte range of stdout or stderr retained by an earlier command that set retain_output. Local only; handles are session capabilities and eof means the end of the retained prefix.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ReadOutputRequest>(),
        output_schema = schema_for_type::<ToolReply<ReadData>>()
    )]
    pub(super) async fn inspect_output(
        &self,
        Arguments(request): Arguments<ReadOutputRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = self.state.output_metadata(&context.id);
        if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
            let error = ToolError::cancelled("Output read cancelled before dispatch", false);
            metadata.reject(started, &error);
            return budget.result(ToolReply::<ReadData>::failure(error));
        }
        let deadline = match super::preparation::request_deadline(
            started,
            std::time::Duration::from_secs(self.state.config.limits().operation_timeout_secs),
        ) {
            Ok(deadline) => deadline,
            Err(error) => {
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ReadData>::failure(error));
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
                return budget.result(ToolReply::<ReadData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        let task = self.state.tasks.spawn(async move {
            let _permit = permit;
            let audit = Audit::start(state.output_metadata(&context.id), started);
            let reply = tokio::select! {
                biased;
                () = context.ct.cancelled() => ToolReply::failure(ToolError::cancelled("Output read cancelled", false)),
                () = state.shutdown.cancelled() => ToolReply::failure(ToolError::cancelled("Output read cancelled", false)),
                reply = state.outputs.read(request, state.config.limits().max_file_bytes, budget) => reply,
            };
            audit.finish(None, reply.error());
            reply
        });
        match task.await {
            Ok(reply) => budget.result(reply),
            Err(_) => budget.result(ToolReply::<ReadData>::failure(ToolError::io_error(
                "Output read could not complete",
                false,
            ))),
        }
    }

    #[tool(
        name = "exec_command",
        description = "Run a stateless noninteractive remote shell script (/bin/sh unless bash is requested). Not idempotent: timeout or cancellation may leave remote work running and nothing is replayed.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<ExecRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    pub(super) async fn exec_command(
        &self,
        Arguments(request): Arguments<ExecRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Exec(request), context).await
    }

    #[tool(
        name = "exec_argv",
        description = "Run an explicit argv on the ordinary SSH identity with optional absolute cwd and bounded stdin. The remote login shell still participates, so pass an absolute path to pin the executable; use exec_command for shell syntax.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RunRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    pub(super) async fn exec_argv(
        &self,
        Arguments(request): Arguments<RunRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Run(request), context).await
    }

    #[tool(
        name = "inspect_file",
        description = "Read a bounded byte range of a literal remote path over SFTP. Pass expected_content_sha256 to verify the returned bytes; no expansion, sandbox, sudo or retry.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ReadRequest>(),
        output_schema = schema_for_type::<ToolReply<ReadData>>()
    )]
    pub(super) async fn inspect_file(
        &self,
        Arguments(request): Arguments<ReadRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.read_file(request, context).await
    }

    #[tool(
        name = "observe_stat",
        description = "Read SFTP metadata for a literal path: lstat by default, or follow_symlinks=true for a final symlink's target. Missing attributes stay null rather than being inferred.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<StatRequest>(),
        output_schema = schema_for_type::<ToolReply<StatData>>()
    )]
    pub(super) async fn observe_stat(
        &self,
        Arguments(request): Arguments<StatRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.stat_file(request, context).await
    }

    #[tool(
        name = "inspect_directory",
        description = "List one bounded page of a literal directory path (max_entries 1–1000, default 200). truncated=true means more entries existed; the page is not a filesystem snapshot.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ListRequest>(),
        output_schema = schema_for_type::<ToolReply<ListData>>()
    )]
    pub(super) async fn inspect_directory(
        &self,
        Arguments(request): Arguments<ListRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.list_directory(request, context).await
    }

    #[tool(
        name = "change_file_write",
        description = "Write bounded content to a literal path, refusing an existing destination unless overwrite=true. Not atomic; a failure after dispatch reports remote_state_unknown=true.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<WriteRequest>(),
        output_schema = schema_for_type::<ToolReply<WriteData>>()
    )]
    pub(super) async fn change_file_write(
        &self,
        Arguments(request): Arguments<WriteRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write_file(request, context).await
    }

    #[tool(
        name = "change_mkdir",
        description = "Create one directory under an existing parent. Any entry already at the path, including a final symlink, is rejected as already_exists.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<MkdirRequest>(),
        output_schema = schema_for_type::<ToolReply<MkdirData>>()
    )]
    pub(super) async fn change_mkdir(
        &self,
        Arguments(request): Arguments<MkdirRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.mkdir(request, context).await
    }

    #[tool(
        name = "change_rename",
        description = "Rename one entry through POSIX rename; overwrite=true is required because this backend cannot guarantee atomic no-overwrite rename. A final source symlink moves itself, not its target.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RenameRequest>(),
        output_schema = schema_for_type::<ToolReply<RenameData>>()
    )]
    pub(super) async fn change_rename(
        &self,
        Arguments(request): Arguments<RenameRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.rename(request, context).await
    }

    #[tool(
        name = "change_file_remove",
        description = "Unlink one file or final symlink entry. Directories and missing paths are errors, and this is not secure erasure.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RemoveFileRequest>(),
        output_schema = schema_for_type::<ToolReply<RemoveFileData>>()
    )]
    pub(super) async fn change_file_remove(
        &self,
        Arguments(request): Arguments<RemoveFileRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.remove_file(request, context).await
    }

    #[tool(
        name = "change_directory_remove",
        description = "Remove one empty directory with a single RMDIR. Nonempty directories, files and missing paths are errors.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RemoveDirectoryRequest>(),
        output_schema = schema_for_type::<ToolReply<RemoveDirectoryData>>()
    )]
    pub(super) async fn change_directory_remove(
        &self,
        Arguments(request): Arguments<RemoveDirectoryRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.remove_directory(request, context).await
    }

    #[tool(
        name = "change_file_replace",
        description = "Replace a file atomically: stage a mode-0600 sibling, write and close it, then rename over the destination. Requires overwrite=true and advertised POSIX rename; an uncertain dispatch may leave .estus-replace-* siblings to inspect out of band.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<ReplaceRequest>(),
        output_schema = schema_for_type::<ToolReply<ReplaceData>>()
    )]
    pub(super) async fn change_file_replace(
        &self,
        Arguments(request): Arguments<ReplaceRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.replace_file(request, context).await
    }

    #[tool(
        name = "exec_sudo",
        description = "Run one allowlisted absolute executable via sudo -H -n -k under the target's declared user and program policy. Requires passwordless sudo; no PTY, environment preservation or retry.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<SudoRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    pub(super) async fn exec_sudo(
        &self,
        Arguments(request): Arguments<SudoRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Sudo(request), context).await
    }

    #[tool(
        name = "change_target_quarantine_clear",
        description = "Clear the write quarantine for one logical target after independently confirming remote state; a persisted record is unlinked first. Requires acknowledge_remote_state_reconciled=true, which asserts reconciliation, not that remote work stopped.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<ClearTargetQuarantineRequest>(),
        output_schema = schema_for_type::<ToolReply<ClearTargetQuarantineData>>()
    )]
    pub(super) async fn change_target_quarantine_clear(
        &self,
        Arguments(request): Arguments<ClearTargetQuarantineRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let host_known = self.state.admission.contains(&request.host);
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.tool_name(ToolId::ClearTargetQuarantine),
            host: host_known.then_some(request.host.as_str()),
            identity_role: IdentityRole::Ordinary,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: None,
            executor: None,
        };
        let reject = |error: ToolError| {
            metadata.reject(started, &error);
            budget.result(ToolReply::<ClearTargetQuarantineData>::failure(error))
        };
        if context.ct.is_cancelled() || self.state.shutdown.is_cancelled() {
            return reject(ToolError::cancelled(
                "Quarantine clear cancelled before execution",
                false,
            ));
        }
        if !self
            .state
            .config
            .tool_enabled(ToolId::ClearTargetQuarantine)
        {
            return reject(ToolError::policy_denied(
                "Operation is not authorized",
                false,
            ));
        }
        if request.host.is_empty()
            || request.host.len() > 256
            || request.host.contains('\0')
            || request.host.chars().any(char::is_control)
        {
            return reject(ToolError::invalid_argument("Invalid target host", false));
        }
        if !request.acknowledge_remote_state_reconciled {
            return reject(ToolError::invalid_argument(
                "Clearing target quarantine requires acknowledge_remote_state_reconciled=true",
                false,
            ));
        }
        let deadline = match super::preparation::request_deadline(
            started,
            std::time::Duration::from_secs(self.state.config.limits().operation_timeout_secs),
        ) {
            Ok(deadline) => deadline,
            Err(error) => return reject(error),
        };
        let _permit = match self
            .state
            .acquire_permit(&self.state.operations, deadline, &context.ct)
            .await
        {
            Ok(permit) => permit,
            Err(error) => return reject(error),
        };
        let audit = Audit::start(metadata, started);
        let cleared = match self.state.admission.clear_quarantine(&request.host).await {
            Ok(cleared) => cleared,
            Err(error) => {
                audit.finish(None, Some(&error));
                return budget.result(ToolReply::<ClearTargetQuarantineData>::failure(error));
            }
        };
        let data = match cleared {
            Some(previous) => {
                crate::audit::target_quarantine(
                    "cleared",
                    &request.host,
                    Some(&previous.authority),
                    Some(previous.executor),
                    previous.cause,
                );
                ClearTargetQuarantineData {
                    cleared: true,
                    was_quarantined: true,
                    previous_cause: Some(previous.cause),
                }
            }
            None => ClearTargetQuarantineData {
                cleared: false,
                was_quarantined: false,
                previous_cause: None,
            },
        };
        let reply = ToolReply::success(data);
        audit.finish(None, None);
        budget.result(reply)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Estus {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(super::guidance::INSTRUCTIONS)
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, ErrorData> {
        Ok(super::guidance::list_prompts())
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, ErrorData> {
        super::guidance::get_prompt(self, request).map(Into::into)
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, ErrorData> {
        Ok(super::guidance::list_resources(self))
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourceTemplatesResult, ErrorData> {
        Ok(super::guidance::list_resource_templates())
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, ErrorData> {
        super::guidance::read_resource(self, request).map(Into::into)
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        let _request_credit = self.state.pending_replies.enter_handler(&context.id);
        context.extensions.insert(_request_credit.clone());
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
                &ToolError::invalid_argument("Tool is not registered", false),
            );
            return Err(ErrorData::invalid_params("Tool is not registered", None));
        }
        let scope = self
            .state
            .progress
            .start(&context, &self.state.shutdown, &self.state.tasks);
        if let Some(scope) = &scope {
            context.extensions.insert(scope.reporter.clone());
        }
        let result = self
            .tool_router
            .call(ToolCallContext::new(self, request, context))
            .await;
        drop(scope);
        result
    }
}
