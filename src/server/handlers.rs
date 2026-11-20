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
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered binding exists");
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
                        .controller_metadata(id, &context.id)
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
        description = "Discover configured logical targets, public advisory descriptions/labels, startup-permitted operations and resolved policy limits without connecting or probing. Permitted operations do not imply remote support or authorization; observed capabilities remain unknown. Limits are ceilings, further constrained by per-request escaping, request IDs and the response-wire budget. Open mode returns no target inventory and never enumerates SSH configuration. Backend aliases, credential/config paths and authentication state are not returned.",
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
        description = "Read a bounded exact raw-byte range from stdout/stderr retained by an explicitly opted-in synchronous native/controller command in this server session. Opaque handles select only private server-owned artifacts, never caller file paths or another process/session's output. No SSH or remote execution occurs. UTF-8 is strict; base64 is padded and lossless; SHA-256 covers returned raw bytes. eof means end of the retained prefix, not complete command output; the command's output receipt reports stream truncation and observed byte count. Expired/foreign/unknown handles return not_found without reflecting secrets. File/read limits and the complete reply budget apply. Retention, local storage failure and reads never change command exit/termination/uncertainty evidence. Automation private Runner frames are never eligible.",
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
        description = "Execute a stateless noninteractive remote shell script (/bin/sh by default; Bash is opt-in). Potentially destructive; not idempotent. Timeout/cancellation closes only this channel: remote work may continue, and operations are never replayed. Ordinary shell authority can bypass same-account sudo approval separation. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
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
        description = "Execute an explicit argv on the ordinary SSH identity, with optional absolute cwd and bounded stdin. Argument boundaries are preserved through POSIX command --, but the remote login shell still participates: this is not remote execve or a sandbox. Remote-PATH names may resolve shell builtins; use an absolute path to pin the executable. Use exec_command for shell syntax. Potentially destructive and non-idempotent; ordinary authority can bypass same-account sudo approval separation. Timeout/cancellation closes only this channel, remote work may continue, and operations are never replayed. Output may be truncated within the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
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
        description = "Read a bounded range through an independent ordinary-identity SFTP channel. Paths are literal: no shell, tilde, environment or wildcard expansion, and no path sandbox. UTF-8 is strict, including split codepoints; use base64 for arbitrary bytes. content_sha256 is lowercase SHA-256 of returned raw bytes, excluding lookahead and before encoding. Optional expected_content_sha256 must be 64 hex characters; mismatch returns checksum_mismatch without content. This verifies only that range, not a whole-file snapshot. Reads follow server symlink semantics. No sudo, shell/SCP fallback, remote hash helper, installation or automatic retries/replay. Timeout/cancellation disconnects only this channel; remote completion is not guaranteed. The requested lossless range must fit both the configured file cap and fixed 16 MiB reply limit.",
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
        description = "Query ordinary-identity SFTP metadata for a literal UTF-8 path. Default lstat reports a final symlink itself; follow_symlinks=true queries its target. Intermediate symlinks follow server semantics. No path sandbox, race-free no-follow guarantee, shell/SCP fallback, sudo or automatic retry. Missing attributes remain null and missing type is unknown; permissions contain only mode bits. Each call owns an independent SFTP channel under the original timeout.",
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
        description = "List a literal UTF-8 directory path over an ordinary SFTP enumeration. max_entries defaults to 200 (1–1000); bounded page-entry bytes and the complete 16 MiB reply budget can shorten a page. Entries retain server order, omit dot/dot-dot, and use server-provided metadata without following each symlink. name_base64 preserves raw filename bytes; name is null for non-UTF-8 names, which UTF-8 path tools cannot address directly. One request returns a single bounded page; truncated=true means more entries existed, not an error, and the result is not a filesystem snapshot: mutation remains server-defined. No sorting, recursion, path sandbox, shell/SCP fallback, sudo or automatic retries. Remote completion is not guaranteed on interruption.",
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
        description = "Write bounded content through an independent ordinary SFTP channel. Default exclusive create refuses an existing destination, including symlinks. overwrite=true directly creates or truncates and follows server symlink semantics: a later failure can leave partial, empty or completed changes. Success requires write and close acknowledgements, not atomic replacement or durable fsync. Paths are literal UTF-8, without shell expansion or a path sandbox. Content is UTF-8 by default (NUL allowed), or canonical padded standard base64; decoded bytes must fit the configured file cap before connecting. No append, parent creation, sudo, fallback, retries, replay or rollback. Failures after a mutating OPEN is dispatched report remote_state_unknown=true and null data. Timeout/cancellation closes only this channel; remote work may continue. SFTP v3 can report concurrent exclusive-create conflicts as io_error.",
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
        description = "Create one directory through an independently owned ordinary SFTP channel. Paths are literal UTF-8, without shell, tilde, variable or wildcard expansion or a path sandbox. Parents must exist; no recursive creation, exist_ok, mode override, sudo or shell/SCP fallback. Any entry observed at the path, including a final symlink, is rejected as already_exists; this preflight is not a race-free no-follow guarantee and intermediate symlinks follow server semantics. A successful acknowledgement returns created=true. Failure after MKDIR dispatch retains remote-state uncertainty, even for server refusal or cleanup failure. Timeout/cancellation closes only this channel, never asserts rollback, and never retries/replays.",
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
        description = "Rename one file, directory or symlink entry through ordinary SFTP. source and destination are literal UTF-8 without shell, tilde, variable or wildcard expansion or a path sandbox. overwrite defaults to false: this SFTP v3 backend cannot guarantee atomic no-overwrite rename, so false/omitted returns unsupported without mutation even when destination is absent. Explicit overwrite=true requires the advertised POSIX-rename extension and permits atomic replacement under server filesystem rules; no standard-rename, stat-then-rename, unlink, copy, sudo or shell/SCP fallback. Intermediate symlinks follow server semantics; a final source symlink itself moves. Success returns renamed=true only after acknowledgement and bounded channel cleanup. Any failure after rename dispatch retains remote-state uncertainty, including server refusal or cleanup failure. Never retries, replays or asserts rollback; no cross-filesystem or durability guarantee.",
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
        description = "Unlink one file or final symlink entry through an independently owned ordinary SFTP channel. path is literal UTF-8: no shell, tilde, variable or wildcard expansion or path sandbox. A final symlink itself is removed, not its file/directory target; intermediate symlinks follow server semantics. Directories and missing paths remain backend errors, never recursive deletion or missing_ok success. No RMDIR, canonicalization, sudo, shell/SCP fallback, retry or replay. Success returns removed=true only after REMOVE acknowledgement and bounded channel cleanup. Any failure after REMOVE dispatch retains remote-state uncertainty, including server refusal or cleanup failure; timeout/cancellation never asserts rollback or secure erasure.",
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
        description = "Remove one empty directory through an independently owned ordinary SFTP channel. path is literal UTF-8 without shell, tilde, variable or wildcard expansion or a path sandbox. The server's RMDIR enforces emptiness; nonempty directories, files and missing entries remain backend errors, never recursive deletion or missing_ok success. No directory walk, REMOVE, canonicalization, sudo, shell/SCP fallback, retry or replay. Path components, symlinks and trailing slashes retain server filesystem semantics; no race-free no-follow or entry-identity guarantee is added. Success returns removed=true only after RMDIR acknowledgement and bounded cleanup. Any failure after RMDIR dispatch retains remote-state uncertainty, including server refusal or cleanup failure. Channel closure never proves rollback.",
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
        description = "Explicit atomic-visibility file replacement over ordinary SFTP; requires overwrite=true and advertised POSIX rename before any mutation. Stages one random EXCL-created sibling with mode0600 in the original OPEN, confirms permissions by handle before content writes, completes write_all and file CLOSE before atomic rename. UTF-8/base64 content obeys the configured file byte limit. Literal UTF-8 paths; final segment must be a file name, not root, trailing slash, . or ... A final destination symlink entry is replaced, not its target; parent components retain server semantics. New inode/owner/server group rules, no old mode/ownership/ACL/xattr preservation, path sandbox, adversarial pathname/CAS or crash-durability guarantee. Success returns bytes_written after rename acknowledgement and bounded cleanup. Failures after mutating OPEN polling retain uncertainty. Normal pre-rename errors may remove only an acknowledged exclusively created staging entry; uncertain OPEN/cancel/loss/rename may leave .estus-replace-* siblings. Never cleans destination or any staging path after rename polling, retries/replays, uses weaker rename, truncate/unlink fallback, sudo or shell/SCP.",
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
        description = "Execute an authorized absolute executable via sudo -n -k with the target's configured identity/user/program policy. argv is not a shell script. Requires remote passwordless sudo; no passwords, PTY, environment preservation, or retries. Potentially destructive and not idempotent. Cancellation cannot guarantee remote termination. Permitted executables may themselves grant shell-like authority; sudoers remains authoritative. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
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
        description = "Explicitly clear this session's in-memory mutation quarantine for a logical target after an uncertain remote mutation. Requires host and acknowledge_remote_state_reconciled=true; this is an operator assertion of independent reconciliation, not proof that remote work stopped. Only affects this server session's in-memory gate (estus doctor is a separate process and cannot clear session state). An unknown or non-quarantined target returns a bounded no-change result without probing or connecting.",
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
        let cleared = match self.state.admission.clear_quarantine(&request.host) {
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
        if let Some(args) = &request.arguments
            && let Some(serde_json::Value::String(host)) = args.get("host")
            && self
                .state
                .input_schemas
                .get(request.name.as_ref())
                .is_some_and(|route| {
                    route
                        .validator
                        .is_valid(&serde_json::Value::Object(args.clone()))
                })
        {
            let check = match self.state.tools.get_by_name(request.name.as_ref()) {
                Some(crate::config::ToolKey::Builtin(id)) => self
                    .state
                    .config
                    .check_builtin_params(host, request.name.as_ref(), id, args),
                Some(crate::config::ToolKey::Binding(id)) => {
                    self.state.config.check_binding_params(host, id, args)
                }
                None => Ok(()),
            };
            if let Err(error) = check {
                let budget = ReplyBudget::new(&context.id)?;
                let metadata = Metadata {
                    request_id: &context.id,
                    tool: request.name.as_ref(),
                    host: self.state.admission.contains(host).then_some(host.as_str()),
                    identity_role: IdentityRole::Ordinary,
                    sudo_mode: None,
                    user: None,
                    program: None,
                    binding_revision: None,
                    executor: None,
                };
                metadata.reject(Instant::now(), &error);
                return budget
                    .result(ToolReply::<serde_json::Value>::failure(error))
                    .map(Into::into);
            }
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
