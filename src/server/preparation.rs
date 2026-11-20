use std::time::{Duration, Instant};

use rmcp::model::RequestId;

use crate::{
    audit::Metadata,
    bindings::{BindingId, BindingRequest},
    command::{ExecRequest, Invocation, RunRequest, SudoRequest},
    config::{Config, IdentityRole, ResolvedTarget, SudoMode, ToolId, ToolKey},
    reply::ToolError,
};

use super::State;

pub(super) enum Operation {
    Exec(ExecRequest),
    Run(RunRequest),
    Sudo(SudoRequest),
    Binding {
        id: BindingId,
        request: BindingRequest,
    },
}

pub(super) struct PreparedCommand<'a> {
    pub(super) target: ResolvedTarget<'a>,
    pub(super) duration: Duration,
    pub(super) invocation: Invocation<'a>,
    pub(super) stdin: Option<&'a str>,
    pub(super) max_output_bytes: u64,
}

impl Operation {
    pub(super) fn retain_output(&self) -> bool {
        match self {
            Self::Exec(request) => request.retain_output,
            Self::Run(request) => request.retain_output,
            Self::Sudo(request) => request.retain_output,
            Self::Binding { request, .. } => request.retain_output,
        }
    }

    pub(super) fn admission_policy(
        &self,
        config: &Config,
    ) -> (super::admission::AdmissionMode, &'static str, String) {
        use super::admission::AdmissionMode;
        match self {
            Self::Exec(_) => (
                AdmissionMode::MultiplexedExec,
                "native_shell",
                "ordinary".into(),
            ),
            Self::Run(_) => (
                AdmissionMode::MultiplexedExec,
                "native_argv",
                "ordinary".into(),
            ),
            Self::Sudo(req) => (
                AdmissionMode::MultiplexedExec,
                "native_sudo",
                format!("sudo:{}", req.user),
            ),
            Self::Binding { id, .. } => {
                let binding = config
                    .bindings()
                    .get(*id)
                    .expect("registered binding exists");
                let mode = if binding.is_shared_read() {
                    AdmissionMode::SharedRead
                } else if binding.is_probe_only() {
                    AdmissionMode::ExclusiveProbe
                } else {
                    AdmissionMode::ExclusiveWrite
                };
                let authority = binding
                    .sudo()
                    .map_or_else(|| "ordinary".to_owned(), |(user, _)| format!("sudo:{user}"));
                (mode, "native_argv", authority)
            }
        }
    }

    // Safe before validation, authorization, admission or cancellation checks.
    // Caller-supplied sudo identifiers are added only from a prepared invocation.
    pub(super) fn metadata<'a>(
        &'a self,
        state: &'a State,
        request_id: &'a RequestId,
    ) -> Metadata<'a> {
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
                None,
                None,
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
                    binding.sudo().map(|(user, _)| user),
                    None,
                    Some(binding.revision.as_str()),
                    Some(binding.executor_kind()),
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
            identity_role: if (matches!(self, Self::Sudo(_)) || user.is_some())
                && mode != Some(SudoMode::SameAccount)
            {
                IdentityRole::Elevated
            } else {
                IdentityRole::Ordinary
            },
        }
    }

    pub(super) fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> Result<PreparedCommand<'a>, ToolError> {
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

pub(super) fn file_metadata<'a>(
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

pub(super) fn request_deadline(
    started: Instant,
    duration: Duration,
) -> Result<tokio::time::Instant, ToolError> {
    tokio::time::Instant::from_std(started)
        .checked_add(duration)
        .ok_or_else(|| {
            ToolError::invalid_argument("timeout_secs exceeds the supported clock range", false)
        })
}

impl State {
    pub(super) async fn acquire_permit(
        &self,
        semaphore: &std::sync::Arc<tokio::sync::Semaphore>,
        deadline: tokio::time::Instant,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ToolError> {
        if ct.is_cancelled() || self.shutdown.is_cancelled() {
            return Err(ToolError::cancelled(
                "Request cancelled before dispatch",
                false,
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ToolError::timeout(
                "Operation deadline expired waiting for execution slot",
                false,
            ));
        }
        tokio::select! {
            biased;
            () = ct.cancelled() => Err(ToolError::cancelled(
                "Request cancelled before dispatch",
                false,
            )),
            () = self.shutdown.cancelled() => Err(ToolError::cancelled(
                "Server shutting down before dispatch",
                false,
            )),
            () = tokio::time::sleep_until(deadline) => Err(ToolError::timeout(
                "Operation deadline expired waiting for execution slot",
                false,
            )),
            permit = std::sync::Arc::clone(semaphore).acquire_owned() => permit.map_err(|_| {
                ToolError::cancelled("Server shutting down before dispatch", false)
            }),
        }
    }

    pub(super) fn output_metadata<'a>(&'a self, request_id: &'a RequestId) -> Metadata<'a> {
        Metadata {
            request_id,
            tool: self.tool_name(ToolId::ReadOutput),
            host: None,
            identity_role: IdentityRole::Controller,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: None,
            executor: None,
        }
    }

    pub(super) fn tool_name(&self, id: ToolId) -> &str {
        self.tools
            .name(ToolKey::Builtin(id))
            .expect("executing tool is registered")
    }

    pub(super) fn binding_name(&self, id: BindingId) -> &str {
        self.tools
            .name(ToolKey::Binding(id))
            .expect("executing binding is registered")
    }

    pub(super) fn controller_metadata<'a>(
        &'a self,
        id: BindingId,
        request_id: &'a RequestId,
    ) -> Metadata<'a> {
        let binding = self
            .config
            .bindings()
            .get(id)
            .expect("registered controller binding exists");
        Metadata {
            request_id,
            tool: self.binding_name(id),
            host: None,
            identity_role: IdentityRole::Controller,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some(binding.executor_kind()),
        }
    }
}
