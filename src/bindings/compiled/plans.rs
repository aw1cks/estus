use std::{
    borrow::Cow,
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    command::Invocation,
    config::{ConfigError, Limits},
    reply::{ControllerError, ToolError},
};

use super::{
    AnsibleSource, Authority, AutomationRequest, BindingId, BindingRequest, Bindings,
    CompiledBinding, ControllerActivation, ControllerRequest, Execution, Input, ScriptSource, Slot,
    bound, invalid,
};
use super::super::raw::RawInterpreter;

pub(crate) fn controller_root(root: Option<&str>) -> Result<Arc<Path>, ConfigError> {
    let root = root.ok_or_else(|| invalid("Active controller tools require workspace_root"))?;
    let root =
        fs::canonicalize(root).map_err(|_| invalid("Controller workspace is unavailable"))?;
    let metadata =
        fs::metadata(&root).map_err(|_| invalid("Controller workspace is unavailable"))?;
    if root.as_os_str().as_bytes().len() > 1024
        || !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "Controller workspace must be an owned private directory",
        ));
    }
    Ok(Arc::from(root))
}

pub(crate) struct PreparedBinding<'a> {
    pub(crate) invocation: Invocation<'a>,
    pub(crate) script: Option<&'a ScriptSource>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
}

pub(crate) struct AutomationTransport<'a> {
    pub authority: crate::config::ResolvedAutomation<'a>,
    pub scratch_bytes: u64,
    pub scratch_files: usize,
    pub started: std::time::Instant,
}

pub(super) struct AutomationPlan {
    reviewed: ReviewedContent,
    binding: crate::contracts::module_schema::CapabilityBinding,
    runtime: Value,
    controller: Arc<ControllerPlan>,
}

impl std::fmt::Debug for AutomationPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AutomationPlan { reviewed: <private> }")
    }
}

enum ReviewedContent {
    Module {
        reviewed: crate::contracts::schema_import::ReviewedModule,
        source: String,
    },
    Role {
        reviewed: crate::contracts::role_import::ReviewedRole,
        role_path: Option<PathBuf>,
    },
    Playbook {
        reviewed: crate::contracts::playbook_import::ReviewedPlaybook,
        project_root: PathBuf,
    },
}

impl ReviewedContent {
    fn contract(&self) -> &Value {
        match self {
            Self::Module { reviewed, .. } => &reviewed.contract,
            Self::Role { reviewed, .. } => &reviewed.contract,
            Self::Playbook { reviewed, .. } => &reviewed.contract,
        }
    }

    fn binding(&self) -> Option<&Value> {
        match self {
            Self::Module { reviewed, .. } => reviewed.binding.as_ref(),
            Self::Role { reviewed, .. } => reviewed.binding.as_ref(),
            Self::Playbook { reviewed, .. } => reviewed.binding.as_ref(),
        }
    }

    fn expected(&self) -> ExpectedContent<'_> {
        match self {
            Self::Module { reviewed, source } => ExpectedContent::Module(ModuleContent {
                identity: &reviewed.runtime,
                collection: &reviewed.collection,
                content_sha256: &reviewed.content_sha256,
                source,
                module: &reviewed.module,
            }),
            Self::Role {
                reviewed,
                role_path,
            } => ExpectedContent::Role(RoleContent {
                identity: &reviewed.runtime,
                collection: &reviewed.collection,
                content_sha256: &reviewed.content_sha256,
                role: &reviewed.role,
                entry_point: &reviewed.entry_point,
                role_path: role_path.as_deref(),
                bundle_root: reviewed.bundle_root.as_deref(),
            }),
            Self::Playbook {
                reviewed,
                project_root,
            } => ExpectedContent::Playbook(PlaybookContent {
                identity: &reviewed.runtime,
                content_sha256: &reviewed.content_sha256,
                playbook: &reviewed.playbook,
                project_root,
            }),
        }
    }

    fn mode(&self) -> crate::automation::protocol::ExecutionMode {
        match self {
            Self::Module { .. } => crate::automation::protocol::ExecutionMode::Module,
            Self::Role { .. } => crate::automation::protocol::ExecutionMode::Role,
            Self::Playbook { .. } => crate::automation::protocol::ExecutionMode::Playbook,
        }
    }
}

struct BoundedJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "payload limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct ModuleContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    collection: &'a Option<crate::automation::RuntimeCollection>,
    content_sha256: &'a str,
    source: &'a str,
    module: &'a str,
}

#[derive(Serialize)]
struct RoleContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    collection: &'a Option<crate::automation::RuntimeCollection>,
    content_sha256: &'a str,
    role: &'a str,
    entry_point: &'a str,
    role_path: Option<&'a Path>,
    bundle_root: Option<&'a Path>,
}

#[derive(Serialize)]
struct PlaybookContent<'a> {
    identity: &'a crate::automation::RuntimeIdentity,
    content_sha256: &'a str,
    playbook: &'a str,
    project_root: &'a Path,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ExpectedContent<'a> {
    Module(ModuleContent<'a>),
    Role(RoleContent<'a>),
    Playbook(PlaybookContent<'a>),
}

#[derive(Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum AgentReference<'a> {
    Inherit,
    Disabled,
    Fixed { socket: &'a Path },
}

#[derive(Serialize)]
struct AutomationSpec<'a> {
    schema: u32,
    invocation_id: &'a str,
    runtime: &'a Value,
    expected: ExpectedContent<'a>,
    destination: &'a str,
    target_python: &'a str,
    ssh_config: Option<&'a Path>,
    ssh_executable: &'a Path,
    r#become: Option<&'a crate::config::AutomationBecome>,
    agent: AgentReference<'a>,
    arguments: &'a Value,
    no_log: bool,
    projection: Option<&'a crate::contracts::projection::Plan>,
    timeout_secs: f64,
    scratch_bytes: u64,
    scratch_files: usize,
}

#[derive(Debug)]
pub(crate) struct ControllerPlan {
    pub(crate) source: Cow<'static, str>,
    pub(crate) interpreter: String,
    pub(crate) interpreter_argv: Vec<String>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) workspace_root: Arc<Path>,
}

pub(crate) struct PreparedController {
    pub(crate) plan: Arc<ControllerPlan>,
    pub(crate) input_json: Vec<u8>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
    pub(crate) supervision: crate::controller::ControllerSupervision,
}

impl ControllerActivation<'_> {
    fn root(&mut self) -> Result<Arc<Path>, ConfigError> {
        match &self.canonical_root {
            Some(root) => Ok(Arc::clone(root)),
            None => {
                let root = controller_root(self.workspace_root)?;
                self.canonical_root = Some(Arc::clone(&root));
                Ok(root)
            }
        }
    }
}

impl ControllerActivation<'_> {
    pub(super) fn prepare(
        &mut self,
        enabled: bool,
        source: ScriptSource,
        interpreter: RawInterpreter,
        environment: BTreeMap<String, String>,
        cwd: Option<String>,
    ) -> Result<Option<Arc<ControllerPlan>>, ConfigError> {
        let plan = if enabled && self.permitted {
            let root = self.root()?;
            let metadata = fs::metadata(&interpreter.program)
                .map_err(|_| invalid("Controller runtime is unavailable"))?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o111 == 0
                || cwd.as_ref().is_some_and(|path| !Path::new(path).is_dir())
            {
                return Err(invalid("Controller runtime or cwd is unavailable"));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                .open(&source.path)
                .map_err(|_| invalid("Controller source is unavailable"))?;
            if !file
                .metadata()
                .map_err(|_| invalid("Controller source is unavailable"))?
                .is_file()
            {
                return Err(invalid("Controller source must be a regular file"));
            }
            let mut bytes = Vec::new();
            file.take(source.max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid("Controller source is unavailable"))?;
            let source = crate::filesystem::data::verify_script(
                bytes,
                true,
                &source.content_sha256,
                source.max_bytes,
            )
            .map_err(|_| invalid("Controller source verification failed"))?;
            Some(Arc::new(ControllerPlan {
                source: Cow::Owned(source),
                interpreter: interpreter.program,
                interpreter_argv: interpreter.argv,
                cwd: cwd.map(PathBuf::from),
                environment,
                workspace_root: root,
            }))
        } else {
            None
        };
        Ok(plan)
    }
}

impl Bindings {
    pub(crate) async fn activate_automation(
        &mut self,
        id: BindingId,
        runtime: Option<PathBuf>,
        root: Arc<Path>,
        agent_socket: Option<std::ffi::OsString>,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<(), ConfigError> {
        if self.get(id).is_some_and(|binding| binding.is_generic()) {
            return self.activate_generic(id, runtime, root, agent_socket, ct).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let check_interrupted = || {
            if ct.is_cancelled() {
                Err(invalid("cancelled").with_cause("cancelled", "activation"))
            } else if tokio::time::Instant::now() >= deadline {
                Err(invalid("timeout").with_cause("timeout", "activation"))
            } else {
                Ok(())
            }
        };
        check_interrupted()?;
        let binding = self
            .entries
            .get_mut(id.0)
            .ok_or_else(|| invalid("Unknown automation binding"))?;
        let Execution::Ansible {
            snapshot,
            overlay,
            source,
            plan,
            ..
        } = &mut binding.execution
        else {
            return Err(invalid("Not an automation binding"));
        };
        let snapshot = snapshot.clone();
        let overlay = overlay.clone();
        let source = source.clone();
        // Await started blocking work even when cancellation arrives, retaining its ownership.
        let prepared = tokio::task::spawn_blocking(move || {
            let reviewed = match source {
                AnsibleSource::Role { path } => ReviewedContent::Role {
                    reviewed: crate::contracts::role_import::load_reviewed(&snapshot)
                        .map_err(|code| invalid(code).with_cause(code, "role_snapshot"))?,
                    role_path: path,
                },
                AnsibleSource::Module => ReviewedContent::Module {
                    reviewed: crate::contracts::schema_import::load_reviewed(&snapshot)
                        .map_err(|code| invalid(code).with_cause(code, "module_snapshot"))?,
                    source: String::new(),
                },
                AnsibleSource::Playbook { project_root } => ReviewedContent::Playbook {
                    reviewed: crate::contracts::playbook_import::load_reviewed(&snapshot)
                        .map_err(|code| invalid(code).with_cause(code, "playbook_snapshot"))?,
                    project_root,
                },
            };
            if reviewed
                .binding()
                .is_some_and(|expected| expected != &overlay)
            {
                return Err(invalid(
                    "Reviewed binding overlay does not match configuration",
                ));
            }
            let compiled = match &reviewed {
                ReviewedContent::Module { .. } => {
                    crate::contracts::module_schema::compile_binding(reviewed.contract(), &overlay)
                }
                ReviewedContent::Role { .. } => {
                    crate::contracts::role_import::compile_binding(reviewed.contract(), &overlay)
                }
                ReviewedContent::Playbook { .. } => {
                    crate::contracts::playbook_import::compile_binding(reviewed.contract(), &overlay)
                }
            }
            .map_err(|code| invalid(code).with_cause(code, "binding_compilation"))?;
            Ok((reviewed, compiled))
        })
        .await;
        check_interrupted()?;
        let (mut reviewed, compiled) = prepared.map_err(|_| {
            invalid("Automation activation preparation failed")
                .with_cause("activation_preparation_failed", "activation_preparation")
        })??;
        let context = crate::automation::RuntimeContext {
            deadline,
            ct,
            shutdown: ct,
        };
        match &mut reviewed {
            ReviewedContent::Module { reviewed, source } => {
                *source = crate::contracts::schema_import::verify_reviewed(reviewed, runtime.clone(), context)
                    .await
                    .map_err(|code| invalid(code).with_cause(code, "module_verification"))?;
            }
            ReviewedContent::Role {
                reviewed,
                role_path,
            } => {
                crate::contracts::role_import::verify_reviewed(
                    reviewed,
                    role_path.as_deref(),
                    runtime.clone(),
                    context,
                )
                .await
                .map_err(|code| invalid(code).with_cause(code, "role_verification"))?;
            }
            ReviewedContent::Playbook {
                reviewed,
                project_root,
            } => {
                crate::contracts::playbook_import::verify_reviewed(
                    reviewed,
                    project_root,
                    runtime.clone(),
                    context,
                )
                .await
                .map_err(|code| invalid(code).with_cause(code, "playbook_verification"))?;
            }
        }
        check_interrupted()?;
        let selected = tokio::task::spawn_blocking(move || {
            crate::automation::runner_runtime(runtime, root, agent_socket)
                .map_err(|code| invalid(code).with_cause(code, "runtime_selection"))
        })
        .await;
        check_interrupted()?;
        let selected = selected.map_err(|_| {
            invalid("Automation runtime preparation failed")
                .with_cause("runtime_preparation_failed", "runtime_selection")
        })??;
        *plan = Some(Box::new(AutomationPlan {
            reviewed,
            binding: compiled,
            runtime: selected.payload,
            controller: selected.plan,
        }));
        Ok(())
    }
}

impl CompiledBinding {
    pub(crate) fn prepare_automation(
        &self,
        request: &AutomationRequest,
        limits: &Limits,
        transport: AutomationTransport<'_>,
    ) -> Result<crate::automation::execution::PreparedAutomation, ToolError> {
        let AutomationTransport {
            authority,
            scratch_bytes,
            scratch_files,
            started,
        } = transport;
        let Execution::Ansible {
            plan: Some(plan),
            no_log,
            projection,
            ..
        } = &self.execution
        else {
            return Err(ToolError::new(
                "policy_denied",
                "Operation is not authorized",
                false,
            ));
        };
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if !self.targets.contains(&request.host)
            || timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
        {
            return Err(bound("Invalid automation host or timeout"));
        }
        let arguments = plan
            .binding
            .prepare(&request.inputs)
            .map_err(|_| bound("Automation inputs violate the reviewed binding"))?;
        let invocation_id = crate::automation::execution::invocation_id();
        let spec = AutomationSpec {
            schema: 2,
            invocation_id: &invocation_id,
            runtime: &plan.runtime,
            expected: plan.reviewed.expected(),
            destination: &authority.target.destination,
            target_python: &authority.target.python,
            ssh_config: authority.ssh_config,
            ssh_executable: authority.ssh_executable,
            r#become: authority.r#become,
            agent: match authority.agent {
                crate::config::AutomationAgent::Inherit => AgentReference::Inherit,
                crate::config::AutomationAgent::Disabled => AgentReference::Disabled,
                crate::config::AutomationAgent::Fixed(socket) => AgentReference::Fixed { socket },
            },
            arguments: &arguments,
            no_log: *no_log,
            projection: projection.as_deref(),
            timeout_secs: Duration::from_secs(timeout)
                .saturating_sub(started.elapsed())
                .as_secs_f64(),
            scratch_bytes,
            scratch_files,
        };
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: 256 * 1024,
        };
        serde_json::to_writer(&mut writer, &spec)
            .map_err(|_| bound("Automation invocation exceeds byte bound"))?;
        let input_json = writer.bytes;
        Ok(crate::automation::execution::PreparedAutomation {
            controller: PreparedController {
                plan: Arc::clone(&plan.controller),
                input_json,
                duration: Duration::from_secs(timeout),
                max_output_bytes: 65_536,
                supervision: crate::controller::ControllerSupervision::Automation {
                    invocation_id,
                    mode: plan.reviewed.mode(),
                    scratch_bytes,
                    scratch_files,
                },
            },
            host: request.host.clone(),
            projection: projection.clone(),
        })
    }

    pub(super) fn arguments(&self) -> Vec<Cow<'_, str>> {
        let prefix = match &self.execution {
            Execution::NativeArgv { .. }
            | Execution::ControllerScript { .. }
            | Execution::Ansible { .. }
            | Execution::Generic { .. }
            | Execution::Payload { .. } => &[][..],
            Execution::RemoteScript { prefix, .. } => prefix.as_slice(),
        };
        let mut arguments = Vec::with_capacity(prefix.len() + self.argv.len());
        arguments.extend(prefix.iter().map(|v| Cow::Borrowed(v.as_str())));
        arguments
    }

    pub(super) fn invocation<'a>(&'a self, arguments: Vec<Cow<'a, str>>) -> Invocation<'a> {
        match &self.execution {
            Execution::NativeArgv {
                program,
                authority: Authority::Sudo(user),
                ..
            } => Invocation::BoundSudo {
                program,
                arguments,
                user,
            },
            Execution::NativeArgv {
                program,
                cwd,
                authority: Authority::Ordinary,
            }
            | Execution::RemoteScript { program, cwd, .. } => Invocation::BoundArgv {
                program,
                arguments,
                cwd: cwd.as_deref(),
            },
            Execution::ControllerScript { .. }
            | Execution::Ansible { .. }
            | Execution::Generic { .. }
            | Execution::Payload { .. }
            | Execution::NativeArgv {
                authority: Authority::Controller,
                ..
            } => unreachable!("controller bindings never produce remote invocations"),
        }
    }

    pub(crate) fn prepare<'a>(
        &'a self,
        request: &'a BindingRequest,
        limits: &Limits,
    ) -> Result<PreparedBinding<'a>, ToolError> {
        if !self.targets.contains(&request.host) {
            return Err(bound("Host is not a declared tool target"));
        }
        let ceiling = self.timeout_secs.unwrap_or(limits.max_timeout_secs);
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if timeout == 0 || timeout > ceiling || timeout > limits.max_timeout_secs {
            return Err(bound("Timeout exceeds named tool ceiling"));
        }
        if request.values.len() != self.inputs.len() {
            return Err(bound("Invalid named tool inputs"));
        }
        for (input, value) in self.inputs.iter().zip(&request.values) {
            input.validate(value)?;
        }
        let mut arguments = self.arguments();
        // Reused integer slots copy their already formatted bounded representation, never reformat.
        let mut numeric_slots: [Option<usize>; 16] = [None; 16];
        for slot in &self.argv {
            let value = match slot {
                Slot::Fixed(value) => Cow::Borrowed(value.as_str()),
                Slot::Input(index) => match &request.values[*index] {
                    Value::String(value) => Cow::Borrowed(value.as_str()),
                    Value::Bool(value) => Cow::Borrowed(if *value { "true" } else { "false" }),
                    Value::Number(value) => {
                        if let Some(previous) = numeric_slots[*index] {
                            arguments[previous].clone()
                        } else {
                            numeric_slots[*index] = Some(arguments.len());
                            Cow::Owned(value.to_string())
                        }
                    }
                    _ => return Err(bound("Invalid named tool inputs")),
                },
            };
            arguments.push(value);
        }
        let invocation = self.invocation(arguments);
        invocation.encoded_len()?;
        Ok(PreparedBinding {
            invocation,
            script: match &self.execution {
                Execution::RemoteScript { source, .. } => Some(source),
                Execution::NativeArgv { .. } => None,
                Execution::ControllerScript { .. } | Execution::Ansible { .. }
                | Execution::Generic { .. } | Execution::Payload { .. } => {
                    return Err(bound("Controller requires local preparation"));
                }
            },
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }

    pub(crate) fn prepare_controller(
        &self,
        request: &ControllerRequest,
        limits: &Limits,
    ) -> Result<PreparedController, ControllerError> {
        let invalid = || ControllerError::new("invalid_argument", "Invalid controller tool inputs");
        let Execution::ControllerScript { plan: Some(plan) } = &self.execution else {
            return Err(ControllerError::new(
                "policy_denied",
                "Operation is not authorized",
            ));
        };
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
            || timeout > limits.max_timeout_secs
            || request.values.len() != self.inputs.len()
        {
            return Err(invalid());
        }
        for (input, value) in self.inputs.iter().zip(&request.values) {
            input.validate(value).map_err(|_| invalid())?;
        }
        use serde::ser::SerializeMap;
        struct Payload<'a> {
            inputs: &'a [Input],
            values: &'a [Value],
        }
        impl Serialize for Payload<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut map = serializer.serialize_map(Some(self.inputs.len()))?;
                for (input, value) in self.inputs.iter().zip(self.values) {
                    map.serialize_entry(&input.name, value)?;
                }
                map.end()
            }
        }
        let mut writer = BoundedJson {
            bytes: Vec::new(),
            limit: 65_536,
        };
        serde_json::to_writer(
            &mut writer,
            &Payload {
                inputs: &self.inputs,
                values: &request.values,
            },
        )
        .map_err(|_| {
            ControllerError::new("resource_limit", "Controller input exceeds byte bound")
        })?;
        Ok(PreparedController {
            plan: Arc::clone(plan),
            input_json: writer.bytes,
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
            supervision: crate::controller::ControllerSupervision::Script,
        })
    }
}
