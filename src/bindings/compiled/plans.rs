#[cfg(unix)]
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
use std::{
    borrow::Cow,
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Serialize;
use serde_json::Value;

use crate::{
    bundle::BundlePack,
    command::Invocation,
    config::{ConfigError, Limits},
    reply::{ControllerError, ErrorCode, ToolError},
};

use super::super::raw::RawInterpreter;
use super::{
    AnsibleState, Authority, AutomationAuthority, AutomationRequest, BindingId, BindingRequest,
    Bindings, CompiledBinding, ControllerActivation, ControllerRequest, Execution, Input,
    ScriptSource, Slot, bound, invalid,
};

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn controller_root(root: Option<&str>) -> Result<Arc<Path>, ConfigError> {
    #[cfg(windows)]
    {
        let _ = root;
        Err(invalid(
            "Controller script tools are not supported on Windows",
        ))
    }
    #[cfg(unix)]
    {
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
}

pub(crate) struct PreparedBinding<'a> {
    pub(crate) invocation: Invocation<'a>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
}

#[derive(Debug)]
pub(super) struct UnactivatedAutomation {
    pub(super) module: String,
    pub(super) bundle: Option<PathBuf>,
    pub(super) authority: AutomationAuthority,
    pub(super) overlay: Value,
    pub(super) no_log: bool,
    pub(super) check_mode: bool,
    pub(super) diff: bool,
    pub(super) projection: Option<Arc<crate::contracts::projection::Plan>>,
}

#[derive(Debug)]
pub(crate) struct ActivatedAutomation {
    pub(crate) pack: Arc<BundlePack>,
    pub(crate) module: String,
    pub(crate) binding: crate::contracts::module_schema::CapabilityBinding,
    pub(crate) authority: AutomationAuthority,
    pub(crate) overlay: Value,
    pub(crate) no_log: bool,
    pub(crate) check_mode: bool,
    pub(crate) diff: bool,
    pub(crate) projection: Option<Arc<crate::contracts::projection::Plan>>,
}

pub(crate) struct PreparedBundle {
    pub(crate) arguments: Value,
    pub(crate) duration: Duration,
    pub(crate) output_limit: usize,
}

impl AnsibleState {
    pub(super) fn authority(&self) -> &AutomationAuthority {
        match self {
            Self::Unactivated(u) => &u.authority,
            Self::Activated(a) => &a.authority,
        }
    }

    pub(super) fn bundle_override(&self) -> Option<&Path> {
        match self {
            Self::Unactivated(u) => u.bundle.as_deref(),
            Self::Activated(_) => None,
        }
    }

    pub(super) fn projection(&self) -> Option<&Arc<crate::contracts::projection::Plan>> {
        match self {
            Self::Unactivated(u) => u.projection.as_ref(),
            Self::Activated(a) => a.projection.as_ref(),
        }
    }

    #[cfg(test)]
    pub(super) fn overlay(&self) -> &Value {
        match self {
            Self::Unactivated(u) => &u.overlay,
            Self::Activated(a) => &a.overlay,
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

#[cfg_attr(windows, allow(dead_code))]
#[derive(Debug)]
pub(crate) struct ControllerPlan {
    pub(crate) source: Cow<'static, str>,
    pub(crate) interpreter: String,
    pub(crate) interpreter_argv: Vec<String>,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) environment: BTreeMap<String, String>,
    pub(crate) workspace_root: Arc<Path>,
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) struct PreparedController {
    pub(crate) plan: Arc<ControllerPlan>,
    pub(crate) input_json: Vec<u8>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
}

impl ControllerActivation<'_> {
    #[cfg_attr(windows, allow(dead_code))]
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

    pub(super) fn prepare(
        &mut self,
        enabled: bool,
        source: ScriptSource,
        interpreter: RawInterpreter,
        environment: BTreeMap<String, String>,
        cwd: Option<String>,
    ) -> Result<Option<Arc<ControllerPlan>>, ConfigError> {
        #[cfg(windows)]
        {
            let _ = (source, interpreter, environment, cwd);
            if enabled && self.permitted {
                Err(invalid(
                    "Controller script tools are not supported on Windows",
                ))
            } else {
                Ok(None)
            }
        }
        #[cfg(unix)]
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
        #[cfg(unix)]
        Ok(plan)
    }
}

impl Bindings {
    pub(crate) fn activate_automation(
        &mut self,
        id: BindingId,
        pack: Arc<BundlePack>,
    ) -> Result<(), ConfigError> {
        let binding = self
            .entries
            .get_mut(id.0)
            .ok_or_else(|| invalid("Unknown automation binding"))?;
        binding.activate_with_bundle(pack)
    }
}

impl CompiledBinding {
    pub(super) fn activate_with_bundle(
        &mut self,
        pack: Arc<BundlePack>,
    ) -> Result<(), ConfigError> {
        let Execution::Ansible(AnsibleState::Unactivated(unactivated)) = &self.execution else {
            return Err(invalid("Not an unactivated automation binding"));
        };
        if unactivated.check_mode
            && (!crate::server::preview::is_qualified_module(&unactivated.module)
                || !pack.supports_check_mode(&unactivated.module))
        {
            return Err(invalid(
                "check_mode preview is only allowed for qualified modules",
            ));
        }
        let contract = pack
            .contract_for(&unactivated.module)
            .map_err(|code| invalid(code).with_cause(code, "bundle_module"))?;
        crate::contracts::module_schema::validate_setup_overlay(
            &unactivated.module,
            &unactivated.overlay,
        )
        .map_err(|code| invalid(code).with_cause(code, "setup_validation"))?;
        let compiled =
            crate::contracts::module_schema::compile_binding(&contract, &unactivated.overlay)
                .map_err(|code| invalid(code).with_cause(code, "binding_compilation"))?;
        let activated = Arc::new(ActivatedAutomation {
            pack,
            module: unactivated.module.clone(),
            binding: compiled,
            authority: unactivated.authority.clone(),
            overlay: unactivated.overlay.clone(),
            no_log: unactivated.no_log,
            check_mode: unactivated.check_mode,
            diff: unactivated.diff,
            projection: unactivated.projection.clone(),
        });
        self.execution = Execution::Ansible(AnsibleState::Activated(activated));
        Ok(())
    }

    pub(crate) fn prepare_activated_automation(
        &self,
        activated: &ActivatedAutomation,
        request: &AutomationRequest,
        limits: &Limits,
    ) -> Result<PreparedBundle, ToolError> {
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if !self.permits_host(&request.host)
            || timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
            || timeout > limits.max_timeout_secs
        {
            return Err(bound("Invalid automation host or timeout"));
        }
        let arguments = activated
            .binding
            .prepare(&request.inputs)
            .map_err(|_| bound("Automation inputs violate the reviewed binding"))?;
        let output_limit = self
            .max_output_bytes
            .unwrap_or(limits.max_output_bytes)
            .min(16_777_216);
        Ok(PreparedBundle {
            arguments,
            duration: Duration::from_secs(timeout),
            output_limit: usize::try_from(output_limit)
                .map_err(|_| bound("Invalid automation output ceiling"))?,
        })
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
            } => Invocation::BoundArgv {
                program,
                arguments,
                cwd: cwd.as_deref(),
            },
            Execution::ControllerScript(_)
            | Execution::Ansible(_)
            | Execution::Payload(_)
            | Execution::NativeArgv {
                authority: Authority::Controller,
                ..
            } => unreachable!("non-native-argv bindings never produce remote command invocations"),
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
        let mut arguments: Vec<Cow<'_, str>> = Vec::with_capacity(self.argv.len());
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
        if !matches!(self.execution, Execution::NativeArgv { .. }) {
            return Err(bound("Controller requires local preparation"));
        }
        let invocation = self.invocation(arguments);
        invocation.encoded_len()?;
        Ok(PreparedBinding {
            invocation,
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }

    #[cfg(test)]
    pub(crate) fn prepare_controller(
        &self,
        request: &ControllerRequest,
        limits: &Limits,
    ) -> Result<PreparedController, ControllerError> {
        let Execution::ControllerScript(super::ControllerState::Activated(plan)) = &self.execution
        else {
            return Err(ControllerError::new(
                ErrorCode::PolicyDenied,
                "Operation is not authorized",
            ));
        };
        self.prepare_activated_controller(plan, request, limits)
    }

    pub(crate) fn prepare_activated_controller(
        &self,
        plan: &Arc<ControllerPlan>,
        request: &ControllerRequest,
        limits: &Limits,
    ) -> Result<PreparedController, ControllerError> {
        let invalid =
            || ControllerError::new(ErrorCode::InvalidArgument, "Invalid controller tool inputs");
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
            ControllerError::new(
                ErrorCode::ResourceLimit,
                "Controller input exceeds byte bound",
            )
        })?;
        Ok(PreparedController {
            plan: Arc::clone(plan),
            input_json: writer.bytes,
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }
}
