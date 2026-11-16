use super::*;
use crate::automation::generic::{Policy, Request};

impl CompiledBinding {
    pub(super) fn compile_generic(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
    ) -> Result<Self, ConfigError> {
        let RawExecution::AnsibleGeneric { policy } = raw.execution else {
            unreachable!("generic compiler selected")
        };
        let targets = raw.targets.unwrap_or_default();
        if raw.description.is_empty()
            || raw.description.len() > 1024
            || !identifier(&raw.revision)
            || targets.is_empty()
            || targets.len() > 32
            || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
            || targets.iter().any(|t| !target_exists(t))
            || raw.input_schema.is_some()
            || raw.fixed_args.is_some()
            || raw.input_map.is_some()
            || raw.argument_types.is_some()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
            || ![
                Effect::SensitiveRead,
                Effect::RuntimeWrite,
                Effect::PersistentWrite,
                Effect::Availability,
                Effect::Unknown,
            ]
            .iter()
            .all(|effect| raw.effects.contains(effect))
        {
            return Err(invalid(
                "Generic bindings require explicit broad effects, targets and no outer argument contract",
            ));
        }
        let authority = AutomationAuthority::parse(&raw.authority)?;
        let selected=match raw.result {
            RawResult::AnsibleSummary {}=>None,
            RawResult::AnsibleProjection {fields,schema,max_bytes,max_items,max_depth}=>Some(Arc::new(crate::contracts::projection::compile(json!({"fields":fields,"schema":serde_json::to_value(schema).map_err(|_|invalid("Invalid generic projection"))?,"max_bytes":max_bytes,"max_items":max_items,"max_depth":max_depth})).map_err(invalid)?)),
            _=>return Err(invalid("Generic bindings require an Ansible result policy")),
        };
        let policy = Policy::compile(policy, selected)?;
        if policy.target_names().any(|host| !targets.contains(host)) {
            return Err(invalid(
                "Generic target policy must name an approved binding target",
            ));
        }
        let timeout_secs = raw.limits.as_ref().and_then(|l| l.timeout_secs);
        if timeout_secs.is_some_and(|t| t == 0 || t > limits.max_timeout_secs)
            || raw
                .limits
                .as_ref()
                .and_then(|l| l.max_output_bytes)
                .is_some()
        {
            return Err(invalid(
                "Generic outer limits support timeout only; use policy output ceilings",
            ));
        }
        let schema = json!({"type":"object","additionalProperties":false,"required":["operation","host"],"properties":{
            "operation":{"type":"string","enum":["call","list","describe","receipts"]},"host":{"type":"string","enum":targets},
            "module":{"type":"string","minLength":5,"maxLength":256},"arguments":{"type":"object"},
            "timeout_secs":{"type":"integer","minimum":1,"maximum":timeout_secs.unwrap_or(limits.max_timeout_secs)},
            "after":{"type":"string","maxLength":256},"limit":{"type":"integer","minimum":1,"maximum":64},"receipt":{"type":"string","maxLength":32}}});
        Ok(Self {
            name,
            description: format!(
                "{} Broad/controller-code-capable Ansible authority; not a sandbox. Ansible validates unrestricted arguments; changed is backend-reported; no replay.",
                raw.description
            ),
            revision: raw.revision,
            targets,
            input_schema: Arc::new(
                schema
                    .as_object()
                    .cloned()
                    .ok_or_else(|| invalid("Invalid generic request schema"))?,
            ),
            enabled,
            effects: raw.effects,
            inputs: Vec::new(),
            execution: Execution::Generic {
                policy: Box::new(policy),
                authority,
            },
            argv: Vec::new(),
            timeout_secs,
            max_output_bytes: None,
        })
    }
    pub(crate) fn generic_policy(&self) -> Option<&Policy> {
        match &self.execution {
            Execution::Generic { policy, .. } => Some(policy),
            _ => None,
        }
    }
    pub(super) fn parse_generic(&self, arguments: JsonObject) -> Result<Request, ErrorData> {
        // Structural shape belongs to protocol errors; authorization remains dispatch policy.
        if serde_json::to_vec(&arguments).map_or(true, |b| b.len() > 256 * 1024) {
            return Err(shape());
        }
        let request: Request =
            serde_json::from_value(Value::Object(arguments)).map_err(|_| shape())?;
        if request.host().is_empty() || request.host().len() > 128 {
            return Err(shape());
        }
        Ok(request)
    }
    pub(crate) fn prepare_generic(
        &self,
        request: &Request,
        limits: &Limits,
        transport: AutomationTransport<'_>,
    ) -> Result<crate::automation::execution::PreparedAutomation, ToolError> {
        let policy = self
            .generic_policy()
            .ok_or_else(|| bound("Not a generic binding"))?;
        let Request::Call {
            host, timeout_secs, ..
        } = request
        else {
            return Err(bound("Not a generic call"));
        };
        if !self.targets.contains(host) {
            return Err(ToolError::new(
                "policy_denied",
                "Generic target is not authorized",
                false,
            ));
        }
        let ceiling = self
            .timeout_secs
            .unwrap_or(limits.max_timeout_secs)
            .min(limits.max_timeout_secs)
            .min(policy.ceilings(host).timeout_secs);
        let timeout = timeout_secs.unwrap_or(limits.operation_timeout_secs.min(ceiling));
        if timeout == 0 || timeout > ceiling {
            return Err(bound("Generic timeout exceeds policy ceiling"));
        }
        policy.prepare(request, transport, timeout)
    }
}
impl Bindings {
    pub(crate) async fn activate_generic(
        &mut self,
        id: BindingId,
        runtime: Option<PathBuf>,
        workspace_root: Arc<Path>,
        agent_socket: Option<std::ffi::OsString>,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<(), ConfigError> {
        let binding = self
            .entries
            .get_mut(id.0)
            .ok_or_else(|| invalid("Unknown generic binding"))?;
        let Execution::Generic { policy, .. } = &mut binding.execution else {
            return Err(invalid("Not a generic binding"));
        };
        let runner =
            crate::automation::runner_runtime(runtime.clone(), workspace_root, agent_socket)
                .map_err(|code| invalid(code).with_cause(code, "generic_runtime"))?;
        policy
            .activate(
                runtime,
                runner,
                crate::automation::RuntimeContext {
                    deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                    ct,
                    shutdown: ct,
                },
            )
            .await
            .map_err(|code| invalid(code).with_cause(code, "generic_activation"))
    }
}
