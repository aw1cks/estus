use super::*;
use std::time::Duration;

use crate::native_payload::PayloadPlan;

pub(crate) struct PreparedPayload<'a> {
    pub(crate) plan: &'a PayloadPlan,
    pub(crate) argv: Vec<String>,
    pub(crate) duration: Duration,
    pub(crate) output_limit: usize,
}

impl CompiledBinding {
    pub(super) fn compile_payload(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
    ) -> Result<Self, ConfigError> {
        let RawExecution::NativePayload {
            snapshot,
            source,
            no_log,
        } = raw.execution
        else {
            return Err(invalid("Not a payload binding"));
        };
        let targets = raw.targets.unwrap_or_default();
        let authority = AutomationAuthority::parse(&raw.authority)?;
        if raw.argument_types.is_some()
            || raw.description.is_empty()
            || raw.description.len() > 1024
            || !identifier(&raw.revision)
            || !absolute(&snapshot)
            || !absolute(&source)
            || targets.is_empty()
            || targets.len() > 32
            || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
            || targets.iter().any(|target| !target_exists(target))
            || raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid("Invalid native payload definition"));
        }
        let RawResult::CapabilityProjection {
            fields,
            schema,
            max_bytes,
            max_items,
            max_depth,
        } = raw.result
        else {
            return Err(invalid("Native payload requires capability projection"));
        };
        let projection = Arc::new(
            crate::contracts::projection::compile(json!({
                "fields": fields,
                "schema": schema,
                "max_bytes": max_bytes,
                "max_items": max_items,
                "max_depth": max_depth,
            }))
            .map_err(invalid)?,
        );
        let schema = serde_json::to_value(
            raw.input_schema
                .ok_or_else(|| invalid("Payload input schema is required"))?,
        )
        .map_err(|_| invalid("Invalid payload schema"))?;
        let fixed = raw
            .fixed_args
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| invalid("Invalid payload fixed arguments"))?
            .unwrap_or_else(|| json!({}));
        let overlay = json!({
            "input_schema": schema,
            "fixed_args": fixed,
            "input_map": raw.input_map.unwrap_or_default(),
        });
        crate::contracts::module_schema::validate_overlay(&overlay).map_err(invalid)?;
        let timeout_secs = raw.limits.as_ref().and_then(|limits| limits.timeout_secs);
        let max_output_bytes = raw
            .limits
            .as_ref()
            .and_then(|limits| limits.max_output_bytes);
        if timeout_secs.is_some_and(|timeout| timeout == 0 || timeout > limits.max_timeout_secs)
            || max_output_bytes.is_some_and(|bytes| {
                bytes == 0 || bytes > limits.max_output_bytes || bytes > 16_777_216
            })
        {
            return Err(invalid("Invalid payload limits"));
        }
        let published = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["host", "inputs"],
            "properties": {
                "host": {"type": "string", "enum": targets},
                "inputs": overlay["input_schema"],
                "timeout_secs": {
                    "type": "integer", "minimum": 1,
                    "maximum": timeout_secs.unwrap_or(limits.max_timeout_secs),
                },
            },
        })
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("Invalid payload metadata"))?;
        if !schema_fits(&published) || !schema_fits(&overlay) {
            return Err(invalid("Payload metadata exceeds bounds"));
        }
        Ok(Self {
            name,
            description: raw.description,
            revision: raw.revision,
            targets,
            input_schema: Arc::new(published),
            enabled,
            effects: raw.effects,
            inputs: Vec::new(),
            execution: Execution::Payload {
                plan: None,
                authority,
                overlay,
                projection,
                snapshot: snapshot.into(),
                source: source.into(),
                no_log,
            },
            argv: Vec::new(),
            timeout_secs,
            max_output_bytes,
        })
    }

    pub(crate) fn payload_plan(&self) -> Option<&PayloadPlan> {
        match &self.execution {
            Execution::Payload { plan, .. } => plan.as_deref(),
            _ => None,
        }
    }

    pub(super) fn parse_payload(
        &self,
        mut arguments: JsonObject,
    ) -> Result<BindingCall, ErrorData> {
        let Execution::Payload { overlay, .. } = &self.execution else {
            return Err(shape());
        };
        let host = match arguments.remove("host") {
            Some(Value::String(host)) => host,
            _ => return Err(shape()),
        };
        let timeout_secs = arguments
            .remove("timeout_secs")
            .map(|value| unsigned_integer(&value).ok_or_else(shape))
            .transpose()?;
        let inputs = arguments.remove("inputs").ok_or_else(shape)?;
        if !arguments.is_empty() {
            return Err(shape());
        }
        crate::contracts::module_schema::validate_input_shape(&overlay["input_schema"], &inputs)
            .map_err(|_| shape())?;
        Ok(BindingCall::Payload(AutomationRequest {
            host,
            timeout_secs,
            inputs,
        }))
    }

    pub(crate) fn prepare_payload(
        &self,
        request: &AutomationRequest,
        limits: &Limits,
    ) -> Result<PreparedPayload<'_>, ToolError> {
        let plan = self.payload_plan().ok_or_else(|| {
            ToolError::new("policy_denied", "Native payload is not activated", false)
        })?;
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if !self.targets.contains(&request.host)
            || timeout == 0
            || timeout > self.timeout_secs.unwrap_or(limits.max_timeout_secs)
            || timeout > limits.max_timeout_secs
        {
            return Err(bound("Invalid payload host or timeout"));
        }
        let output_limit = self
            .max_output_bytes
            .unwrap_or(limits.max_output_bytes)
            .min(16_777_216);
        Ok(PreparedPayload {
            plan,
            argv: plan.arguments(&request.inputs)?,
            duration: Duration::from_secs(timeout),
            output_limit: usize::try_from(output_limit)
                .map_err(|_| bound("Invalid payload output ceiling"))?,
        })
    }
}

impl Bindings {
    pub(crate) async fn activate_payload(
        &mut self,
        id: BindingId,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<(), ConfigError> {
        if ct.is_cancelled() {
            return Err(invalid("Payload activation cancelled"));
        }
        let binding = self
            .entries
            .get(id.0)
            .ok_or_else(|| invalid("Unknown payload binding"))?;
        let Execution::Payload {
            snapshot,
            source,
            overlay,
            projection,
            authority,
            no_log,
            ..
        } = &binding.execution
        else {
            return Err(invalid("Not a payload binding"));
        };
        let snapshot = snapshot.clone();
        let source = source.clone();
        let overlay = overlay.clone();
        let projection = Arc::clone(projection);
        let revision = binding.revision.clone();
        let no_log = *no_log;
        let authority = serde_json::to_value(authority)
            .map_err(|_| invalid("Invalid payload authority"))?
            .as_str()
            .ok_or_else(|| invalid("Invalid payload authority"))?
            .to_owned();
        let result = json!({
            "kind": "capability_projection",
            "fields": projection.fields,
            "schema": projection.schema,
            "max_bytes": projection.max_bytes,
            "max_items": projection.max_items,
            "max_depth": projection.max_depth,
        });
        // Await blocking ownership even if activation cancellation arrives meanwhile.
        let loaded = tokio::task::spawn_blocking(move || {
            PayloadPlan::load(
                &snapshot,
                &source,
                &overlay,
                &result,
                &authority,
                &revision,
                no_log,
                Some(projection),
            )
        })
        .await
        .map_err(|_| invalid("Payload approval loading failed"))??;
        if ct.is_cancelled() {
            return Err(invalid("Payload activation cancelled"));
        }
        let Execution::Payload { plan, .. } = &mut self.entries[id.0].execution else {
            return Err(invalid("Not a payload binding"));
        };
        *plan = Some(Box::new(loaded));
        Ok(())
    }
}
