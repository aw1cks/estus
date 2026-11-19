use super::*;
use std::time::Duration;

use crate::native_payload::PayloadPlan;

#[derive(Debug)]
pub(super) struct UnactivatedPayload {
    authority: AutomationAuthority,
    overlay: Value,
    projection: Arc<crate::contracts::projection::Plan>,
    snapshot: PathBuf,
    source: PathBuf,
    no_log: bool,
}

#[derive(Debug)]
pub(crate) struct ActivatedPayload {
    pub(crate) plan: PayloadPlan,
    pub(crate) authority: AutomationAuthority,
    pub(crate) overlay: Value,
    pub(crate) projection: Arc<crate::contracts::projection::Plan>,
}

impl PayloadState {
    pub(super) fn authority(&self) -> &AutomationAuthority {
        match self {
            Self::Unactivated(u) => &u.authority,
            Self::Activated(a) => &a.authority,
        }
    }

    pub(super) fn projection(&self) -> &Arc<crate::contracts::projection::Plan> {
        match self {
            Self::Unactivated(u) => &u.projection,
            Self::Activated(a) => &a.projection,
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

pub(crate) struct PreparedPayload {
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
        workstation: bool,
    ) -> Result<Self, ConfigError> {
        validate_risk_prefix_effects(&name, &raw.effects)?;
        let RawExecution::NativePayload {
            snapshot,
            source,
            no_log,
        } = raw.execution
        else {
            return Err(invalid("Not a payload binding"));
        };
        let authority = AutomationAuthority::parse(&raw.authority)?;
        let dynamic_targets = raw.targets.is_none()
            && workstation
            && matches!(authority, AutomationAuthority::Ordinary);
        let targets = raw.targets.unwrap_or_default();
        if raw.argument_types.is_some()
            || raw.description.is_empty()
            || raw.description.len() > 1024
            || !identifier(&raw.revision)
            || !absolute(&snapshot)
            || !absolute(&source)
            || (!dynamic_targets
                && (targets.is_empty()
                    || targets.len() > 32
                    || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
                    || targets.iter().any(|target| !target_exists(target))))
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
        let mut schema = serde_json::to_value(
            raw.input_schema
                .ok_or_else(|| invalid("Payload input schema is required"))?,
        )
        .map_err(|_| invalid("Invalid payload schema"))?;
        let mut fixed = raw
            .fixed_args
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| invalid("Invalid payload fixed arguments"))?
            .unwrap_or_else(|| json!({}));
        apply_site_constraints(&mut schema, &mut fixed, raw.constraints.as_ref())
            .map_err(invalid)?;
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
        let host_schema = if dynamic_targets {
            json!({"type": "string", "minLength": 1, "maxLength": 256})
        } else {
            json!({"type": "string", "enum": targets})
        };
        let published = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["host", "inputs"],
            "properties": {
                "host": host_schema,
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
            dynamic_targets,
            input_schema: Arc::new(published),
            enabled,
            effects: raw.effects,
            inputs: Vec::new(),
            execution: Execution::Payload(PayloadState::Unactivated(UnactivatedPayload {
                authority,
                overlay,
                projection,
                snapshot: snapshot.into(),
                source: source.into(),
                no_log,
            })),
            argv: Vec::new(),
            timeout_secs,
            max_output_bytes,
        })
    }

    pub(super) fn activate_bundled_payload(
        &mut self,
        source: Vec<u8>,
        manifest_bytes: &[u8],
    ) -> Result<(), ConfigError> {
        let revision = self.revision.clone();
        let Execution::Payload(PayloadState::Unactivated(unactivated)) = &self.execution else {
            return Err(invalid("Not an unactivated payload binding"));
        };
        let authority = serde_json::to_value(&unactivated.authority)
            .map_err(|_| invalid("Invalid payload authority"))?
            .as_str()
            .ok_or_else(|| invalid("Invalid payload authority"))?
            .to_owned();
        let result = json!({
            "kind": "capability_projection",
            "fields": unactivated.projection.fields,
            "schema": unactivated.projection.schema,
            "max_bytes": unactivated.projection.max_bytes,
            "max_items": unactivated.projection.max_items,
            "max_depth": unactivated.projection.max_depth,
        });
        let loaded = crate::native_payload::PayloadPlan::load_from_bytes(
            source,
            manifest_bytes,
            &crate::native_payload::PayloadApprovalInline {
                overlay: &unactivated.overlay,
                result: &result,
                authority: &authority,
                revision: &revision,
                no_log: unactivated.no_log,
                projection: Some(Arc::clone(&unactivated.projection)),
            },
        )?;
        let activated = Arc::new(ActivatedPayload {
            plan: loaded,
            authority: unactivated.authority.clone(),
            overlay: unactivated.overlay.clone(),
            projection: Arc::clone(&unactivated.projection),
        });
        self.execution = Execution::Payload(PayloadState::Activated(activated));
        Ok(())
    }

    pub(crate) fn payload_activated(&self) -> bool {
        matches!(
            self.execution,
            Execution::Payload(PayloadState::Activated(_))
        )
    }

    pub(crate) fn prepare_activated_payload(
        &self,
        activated: &ActivatedPayload,
        request: &AutomationRequest,
        limits: &Limits,
    ) -> Result<PreparedPayload, ToolError> {
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if !self.permits_host(&request.host)
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
            argv: activated.plan.arguments(&request.inputs)?,
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
        let Execution::Payload(PayloadState::Unactivated(unactivated)) = &binding.execution else {
            return Err(invalid("Not an unactivated payload binding"));
        };
        let snapshot = unactivated.snapshot.clone();
        let source = unactivated.source.clone();
        let overlay = unactivated.overlay.clone();
        let projection = Arc::clone(&unactivated.projection);
        let revision = binding.revision.clone();
        let no_log = unactivated.no_log;
        let authority = serde_json::to_value(&unactivated.authority)
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
            crate::native_payload::PayloadPlan::load(crate::native_payload::PayloadApproval {
                snapshot: &snapshot,
                source: &source,
                overlay: &overlay,
                result: &result,
                authority: &authority,
                revision: &revision,
                no_log,
                projection: Some(projection),
            })
        })
        .await
        .map_err(|_| invalid("Payload approval loading failed"))??;
        if ct.is_cancelled() {
            return Err(invalid("Payload activation cancelled"));
        }
        let Execution::Payload(PayloadState::Unactivated(unactivated)) =
            &self.entries[id.0].execution
        else {
            return Err(invalid("Not an unactivated payload binding"));
        };
        let activated = Arc::new(ActivatedPayload {
            plan: loaded,
            authority: unactivated.authority.clone(),
            overlay: unactivated.overlay.clone(),
            projection: Arc::clone(&unactivated.projection),
        });
        self.entries[id.0].execution = Execution::Payload(PayloadState::Activated(activated));
        Ok(())
    }
}
