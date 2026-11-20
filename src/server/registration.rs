use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use rmcp::{
    handler::server::{
        router::tool::{IntoToolRoute, ToolRoute, ToolRouter},
        tool::{ToolCallContext, schema_for_type},
    },
    model::{JsonObject, Tool, ToolAnnotations},
};

use crate::{
    config::{Config, ConfigError, ToolCatalog, ToolEntry, ToolId, ToolKey},
    reply::ControllerReply,
};

use super::{Estus, schemas::automation_output_schema};

pub(super) struct RouteSchema {
    pub(super) schema: serde_json::Value,
    pub(super) validator: jsonschema::Validator,
}

pub(super) struct Registration {
    pub(super) router: ToolRouter<Estus>,
    pub(super) tools: ToolCatalog,
    pub(super) sudo_name: Cow<'static, str>,
    pub(super) input_schemas: BTreeMap<String, RouteSchema>,
}

pub(super) fn register(config: &Config) -> Result<Registration, ConfigError> {
    for (id, binding) in config.bindings().entries() {
        if config.binding_enabled(id) && binding.activated_execution().is_none() {
            if binding.is_automation() {
                return Err(ConfigError::new(
                    "automation",
                    "Enabled module bindings require successful startup activation",
                ));
            }
            if binding.is_payload() {
                return Err(ConfigError::new(
                    "native_payload",
                    "Enabled payloads require successful startup activation",
                ));
            }
            return Err(ConfigError::new(
                "tools",
                "Enabled binding is not activated",
            ));
        }
    }
    // This is the explicit publication inventory. Each entry binds native
    // SDK metadata and its callable handler to a target-policy identity.
    let mut routes: [(ToolId, ToolRoute<Estus>); 15] = [
        (
            ToolId::Targets,
            (Estus::observe_targets_tool_attr(), Estus::observe_targets).into_tool_route(),
        ),
        (
            ToolId::ReadOutput,
            (Estus::inspect_output_tool_attr(), Estus::inspect_output).into_tool_route(),
        ),
        (
            ToolId::Exec,
            (Estus::exec_command_tool_attr(), Estus::exec_command).into_tool_route(),
        ),
        (
            ToolId::Run,
            (Estus::exec_argv_tool_attr(), Estus::exec_argv).into_tool_route(),
        ),
        (
            ToolId::ReadFile,
            (Estus::inspect_file_tool_attr(), Estus::inspect_file).into_tool_route(),
        ),
        (
            ToolId::WriteFile,
            (
                Estus::change_file_write_tool_attr(),
                Estus::change_file_write,
            )
                .into_tool_route(),
        ),
        (
            ToolId::Mkdir,
            (Estus::change_mkdir_tool_attr(), Estus::change_mkdir).into_tool_route(),
        ),
        (
            ToolId::Rename,
            (Estus::change_rename_tool_attr(), Estus::change_rename).into_tool_route(),
        ),
        (
            ToolId::RemoveFile,
            (
                Estus::change_file_remove_tool_attr(),
                Estus::change_file_remove,
            )
                .into_tool_route(),
        ),
        (
            ToolId::RemoveDirectory,
            (
                Estus::change_directory_remove_tool_attr(),
                Estus::change_directory_remove,
            )
                .into_tool_route(),
        ),
        (
            ToolId::ReplaceFile,
            (
                Estus::change_file_replace_tool_attr(),
                Estus::change_file_replace,
            )
                .into_tool_route(),
        ),
        (
            ToolId::Stat,
            (Estus::observe_stat_tool_attr(), Estus::observe_stat).into_tool_route(),
        ),
        (
            ToolId::ListDirectory,
            (
                Estus::inspect_directory_tool_attr(),
                Estus::inspect_directory,
            )
                .into_tool_route(),
        ),
        (
            ToolId::Sudo,
            (Estus::exec_sudo_tool_attr(), Estus::exec_sudo).into_tool_route(),
        ),
        (
            ToolId::ClearTargetQuarantine,
            (
                Estus::change_target_quarantine_clear_tool_attr(),
                Estus::change_target_quarantine_clear,
            )
                .into_tool_route(),
        ),
    ];
    for (id, route) in &mut routes {
        let tier = crate::config::risk_tier_for_builtin(*id);
        let meta = route
            .attr
            .meta
            .get_or_insert_with(rmcp::model::MetaObject::default);
        meta.insert("risk_tier".into(), serde_json::json!(tier));
        if *id == ToolId::Targets {
            continue;
        }
        // SDK schemas are shared; only this server's copy gets its resolved
        // immutable limits. Null optional values remain valid schema values.
        let schema = Arc::make_mut(&mut route.attr.input_schema);
        let properties = schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("builtin request schemas have object properties");
        for (name, maximum) in [
            ("timeout_secs", config.limits().max_timeout_secs),
            ("max_bytes", config.limits().max_file_bytes),
        ] {
            if let Some(property) = properties
                .get_mut(name)
                .and_then(serde_json::Value::as_object_mut)
            {
                property.insert("maximum".into(), maximum.into());
            }
        }
        if matches!(*id, ToolId::ReplaceFile | ToolId::Rename) {
            properties
                .get_mut("overwrite")
                .and_then(serde_json::Value::as_object_mut)
                .expect("overwrite requires explicit overwrite consent")
                .insert("const".into(), true.into());
        }
        if *id == ToolId::ClearTargetQuarantine {
            properties
                .get_mut("acknowledge_remote_state_reconciled")
                .and_then(serde_json::Value::as_object_mut)
                .expect("change_target_quarantine_clear requires explicit reconciliation consent")
                .insert("const".into(), true.into());
        }
    }
    let command_output_schema = routes
        .iter()
        .find(|(id, _)| *id == ToolId::Exec)
        .and_then(|(_, route)| route.attr.output_schema.as_ref())
        .expect("command registration has its output contract")
        .clone();
    let controller_output_schema = config
        .bindings()
        .entries()
        .any(|(_, binding)| binding.is_controller())
        .then(schema_for_type::<ControllerReply>);
    let summary_output_schema = automation_output_schema(None);
    let binding_routes = config.bindings().entries().map(|(id, binding)| {
        let tier = crate::config::risk_tier_for_binding(binding);
        let read_only = binding.read_only() && !matches!(tier, crate::config::RiskTier::Preview);
        let annotations = ToolAnnotations::new()
            .read_only(read_only)
            .destructive(!read_only)
            .idempotent(false);
        let local = binding.is_controller();
        let description = binding.description.clone();
        let meta = JsonObject::from_iter([
            ("risk_tier".into(), serde_json::json!(tier)),
            ("revision".into(), serde_json::json!(binding.revision)),
            ("result".into(), serde_json::json!(binding.result_kind())),
            ("effects".into(), serde_json::json!(binding.effects())),
            (
                "executor".into(),
                serde_json::json!(binding.executor_kind()),
            ),
            ("authority".into(), binding.public_authority()),
            (
                "execution_location".into(),
                serde_json::json!(binding.execution_location()),
            ),
            (
                "trusted_controller_code".into(),
                serde_json::json!(binding.trusted_controller_code()),
            ),
            (
                "restriction_boundary".into(),
                binding.restriction_boundary(),
            ),
        ]);
        let output_schema = if binding.is_automation() || binding.is_payload() {
            binding.projection().map_or_else(
                || Arc::clone(&summary_output_schema),
                |plan| automation_output_schema(Some(plan)),
            )
        } else if local {
            Arc::clone(
                controller_output_schema
                    .as_ref()
                    .expect("controller registration has its result schema"),
            )
        } else {
            Arc::clone(&command_output_schema)
        };
        let metadata = Tool::new(
            binding.name.clone(),
            description,
            Arc::clone(&binding.input_schema),
        )
        .with_raw_output_schema(output_schema)
        .with_annotations(annotations)
        .with_meta(rmcp::model::MetaObject(meta));
        let activated = binding.activated_execution();
        let route = ToolRoute::new_dyn(metadata, move |context: ToolCallContext<'_, Estus>| {
            let activated = activated.clone();
            Box::pin(async move {
                let Some(activated) = activated else {
                    return Err(rmcp::ErrorData::invalid_params(
                        "Tool binding is not activated",
                        None,
                    ));
                };
                context
                    .service
                    .binding(
                        id,
                        activated,
                        context.arguments.unwrap_or_default(),
                        context.request_context,
                    )
                    .await
                    .map(Into::into)
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
    let mut input_schemas = BTreeMap::new();
    for (id, route) in routes {
        if tools.contains(id) {
            let schema = serde_json::Value::Object((*route.attr.input_schema).clone());
            let validator = jsonschema::validator_for(&schema).map_err(|_| {
                ConfigError::new("tools", "Registered tool input schema cannot be compiled")
            })?;
            input_schemas.insert(
                route.attr.name.to_string(),
                RouteSchema { schema, validator },
            );
            tool_router.add_route(route);
        }
    }
    Ok(Registration {
        router: tool_router,
        tools,
        sudo_name,
        input_schemas,
    })
}
