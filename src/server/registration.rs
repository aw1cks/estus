use std::{borrow::Cow, sync::Arc};

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

pub(super) struct Registration {
    pub(super) router: ToolRouter<Estus>,
    pub(super) tools: ToolCatalog,
    pub(super) sudo_name: Cow<'static, str>,
}

pub(super) fn register(config: &Config) -> Result<Registration, ConfigError> {
    if config.bindings().entries().any(|(id, binding)| {
        binding.is_automation() && config.binding_enabled(id) && !binding.automation_activated()
    }) {
        return Err(ConfigError::new(
            "automation",
            "Enabled module bindings require successful startup activation",
        ));
    }
    // This is the explicit publication inventory. Each entry binds native
    // SDK metadata and its callable handler to a target-policy identity.
    let mut routes: [(ToolId, ToolRoute<Estus>); 14] = [
        (
            ToolId::Targets,
            (Estus::ssh_targets_tool_attr(), Estus::ssh_targets).into_tool_route(),
        ),
        (
            ToolId::ReadOutput,
            (Estus::ssh_read_output_tool_attr(), Estus::ssh_read_output).into_tool_route(),
        ),
        (
            ToolId::Exec,
            (Estus::ssh_exec_tool_attr(), Estus::ssh_exec).into_tool_route(),
        ),
        (
            ToolId::Run,
            (Estus::ssh_run_tool_attr(), Estus::ssh_run).into_tool_route(),
        ),
        (
            ToolId::ReadFile,
            (Estus::ssh_read_file_tool_attr(), Estus::ssh_read_file).into_tool_route(),
        ),
        (
            ToolId::WriteFile,
            (Estus::ssh_write_file_tool_attr(), Estus::ssh_write_file).into_tool_route(),
        ),
        (
            ToolId::Mkdir,
            (Estus::ssh_mkdir_tool_attr(), Estus::ssh_mkdir).into_tool_route(),
        ),
        (
            ToolId::Rename,
            (Estus::ssh_rename_tool_attr(), Estus::ssh_rename).into_tool_route(),
        ),
        (
            ToolId::RemoveFile,
            (Estus::ssh_remove_file_tool_attr(), Estus::ssh_remove_file).into_tool_route(),
        ),
        (
            ToolId::RemoveDirectory,
            (
                Estus::ssh_remove_directory_tool_attr(),
                Estus::ssh_remove_directory,
            )
                .into_tool_route(),
        ),
        (
            ToolId::ReplaceFile,
            (Estus::ssh_replace_file_tool_attr(), Estus::ssh_replace_file).into_tool_route(),
        ),
        (
            ToolId::Stat,
            (Estus::ssh_stat_tool_attr(), Estus::ssh_stat).into_tool_route(),
        ),
        (
            ToolId::ListDirectory,
            (
                Estus::ssh_list_directory_tool_attr(),
                Estus::ssh_list_directory,
            )
                .into_tool_route(),
        ),
        (
            ToolId::Sudo,
            (Estus::ssh_sudo_tool_attr(), Estus::ssh_sudo).into_tool_route(),
        ),
    ];
    for (id, route) in &mut routes {
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
        if *id == ToolId::ReplaceFile {
            properties
                .get_mut("overwrite")
                .and_then(serde_json::Value::as_object_mut)
                .expect("replacement requires explicit overwrite consent")
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
        let annotations = ToolAnnotations::new()
            .read_only(binding.read_only())
            .destructive(!binding.read_only())
            .idempotent(false);
        let local = binding.is_controller();
        let description = if local {
            format!("{} Trusted operator controller code executes under the server's OS account and can access that account's credentials; this is not SSH authority or a sandbox. Typed inputs use a private JSON file, never caller argv/source. Cleanup reports anchored-group signalling and direct-child reaping, not rollback or escaped-descendant containment. Operations are never replayed.", binding.description)
        } else if binding.is_automation() {
            format!("{} Trusted Ansible/controller code executes under the server's OS account and may access its credentials; remote work uses the configured automation authority. no_log and projections restrict disclosure, not code authority. Process cleanup is not a sandbox or authorization boundary. Operations are never replayed.", binding.description)
        } else {
            format!("{} Fixed remote execution with declared authority on declared targets; typed values fill whole arguments, not templates. Effects are operator-reviewed, not a sandbox or remote authorization. Cancellation may leave remote work running; operations are never replayed.", binding.description)
        };
        let meta = JsonObject::from_iter([
            ("revision".into(), serde_json::json!(binding.revision)),
            ("result".into(), serde_json::json!(binding.result_kind())),
            ("effects".into(), serde_json::json!(binding.effects())),
            ("executor".into(), serde_json::json!(binding.executor_kind())),
            ("authority".into(), binding.public_authority()),
            ("execution_location".into(), serde_json::json!(binding.execution_location())),
            ("trusted_controller_code".into(), serde_json::json!(binding.trusted_controller_code())),
            ("restriction_boundary".into(), binding.restriction_boundary()),
        ]);
        let output_schema = if binding.is_automation() {
            binding.projection().map_or_else(
                || Arc::clone(&summary_output_schema),
                |plan| automation_output_schema(Some(plan)),
            )
        } else if local {
            Arc::clone(controller_output_schema.as_ref().expect("controller registration has its result schema"))
        } else {
            Arc::clone(&command_output_schema)
        };
        let metadata = Tool::new(
            binding.name.clone(), description, Arc::clone(&binding.input_schema),
        )
        .with_raw_output_schema(output_schema)
        .with_annotations(annotations)
        .with_meta(rmcp::model::MetaObject(meta));
        let route = ToolRoute::new_dyn(metadata, move |context: ToolCallContext<'_, Estus>| {
            Box::pin(async move {
                context.service.binding(
                    id,
                    context.arguments.unwrap_or_default(),
                    context.request_context,
                ).await.map(Into::into)
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
    for (id, route) in routes {
        if tools.contains(id) {
            tool_router.add_route(route);
        }
    }
    Ok(Registration { router: tool_router, tools, sudo_name })
}
