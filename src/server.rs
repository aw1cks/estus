use std::{
    borrow::Cow,
    sync::Arc,
    time::{Duration, Instant},
};

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{
        common::FromContextPart,
        router::tool::{IntoToolRoute, ToolRoute, ToolRouter},
        tool::{ToolCallContext, schema_for_type},
    },
    model::{
        CallToolResult, JsonObject, RequestId, ServerCapabilities, ServerConfig, Tool,
        ToolAnnotations,
    },
    service::RequestContext,
    tool, tool_handler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    audit::{Audit, Metadata},
    bindings::{self, BindingCall, BindingId, BindingRequest, ControllerRequest},
    command::{ExecRequest, Invocation, RunRequest, SudoRequest},
    config::{
        Config, ConfigError, IdentityRole, ResolvedTarget, SudoMode, TargetDiscovery, ToolCatalog,
        ToolEntry, ToolId, ToolKey,
    },
    exec::{self, RunContext},
    filedata::{
        ListData, ListRequest, ReadData, ReadRequest, StatRequest, WriteData, WriteRequest,
    },
    filemeta::StatData,
    files::{self, FileContext},
    reply::{CommandData, ControllerError, ControllerReply, Termination, ToolError, ToolReply},
    ssh::{MasterHealth, Pool},
    wire::ReplyBudget,
};

#[derive(Clone)]
pub(crate) struct SshMcp {
    tool_router: ToolRouter<Self>,
    state: Arc<State>,
}

struct State {
    config: Config,
    tools: ToolCatalog,
    sudo_name: Cow<'static, str>,
    pool: Arc<Pool>,
    shutdown: CancellationToken,
    operations: Arc<Semaphore>,
    tasks: TaskTracker,
    local_tasks: TaskTracker,
    automation: Arc<Semaphore>,
    automation_targets: std::collections::BTreeMap<String, Arc<Semaphore>>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}

// RMCP 3.9 converts its Parameters extractor's errors into tool results. This
// extractor keeps argument-shape failures at the protocol boundary and never
// reflects malformed input values or field names in diagnostics.
struct Arguments<T>(T);

impl<T: DeserializeOwned> FromContextPart<ToolCallContext<'_, SshMcp>> for Arguments<T> {
    fn from_context_part(context: &mut ToolCallContext<'_, SshMcp>) -> Result<Self, ErrorData> {
        serde_json::from_value(serde_json::Value::Object(
            context.arguments.take().unwrap_or_default(),
        ))
        .map(Self)
        .map_err(|_| {
            let error = ToolError::new(
                "invalid_argument",
                "Arguments do not match the tool input schema",
                false,
            );
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
            ErrorData::invalid_params(error.message, None)
        })
    }
}

// Keep the envelope and execution evidence generated from the actual reply types.
// Only the operator-reviewed payload schema is binding-specific.
fn automation_output_schema(plan: Option<&crate::projection::Plan>) -> Arc<JsonObject> {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .for_serialize()
        .with(|settings| settings.inline_subschemas = true)
        .into_generator()
        .into_root_schema_for::<ToolReply<crate::reply::AutomationData>>();
    let mut schema = serde_json::to_value(schema).expect("generated reply schema serializes");
    fn specialize(node: &mut serde_json::Value, plan: Option<&crate::projection::Plan>) {
        match node {
            serde_json::Value::Object(object) => {
                if let Some(properties) = object
                    .get_mut("properties")
                    .and_then(serde_json::Value::as_object_mut)
                    && let Some(projection) = properties.get_mut("projection")
                {
                    if let Some(plan) = plan {
                        // Generate the non-optional enum itself: an enabled
                        // projection always has one of its five states.
                        let mut generator = schemars::generate::SchemaSettings::draft2020_12()
                            .for_serialize()
                            .with(|settings| settings.inline_subschemas = true)
                            .into_generator();
                        *projection = serde_json::to_value(
                            crate::reply::ModuleProjection::json_schema(&mut generator),
                        )
                        .expect("generated projection schema serializes");
                        fn payload(node: &mut serde_json::Value, schema: &serde_json::Value) {
                            match node {
                                serde_json::Value::Object(object) => {
                                    if let Some(value) = object
                                        .get_mut("properties")
                                        .and_then(serde_json::Value::as_object_mut)
                                        .and_then(|p| p.get_mut("value"))
                                    {
                                        *value = schema.clone();
                                    } else {
                                        for child in object.values_mut() {
                                            payload(child, schema);
                                        }
                                    }
                                }
                                serde_json::Value::Array(array) => {
                                    for child in array {
                                        payload(child, schema);
                                    }
                                }
                                _ => (),
                            }
                        }
                        payload(projection, &plan.schema);
                    } else {
                        properties.remove("projection");
                    }
                    if plan.is_some() {
                        let required = object
                            .entry("required")
                            .or_insert_with(|| serde_json::json!([]))
                            .as_array_mut()
                            .expect("generated required is an array");
                        if !required.iter().any(|name| name == "projection") {
                            required.push(serde_json::json!("projection"));
                        }
                    }
                    return;
                }
                for child in object.values_mut() {
                    specialize(child, plan);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    specialize(child, plan);
                }
            }
            _ => (),
        }
    }
    specialize(&mut schema, plan);
    Arc::new(
        schema
            .as_object()
            .expect("reply schema is an object")
            .clone(),
    )
}

impl SshMcp {
    pub(crate) fn new(config: Config) -> Result<Self, ConfigError> {
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
        let routes: [(ToolId, ToolRoute<Self>); 8] = [
            (
                ToolId::Targets,
                (Self::ssh_targets_tool_attr(), Self::ssh_targets).into_tool_route(),
            ),
            (
                ToolId::Exec,
                (Self::ssh_exec_tool_attr(), Self::ssh_exec).into_tool_route(),
            ),
            (
                ToolId::Run,
                (Self::ssh_run_tool_attr(), Self::ssh_run).into_tool_route(),
            ),
            (
                ToolId::ReadFile,
                (Self::ssh_read_file_tool_attr(), Self::ssh_read_file).into_tool_route(),
            ),
            (
                ToolId::WriteFile,
                (Self::ssh_write_file_tool_attr(), Self::ssh_write_file).into_tool_route(),
            ),
            (
                ToolId::Stat,
                (Self::ssh_stat_tool_attr(), Self::ssh_stat).into_tool_route(),
            ),
            (
                ToolId::ListDirectory,
                (
                    Self::ssh_list_directory_tool_attr(),
                    Self::ssh_list_directory,
                )
                    .into_tool_route(),
            ),
            (
                ToolId::Sudo,
                (Self::ssh_sudo_tool_attr(), Self::ssh_sudo).into_tool_route(),
            ),
        ];
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
                format!("{} Explicit controller execution under the server's OS account, not SSH authority or a sandbox. Typed inputs use a private JSON file, never caller argv/source. Cleanup reports anchored-group signalling and direct-child reaping, not rollback or escaped-descendant containment. Operations are never replayed.", binding.description)
            } else {
                format!("{} Fixed remote execution with declared authority on declared targets; typed values fill whole arguments, not templates. Effects are operator-reviewed, not a sandbox or remote authorization. Cancellation may leave remote work running; operations are never replayed.", binding.description)
            };
            let mut meta = JsonObject::from_iter([
                ("revision".into(), serde_json::json!(binding.revision)),
                ("result".into(), serde_json::json!(binding.result_kind())),
                ("effects".into(), serde_json::json!(binding.effects())),
                ("executor".into(), serde_json::json!(binding.executor_kind())),
                ("authority".into(), if binding.is_automation() {
                    serde_json::json!("automation")
                } else if local {
                    serde_json::json!("controller")
                } else {
                    binding.sudo().map_or_else(
                        || serde_json::json!("ordinary"),
                        |(user, _)| serde_json::json!({"sudo": user}),
                    )
                }),
            ]);
            let output_schema = if binding.is_automation() {
                binding.projection().map_or_else(
                    || Arc::clone(&summary_output_schema),
                    |plan| automation_output_schema(Some(plan)),
                )
            } else if local {
                meta.insert("execution_location".into(), serde_json::json!("controller"));
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
            let route = ToolRoute::new_dyn(metadata, move |context: ToolCallContext<'_, Self>| {
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
        let shutdown = CancellationToken::new();
        let pool = Pool::new(
            config.ssh_config().map(std::path::Path::to_path_buf),
            Duration::from_secs(config.limits().connect_timeout_secs),
            shutdown.clone(),
        );
        Ok(Self {
            tool_router,
            state: Arc::new(State {
                automation: Arc::new(Semaphore::new(config.automation_concurrency())),
                automation_targets: config
                    .automation_hosts()
                    .map(|host| (host.clone(), Arc::new(Semaphore::new(1))))
                    .collect(),
                config,
                tools,
                sudo_name,
                pool,
                shutdown,
                operations: Arc::new(Semaphore::new(16)),
                tasks: TaskTracker::new(),
                local_tasks: TaskTracker::new(),
            }),
        })
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.state.shutdown.clone()
    }

    pub(crate) async fn shutdown(&self) {
        self.state.shutdown.cancel();
        self.state.local_tasks.close();
        self.state.tasks.close();
        // Local owners must reap before runtime teardown; native cleanup keeps
        // its existing independent bound. An unkillable OS child can delay shutdown.
        tokio::join!(self.state.local_tasks.wait(), async {
            let _ = tokio::time::timeout(Duration::from_secs(3), self.state.tasks.wait()).await;
            self.state.pool.shutdown().await;
        },);
    }

    async fn command(
        &self,
        request: Operation,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let metadata = request.metadata(&self.state, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.command_capture_limit() {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject(
                    started,
                    &ToolError::new("invalid_argument", "Insufficient response budget", false),
                );
                return Err(error);
            }
        };
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<CommandData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        // Keep cleanup/audit alive even if RMCP suppresses the cancelled reply and
        // drops this handler's JoinHandle. Admission above bounds these tasks.
        let task = self.state.tasks.spawn(async move {
            let reply = state
                .command(request, context.id, context.ct, started, capture_limit)
                .await;
            (permit, reply)
        });
        match task.await {
            Ok((_permit, reply)) => budget.command_result(reply),
            Err(_) => budget.result(ToolReply::<CommandData>::failure(ToolError::new(
                "io_error",
                "Command task could not complete; remote state is unknown",
                true,
            ))),
        }
    }

    async fn binding(
        &self,
        id: BindingId,
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
        match binding.parse_request(arguments) {
            Ok(BindingCall::Remote(request)) => {
                self.command(Operation::Binding { id, request }, context)
                    .await
            }
            Ok(BindingCall::Controller(request)) => {
                self.controller_binding(id, request, context).await
            }
            Ok(BindingCall::Automation(request)) => {
                self.automation_binding(id, request, context).await
            }
            Err(error) => {
                if binding.is_controller() {
                    self.state
                        .controller_metadata(id, &context.id)
                        .reject_controller(
                            Instant::now(),
                            &ControllerError::new(
                                "invalid_argument",
                                "Invalid controller tool argument shape",
                            ),
                        );
                    return Err(error);
                }
                Metadata {
                    request_id: &context.id,
                    tool: self.state.binding_name(id),
                    host: None,
                    identity_role: if binding.sudo().is_some()
                        && mode != Some(SudoMode::SameAccount)
                    {
                        IdentityRole::Elevated
                    } else {
                        IdentityRole::Ordinary
                    },
                    sudo_mode: mode,
                    user: binding.sudo().map(|(user, _)| user),
                    program: None,
                    binding_revision: Some(&binding.revision),
                    executor: Some(binding.executor_kind()),
                }
                .reject(
                    Instant::now(),
                    &ToolError::new(
                        "invalid_argument",
                        "Invalid named tool argument shape",
                        false,
                    ),
                );
                Err(error)
            }
        }
    }

    async fn automation_binding(
        &self,
        id: BindingId,
        request: bindings::AutomationRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        use crate::reply::AutomationData;
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let binding = self
            .state
            .config
            .bindings()
            .get(id)
            .expect("registered module binding");
        budget.automation_reserve(
            &request.host,
            binding.projection().map(|plan| plan.max_bytes),
        )?;
        let metadata = Metadata {
            request_id: &context.id,
            tool: self.state.binding_name(id),
            host: binding
                .targets
                .iter()
                .find(|host| **host == request.host)
                .map(String::as_str),
            identity_role: IdentityRole::Ordinary,
            sudo_mode: None,
            user: None,
            program: None,
            binding_revision: Some(&binding.revision),
            executor: Some(binding.executor_kind()),
        };
        let reject = |code, message| {
            let error = ToolError::new(code, message, false);
            metadata.reject(started, &error);
            budget.result(ToolReply::<AutomationData>::failure(error))
        };
        let Ok(operation) = self.state.operations.clone().try_acquire_owned() else {
            return reject("resource_limit", "Tool operation limit reached");
        };
        let Ok(runtime) = self.state.automation.clone().try_acquire_owned() else {
            return reject("resource_limit", "Automation operation limit reached");
        };
        // Authorize before selecting a logical target's fixed semaphore.
        if let Err(error) = self.state.config.automation_target(id, &request.host) {
            metadata.reject(started, &error);
            return budget.result(ToolReply::<AutomationData>::failure(error));
        }
        let Some(target) = self.state.automation_targets.get(&request.host) else {
            return reject("policy_denied", "Operation is not authorized");
        };
        let Ok(target) = target.clone().try_acquire_owned() else {
            return reject(
                "resource_limit",
                "Automation target operation limit reached",
            );
        };
        let state = self.state.clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            let _permits = (operation, runtime, target);
            let binding = state
                .config
                .bindings()
                .get(id)
                .expect("registered module binding");
            let metadata = Metadata {
                request_id: &context.id,
                tool: state.binding_name(id),
                host: Some(&request.host),
                identity_role: IdentityRole::Ordinary,
                sudo_mode: None,
                user: None,
                program: None,
                binding_revision: Some(&binding.revision),
                executor: Some(binding.executor_kind()),
            };
            let prepared = (|| {
                if context.ct.is_cancelled() || state.shutdown.is_cancelled() {
                    return Err(ToolError::new(
                        "cancelled",
                        "Request cancelled before dispatch",
                        false,
                    ));
                }
                let target = state.config.automation_target(id, &request.host)?;
                let (bytes, files) = state.config.automation_scratch();
                let prepared = binding.prepare_automation(
                    &request,
                    state.config.limits(),
                    bindings::AutomationTransport {
                        target,
                        ssh_config: state.config.ssh_config(),
                        scratch_bytes: bytes,
                        scratch_files: files,
                        ssh_executable: state.config.automation_ssh().ok_or_else(|| {
                            ToolError::new("policy_denied", "Operation is not authorized", false)
                        })?,
                        started,
                    },
                )?;
                let deadline = request_deadline(started, prepared.controller.duration)?;
                Ok((prepared, deadline))
            })();
            let (prepared, deadline) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    metadata.reject(started, &error);
                    let _ = sender.send(ToolReply::<AutomationData>::failure(error));
                    return;
                }
            };
            let audit = Audit::start(metadata, started);
            let run = crate::automation_exec::run(
                prepared,
                crate::controller::ControllerContext {
                    deadline,
                    ct: &context.ct,
                    shutdown: &state.shutdown,
                    started,
                    capture_limit: 65_536,
                },
            )
            .await;
            audit.finish_automation(&run.reply);
            let _ = sender.send(run.reply);
            if let Some(pending) = run.pending {
                pending.finish().await;
            }
        });
        let reply = receiver.await.unwrap_or_else(|_| {
            ToolReply::failure(ToolError::new(
                "io_error",
                "Automation operation could not complete; remote state is unknown",
                true,
            ))
        });
        budget.result(reply)
    }

    async fn controller_binding(
        &self,
        id: BindingId,
        request: ControllerRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let metadata = self.state.controller_metadata(id, &context.id);
        let budget = ReplyBudget::new(&context.id)?;
        let capture_limit = match budget.controller_capture_limit() {
            Ok(limit) => limit,
            Err(error) => {
                metadata.reject_controller(
                    started,
                    &ControllerError::new(
                        "invalid_argument",
                        "Insufficient controller response budget",
                    ),
                );
                return Err(error);
            }
        };
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ControllerError::new("resource_limit", "Tool operation limit reached");
                metadata.reject_controller(started, &error);
                return budget.controller_result(ControllerReply::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.state.local_tasks.spawn(async move {
            // Receiver cancellation cannot drop admission, files, or child ownership.
            let _permit = permit;
            let metadata = state.controller_metadata(id, &context.id);
            let prepared = (|| {
                if state.shutdown.is_cancelled() || context.ct.is_cancelled() {
                    return Err(ControllerError::new(
                        "cancelled",
                        "Controller request cancelled before dispatch",
                    ));
                }
                if !state.config.controller_enabled(id) {
                    return Err(ControllerError::new(
                        "policy_denied",
                        "Controller operation is not authorized",
                    ));
                }
                let binding = state
                    .config
                    .bindings()
                    .get(id)
                    .expect("registered controller binding exists");
                let prepared = binding.prepare_controller(&request, state.config.limits())?;
                let deadline = request_deadline(started, prepared.duration)
                    .map_err(|error| ControllerError::new(error.code, error.message))?;
                Ok((prepared, deadline))
            })();
            let (prepared, deadline) = match prepared {
                Ok(value) => value,
                Err(error) => {
                    metadata.reject_controller(started, &error);
                    let _ = sender.send(ControllerReply::failure(error));
                    return;
                }
            };
            let audit = Audit::start(metadata, started);
            let run = crate::controller::run(
                prepared,
                crate::controller::ControllerContext {
                    deadline,
                    ct: &context.ct,
                    shutdown: &state.shutdown,
                    started,
                    capture_limit,
                },
            )
            .await;
            audit.finish_controller(&run.reply);
            let _ = sender.send(run.reply);
            if let Some(pending) = run.pending {
                pending.finish().await;
            }
        });
        match receiver.await {
            Ok(reply) => budget.controller_result(reply),
            Err(_) => budget.controller_result(ControllerReply::failure(ControllerError::new(
                "io_error",
                "Controller operation could not complete; effects may be incomplete",
            ))),
        }
    }

    async fn read_file(
        &self,
        request: ReadRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::ReadFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ReadData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .read_file(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn stat_file(
        &self,
        request: StatRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::Stat, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<StatData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .stat_file(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn list_directory(
        &self,
        request: ListRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(
            &request.host,
            ToolId::ListDirectory,
            &self.state,
            &context.id,
        );
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<ListData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .list_directory(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn write_file(
        &self,
        request: WriteRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let started = Instant::now();
        let budget = ReplyBudget::new(&context.id)?;
        let metadata = file_metadata(&request.host, ToolId::WriteFile, &self.state, &context.id);
        let permit = match Arc::clone(&self.state.operations).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<WriteData>::failure(error));
            }
        };
        let state = Arc::clone(&self.state);
        self.file_result(budget, permit, async move {
            state
                .write_file(request, context.id, context.ct, started, budget)
                .await
        })
        .await
    }

    async fn file_result<T: Serialize + Send + 'static>(
        &self,
        budget: ReplyBudget,
        permit: tokio::sync::OwnedSemaphorePermit,
        operation: impl Future<Output = ToolReply<T>> + Send + 'static,
    ) -> Result<CallToolResult, ErrorData> {
        // A dropped RMCP request never drops the bounded SFTP cleanup owner.
        let task = self
            .state
            .tasks
            .spawn(async move { (permit, operation.await) });
        match task.await {
            Ok((_permit, reply)) => budget.result(reply),
            Err(_) => budget.result(ToolReply::<T>::failure(ToolError::new(
                "io_error",
                "File operation task could not complete; remote state is unknown",
                true,
            ))),
        }
    }
}

impl SshMcp {
    #[tool(
        name = "ssh_targets",
        description = "Discover configured logical targets, public advisory descriptions/labels, startup-permitted operations and resolved policy limits without connecting or probing. Permitted operations do not imply remote support or authorization; observed capabilities remain unknown. Limits are ceilings, further constrained by per-request escaping, request IDs and the response-wire budget. Open mode returns no target inventory and never enumerates SSH configuration. Backend aliases, credential/config paths and authentication state are not returned.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<Empty>(),
        output_schema = schema_for_type::<ToolReply<TargetDiscovery<'static>>>()
    )]
    fn ssh_targets(
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
        let _permit = match self.state.operations.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                let error = ToolError::new("resource_limit", "Tool operation limit reached", false);
                metadata.reject(started, &error);
                return budget.result(ToolReply::<TargetDiscovery<'_>>::failure(error));
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = ToolReply::success(self.state.config.targets(&self.state.tools));
        audit.finish(None, None);
        budget.result(reply)
    }

    #[tool(
        name = "ssh_exec",
        description = "Execute a stateless noninteractive remote shell script (/bin/sh by default; Bash is opt-in). Potentially destructive; not idempotent. Timeout/cancellation closes only this channel: remote work may continue, and operations are never replayed. Ordinary shell authority can bypass same-account sudo approval separation. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<ExecRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_exec(
        &self,
        Arguments(request): Arguments<ExecRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Exec(request), context).await
    }

    #[tool(
        name = "ssh_run",
        description = "Execute an explicit argv on the ordinary SSH identity, with optional absolute cwd and bounded stdin. Argument boundaries are preserved through POSIX command --, but the remote login shell still participates: this is not remote execve or a sandbox. Remote-PATH names may resolve shell builtins; use an absolute path to pin the executable. Use ssh_exec for shell syntax. Potentially destructive and non-idempotent; ordinary authority can bypass same-account sudo approval separation. Timeout/cancellation closes only this channel, remote work may continue, and operations are never replayed. Output may be truncated within the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<RunRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_run(
        &self,
        Arguments(request): Arguments<RunRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Run(request), context).await
    }

    #[tool(
        name = "ssh_read_file",
        description = "Read a bounded range through an independent ordinary-identity SFTP channel. Paths are literal: no shell, tilde, environment or wildcard expansion, and no path sandbox. UTF-8 is strict, including split codepoints; use base64 for arbitrary bytes. content_sha256 is lowercase SHA-256 of returned raw bytes, excluding lookahead and before encoding. Optional expected_content_sha256 must be 64 hex characters; mismatch returns checksum_mismatch without content. This verifies only that range, not a whole-file snapshot. Reads follow server symlink semantics. No sudo, shell/SCP fallback, remote hash helper, installation or automatic retries/replay. Timeout/cancellation disconnects only this channel; remote completion is not guaranteed. The requested lossless range must fit both the configured file cap and fixed 16 MiB reply limit.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ReadRequest>(),
        output_schema = schema_for_type::<ToolReply<ReadData>>()
    )]
    async fn ssh_read_file(
        &self,
        Arguments(request): Arguments<ReadRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.read_file(request, context).await
    }

    #[tool(
        name = "ssh_stat",
        description = "Query ordinary-identity SFTP metadata for a literal UTF-8 path. Default lstat reports a final symlink itself; follow_symlinks=true queries its target. Intermediate symlinks follow server semantics. No path sandbox, race-free no-follow guarantee, shell/SCP fallback, sudo or automatic retry. Missing attributes remain null and missing type is unknown; permissions contain only mode bits. Each call owns an independent SFTP channel under the original timeout.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<StatRequest>(),
        output_schema = schema_for_type::<ToolReply<StatData>>()
    )]
    async fn ssh_stat(
        &self,
        Arguments(request): Arguments<StatRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.stat_file(request, context).await
    }

    #[tool(
        name = "ssh_list_directory",
        description = "List a literal UTF-8 directory path over an independent ordinary SFTP channel. max_entries defaults to 200 (1–1000); the complete 16 MiB reply budget can shorten it further. Entries retain server order, omit dot/dot-dot, and use server-provided metadata without following each symlink. name_base64 always preserves raw filename bytes; name is null for non-UTF-8 names, which UTF-8 path tools cannot address directly. truncated means another entry was observed, not a continuation cursor or snapshot. No sorting, recursion, path sandbox, shell/SCP fallback, sudo or automatic retries. Timeout/cancellation closes only this channel; remote completion is not guaranteed.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        input_schema = schema_for_type::<ListRequest>(),
        output_schema = schema_for_type::<ToolReply<ListData>>()
    )]
    async fn ssh_list_directory(
        &self,
        Arguments(request): Arguments<ListRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.list_directory(request, context).await
    }

    #[tool(
        name = "ssh_write_file",
        description = "Write bounded content through an independent ordinary SFTP channel. Default exclusive create refuses an existing destination, including symlinks. overwrite=true directly creates or truncates and follows server symlink semantics: a later failure can leave partial, empty or completed changes. Success requires write and close acknowledgements, not atomic replacement or durable fsync. Paths are literal UTF-8, without shell expansion or a path sandbox. Content is UTF-8 by default (NUL allowed), or canonical padded standard base64; decoded bytes must fit the configured file cap before connecting. No append, parent creation, sudo, fallback, retries, replay or rollback. Failures after a mutating OPEN is dispatched report remote_state_unknown=true and null data. Timeout/cancellation closes only this channel; remote work may continue. SFTP v3 can report concurrent exclusive-create conflicts as io_error.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<WriteRequest>(),
        output_schema = schema_for_type::<ToolReply<WriteData>>()
    )]
    async fn ssh_write_file(
        &self,
        Arguments(request): Arguments<WriteRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.write_file(request, context).await
    }

    #[tool(
        name = "ssh_sudo",
        description = "Execute an authorized absolute executable via sudo -n -k with the target's configured identity/user/program policy. argv is not a shell script. Requires remote passwordless sudo; no passwords, PTY, environment preservation, or retries. Potentially destructive and not idempotent. Cancellation cannot guarantee remote termination. Permitted executables may themselves grant shell-like authority; sudoers remains authoritative. Output may be further truncated to fit the fixed 16 MiB reply; stdout has priority over stderr. The complete escaped command is limited to 65536 bytes before connecting.",
        annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false),
        input_schema = schema_for_type::<SudoRequest>(),
        output_schema = schema_for_type::<ToolReply<CommandData>>()
    )]
    async fn ssh_sudo(
        &self,
        Arguments(request): Arguments<SudoRequest>,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.command(Operation::Sudo(request), context).await
    }
}

enum Operation {
    Exec(ExecRequest),
    Run(RunRequest),
    Sudo(SudoRequest),
    Binding {
        id: BindingId,
        request: BindingRequest,
    },
}

struct PreparedCommand<'a> {
    target: ResolvedTarget<'a>,
    duration: Duration,
    invocation: Invocation<'a>,
    script: Option<&'a bindings::ScriptSource>,
    stdin: Option<&'a str>,
    max_output_bytes: u64,
}

impl Operation {
    fn metadata<'a>(&'a self, state: &'a State, request_id: &'a RequestId) -> Metadata<'a> {
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
                Some(request.user.as_str()),
                request.argv.first().map(String::as_str),
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
            identity_role: if user.is_some() && mode != Some(SudoMode::SameAccount) {
                IdentityRole::Elevated
            } else {
                IdentityRole::Ordinary
            },
        }
    }

    fn prepare<'a>(&'a self, config: &'a Config) -> Result<PreparedCommand<'a>, ToolError> {
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
                    script: prepared.script,
                    stdin: None,
                    max_output_bytes: prepared.max_output_bytes,
                });
            }
        };
        Ok(PreparedCommand {
            target,
            duration: config.timeout(seconds)?,
            invocation,
            script: None,
            stdin,
            max_output_bytes: config.limits().max_output_bytes,
        })
    }
}

fn file_metadata<'a>(
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

fn request_deadline(
    started: Instant,
    duration: Duration,
) -> Result<tokio::time::Instant, ToolError> {
    tokio::time::Instant::from_std(started)
        .checked_add(duration)
        .ok_or_else(|| {
            ToolError::new(
                "invalid_argument",
                "timeout_secs exceeds the supported clock range",
                false,
            )
        })
}

impl State {
    fn tool_name(&self, id: ToolId) -> &str {
        self.tools
            .name(ToolKey::Builtin(id))
            .expect("executing tool is registered")
    }

    fn binding_name(&self, id: BindingId) -> &str {
        self.tools
            .name(ToolKey::Binding(id))
            .expect("executing binding is registered")
    }

    fn controller_metadata<'a>(&'a self, id: BindingId, request_id: &'a RequestId) -> Metadata<'a> {
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

    async fn command(
        &self,
        request: Operation,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        capture_limit: u64,
    ) -> ToolReply<CommandData> {
        let metadata = request.metadata(self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.prepare(&self.config).and_then(|prepared| {
            request_deadline(started, prepared.duration).map(|deadline| (prepared, deadline))
        });
        let (
            PreparedCommand {
                target,
                invocation,
                script,
                stdin,
                max_output_bytes,
                ..
            },
            deadline,
        ) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let reply = async {
                    let source = if let Some(script) = script {
                        let outcome = files::read_script(
                            lease.session(),
                            &script.path,
                            &script.content_sha256,
                            script.max_bytes,
                            FileContext {
                                deadline,
                                ct: &ct,
                                shutdown: &self.shutdown,
                            },
                        )
                        .await;
                        if outcome.check_master
                            && matches!(lease.check_health().await, MasterHealth::Lost)
                        {
                            lease.invalidate();
                        }
                        match outcome.reply.data {
                            Some(source) => Some(source),
                            None => {
                                return ToolReply::failure(
                                    outcome
                                        .reply
                                        .error
                                        .expect("failed script preparation carries an error"),
                                );
                            }
                        }
                    } else {
                        None
                    };
                    if source.is_some() {
                        if ct.is_cancelled() || self.shutdown.is_cancelled() {
                            return ToolReply::failure(ToolError::new(
                                "cancelled",
                                "Request cancelled before script dispatch",
                                false,
                            ));
                        }
                        if tokio::time::Instant::now() >= deadline {
                            return ToolReply::failure(ToolError::new(
                                "timeout",
                                "Request deadline expired before script dispatch",
                                false,
                            ));
                        }
                    }
                    // The checked snapshot owns stdin until the existing command owner finishes.
                    exec::run(
                        lease.session(),
                        invocation,
                        source.as_deref().or(stdin),
                        RunContext {
                            max_output_bytes: max_output_bytes.min(capture_limit),
                            deadline,
                            ct: &ct,
                            shutdown: &self.shutdown,
                            started,
                        },
                    )
                    .await
                }
                .await;
                if matches!(
                    reply.data.as_ref().map(|data| &data.termination),
                    Some(Termination::ConnectionLost)
                ) && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(
            reply.data.as_ref().and_then(|data| data.exit_code),
            reply.error.as_ref(),
        );
        reply
    }

    async fn read_file(
        &self,
        request: ReadRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ReadData> {
        let metadata = file_metadata(&request.host, ToolId::ReadFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(self.config.limits().max_file_bytes, budget)
            .and_then(|spec| {
                let target = self.config.resolve(&request.host, ToolId::ReadFile)?;
                let deadline =
                    request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
                Ok((spec, target, deadline))
            });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = files::read(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    async fn stat_file(
        &self,
        request: StatRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<StatData> {
        let metadata = file_metadata(&request.host, ToolId::Stat, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::Stat)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = files::stat(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    async fn list_directory(
        &self,
        request: ListRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<ListData> {
        let metadata = file_metadata(&request.host, ToolId::ListDirectory, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request.validate(budget).and_then(|spec| {
            let target = self.config.resolve(&request.host, ToolId::ListDirectory)?;
            let deadline = request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
            Ok((spec, target, deadline))
        });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = files::list(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }

    async fn write_file(
        &self,
        request: WriteRequest,
        request_id: RequestId,
        ct: CancellationToken,
        started: Instant,
        budget: ReplyBudget,
    ) -> ToolReply<WriteData> {
        let metadata = file_metadata(&request.host, ToolId::WriteFile, self, &request_id);
        if self.shutdown.is_cancelled() || ct.is_cancelled() {
            let error = ToolError::new("cancelled", "Request cancelled before dispatch", false);
            metadata.reject(started, &error);
            return ToolReply::failure(error);
        }
        let validated = request
            .validate(self.config.limits().max_file_bytes, budget)
            .and_then(|spec| {
                let target = self.config.resolve(&request.host, ToolId::WriteFile)?;
                let deadline =
                    request_deadline(started, self.config.timeout(request.timeout_secs)?)?;
                Ok((spec, target, deadline))
            });
        let (spec, target, deadline) = match validated {
            Ok(validated) => validated,
            Err(error) => {
                metadata.reject(started, &error);
                return ToolReply::failure(error);
            }
        };
        let audit = Audit::start(metadata, started);
        let reply = match self
            .pool
            .acquire(target.name, target.destination, target.role, deadline, &ct)
            .await
        {
            Ok(lease) => {
                let outcome = files::write(
                    lease.session(),
                    spec,
                    FileContext {
                        deadline,
                        ct: &ct,
                        shutdown: &self.shutdown,
                    },
                )
                .await;
                if outcome.check_master && matches!(lease.check_health().await, MasterHealth::Lost)
                {
                    lease.invalidate();
                }
                outcome.reply
            }
            Err(error) => ToolReply::failure(error),
        };
        audit.finish(None, reply.error.as_ref());
        reply
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            rmcp::model::Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
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
                &ToolError::new("invalid_argument", "Tool is not registered", false),
            );
            return Err(ErrorData::invalid_params("Tool is not registered", None));
        }
        self.tool_router
            .call(ToolCallContext::new(self, request, context))
            .await
    }
}

#[cfg(test)]
mod projection_metadata_tests {
    use super::*;
    use serde_json::{Value, json};

    fn occurrences(value: &Value, expected: &Value) -> usize {
        usize::from(value == expected)
            + match value {
                Value::Object(object) => object.values().map(|v| occurrences(v, expected)).sum(),
                Value::Array(array) => array.iter().map(|v| occurrences(v, expected)).sum(),
                _ => 0,
            }
    }

    #[test]
    fn output_contract_specializes_both_values_without_changing_evidence() {
        let selected = json!({"type":"object","additionalProperties":false,
            "required":["platform"],"properties":{"platform":{"type":"string","maxLength":64}}});
        let plan = crate::projection::compile(json!({
            "fields":{"platform":["ansible_facts","ansible_system"]},"schema":selected,
            "max_bytes":1024,"max_items":32,"max_depth":4
        }))
        .unwrap();
        let projected = Value::Object((*automation_output_schema(Some(&plan))).clone());
        assert_eq!(occurrences(&projected, &selected), 2);
        fn data_schema(node: &Value) -> Option<&JsonObject> {
            match node {
                Value::Object(object) => {
                    if object
                        .get("properties")
                        .and_then(Value::as_object)
                        .is_some_and(|properties| properties.contains_key("projection"))
                    {
                        Some(object)
                    } else {
                        object.values().find_map(data_schema)
                    }
                }
                Value::Array(array) => array.iter().find_map(data_schema),
                _ => None,
            }
        }
        let data = data_schema(&projected).expect("projected data schema exists");
        assert!(
            data["required"]
                .as_array()
                .unwrap()
                .contains(&json!("projection"))
        );
        let projection = &data["properties"]["projection"];
        let variants = projection
            .get("oneOf")
            .or_else(|| projection.get("anyOf"))
            .and_then(Value::as_array)
            .expect("projection is a tagged union");
        assert_eq!(variants.len(), 5);
        assert!(
            variants.iter().all(|variant| {
                variant["properties"]["status"].is_object()
                    && variant.get("type").is_none_or(|kind| kind == "object")
            }),
            "projection must not admit null or a missing state"
        );
        let summary = Value::Object((*automation_output_schema(None)).clone());
        assert_eq!(occurrences(&summary, &selected), 0);
        assert!(
            !serde_json::to_string(&summary)
                .unwrap()
                .contains("\"projection\"")
        );
        assert!(
            serde_json::to_string(&projected)
                .unwrap()
                .contains("\"runner_rc\"")
        );
        assert!(
            serde_json::to_string(&projected)
                .unwrap()
                .contains("\"owned_group_cleanup\"")
        );
    }
}
