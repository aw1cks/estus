use std::sync::Arc;

use crate::config::{Config, TargetDiscovery};

use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::schema_for_type, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub(crate) struct SshMcp {
    tool_router: ToolRouter<Self>,
    config: Arc<Config>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Serialize, JsonSchema)]
struct ToolReply<T> {
    data: Option<T>,
    error: Option<ToolError>,
}

#[derive(Serialize, JsonSchema)]
struct ToolError {
    code: String,
    message: String,
    remote_state_unknown: bool,
}

impl SshMcp {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            tool_router: Self::tool_router(),
            config: Arc::new(config),
        }
    }
}

#[tool_router]
impl SshMcp {
    #[tool(
        description = "List configured logical targets without connecting. Open mode does not enumerate SSH configuration.",
        annotations(read_only_hint = true, destructive_hint = false, idempotent_hint = true),
        output_schema = schema_for_type::<ToolReply<TargetDiscovery<'static>>>()
    )]
    fn ssh_targets(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, ErrorData> {
        let reply = ToolReply {
            data: Some(self.config.targets()),
            error: None,
        };
        let value = serde_json::to_value(reply)
            .map_err(|_| ErrorData::internal_error("Could not serialize target discovery", None))?;
        Ok(CallToolResult::structured(value))
    }
}

#[tool_handler]
impl ServerHandler for SshMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            rmcp::model::Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        )
    }

    async fn call_tool(
        &self,
        request: rmcp::model::CallToolRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, ErrorData> {
        // RMCP converts extractor failures into tool results; shape errors here
        // must remain protocol-level invalid-params.
        if request.name == "ssh_targets"
            && request
                .arguments
                .as_ref()
                .is_some_and(|args| !args.is_empty())
        {
            return Err(ErrorData::invalid_params(
                "ssh_targets requires an empty argument object",
                None,
            ));
        }
        self.tool_router
            .call(rmcp::handler::server::tool::ToolCallContext::new(
                self, request, context,
            ))
            .await
    }
}
