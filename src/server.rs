use std::{borrow::Cow, collections::BTreeMap, sync::Arc, time::Duration};

use rmcp::handler::server::router::tool::ToolRouter;
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    config::{Config, ConfigError, ToolCatalog},
    output::Store as OutputStore,
    ssh::Pool,
};

mod admission;
mod command_execution;
mod file_execution;
mod guidance;
mod handlers;
mod local_execution;
mod payload_execution;
mod preparation;
pub(crate) mod preview;
mod registration;
mod schemas;

#[derive(Clone)]
pub(crate) struct Estus {
    tool_router: ToolRouter<Self>,
    state: Arc<State>,
}

struct State {
    config: Config,
    tools: ToolCatalog,
    sudo_name: Cow<'static, str>,
    input_schemas: BTreeMap<String, registration::RouteSchema>,
    pool: Arc<Pool>,
    shutdown: CancellationToken,
    operations: Arc<Semaphore>,
    tasks: TaskTracker,
    local_tasks: TaskTracker,
    outputs: OutputStore,
    progress: crate::progress::Registry,
    pending_replies: Arc<crate::progress::PendingReplies>,
    automation: Arc<Semaphore>,
    admission: admission::TargetAdmission,
    payload: Arc<crate::native_payload::Engine>,
    cleanup_quarantine: Arc<crate::controller::CleanupQuarantine>,
    previews: preview::PreviewStore,
}

impl Estus {
    pub(crate) fn new(config: Config) -> Result<Self, ConfigError> {
        let registration::Registration {
            router: tool_router,
            tools,
            sudo_name,
            input_schemas,
        } = registration::register(&config)?;
        let shutdown = CancellationToken::new();
        let pending_replies =
            crate::progress::PendingReplies::new(shutdown.clone(), CancellationToken::new());
        // Headless deployments pin trust and suppress host-key/agent mutation;
        // workstation deployments honor the operator's OpenSSH configuration.
        let pool = if config.mode() == crate::config::Mode::Headless {
            Pool::headless(
                config.ssh_executable().to_path_buf(),
                config.ssh_config().map(std::path::Path::to_path_buf),
                Duration::from_secs(config.limits().connect_timeout_secs),
                shutdown.clone(),
            )
        } else {
            Pool::new(
                config.ssh_executable().to_path_buf(),
                config.ssh_config().map(std::path::Path::to_path_buf),
                Duration::from_secs(config.limits().connect_timeout_secs),
                shutdown.clone(),
            )
        };
        let outputs = OutputStore::new(config.output_limits(), shutdown.clone());
        Ok(Self {
            tool_router,
            state: Arc::new(State {
                automation: Arc::new(Semaphore::new(config.automation_concurrency())),
                admission: admission::TargetAdmission::new_with_persistence(
                    config.automation_hosts(),
                    config.allows_dynamic_hosts(),
                    config.quarantine_state_dir(),
                )?,
                payload: crate::native_payload::Engine::new_with_shared_pool(
                    shutdown.clone(),
                    Some(Arc::clone(&pool)),
                    config.mode() == crate::config::Mode::Headless,
                ),
                config,
                tools,
                sudo_name,
                input_schemas,
                pool,
                shutdown,
                operations: Arc::new(Semaphore::new(8)),
                tasks: TaskTracker::new(),
                local_tasks: TaskTracker::new(),
                outputs,
                cleanup_quarantine: Arc::new(crate::controller::CleanupQuarantine::new()),
                previews: preview::PreviewStore::new(),
                progress: crate::progress::Registry::default(),
                pending_replies,
            }),
        })
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.state.shutdown.clone()
    }

    pub(crate) fn pending_replies(&self) -> Arc<crate::progress::PendingReplies> {
        Arc::clone(&self.state.pending_replies)
    }

    pub(crate) async fn shutdown(&self) {
        self.state.shutdown.cancel();
        self.state.local_tasks.close();
        self.state.tasks.close();
        // Local owners must reap before runtime teardown; native cleanup keeps
        // its existing independent bound. An unkillable OS child can delay shutdown.
        let (_, _) = tokio::join!(
            self.state.local_tasks.wait(),
            tokio::time::timeout(Duration::from_secs(3), self.state.tasks.wait()),
        );
        self.state.payload.shutdown().await;
        self.state.pool.shutdown().await;
        self.state.outputs.shutdown().await;
    }
}
