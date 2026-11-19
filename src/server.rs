use std::{borrow::Cow, sync::Arc, time::Duration};

use rmcp::handler::server::router::tool::ToolRouter;
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    config::{Config, ConfigError, ToolCatalog, ToolId, ToolKey},
    filesystem::operations,
    output::Store as OutputStore,
    ssh::Pool,
};

mod command_execution;
mod file_execution;
mod generic_execution;
mod handlers;
mod local_execution;
mod payload_execution;
mod preparation;
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
    pool: Arc<Pool>,
    shutdown: CancellationToken,
    operations: Arc<Semaphore>,
    tasks: TaskTracker,
    local_tasks: TaskTracker,
    outputs: OutputStore,
    directories: Option<operations::DirectoryStore>,
    progress: crate::progress::Registry,
    automation: Arc<Semaphore>,
    automation_targets: std::collections::BTreeMap<String, Arc<Semaphore>>,
    payload: Arc<crate::native_payload::Engine>,
}

impl Estus {
    pub(crate) fn new(config: Config) -> Result<Self, ConfigError> {
        let registration::Registration {
            router: tool_router,
            tools,
            sudo_name,
        } = registration::register(&config)?;
        let shutdown = CancellationToken::new();
        let pool = Pool::new(
            config.ssh_executable().to_path_buf(),
            config.ssh_config().map(std::path::Path::to_path_buf),
            Duration::from_secs(config.limits().connect_timeout_secs),
            shutdown.clone(),
        );
        let outputs = OutputStore::new(config.output_limits(), shutdown.clone());
        let directories = tools
            .contains(ToolKey::Builtin(ToolId::ListDirectory))
            .then(|| operations::DirectoryStore::new(config.directory_limits(), shutdown.clone()));
        Ok(Self {
            tool_router,
            state: Arc::new(State {
                automation: Arc::new(Semaphore::new(config.automation_concurrency())),
                automation_targets: config
                    .automation_hosts()
                    .map(|host| (host.clone(), Arc::new(Semaphore::new(1))))
                    .collect(),
                payload: crate::native_payload::Engine::new(shutdown.clone()),
                config,
                tools,
                sudo_name,
                pool,
                shutdown,
                operations: Arc::new(Semaphore::new(8)),
                tasks: TaskTracker::new(),
                local_tasks: TaskTracker::new(),
                outputs,
                directories,
                progress: crate::progress::Registry::default(),
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
            if let Some(directories) = &self.state.directories {
                directories.shutdown().await;
            }
            self.state.pool.shutdown().await;
        },);
        self.state.payload.shutdown().await;
        self.state.outputs.shutdown().await;
    }
}
