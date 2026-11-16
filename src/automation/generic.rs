//! Separately authorized broad Ansible execution; never a sandbox.
use super::runtime::{RunnerRuntime, RuntimeContext, RuntimeIdentity};
use crate::{
    bindings::PreparedController,
    config::ConfigError,
    contracts::{module_schema, projection},
    reply::ToolError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const INVENTORY_BYTES: u64 = 2 * 1024 * 1024;
const WARNING: &str = "Broad administrative automation: modules/action plugins can execute controller code and access controller files, credentials and network. Module scope is not a sandbox. Ansible changed is backend-reported, not independent effect verification. No automatic replay.";
fn invalid(reason: &'static str) -> ConfigError {
    ConfigError::new("tools", reason)
}
fn denied() -> ToolError {
    ToolError::new(
        "policy_denied",
        "Generic operation is not authorized",
        false,
    )
}
fn bad() -> ToolError {
    ToolError::new("invalid_argument", "Invalid bounded generic request", false)
}
fn hash(value: &impl Serialize) -> Result<String, &'static str> {
    Ok(hex::encode(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| "invalid_generic_policy")?,
    )))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Module {
    pub collection: String,
    pub documentation: Documentation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Documentation {
    pub status: String,
    pub short_description: Option<String>,
    pub reason: String,
}
impl Documentation {
    fn valid(&self) -> bool {
        self.reason.len() <= 64
            && self
                .reason
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
            && match self.status.as_str() {
                "partial" => {
                    self.short_description
                        .as_ref()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 512)
                        && matches!(self.reason.as_str(), "summary_only" | "summary_truncated")
                }
                "unavailable" => self.short_description.is_none(),
                _ => false,
            }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inventory {
    pub schema: u32,
    pub identity: RuntimeIdentity,
    pub content_sha256: String,
    pub modules: BTreeMap<String, Module>,
}
impl Inventory {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || !super::runtime::valid_identity(&self.identity)
            || !digest(&self.content_sha256)
            || self.modules.is_empty()
            || self.modules.len() > 16384
            || self.modules.iter().any(|(name, module)| {
                !module_schema::valid_fqcn(name)
                    || collection(name) != module.collection
                    || !module.documentation.valid()
            })
        {
            return Err("invalid_generic_inventory");
        }
        Ok(())
    }
}
fn collection(name: &str) -> &str {
    name.match_indices('.')
        .nth(1)
        .map_or("", |(i, _)| &name[..i])
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Scope {
    Exact { modules: BTreeSet<String> },
    Collections { collections: BTreeSet<String> },
    SelectedRuntime {},
}
impl Scope {
    fn valid(&self) -> bool {
        match self {
            Self::Exact { modules } => {
                !modules.is_empty()
                    && modules.len() <= 1024
                    && modules.iter().all(|v| module_schema::valid_fqcn(v))
            }
            Self::Collections { collections } => {
                !collections.is_empty()
                    && collections.len() <= 128
                    && collections
                        .iter()
                        .all(|v| module_schema::valid_fqcn(&format!("{v}.module")))
            }
            Self::SelectedRuntime {} => true,
        }
    }
    fn allows(&self, name: &str) -> bool {
        match self {
            Self::Exact { modules } => modules.contains(name),
            Self::Collections { collections } => collections.contains(collection(name)),
            Self::SelectedRuntime {} => true,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimePolicy {
    #[default]
    Locked,
    FollowSelectedRuntime,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Ceilings {
    pub timeout_secs: u64,
    pub argument_bytes: usize,
    pub argument_depth: usize,
    pub argument_items: usize,
    pub output_bytes: usize,
    pub output_depth: usize,
    pub output_items: usize,
    pub concurrency: usize,
    pub scratch_bytes: u64,
    pub scratch_files: usize,
}
impl Default for Ceilings {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            argument_bytes: 65536,
            argument_depth: 16,
            argument_items: 4096,
            output_bytes: 4096,
            output_depth: 8,
            output_items: 256,
            concurrency: 1,
            scratch_bytes: 16 * 1024 * 1024,
            scratch_files: 1024,
        }
    }
}
impl Ceilings {
    fn valid(&self) -> bool {
        self.timeout_secs > 0
            && self.timeout_secs <= 86400
            && (1..=196608).contains(&self.argument_bytes)
            && (1..=32).contains(&self.argument_depth)
            && (1..=16384).contains(&self.argument_items)
            && (64..=4096).contains(&self.output_bytes)
            && (1..=8).contains(&self.output_depth)
            && (1..=256).contains(&self.output_items)
            && (1..=32).contains(&self.concurrency)
            && (1..=64 * 1024 * 1024).contains(&self.scratch_bytes)
            && (1..=4096).contains(&self.scratch_files)
    }
    pub(crate) fn lower(&self, other: &Self) -> Self {
        Self {
            timeout_secs: self.timeout_secs.min(other.timeout_secs),
            argument_bytes: self.argument_bytes.min(other.argument_bytes),
            argument_depth: self.argument_depth.min(other.argument_depth),
            argument_items: self.argument_items.min(other.argument_items),
            output_bytes: self.output_bytes.min(other.output_bytes),
            output_depth: self.output_depth.min(other.output_depth),
            output_items: self.output_items.min(other.output_items),
            concurrency: self.concurrency.min(other.concurrency),
            scratch_bytes: self.scratch_bytes.min(other.scratch_bytes),
            scratch_files: self.scratch_files.min(other.scratch_files),
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetPolicy {
    pub scope: Option<Scope>,
    #[serde(default)]
    pub deny: BTreeSet<String>,
    pub ceilings: Option<Ceilings>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Disclosure {
    #[default]
    Summary,
    Selected,
    ModuleResult {
        max_bytes: usize,
        max_items: usize,
        max_depth: usize,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retention {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub lifetime_secs: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawPolicy {
    pub snapshot: String,
    pub scope: Scope,
    #[serde(default)]
    pub deny: BTreeSet<String>,
    #[serde(default)]
    pub targets: BTreeMap<String, TargetPolicy>,
    #[serde(default)]
    pub runtime_policy: RuntimePolicy,
    #[serde(default)]
    pub restrictions: BTreeMap<String, Value>,
    #[serde(default)]
    pub ceilings: Ceilings,
    #[serde(default)]
    pub no_log: bool,
    #[serde(default)]
    pub disclosure: Disclosure,
    pub retention: Option<Retention>,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Call {
        host: String,
        module: String,
        arguments: Value,
        timeout_secs: Option<u64>,
    },
    List {
        host: String,
        after: Option<String>,
        limit: Option<usize>,
    },
    Describe {
        host: String,
        module: String,
    },
    Receipts {
        host: String,
        receipt: Option<String>,
    },
}
impl Request {
    pub(crate) fn host(&self) -> &str {
        match self {
            Self::Call { host, .. }
            | Self::List { host, .. }
            | Self::Describe { host, .. }
            | Self::Receipts { host, .. } => host,
        }
    }
}
struct Active {
    inventory: Inventory,
    generation: String,
    policy_generation: String,
    added: Vec<String>,
    removed: Vec<String>,
    runner: RunnerRuntime,
    restrictions: BTreeMap<String, module_schema::CapabilityBinding>,
}
struct Receipt {
    id: String,
    host: String,
    generation: String,
    expires: Instant,
    bytes: usize,
    value: Value,
}
pub(crate) struct Policy {
    raw: RawPolicy,
    projection: Option<Arc<projection::Plan>>,
    active: Option<Active>,
    permits: Arc<Semaphore>,
    target_permits: BTreeMap<String, Arc<Semaphore>>,
    receipts: Arc<Mutex<VecDeque<Receipt>>>,
}
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenericPolicy")
            .field("activated", &self.is_activated())
            .finish_non_exhaustive()
    }
}
impl Policy {
    pub(crate) fn compile(
        raw: RawPolicy,
        selected: Option<Arc<projection::Plan>>,
    ) -> Result<Self, ConfigError> {
        if !raw.snapshot.starts_with('/')
            || raw.snapshot.len() > 4096
            || raw.snapshot.contains('\0')
            || !raw.scope.valid()
            || !raw.ceilings.valid()
            || raw.deny.len() > 1024
            || raw.deny.iter().any(|v| !module_schema::valid_fqcn(v))
            || raw.targets.len() > 32
            || raw.restrictions.len() > 128
        {
            return Err(invalid("Invalid generic scope or bounds"));
        }
        for target in raw.targets.values() {
            if target.scope.as_ref().is_some_and(|s| !s.valid())
                || target.ceilings.as_ref().is_some_and(|c| !c.valid())
                || target.deny.len() > 1024
                || target.deny.iter().any(|v| !module_schema::valid_fqcn(v))
            {
                return Err(invalid("Invalid generic target policy"));
            }
        }
        for (module, overlay) in &raw.restrictions {
            if !module_schema::valid_fqcn(module) {
                return Err(invalid("Invalid generic restriction module"));
            }
            module_schema::validate_overlay(overlay).map_err(invalid)?;
        }
        if raw.retention.as_ref().is_some_and(|r| {
            !(1..=128).contains(&r.max_entries)
                || !(1024..=1024 * 1024).contains(&r.max_bytes)
                || !(1..=86400).contains(&r.lifetime_secs)
        }) {
            return Err(invalid("Invalid generic retention bounds"));
        }
        let projection = match &raw.disclosure {
            Disclosure::Summary if selected.is_none() => None,
            Disclosure::Selected if selected.is_some() => selected,
            Disclosure::ModuleResult {max_bytes,max_items,max_depth} if selected.is_none() && (64..=2048).contains(max_bytes) && (1..=256).contains(max_items) && (1..=8).contains(max_depth) => Some(Arc::new(projection::compile(json!({"fields":{"module_result_json":["module_result_json"]},"schema":{"type":"object","additionalProperties":false,"required":["module_result_json"],"properties":{"module_result_json":{"type":"string","maxLength":max_bytes}}},"max_bytes":4096,"max_items":4,"max_depth":2})).map_err(invalid)?)),
            _ => return Err(invalid("Generic disclosure and result contract disagree")),
        };
        let target_permits = raw
            .targets
            .iter()
            .map(|(host, target)| {
                (
                    host.clone(),
                    Arc::new(Semaphore::new(
                        target
                            .ceilings
                            .as_ref()
                            .map_or(raw.ceilings.concurrency, |c| {
                                c.concurrency.min(raw.ceilings.concurrency)
                            }),
                    )),
                )
            })
            .collect();
        Ok(Self {
            permits: Arc::new(Semaphore::new(raw.ceilings.concurrency)),
            raw,
            projection,
            active: None,
            target_permits,
            receipts: Arc::new(Mutex::new(VecDeque::new())),
        })
    }
    pub(crate) fn projection(&self) -> Option<&Arc<projection::Plan>> {
        self.projection.as_ref()
    }
    pub(crate) fn is_activated(&self) -> bool {
        self.active.is_some()
    }
    pub(crate) fn target_names(&self) -> impl Iterator<Item = &String> {
        self.raw.targets.keys()
    }
    pub(crate) async fn activate(
        &mut self,
        runtime: Option<PathBuf>,
        runner: RunnerRuntime,
        ctx: RuntimeContext<'_>,
    ) -> Result<(), &'static str> {
        let snapshot = self.raw.snapshot.clone();
        // Activation owns and awaits the bounded blocking read, even on cancellation.
        let approved = tokio::task::spawn_blocking(move || {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
                .open(snapshot)
                .map_err(|_| "generic_approval_unavailable")?;
            if !file
                .metadata()
                .map_err(|_| "generic_approval_unavailable")?
                .is_file()
            {
                return Err("invalid_generic_inventory");
            }
            let mut bytes = Vec::new();
            file.take(INVENTORY_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "generic_approval_unavailable")?;
            if bytes.len() as u64 > INVENTORY_BYTES {
                return Err("invalid_generic_inventory");
            }
            let inventory: Inventory = serde_json::from_value(
                crate::strict_json::parse(&bytes).map_err(|_| "invalid_generic_inventory")?,
            )
            .map_err(|_| "invalid_generic_inventory")?;
            inventory.validate()?;
            Ok(inventory)
        })
        .await
        .map_err(|_| "generic_approval_unavailable")??;
        let observed = super::runtime::import_inventory(
            runtime.clone(),
            RuntimeContext {
                deadline: ctx.deadline,
                ct: ctx.ct,
                shutdown: ctx.shutdown,
            },
        )
        .await?;
        if self.raw.runtime_policy == RuntimePolicy::Locked && approved != observed {
            return Err("generic_runtime_drift");
        }
        if let Scope::Exact { modules } = &self.raw.scope {
            if modules.iter().any(|m| !observed.modules.contains_key(m)) {
                return Err("generic_module_not_provisioned");
            }
        }
        let mut restrictions = BTreeMap::new();
        for (name, overlay) in &self.raw.restrictions {
            if !observed.modules.contains_key(name) {
                return Err("generic_restricted_module_not_provisioned");
            }
            let imported = super::runtime::import_module(
                runtime.clone(),
                name,
                RuntimeContext {
                    deadline: ctx.deadline,
                    ct: ctx.ct,
                    shutdown: ctx.shutdown,
                },
            )
            .await?;
            if imported.identity != observed.identity {
                return Err("generic_runtime_drift");
            }
            let contract = module_schema::import_document(&imported.document)?;
            restrictions.insert(
                name.clone(),
                module_schema::compile_binding(&contract, overlay)?,
            );
        }
        let added = observed
            .modules
            .keys()
            .filter(|m| !approved.modules.contains_key(*m))
            .cloned()
            .collect();
        let removed = approved
            .modules
            .keys()
            .filter(|m| !observed.modules.contains_key(*m))
            .cloned()
            .collect();
        let generation = hash(&observed)?;
        let policy_generation = hash(
            &json!({"policy":self.raw,"projection":self.projection,"runtime_generation":generation}),
        )?;
        if self.active.is_none() && self.raw.retention.is_some() {
            let weak = Arc::downgrade(&self.receipts);
            tokio::spawn(async move {
                loop {
                    let delay = {
                        let Some(store) = weak.upgrade() else {
                            break;
                        };
                        let Ok(mut receipts) = store.lock() else {
                            break;
                        };
                        let now = Instant::now();
                        receipts.retain(|r| r.expires > now);
                        receipts.front().map_or(Duration::from_secs(1), |r| {
                            r.expires.saturating_duration_since(now)
                        })
                    };
                    tokio::time::sleep(delay).await;
                }
            });
        }
        self.active = Some(Active {
            inventory: observed,
            generation,
            policy_generation,
            added,
            removed,
            runner,
            restrictions,
        });
        self.receipts
            .lock()
            .map_err(|_| "generic_retention_unavailable")?
            .clear();
        Ok(())
    }
    fn active(&self) -> Result<&Active, ToolError> {
        self.active.as_ref().ok_or_else(denied)
    }
    fn allowed(&self, host: &str, module: &str) -> bool {
        self.raw.scope.allows(module)
            && !self.raw.deny.contains(module)
            && self.raw.targets.get(host).is_none_or(|target| {
                target.scope.as_ref().is_none_or(|s| s.allows(module))
                    && !target.deny.contains(module)
            })
    }
    pub(crate) fn ceilings(&self, host: &str) -> Ceilings {
        self.raw
            .targets
            .get(host)
            .and_then(|t| t.ceilings.as_ref())
            .map_or_else(|| self.raw.ceilings.clone(), |c| self.raw.ceilings.lower(c))
    }
    pub(crate) fn admit(
        &self,
        host: &str,
    ) -> Result<(OwnedSemaphorePermit, Option<OwnedSemaphorePermit>), ToolError> {
        let limit = || {
            ToolError::new(
                "resource_limit",
                "Generic policy operation limit reached",
                false,
            )
        };
        let policy = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| limit())?;
        let target = self
            .target_permits
            .get(host)
            .map(|s| s.clone().try_acquire_owned().map_err(|_| limit()))
            .transpose()?;
        Ok((policy, target))
    }
    pub(crate) fn inspect(&self) -> Value {
        json!({"boundary":WARNING,"scope":self.raw.scope,"deny":self.raw.deny,"targets":self.raw.targets,"runtime_policy":self.raw.runtime_policy,"ceilings":self.raw.ceilings,"disclosure":self.raw.disclosure,"module_result_encoding":"module_result_json is JSON text; may contain secrets; internal/invocation fields excluded; censorship always wins","retention":self.raw.retention,"generation":self.active.as_ref().map(|a|&a.generation),"policy_generation":self.active.as_ref().map(|a|&a.policy_generation),"scope_diff":self.active.as_ref().map(|a|json!({"added":a.added.iter().take(64).collect::<Vec<_>>(),"removed":a.removed.iter().take(64).collect::<Vec<_>>(),"added_count":a.added.len(),"removed_count":a.removed.len(),"incomplete":a.added.len()>64 || a.removed.len()>64}))})
    }
    pub(crate) fn call_metadata(&self, request: &Request) -> Value {
        let module = match request {
            Request::Call { module, .. } => Some(module),
            _ => None,
        };
        json!({"module":module,"host":request.host(),"generation":self.active.as_ref().map(|a|&a.generation),"policy_generation":self.active.as_ref().map(|a|&a.policy_generation),"validation":if module.is_some_and(|m|self.raw.restrictions.contains_key(m)){"reviewed_restriction"}else{"ansible_runtime"},"boundary":WARNING,"disclosure":self.raw.disclosure,"retention":self.raw.retention})
    }
    pub(crate) fn discover(&self, request: &Request) -> Result<Value, ToolError> {
        let active = self.active()?;
        let host = request.host();
        match request {
            Request::List { after, limit, .. } => {
                let limit = limit.unwrap_or(32);
                if !(1..=64).contains(&limit)
                    || after
                        .as_ref()
                        .is_some_and(|s| !module_schema::valid_fqcn(s))
                {
                    return Err(bad());
                }
                let mut modules = active
                    .inventory
                    .modules
                    .keys()
                    .filter(|m| self.allowed(host, m) && after.as_ref().is_none_or(|a| *m > a))
                    .take(limit + 1)
                    .cloned()
                    .collect::<Vec<_>>();
                let more = modules.len() > limit;
                modules.truncate(limit);
                let next = more.then(|| modules.last().cloned()).flatten();
                let descriptions = modules
                    .iter()
                    .map(|name| (name, &active.inventory.modules[name].documentation))
                    .collect::<BTreeMap<_, _>>();
                Ok(
                    json!({"modules":modules,"descriptions":descriptions,"next":next,"generation":active.generation,"policy_generation":active.policy_generation,"boundary":WARNING}),
                )
            }
            Request::Describe { module, .. } => {
                if !module_schema::valid_fqcn(module)
                    || !self.allowed(host, module)
                    || !active.inventory.modules.contains_key(module)
                {
                    return Err(denied());
                }
                Ok(
                    json!({"module":module,"generation":active.generation,"policy_generation":active.policy_generation,"validation":if active.restrictions.contains_key(module){"reviewed_restriction"}else{"ansible_runtime"},"documentation":active.inventory.modules[module].documentation,"documentation_source":"ansible-doc --list --json captured at explicit activation; summary only, not an argument schema","boundary":WARNING,"disclosure":self.raw.disclosure,"retention":self.raw.retention,"ceilings":self.ceilings(host)}),
                )
            }
            Request::Receipts { receipt, .. } => {
                if self.raw.retention.is_none()
                    || receipt
                        .as_ref()
                        .is_some_and(|r| r.len() != 32 || !r.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(denied());
                }
                let mut receipts = self.receipts.lock().map_err(|_| denied())?;
                receipts.retain(|r| r.expires > Instant::now());
                if let Some(id) = receipt {
                    return receipts
                        .iter()
                        .find(|r| {
                            r.id == *id
                                && r.host == host
                                && r.generation == active.policy_generation
                        })
                        .map(|r| r.value.clone())
                        .ok_or_else(denied);
                }
                Ok(
                    json!({"receipts":receipts.iter().filter(|r|r.host==host && r.generation==active.policy_generation).rev().take(32).map(|r|&r.id).collect::<Vec<_>>(),"policy_generation":active.policy_generation}),
                )
            }
            Request::Call { .. } => Err(bad()),
        }
    }
    pub(crate) fn retain(&self, host: &str, value: Value) -> Option<String> {
        let retention = self.raw.retention.as_ref()?;
        let active = self.active.as_ref()?;
        let bytes = serde_json::to_vec(&value).ok()?.len();
        if bytes > retention.max_bytes {
            return None;
        }
        let mut receipts = self.receipts.lock().ok()?;
        let now = Instant::now();
        receipts.retain(|r| r.expires > now);
        while receipts.len() >= retention.max_entries
            || receipts.iter().map(|r| r.bytes).sum::<usize>() + bytes > retention.max_bytes
        {
            receipts.pop_front()?;
        }
        let id = super::execution::invocation_id();
        receipts.push_back(Receipt {
            id: id.clone(),
            host: host.to_owned(),
            generation: active.policy_generation.clone(),
            expires: now + Duration::from_secs(retention.lifetime_secs),
            bytes,
            value,
        });
        Some(id)
    }
    pub(crate) fn prepare(
        &self,
        request: &Request,
        transport: crate::bindings::AutomationTransport<'_>,
        timeout: u64,
    ) -> Result<super::execution::PreparedAutomation, ToolError> {
        let Request::Call {
            host,
            module,
            arguments,
            ..
        } = request
        else {
            return Err(bad());
        };
        let active = self.active()?;
        if !module_schema::valid_fqcn(module)
            || !self.allowed(host, module)
            || !active.inventory.modules.contains_key(module)
        {
            return Err(denied());
        }
        let ceilings = self.ceilings(host);
        check_arguments(arguments, &ceilings)?;
        let arguments = match active.restrictions.get(module) {
            Some(binding) => binding.prepare(arguments).map_err(|_| bad())?,
            None => arguments.clone(),
        };
        check_arguments(&arguments, &ceilings)?;
        let invocation_id = super::execution::invocation_id();
        let authority = transport.authority;
        let agent = match authority.agent {
            crate::config::AutomationAgent::Inherit => json!({"mode":"inherit"}),
            crate::config::AutomationAgent::Disabled => json!({"mode":"disabled"}),
            crate::config::AutomationAgent::Fixed(socket) => {
                json!({"mode":"fixed","socket":socket})
            }
        };
        let projection = self.projection.as_ref().map(|p| {
            Arc::new(projection::Plan {
                fields: p.fields.clone(),
                schema: p.schema.clone(),
                max_bytes: p.max_bytes.min(ceilings.output_bytes),
                max_items: p.max_items.min(ceilings.output_items),
                max_depth: p.max_depth.min(ceilings.output_depth),
            })
        });
        let disclosure = match &self.raw.disclosure {
            Disclosure::ModuleResult {
                max_bytes,
                max_items,
                max_depth,
            } => Disclosure::ModuleResult {
                max_bytes: (*max_bytes).min(ceilings.output_bytes.saturating_sub(64) / 2),
                max_items: (*max_items).min(ceilings.output_items),
                max_depth: (*max_depth).min(ceilings.output_depth),
            },
            other => other.clone(),
        };
        let spec = json!({"schema":2,"invocation_id":invocation_id,"runtime":active.runner.payload,"expected":{"generic":true,"module":module,"identity":active.inventory.identity,"content_sha256":active.inventory.content_sha256,"generation":active.generation,"policy_generation":active.policy_generation,"disclosure":disclosure},"destination":authority.target.destination,"target_python":authority.target.python,"ssh_config":authority.ssh_config,"ssh_executable":authority.ssh_executable,"become":authority.r#become,"agent":agent,"arguments":arguments,"no_log":self.raw.no_log,"projection":projection,"timeout_secs":Duration::from_secs(timeout).saturating_sub(transport.started.elapsed()).as_secs_f64(),"scratch_bytes":ceilings.scratch_bytes.min(transport.scratch_bytes),"scratch_files":ceilings.scratch_files.min(transport.scratch_files)});
        let input_json = serde_json::to_vec(&spec).map_err(|_| bad())?;
        if input_json.len() > 256 * 1024 {
            return Err(bad());
        }
        Ok(super::execution::PreparedAutomation {
            controller: PreparedController {
                plan: Arc::clone(&active.runner.plan),
                input_json,
                duration: Duration::from_secs(timeout),
                max_output_bytes: 65536,
                supervision: crate::controller::ControllerSupervision::Automation {
                    invocation_id,
                    mode: super::protocol::ExecutionMode::Module,
                    scratch_bytes: ceilings.scratch_bytes.min(transport.scratch_bytes),
                    scratch_files: ceilings.scratch_files.min(transport.scratch_files),
                },
            },
            host: host.clone(),
            projection,
        })
    }
}
fn check_arguments(value: &Value, ceilings: &Ceilings) -> Result<(), ToolError> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize, c: &Ceilings) -> bool {
        *nodes += 1;
        if depth > c.argument_depth || *nodes > c.argument_items {
            return false;
        }
        match value {
            Value::Object(map) => map.iter().all(|(key, v)| {
                !key.contains('\0') && key.len() <= 4096 && walk(v, depth + 1, nodes, c)
            }),
            Value::Array(list) => list.iter().all(|v| walk(v, depth + 1, nodes, c)),
            Value::String(v) => !v.contains('\0'),
            Value::Number(v) => v
                .as_f64()
                .is_some_and(|v| v.is_finite() && v.abs() <= 9007199254740991.0),
            _ => true,
        }
    }
    let Some(args) = value.as_object() else {
        return Err(bad());
    };
    // Internal action-plugin controls are not public module-domain options.
    if args.keys().any(|k| {
        k.starts_with('_')
            || k.starts_with("ansible_")
            || k.is_empty()
            || !k.bytes().enumerate().all(|(i, b)| {
                b == b'_' || b.is_ascii_alphabetic() || i > 0 && (b.is_ascii_digit() || b == b'-')
            })
    }) || !walk(value, 0, &mut 0, ceilings)
        || serde_json::to_vec(value).map_err(|_| bad())?.len() > ceilings.argument_bytes
    {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn raw() -> RawPolicy {
        serde_json::from_value(json!({"snapshot":"/approval.json","scope":{"kind":"exact","modules":["ansible.builtin.copy"]},"retention":null})).unwrap()
    }
    #[test]
    fn deny_wins_in_every_scope() {
        let mut r = raw();
        r.scope = Scope::SelectedRuntime {};
        r.deny.insert("ansible.builtin.copy".into());
        let p = Policy::compile(r, None).unwrap();
        assert!(!p.allowed("target", "ansible.builtin.copy"));
        assert!(p.allowed("target", "ansible.builtin.stat"));
    }
    #[test]
    fn target_scope_only_narrows() {
        let mut r = raw();
        r.targets.insert(
            "target".into(),
            TargetPolicy {
                scope: Some(Scope::SelectedRuntime {}),
                ..Default::default()
            },
        );
        let p = Policy::compile(r, None).unwrap();
        assert!(!p.allowed("target", "ansible.builtin.shell"));
    }
    #[test]
    fn legitimate_options_are_literal_module_data() {
        let value = json!({"content":"{{ lookup('pipe', 'touch /tmp/no') }}; $(false)","connection":"not a transport override","nested":{"ansible_host":"literal","odd key":"literal"}});
        check_arguments(&value, &Ceilings::default()).unwrap();
        assert_eq!(
            value["content"],
            "{{ lookup('pipe', 'touch /tmp/no') }}; $(false)"
        );
        assert!(check_arguments(&json!({"_ansible_no_log":false}), &Ceilings::default()).is_err());
    }
    #[test]
    fn caller_cannot_supply_execution_controls() {
        assert!(serde_json::from_value::<Request>(json!({"operation":"call","host":"target","module":"ansible.builtin.copy","arguments":{},"become":true})).is_err());
    }
    #[test]
    fn envelope_and_argument_bounds_fail_closed() {
        let mut c = Ceilings::default();
        c.argument_depth = 1;
        assert!(check_arguments(&json!({"a":{"b":1}}), &c).is_err());
        assert!(
            serde_json::from_value::<Request>(
                json!({"operation":"list","host":"target","inventory":{}})
            )
            .is_err()
        );
    }
    #[test]
    fn reviewed_restrictions_reject_alias_collisions_and_fixed_overrides() {
        let contract = json!({"schema":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string","maxLength":128},"state":{"type":"string","enum":["file"]}}},"aliases":{"aliases":{"dest":"path"},"properties":{"path":{},"state":{}}},"defaults":{},"review_required":[]});
        let overlay = json!({"input_schema":{"type":"object","additionalProperties":false,"required":["requested"],"properties":{"requested":{"type":"string","maxLength":128}}},"fixed_args":{"state":"file"},"input_map":{"dest":"requested"}});
        let binding = module_schema::compile_binding(&contract, &overlay).unwrap();
        assert_eq!(
            binding
                .prepare(&json!({"requested":"{{ literal }}; $(false)"}))
                .unwrap(),
            json!({"path":"{{ literal }}; $(false)","state":"file"})
        );
        assert!(
            binding
                .prepare(&json!({"requested":"/owned","state":"absent"}))
                .is_err()
        );
        let collision = json!({"input_schema":{"type":"object","additionalProperties":false,"properties":{}},"fixed_args":{"dest":"/owned","path":"/different"},"input_map":{}});
        assert!(module_schema::compile_binding(&contract, &collision).is_err());
    }
}
