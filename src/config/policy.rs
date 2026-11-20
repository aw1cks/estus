use std::ffi::OsString;

use crate::bindings::AutomationAuthority;

use super::{validation::validate_runtime_path, *};

pub(crate) fn risk_tier_for_builtin(tool: ToolId) -> RiskTier {
    match tool {
        ToolId::Targets | ToolId::Stat => RiskTier::Observe,
        ToolId::ReadOutput | ToolId::ReadFile | ToolId::ListDirectory => RiskTier::Inspect,
        ToolId::WriteFile
        | ToolId::Mkdir
        | ToolId::Rename
        | ToolId::RemoveFile
        | ToolId::RemoveDirectory
        | ToolId::ReplaceFile
        | ToolId::ClearTargetQuarantine => RiskTier::Change,
        ToolId::Exec | ToolId::Run | ToolId::Sudo => RiskTier::Exec,
    }
}

pub(crate) fn risk_tier_for_binding(binding: &crate::bindings::CompiledBinding) -> RiskTier {
    if binding.sudo().is_some() {
        return RiskTier::Exec;
    }
    if binding.name.starts_with("preview_") {
        return RiskTier::Preview;
    }
    if binding.is_shared_read() {
        if binding
            .effects()
            .contains(&crate::bindings::Effect::SensitiveRead)
        {
            RiskTier::Inspect
        } else {
            RiskTier::Observe
        }
    } else if binding.read_only() || binding.effects().contains(&crate::bindings::Effect::Probe) {
        RiskTier::Inspect
    } else {
        RiskTier::Change
    }
}

impl Capabilities {
    pub(super) fn permits(self, tool: ToolId) -> bool {
        // Keep every ID classified explicitly so a new binding requires a policy decision.
        match tool {
            ToolId::Targets | ToolId::ReadOutput => true,
            ToolId::ReadFile | ToolId::Stat | ToolId::ListDirectory => self.file_read,
            ToolId::WriteFile
            | ToolId::Mkdir
            | ToolId::Rename
            | ToolId::RemoveFile
            | ToolId::ReplaceFile
            | ToolId::RemoveDirectory => self.file_write,
            ToolId::Exec | ToolId::Run => self.exec,
            ToolId::Sudo => self.sudo,
            ToolId::ClearTargetQuarantine => {
                self.named || self.file_write || self.exec || self.sudo
            }
        }
    }

    pub(super) fn permits_bindings(self) -> bool {
        self.named
    }
}

impl Target {
    pub(super) fn permits_binding(&self, name: &str) -> bool {
        Capabilities::from(self.capabilities).permits_bindings()
            && self
                .selected_bindings
                .as_ref()
                .is_none_or(|names| names.contains(name))
    }

    pub(super) fn permits_workstation_sudo(&self) -> bool {
        Capabilities::from(self.capabilities).sudo
            && matches!(
                self.sudo.workstation_route(),
                WorkstationSudoRoute::SameAccountRoot | WorkstationSudoRoute::SeparateIdentity(_)
            )
    }
}

impl Sudo {
    pub(super) fn mode(&self) -> SudoMode {
        match self {
            Self::Disabled => SudoMode::Disabled,
            Self::SameAccount { .. } => SudoMode::SameAccount,
            Self::SeparateIdentity { .. } => SudoMode::SeparateIdentity,
        }
    }

    pub(super) fn permits(&self, user: &str, program: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::SameAccount { users, programs }
            | Self::SeparateIdentity {
                users, programs, ..
            } => {
                users.iter().any(|allowed| allowed == user)
                    && programs
                        .as_ref()
                        .is_none_or(|allowed| allowed.iter().any(|allowed| allowed == program))
            }
        }
    }

    fn resolve<'a>(
        &'a self,
        host: &'a str,
        ordinary: &'a str,
        user: &str,
        program: &str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        if !self.permits(user, program) {
            return Err(ToolError::policy_denied(
                "Elevated target, user, or program is not authorized",
                false,
            ));
        }
        let (destination, role) = match self {
            Self::Disabled => unreachable!("disabled sudo policy cannot permit execution"),
            Self::SameAccount { .. } => (ordinary, IdentityRole::Ordinary),
            Self::SeparateIdentity { ssh_host, .. } => (ssh_host.as_str(), IdentityRole::Elevated),
        };
        Ok(ResolvedTarget {
            name: host,
            destination,
            role,
        })
    }

    pub(super) fn permits_programs(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::SameAccount { programs, .. } | Self::SeparateIdentity { programs, .. } => {
                programs
                    .as_ref()
                    .is_none_or(|programs| !programs.is_empty())
            }
        }
    }

    /// Elevation route a dynamic workstation binding may use. Dynamic Python and
    /// Ansible payloads never pin the native program a sudo policy allowlists, so
    /// only an unrestricted root policy is equivalent to workstation sudo.
    pub(super) fn workstation_route(&self) -> WorkstationSudoRoute<'_> {
        match self {
            Self::Disabled => WorkstationSudoRoute::Denied,
            Self::SameAccount { users, programs } => {
                if unrestricted_root(users, programs) {
                    WorkstationSudoRoute::SameAccountRoot
                } else {
                    WorkstationSudoRoute::Denied
                }
            }
            Self::SeparateIdentity {
                ssh_host,
                users,
                programs,
            } => {
                if unrestricted_root(users, programs) {
                    WorkstationSudoRoute::SeparateIdentity(ssh_host)
                } else {
                    WorkstationSudoRoute::Denied
                }
            }
        }
    }
}

/// The elevation a dynamic workstation binding is allowed to use on one target.
/// `Denied` covers both "no unrestricted root grant" and "no configured target",
/// so an open destination policy can never resolve to elevation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WorkstationSudoRoute<'a> {
    Denied,
    SameAccountRoot,
    SeparateIdentity(&'a str),
}

impl<'a> WorkstationSudoRoute<'a> {
    /// Destination override for separate-identity elevation, if any.
    pub(super) fn elevated_destination(self) -> Option<&'a str> {
        match self {
            Self::SeparateIdentity(host) => Some(host),
            Self::Denied | Self::SameAccountRoot => None,
        }
    }
}

fn unrestricted_root(users: &[String], programs: &Option<Vec<String>>) -> bool {
    users.iter().any(|user| user == "root") && programs.is_none()
}

impl Config {
    pub(crate) fn output_limits(&self) -> crate::output::Limits {
        self.output
    }

    /// A startup prerequisite only; this does not enable automation tools.
    pub(crate) fn automation_required(&self) -> bool {
        self.automation.required
    }

    /// Resolve the optional bundle reference when runtime health or activation is requested.
    pub(crate) fn automation_runtime(&self) -> Result<Option<PathBuf>, ConfigError> {
        self.automation_bundle_with(|key| std::env::var_os(key))
    }

    pub(super) fn automation_bundle_with(
        &self,
        env: impl FnOnce(&str) -> Option<OsString>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        if let Some(path) = &self.automation.bundle {
            return Ok(Some(path.clone()));
        }
        env("ESTUS_ANSIBLE_BUNDLE")
            .map(|value| {
                let value = value.to_str().ok_or_else(|| {
                    invalid("automation.bundle", "must be a bounded absolute path")
                })?;
                validate_runtime_path(value)?;
                Ok(PathBuf::from(value))
            })
            .transpose()
    }

    pub(crate) async fn activate_automation(
        &mut self,
        ct: &tokio_util::sync::CancellationToken,
    ) -> Result<bool, ConfigError> {
        let payloads: Vec<_> = self
            .bindings
            .entries()
            .filter(|(id, binding)| {
                binding.is_payload() && self.binding_enabled(*id) && !binding.payload_activated()
            })
            .map(|(id, _)| id)
            .collect();
        let mut inspected_payload_authorities = BTreeSet::new();
        for id in payloads {
            if let Some(AutomationAuthority::Named(name)) = self
                .bindings
                .get(id)
                .and_then(|binding| binding.automation_authority())
            {
                if let Some((name, authority)) = self.automation.authorities.get_key_value(name) {
                    if inspected_payload_authorities.insert(name.as_str()) {
                        let config = authority.ssh_config_file.clone();
                        let socket = authority.ssh_auth_sock.clone();
                        tokio::task::spawn_blocking(move || {
                            inspect_automation_authority(&config, socket.as_deref())
                        })
                        .await
                        .map_err(|_| {
                            invalid(
                                "automation.authorities.*",
                                "cannot inspect selected authority",
                            )
                        })??;
                    }
                } else if self.mode != Mode::Workstation || !self.capabilities.sudo {
                    return Err(invalid("tools", "automation authority is not configured"));
                }
            }
            self.bindings.activate_payload(id, ct).await?;
        }
        let active: Vec<_> = self
            .bindings
            .entries()
            .filter(|(id, binding)| {
                binding.is_automation()
                    && self.binding_enabled(*id)
                    && !binding.automation_activated()
            })
            .map(|(id, _)| id)
            .collect();
        if active.is_empty() {
            return Ok(false);
        }
        let inherited_bundle = self.automation_runtime()?;
        let mut inspected = inspected_payload_authorities;
        let mut loaded_packs: BTreeMap<PathBuf, std::sync::Arc<crate::bundle::BundlePack>> =
            BTreeMap::new();
        for id in active {
            if ct.is_cancelled() {
                return Err(
                    invalid("automation", "cancelled").with_cause("cancelled", "activation")
                );
            }
            let (authority_bundle, per_binding_bundle) = {
                let binding = self
                    .bindings
                    .get(id)
                    .ok_or_else(|| invalid("tools", "unknown automation binding"))?;
                let override_path = binding.bundle_override().map(Path::to_path_buf);
                let auth_bundle = match binding.automation_authority() {
                    Some(AutomationAuthority::Named(name)) => {
                        if let Some((name, authority)) =
                            self.automation.authorities.get_key_value(name)
                        {
                            if inspected.insert(name.as_str()) {
                                let config = authority.ssh_config_file.clone();
                                let socket = authority.ssh_auth_sock.clone();
                                tokio::task::spawn_blocking(move || {
                                    inspect_automation_authority(&config, socket.as_deref())
                                })
                                .await
                                .map_err(|_| {
                                    invalid(
                                        "automation.authorities.*",
                                        "cannot inspect selected authority",
                                    )
                                })??;
                            }
                            authority.bundle.clone()
                        } else if self.mode == Mode::Workstation && self.capabilities.sudo {
                            None
                        } else {
                            return Err(invalid("tools", "automation authority is not configured"));
                        }
                    }
                    Some(AutomationAuthority::Ordinary) => None,
                    None => return Err(invalid("tools", "automation authority is not configured")),
                };
                (auth_bundle, override_path)
            };
            let dynamic_optional = self
                .bindings
                .get(id)
                .is_some_and(|b| b.has_dynamic_targets())
                && !self.automation.required;
            let Some(bundle_path) = per_binding_bundle
                .or(authority_bundle)
                .or_else(|| inherited_bundle.clone())
                .or_else(crate::bundle::discover_default_bundle)
            else {
                if dynamic_optional {
                    self.bindings.disable(id);
                    continue;
                }
                return Err(
                    invalid("automation.bundle", "Ansible bundle pack is unavailable")
                        .with_cause("runtime_unavailable", "runtime_selection"),
                );
            };
            let pack = if let Some(existing) = loaded_packs.get(&bundle_path) {
                std::sync::Arc::clone(existing)
            } else {
                let load_path = bundle_path.clone();
                let loaded = tokio::task::spawn_blocking(move || {
                    crate::bundle::BundlePack::load(&load_path)
                })
                .await
                .map_err(|_| {
                    invalid("automation.bundle", "bundle verification failed")
                        .with_cause("runtime_unavailable", "runtime_selection")
                })?
                .map_err(|code| {
                    invalid("automation.bundle", code).with_cause(code, "bundle_load")
                })?;
                loaded_packs.insert(bundle_path, std::sync::Arc::clone(&loaded));
                loaded
            };
            self.bindings.activate_automation(id, pack)?;
        }
        Ok(true)
    }

    pub(crate) fn automation_concurrency(&self) -> usize {
        self.automation.max_concurrent
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub(crate) fn allows_dynamic_hosts(&self) -> bool {
        self.targets.is_none()
    }

    pub(crate) fn check_builtin_params(
        &self,
        host: &str,
        tool_name: &str,
        tool: ToolId,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), ToolError> {
        rules::check_host_params(
            &self.rules,
            host,
            tool_name,
            risk_tier_for_builtin(tool),
            params,
        )
    }

    pub(crate) fn check_binding_params(
        &self,
        host: &str,
        id: BindingId,
        params: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<(), ToolError> {
        let Some(binding) = self.bindings.get(id) else {
            return Err(ToolError::policy_denied(
                "Operation is not authorized",
                false,
            ));
        };
        rules::check_host_params(
            &self.rules,
            host,
            &binding.name,
            risk_tier_for_binding(binding),
            params,
        )
    }

    pub(crate) fn automation_target(
        &self,
        id: BindingId,
        host: &str,
    ) -> Result<ResolvedAutomation<'_>, ToolError> {
        let denied = || ToolError::policy_denied("Operation is not authorized", false);
        let binding = self.bindings.get(id).ok_or_else(denied)?;
        if !self.binding_enabled(id) || binding.automation_authority().is_none() {
            return Err(denied());
        }
        let ssh_executable = self.ssh_executable();
        if binding.has_dynamic_targets() {
            if self.mode != Mode::Workstation {
                return Err(denied());
            }
            destination(host, "host").map_err(|_| {
                ToolError::invalid_argument("Host must be a safe nonempty SSH destination", false)
            })?;
            // A configured destination policy is an allowlist, not a default:
            // an unlisted host is denied rather than used as a raw destination.
            let target = match &self.targets {
                Some(targets) => Some(targets.get(host).ok_or_else(denied)?),
                None => None,
            };
            if let Some(target) = target
                && !target.permits_binding(&binding.name)
            {
                return Err(denied());
            }
            rules::check_host_tool(
                &self.rules,
                host,
                &binding.name,
                risk_tier_for_binding(binding),
            )?;
            static WORKSTATION_SUDO: std::sync::LazyLock<AutomationBecome> =
                std::sync::LazyLock::new(|| AutomationBecome::Sudo {
                    user: "root".to_owned(),
                    executable: "/usr/bin/sudo".to_owned(),
                });
            let workstation_become = match binding.automation_authority() {
                Some(AutomationAuthority::Ordinary) => None,
                Some(AutomationAuthority::Named(name)) => {
                    if !self.capabilities.sudo {
                        return Err(denied());
                    }
                    if let Some(authority) = self.automation.authorities.get(name) {
                        let mapped = authority.targets.get(host).ok_or_else(denied)?;
                        return Ok(ResolvedAutomation {
                            target: Cow::Borrowed(mapped),
                            ssh_config: Some(&authority.ssh_config_file),
                            ssh_executable,
                            r#become: Some(&authority.r#become),
                            agent: authority
                                .ssh_auth_sock
                                .as_deref()
                                .map_or(AutomationAgent::Disabled, AutomationAgent::Fixed),
                            dynamic_python: mapped.python.is_empty(),
                        });
                    }
                    // Workstation sudo fallback: the per-target policy must grant
                    // unrestricted root elevation. Dynamic payloads run Python
                    // scripts, not an allowlisted native program, so a pinned
                    // program list would otherwise be silently bypassed. An open
                    // destination policy has no target, hence no grant.
                    let target = target.ok_or_else(denied)?;
                    if !target.permits_workstation_sudo() {
                        return Err(denied());
                    }
                    Some(&*WORKSTATION_SUDO)
                }
                None => return Err(denied()),
            };
            // Separate-identity elevation must connect to its own SSH host, and
            // only when this binding actually elevates.
            let elevated_destination = workstation_become.as_ref().and_then(|_| {
                target.and_then(|target| target.sudo.workstation_route().elevated_destination())
            });
            if let Some(mapped) = self.automation.targets.get(host) {
                let destination =
                    elevated_destination.map_or_else(|| mapped.destination.clone(), str::to_owned);
                return Ok(ResolvedAutomation {
                    target: Cow::Owned(AutomationTarget {
                        destination,
                        python: mapped.python.clone(),
                    }),
                    ssh_config: self.ssh_config.as_deref(),
                    ssh_executable,
                    r#become: workstation_become,
                    agent: AutomationAgent::Inherit,
                    dynamic_python: mapped.python.is_empty(),
                });
            }
            let resolved_destination = elevated_destination.map_or_else(
                || target.map_or(host.to_owned(), |target| target.ssh_host.clone()),
                str::to_owned,
            );
            return Ok(ResolvedAutomation {
                target: Cow::Owned(AutomationTarget {
                    destination: resolved_destination,
                    python: String::new(),
                }),
                ssh_config: self.ssh_config.as_deref(),
                ssh_executable,
                r#become: workstation_become,
                agent: AutomationAgent::Inherit,
                dynamic_python: true,
            });
        }
        if !binding.targets.iter().any(|target| target == host)
            || !self
                .targets
                .as_ref()
                .and_then(|targets| targets.get(host))
                .is_some_and(|target| target.permits_binding(&binding.name))
        {
            return Err(denied());
        }
        rules::check_host_tool(
            &self.rules,
            host,
            &binding.name,
            risk_tier_for_binding(binding),
        )?;
        match binding.automation_authority() {
            Some(AutomationAuthority::Ordinary) => Ok(ResolvedAutomation {
                target: Cow::Borrowed(self.automation.targets.get(host).ok_or_else(denied)?),
                ssh_config: self.ssh_config.as_deref(),
                ssh_executable,
                r#become: None,
                agent: AutomationAgent::Inherit,
                dynamic_python: false,
            }),
            Some(AutomationAuthority::Named(name)) => {
                let authority = self.automation.authorities.get(name).ok_or_else(denied)?;
                Ok(ResolvedAutomation {
                    target: Cow::Borrowed(authority.targets.get(host).ok_or_else(denied)?),
                    ssh_config: Some(&authority.ssh_config_file),
                    ssh_executable,
                    r#become: Some(&authority.r#become),
                    agent: authority
                        .ssh_auth_sock
                        .as_deref()
                        .map_or(AutomationAgent::Disabled, AutomationAgent::Fixed),
                    dynamic_python: false,
                })
            }
            None => Err(denied()),
        }
    }

    pub(crate) fn automation_hosts(&self) -> impl Iterator<Item = &String> {
        self.targets.iter().flat_map(|targets| targets.keys())
    }

    pub(crate) fn ssh_config(&self) -> Option<&Path> {
        self.ssh_config.as_deref()
    }

    pub(crate) fn ssh_executable(&self) -> &Path {
        &self.ssh_executable
    }

    pub(crate) fn quarantine_state_dir(&self) -> Option<&Path> {
        self.quarantine_state_dir.as_deref()
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) fn bindings(&self) -> &Bindings {
        &self.bindings
    }

    pub(crate) fn requires_preview(&self, host: &str) -> bool {
        rules::requires_preview(&self.rules, host)
    }

    /// Import against exactly the runtime used by this authority at activation.
    pub(crate) fn catalog_runtime(&self, authority: &str) -> Result<Option<PathBuf>, ConfigError> {
        if authority == "automation" {
            return self.automation_runtime();
        }
        let name = authority
            .strip_prefix("automation:")
            .ok_or_else(|| invalid("tools", "invalid catalog automation authority"))?;
        let selected = self
            .automation
            .authorities
            .get(name)
            .ok_or_else(|| invalid("tools", "automation authority is not configured"))?;
        match &selected.bundle {
            Some(path) => Ok(Some(path.clone())),
            None => self.automation_runtime(),
        }
    }

    pub(crate) fn binding_enabled(&self, id: BindingId) -> bool {
        self.capabilities.permits_bindings()
            && self.bindings.get(id).is_some_and(|binding| {
                binding.enabled()
                    && (binding.automation_authority().is_none()
                        || (binding.has_dynamic_targets()
                            && self.mode == Mode::Workstation
                            && self.dynamic_workstation_enabled(binding))
                        || binding.targets.iter().any(|name| {
                            self.targets
                                .as_ref()
                                .and_then(|targets| targets.get(name))
                                .is_some_and(|target| target.permits_binding(&binding.name))
                        }))
            })
    }

    /// A dynamic workstation binding is exposed only when a configured target
    /// would actually authorize it; an empty `[targets]` table exposes none, and
    /// an open destination policy never exposes privileged bindings because it
    /// carries no per-target sudo grant to check.
    fn dynamic_workstation_enabled(&self, binding: &crate::bindings::CompiledBinding) -> bool {
        let Some(targets) = &self.targets else {
            return !matches!(
                binding.automation_authority(),
                Some(AutomationAuthority::Named(_))
            );
        };
        let authority = binding.automation_authority();
        targets.iter().any(|(host_name, target)| {
            target.permits_binding(&binding.name)
                && match authority {
                    Some(AutomationAuthority::Ordinary) => true,
                    Some(AutomationAuthority::Named(name)) => {
                        self.automation
                            .authorities
                            .get(name)
                            .is_some_and(|authority| authority.targets.contains_key(host_name))
                            || (self.capabilities.sudo && target.permits_workstation_sudo())
                    }
                    None => false,
                }
        })
    }

    pub(crate) fn controller_enabled(&self, id: BindingId) -> bool {
        self.binding_enabled(id)
            && self
                .bindings
                .get(id)
                .is_some_and(|binding| binding.is_controller())
    }

    pub(crate) fn resolve_binding<'a>(
        &'a self,
        host: &'a str,
        id: BindingId,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || ToolError::policy_denied("Operation is not authorized", false);
        let binding = self.bindings.get(id).ok_or_else(denied)?;
        if binding.is_controller()
            || !self.binding_enabled(id)
            || !binding.targets.iter().any(|name| name == host)
        {
            return Err(denied());
        }
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        if !target.permits_binding(&binding.name) {
            return Err(denied());
        }
        rules::check_host_tool(
            &self.rules,
            host,
            &binding.name,
            risk_tier_for_binding(binding),
        )?;
        let resolved = match binding.sudo() {
            Some((user, program)) => target.sudo.resolve(host, &target.ssh_host, user, program),
            None => self.resolve_ordinary(host),
        }?;
        if matches!(
            risk_tier_for_binding(binding),
            RiskTier::Change | RiskTier::Exec
        ) && self.requires_preview(host)
        {
            return Err(ToolError::preview_required(
                "Operation has no qualified preview path under require_preview policy",
                false,
            ));
        }
        Ok(resolved)
    }

    pub(crate) fn tool_enabled(&self, tool: ToolId) -> bool {
        self.capabilities.permits(tool) && (tool != ToolId::Sudo || self.has_sudo())
    }

    pub(crate) fn has_sudo(&self) -> bool {
        self.targets.as_ref().is_some_and(|targets| {
            targets
                .values()
                .any(|target| !matches!(target.sudo, Sudo::Disabled))
        })
    }

    pub(crate) fn sudo_mode(&self, host: &str) -> SudoMode {
        self.targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .map_or(SudoMode::Disabled, |target| target.sudo.mode())
    }

    pub(crate) fn resolve<'a>(
        &'a self,
        host: &'a str,
        tool: ToolId,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || ToolError::policy_denied("Operation is not authorized", false);
        match tool {
            ToolId::Targets | ToolId::ReadOutput | ToolId::ClearTargetQuarantine | ToolId::Sudo => {
                return Err(denied());
            }
            ToolId::Exec
            | ToolId::Run
            | ToolId::ReadFile
            | ToolId::WriteFile
            | ToolId::Mkdir
            | ToolId::Rename
            | ToolId::RemoveFile
            | ToolId::RemoveDirectory
            | ToolId::ReplaceFile
            | ToolId::Stat
            | ToolId::ListDirectory => {}
        }
        if !self.capabilities.permits(tool) {
            return Err(denied());
        }
        if self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .is_some_and(|target| !Capabilities::from(target.capabilities).permits(tool))
        {
            return Err(denied());
        }
        rules::check_host_tool(
            &self.rules,
            host,
            tool.wire_name(),
            risk_tier_for_builtin(tool),
        )?;
        let resolved = self.resolve_ordinary(host)?;
        if matches!(
            risk_tier_for_builtin(tool),
            RiskTier::Change | RiskTier::Exec
        ) && self.requires_preview(host)
        {
            return Err(ToolError::preview_required(
                "Operation has no qualified preview path under require_preview policy",
                false,
            ));
        }
        Ok(resolved)
    }

    /// Resolve an operator diagnostic independently of MCP publication profiles.
    /// Only configured logical names qualify, and sudo identities are never selected.
    pub(crate) fn doctor_target<'a>(
        &'a self,
        host: &'a str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(|| {
                ToolError::policy_denied("Host is not a configured logical target", false)
            })?;
        Ok(ResolvedTarget {
            name: host,
            destination: &target.ssh_host,
            role: IdentityRole::Ordinary,
        })
    }

    fn resolve_ordinary<'a>(&'a self, host: &'a str) -> Result<ResolvedTarget<'a>, ToolError> {
        let destination = match &self.targets {
            Some(targets) => targets
                .get(host)
                .map(|target| target.ssh_host.as_str())
                .ok_or_else(|| {
                    ToolError::policy_denied("Host is not a configured logical target", false)
                })?,
            None => {
                destination(host, "host").map_err(|_| {
                    ToolError::invalid_argument(
                        "Host must be a safe nonempty SSH destination",
                        false,
                    )
                })?;
                host
            }
        };
        Ok(ResolvedTarget {
            name: host,
            destination,
            role: IdentityRole::Ordinary,
        })
    }

    pub(crate) fn resolve_sudo<'a>(
        &'a self,
        host: &'a str,
        user: &str,
        program: &str,
    ) -> Result<ResolvedTarget<'a>, ToolError> {
        let denied = || {
            ToolError::policy_denied("Elevated target, user, or program is not authorized", false)
        };
        if !self.capabilities.permits(ToolId::Sudo) {
            return Err(denied());
        }
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        if !Capabilities::from(target.capabilities).permits(ToolId::Sudo) {
            return Err(denied());
        }
        rules::check_host_tool(
            &self.rules,
            host,
            ToolId::Sudo.wire_name(),
            risk_tier_for_builtin(ToolId::Sudo),
        )?;
        let resolved = target.sudo.resolve(host, &target.ssh_host, user, program)?;
        if self.requires_preview(host) {
            return Err(ToolError::preview_required(
                "Operation has no qualified preview path under require_preview policy",
                false,
            ));
        }
        Ok(resolved)
    }

    pub(crate) fn timeout(&self, seconds: Option<u64>) -> Result<std::time::Duration, ToolError> {
        let seconds = seconds.unwrap_or(self.limits.operation_timeout_secs);
        if seconds == 0 || seconds > self.limits.max_timeout_secs {
            return Err(ToolError::invalid_argument(
                "timeout_secs must be positive and not exceed the configured maximum",
                false,
            ));
        }
        Ok(std::time::Duration::from_secs(seconds))
    }
}

fn inspect_automation_authority(config: &Path, socket: Option<&Path>) -> Result<(), ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(config)
        .map_err(|_| {
            invalid(
                "automation.authorities.*.ssh_config_file",
                "cannot read replacement SSH configuration",
            )
        })?;
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(invalid(
            "automation.authorities.*.ssh_config_file",
            "must be a readable file",
        ));
    }
    if let Some(socket) = socket {
        use std::os::unix::fs::FileTypeExt;
        if !std::fs::metadata(socket).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            return Err(invalid(
                "automation.authorities.*.ssh_auth_sock",
                "selected agent socket is unavailable",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        automation_text, binding_definition, builtin, catalog, load_text, named_authority_text,
    };
    use super::*;
    use crate::reply::ErrorCode;

    #[test]
    fn active_authority_inspection_rejects_missing_config_and_non_socket_agent_privately() {
        let text = named_authority_text("baseline", "baseline", true);
        let config = load_text(&text, &[]).unwrap();
        let authority = &config.automation.authorities["ops"];
        let error = inspect_automation_authority(
            &authority.ssh_config_file,
            authority.ssh_auth_sock.as_deref(),
        )
        .err()
        .unwrap();
        assert_eq!(error.field, "automation.authorities.*.ssh_config_file");
        assert!(!error.to_string().contains("private-authority"));

        let dir = tempfile::tempdir().unwrap();
        let ssh_config = dir.path().join("config");
        std::fs::write(&ssh_config, "").unwrap();
        let text = text.replace(
            "ssh_config_file='/private-authority/config'",
            &format!(
                "ssh_config_file={:?}\nssh_auth_sock={:?}",
                ssh_config.to_str().unwrap(),
                ssh_config.to_str().unwrap()
            ),
        );
        let config = load_text(&text, &[]).unwrap();
        let authority = &config.automation.authorities["ops"];
        let error = inspect_automation_authority(
            &authority.ssh_config_file,
            authority.ssh_auth_sock.as_deref(),
        )
        .err()
        .unwrap();
        assert_eq!(error.field, "automation.authorities.*.ssh_auth_sock");
        assert!(!error.to_string().contains(dir.path().to_str().unwrap()));
        let fifo = dir.path().join("config-fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(inspect_automation_authority(&fifo, None).map_err(|error| error.field))
                .unwrap();
        });
        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("named SSH configuration inspection blocked on a FIFO");
        assert_eq!(
            result.err(),
            Some("automation.authorities.*.ssh_config_file")
        );
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn inactive_named_authorities_do_not_inspect_private_files() {
        for (global, target, enabled) in [
            ("baseline", "baseline", false),
            ("files-only", "baseline", true),
            ("baseline", "files-only", true),
        ] {
            let text = named_authority_text(global, target, enabled).replace(
                "become={",
                "ssh_auth_sock='/private-authority/socket'\nbecome={",
            );
            let mut config = load_text(&text, &[]).unwrap();
            assert!(
                !config
                    .activate_automation(&tokio_util::sync::CancellationToken::new())
                    .await
                    .unwrap()
            );
            assert!(config.automation_target(BindingId(0), "server").is_err());
        }
    }

    #[test]
    fn named_authority_resolution_never_falls_back_to_native_or_ordinary_credentials() {
        let text = named_authority_text("baseline", "baseline", true).replace(
            "become={method='sudo',user='root'}",
            "become={method='sudo',user='root',executable='/private-authority/sudo'}",
        );
        for (socket_config, fixed) in [("", false), ("ssh_auth_sock='/selected/agent'\n", true)] {
            let config = load_text(
                &text.replace("become={", &format!("{socket_config}become={{")),
                &[],
            )
            .unwrap();
            let authority = config.automation_target(BindingId(0), "server").unwrap();
            assert_eq!(authority.target.destination, "private-authority-alias");
            assert_eq!(authority.target.python, "/private-authority/python");
            assert_eq!(
                authority.ssh_config,
                Some(Path::new("/private-authority/config"))
            );
            assert_eq!(authority.ssh_executable, config.ssh_executable());
            assert_eq!(
                serde_json::to_value(authority.r#become).unwrap(),
                serde_json::json!({"method":"sudo","user":"root","executable":"/private-authority/sudo"})
            );
            match authority.agent {
                AutomationAgent::Fixed(socket) if fixed => {
                    assert_eq!(socket, Path::new("/selected/agent"))
                }
                AutomationAgent::Disabled if !fixed => {}
                _ => panic!("named authority must not inherit the ambient agent"),
            }
            for host in [
                "native-alias",
                "automation-alias",
                "private-authority-alias",
                "untrusted-secret-host",
            ] {
                let error = config.automation_target(BindingId(0), host).err().unwrap();
                assert_eq!(error.code(), ErrorCode::PolicyDenied);
            }
            let tools = ToolCatalog::new(Vec::new()).unwrap();
            let discovery = serde_json::to_string(&config.targets(&tools)).unwrap();
            assert!(!discovery.contains("private-authority"));
            assert!(!discovery.contains("/selected/"));
        }
    }

    #[tokio::test]
    async fn automation_activation_is_lazy_for_disabled_and_effectively_hidden_bindings() {
        for (global, target, enabled) in [
            ("baseline", "baseline", false),
            ("files-only", "baseline", true),
            ("baseline", "files-only", true),
        ] {
            let text = automation_text(global, target, enabled);
            let mut config = load_text(&text, &[]).unwrap();
            assert!(
                !config
                    .activate_automation(&tokio_util::sync::CancellationToken::new())
                    .await
                    .unwrap()
            );
            assert!(!config.binding_enabled(BindingId(0)));
        }
    }

    #[tokio::test]
    async fn active_automation_requires_real_startup_prerequisites() {
        let mut config = load_text(&automation_text("baseline", "baseline", true), &[]).unwrap();
        let error = config
            .activate_automation(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.field, "automation.bundle");
        let target = config.automation_target(BindingId(0), "server").unwrap();
        assert_eq!(target.target.destination, "automation-alias");
        assert!(
            config
                .automation_target(BindingId(0), "native-alias")
                .is_err()
        );
    }

    #[test]
    fn doctor_resolves_only_configured_names_with_private_denials() {
        for text in [
            "",
            "[targets]",
            "[targets.one]\nssh_host='private-alias'\n\
             [targets.one.sudo]\nmode='separate-identity'\nssh_host='private-elevated'",
        ] {
            let config = load_text(text, &[]).unwrap();
            for host in [
                "private-alias",
                "private-elevated",
                "private-unknown",
                "user@host",
            ] {
                let error = config.doctor_target(host).err().unwrap();
                assert_eq!(error.code(), ErrorCode::PolicyDenied);
                assert!(!error.remote_state_unknown);
                let encoded = serde_json::to_string(&error).unwrap();
                for secret in [
                    "private-alias",
                    "private-elevated",
                    "private-unknown",
                    "user@host",
                ] {
                    assert!(!encoded.contains(secret));
                    assert!(!format!("{error:?}").contains(secret));
                }
            }
            if config.targets.as_ref().is_none_or(BTreeMap::is_empty) {
                assert!(config.doctor_target("one").is_err());
            }
        }
        // The operator-only restriction must not close native open-host mode.
        let open = load_text(
            &format!(
                "{}\ndestination_policy='open'",
                super::super::test_support::capabilities_toml("baseline")
            ),
            &[],
        )
        .unwrap();
        assert_eq!(
            open.resolve("user@host", ToolId::Exec).unwrap().destination,
            "user@host",
        );
    }

    #[test]
    fn doctor_ignores_publication_profiles_but_never_selects_sudo_identity() {
        for global in ["baseline", "actions-only", "files-only", "read-only-files"] {
            for target in ["baseline", "actions-only", "files-only", "read-only-files"] {
                for sudo in [
                    "",
                    "[targets.one.sudo]\nmode='same-account'\n",
                    "[targets.one.sudo]\nmode='separate-identity'\nssh_host='private-elevated'\n",
                ] {
                    let g_caps = super::super::test_support::capabilities_toml(global);
                    let t_caps = super::super::test_support::capabilities_toml(target);
                    let config = load_text(
                        &format!(
                            "{g_caps}\n[targets.one]\n\
                             ssh_host='private-ordinary'\n{t_caps}\n{sudo}"
                        ),
                        &[],
                    )
                    .unwrap();
                    let resolved = config.doctor_target("one").unwrap();
                    assert_eq!(resolved.name, "one");
                    assert_eq!(resolved.destination, "private-ordinary");
                    assert_eq!(resolved.role, IdentityRole::Ordinary);
                    assert_eq!(
                        config.resolve("one", ToolId::Exec).is_ok(),
                        global == "baseline" && target == "baseline",
                    );
                    assert_eq!(
                        config.resolve("one", ToolId::ReadFile).is_ok(),
                        global != "actions-only" && target != "actions-only",
                    );
                }
            }
        }
    }

    #[test]
    fn catalog_rejects_duplicate_ids_even_with_distinct_names() {
        let error = ToolCatalog::new(vec![
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "first".into(),
            },
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "second".into(),
            },
        ])
        .unwrap_err();
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn catalog_rejects_duplicate_names_before_disabled_routes_can_be_removed() {
        let error = ToolCatalog::new(vec![
            ToolEntry {
                id: ToolKey::Builtin(ToolId::Exec),
                name: "secret_collision".into(),
            },
            ToolEntry {
                id: ToolKey::Binding(BindingId(0)),
                name: "secret_collision".into(),
            },
        ])
        .unwrap_err();
        assert!(!format!("{error:?}").contains("secret_collision"));
    }

    #[test]
    fn binding_policy_intersects_selection_profiles_and_declared_targets() {
        for (global, globally_allowed) in [
            ("baseline", true),
            ("actions-only", true),
            ("read-only-files", false),
            ("files-only", false),
        ] {
            for (target, target_allowed) in [
                ("baseline", true),
                ("actions-only", true),
                ("read-only-files", false),
                ("files-only", false),
            ] {
                for selected in [false, true] {
                    let g_caps = super::super::test_support::capabilities_toml(global);
                    let t_caps = super::super::test_support::capabilities_toml(target);
                    let text = format!(
                        "{g_caps}\nenabled_tools={enabled}\n\
                         [targets.one]\nssh_host='ordinary-private'\n{t_caps}\n\
                         [targets.one.sudo]\nmode='separate-identity'\nssh_host='elevated-private'\n\
                         [targets.two]\nssh_host='other-private'\n{definition}",
                        enabled = if selected { "['observe']" } else { "[]" },
                        definition = binding_definition(),
                    );
                    let config = load_text(&text, &[]).unwrap();
                    let (id, binding) = config.bindings().entries().next().unwrap();
                    assert_eq!(config.binding_enabled(id), selected && globally_allowed);
                    let allowed = selected && globally_allowed && target_allowed;
                    let result = config.resolve_binding("one", id);
                    assert_eq!(result.is_ok(), allowed, "{global}/{target}/{selected}");
                    if let Ok(resolved) = result {
                        assert_eq!(resolved.destination, "ordinary-private");
                        assert_eq!(resolved.role, IdentityRole::Ordinary);
                    } else {
                        let error = result.err().unwrap();
                        assert_eq!(error.code(), ErrorCode::PolicyDenied);
                        assert!(!error.remote_state_unknown);
                    }
                    for host in ["two", "ordinary-private", "elevated-private", "unknown"] {
                        assert!(config.resolve_binding(host, id).is_err());
                    }
                    let tools = ToolCatalog::new(vec![ToolEntry {
                        id: ToolKey::Binding(id),
                        name: binding.name.clone().into(),
                    }])
                    .unwrap();
                    let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
                    let rows = discovery["targets"].as_array().unwrap();
                    let one = rows.iter().find(|row| row["name"] == "one").unwrap();
                    assert_eq!(
                        one["permitted_operations"],
                        if allowed {
                            serde_json::json!(["observe"])
                        } else {
                            serde_json::json!([])
                        }
                    );
                    let two = rows.iter().find(|row| row["name"] == "two").unwrap();
                    assert_eq!(two["permitted_operations"], serde_json::json!([]));
                }
            }
        }
    }

    #[test]
    fn fixed_sudo_bindings_intersect_profiles_without_exposing_generic_sudo() {
        let elevated = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        let ordinary = binding_definition().replace("[tools.observe]", "[tools.ordinary]");
        for (mode, alias, destination, role) in [
            (
                "same-account",
                "",
                "ordinary-private",
                IdentityRole::Ordinary,
            ),
            (
                "separate-identity",
                "ssh_host='elevated-private'\n",
                "elevated-private",
                IdentityRole::Elevated,
            ),
        ] {
            for (global, global_allowed) in [
                ("baseline", true),
                ("actions-only", true),
                ("files-only", false),
                ("read-only-files", false),
            ] {
                for (profile, target_allowed) in [
                    ("baseline", true),
                    ("actions-only", true),
                    ("files-only", false),
                    ("read-only-files", false),
                ] {
                    for selected in [false, true] {
                        let g_caps = super::super::test_support::capabilities_toml(global);
                        let t_caps = super::super::test_support::capabilities_toml(profile);
                        let config = load_text(
                            &format!(
                                "{g_caps}\nenabled_tools={enabled}\n\
                                 [targets.one]\nssh_host='ordinary-private'\n{t_caps}\n\
                                 [targets.one.sudo]\nmode='{mode}'\n{alias}\
                                 users=['root']\nprograms=['/usr/bin/id']\n\
                                 [targets.two]\nssh_host='other-private'\n{elevated}{ordinary}",
                                enabled = if selected {
                                    "['observe','ordinary']"
                                } else {
                                    "[]"
                                },
                            ),
                            &[],
                        )
                        .unwrap();
                        let mut entries = vec![ToolEntry {
                            id: ToolKey::Builtin(ToolId::Sudo),
                            name: "generic-sudo".into(),
                        }];
                        for (id, binding) in config.bindings().entries() {
                            let allowed = selected && global_allowed && target_allowed;
                            assert_eq!(config.binding_enabled(id), selected && global_allowed);
                            let result = config.resolve_binding("one", id);
                            assert_eq!(
                                result.is_ok(),
                                allowed,
                                "{mode}/{global}/{profile}/{selected}/{}",
                                binding.name,
                            );
                            if let Ok(resolved) = result {
                                assert_eq!(resolved.name, "one");
                                let expected = if binding.name == "observe" {
                                    (destination, role)
                                } else {
                                    ("ordinary-private", IdentityRole::Ordinary)
                                };
                                assert_eq!((resolved.destination, resolved.role), expected);
                            } else {
                                let error = result.err().unwrap();
                                assert_eq!(error.code(), ErrorCode::PolicyDenied);
                                assert!(!error.remote_state_unknown);
                            }
                            for host in ["two", "ordinary-private", "elevated-private", "unknown"] {
                                assert!(config.resolve_binding(host, id).is_err(), "{host}");
                            }
                            entries.push(ToolEntry {
                                id: ToolKey::Binding(id),
                                name: binding.name.clone().into(),
                            });
                        }
                        let tools = ToolCatalog::new(entries).unwrap();
                        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
                        let rows = discovery["targets"].as_array().unwrap();
                        let one = rows.iter().find(|row| row["name"] == "one").unwrap();
                        let generic_allowed = global == "baseline" && profile == "baseline";
                        let mut expected = Vec::new();
                        if generic_allowed {
                            expected.push("generic-sudo");
                        }
                        if selected && global_allowed && target_allowed {
                            expected.extend(["observe", "ordinary"]);
                        }
                        assert_eq!(one["permitted_operations"], serde_json::json!(expected));
                        assert_eq!(
                            config.resolve_sudo("one", "root", "/usr/bin/id").is_ok(),
                            generic_allowed,
                        );
                        assert_eq!(config.tool_enabled(ToolId::Sudo), global == "baseline");
                        for tool in [ToolId::Exec, ToolId::Run] {
                            assert_eq!(config.resolve("one", tool).is_ok(), generic_allowed,);
                        }
                        let two = rows.iter().find(|row| row["name"] == "two").unwrap();
                        assert_eq!(two["permitted_operations"], serde_json::json!([]));
                    }
                }
            }
        }
    }

    #[test]
    fn binding_dispatch_and_discovery_recheck_sudo_policy_without_affecting_ordinary() {
        let definition = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        let ordinary = binding_definition().replace("[tools.observe]", "[tools.ordinary]");
        for (users, programs, disabled, allowed) in [
            (vec!["root".to_owned()], None, false, true),
            (
                vec!["root".to_owned()],
                Some(vec!["/usr/bin/id".to_owned()]),
                false,
                true,
            ),
            (vec!["service".to_owned()], None, false, false),
            (vec!["root".to_owned()], Some(vec![]), false, false),
            (
                vec!["root".to_owned()],
                Some(vec!["/bin/id".to_owned()]),
                false,
                false,
            ),
            (vec!["root".to_owned()], None, true, false),
        ] {
            let caps = super::super::test_support::capabilities_toml("actions-only");
            let mut config = load_text(
                &format!(
                    "{caps}\nenabled_tools=['observe','ordinary']\n\
                     [targets.one]\nssh_host='ordinary-private'\n{caps}\n\
                     [targets.one.sudo]\nmode='same-account'\n{definition}{ordinary}",
                ),
                &[],
            )
            .unwrap();
            // Exercise runtime/discovery independently of startup rejection.
            config
                .targets
                .as_mut()
                .unwrap()
                .get_mut("one")
                .unwrap()
                .sudo = if disabled {
                Sudo::Disabled
            } else {
                Sudo::SameAccount { users, programs }
            };
            let mut entries = Vec::new();
            for (id, binding) in config.bindings().entries() {
                let permitted = binding.name == "ordinary" || allowed;
                assert_eq!(config.resolve_binding("one", id).is_ok(), permitted);
                entries.push(ToolEntry {
                    id: ToolKey::Binding(id),
                    name: binding.name.clone().into(),
                });
            }
            let tools = ToolCatalog::new(entries).unwrap();
            let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                if allowed {
                    serde_json::json!(["observe", "ordinary"])
                } else {
                    serde_json::json!(["ordinary"])
                },
            );
            assert!(!config.tool_enabled(ToolId::Sudo));
        }
    }

    #[test]
    fn omitted_profile_closes_generic_authority_and_explicit_baseline_preserves_it() {
        for (root, native_allowed) in [
            ("", false),
            (
                "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n",
                true,
            ),
        ] {
            let config = load_text(
                &format!(
                    "{root}[targets.one]\nssh_host='ordinary'\n\
                     [targets.one.sudo]\nmode='separate-identity'\nssh_host='elevated'\n\
                     users=['service']\nprograms=['/usr/bin/id']"
                ),
                &[],
            )
            .unwrap();
            let mut tools = catalog();
            tools.retain(|id| config.tool_enabled(builtin(id)));
            assert_eq!(tools.entries.len(), if native_allowed { 8 } else { 1 });
            if !native_allowed {
                for entry in catalog().entries {
                    if builtin(entry.id) != ToolId::Targets {
                        assert_eq!(
                            config
                                .resolve("one", builtin(entry.id))
                                .err()
                                .unwrap()
                                .code(),
                            ErrorCode::PolicyDenied
                        );
                    }
                }
                assert!(
                    config
                        .resolve_sudo("one", "service", "/usr/bin/id")
                        .is_err()
                );
                assert_eq!(
                    serde_json::to_value(config.targets(&tools)).unwrap()["targets"][0]["permitted_operations"],
                    serde_json::json!([])
                );
                continue;
            }
            for entry in &tools.entries {
                if !matches!(builtin(entry.id), ToolId::Targets | ToolId::Sudo) {
                    let resolved = config.resolve("one", builtin(entry.id)).unwrap();
                    assert_eq!(resolved.destination, "ordinary");
                    assert_eq!(resolved.role, IdentityRole::Ordinary);
                }
            }
            let elevated = config
                .resolve_sudo("one", "service", "/usr/bin/id")
                .unwrap();
            assert_eq!(elevated.destination, "elevated");
            assert_eq!(elevated.role, IdentityRole::Elevated);
            assert!(config.resolve_sudo("one", "root", "/usr/bin/id").is_err());
            assert!(config.resolve_sudo("one", "service", "/bin/sh").is_err());
            assert_eq!(
                serde_json::to_value(config.targets(&tools)).unwrap()["targets"][0]["permitted_operations"],
                serde_json::json!([
                    "a-run",
                    "b-list",
                    "c-write",
                    "m-elevate",
                    "n-read",
                    "q-stat",
                    "z-exec"
                ])
            );
        }
    }

    #[test]
    fn restrictive_profiles_publish_authorize_and_discover_only_their_file_sets() {
        for (profile, published, permitted) in [
            (
                "read-only-files",
                vec!["0-global-discovery", "b-list", "n-read", "q-stat"],
                vec!["b-list", "n-read", "q-stat"],
            ),
            (
                "files-only",
                vec![
                    "0-global-discovery",
                    "b-list",
                    "c-write",
                    "n-read",
                    "q-stat",
                ],
                vec!["b-list", "c-write", "n-read", "q-stat"],
            ),
            ("actions-only", vec!["0-global-discovery"], vec![]),
        ] {
            let caps = super::super::test_support::capabilities_toml(profile);
            let config = load_text(
                &format!(
                    "{caps}\n[targets.one]\nssh_host='private-alias'\n\
                     description='execution allowed'\nlabels={{exec='enabled'}}\n\
                     [targets.one.sudo]\nmode='same-account'"
                ),
                &[],
            )
            .unwrap();
            let all = catalog();
            let mut active = catalog();
            active.retain(|id| config.tool_enabled(builtin(id)));
            assert_eq!(
                active
                    .entries
                    .iter()
                    .map(|entry| entry.name.as_ref())
                    .collect::<Vec<_>>(),
                published,
                "{profile}"
            );
            for entry in &all.entries {
                if matches!(builtin(entry.id), ToolId::Targets | ToolId::Sudo) {
                    continue;
                }
                let result = config.resolve("one", builtin(entry.id));
                if permitted.contains(&entry.name.as_ref()) {
                    assert_eq!(result.unwrap().destination, "private-alias", "{profile}");
                } else {
                    let error = result.err().unwrap();
                    assert_eq!(
                        error.code(),
                        ErrorCode::PolicyDenied,
                        "{profile}/{:?}",
                        entry.id
                    );
                    assert!(!error.remote_state_unknown);
                    assert!(!format!("{error:?}").contains("private"));
                    assert!(!format!("{error:?}").contains(profile));
                }
            }
            assert_eq!(
                config
                    .resolve_sudo("one", "root", "/bin/sh")
                    .err()
                    .unwrap()
                    .code(),
                ErrorCode::PolicyDenied
            );
            // Even an unfiltered catalogue cannot advertise a profile-disabled operation.
            let discovery = serde_json::to_value(config.targets(&all)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                serde_json::json!(permitted),
                "{profile}"
            );
            assert_eq!(discovery["targets"][0]["sudo_mode"], "same-account");
            assert_eq!(discovery["targets"][0]["observed_capabilities"], "unknown");
        }
    }

    #[test]
    fn target_profiles_intersect_global_policy_without_changing_publication() {
        let config = load_text(
            &format!(
                "{}\n\
                 [targets.base]\nssh_host='base-alias'\n{}\n\
                 [targets.reader]\nssh_host='reader-alias'\n{}\n\
                 [targets.actions]\nssh_host='actions-alias'\n{}\n\
                 [targets.implicit]\nssh_host='implicit-alias'",
                super::super::test_support::capabilities_toml("files-only"),
                super::super::test_support::capabilities_toml("baseline"),
                super::super::test_support::capabilities_toml("read-only-files"),
                super::super::test_support::capabilities_toml("actions-only"),
            ),
            &[],
        )
        .unwrap();
        let mut tools = catalog();
        tools.retain(|id| config.tool_enabled(builtin(id)));
        assert!(tools.contains(ToolKey::Builtin(ToolId::WriteFile)));
        assert!(!tools.contains(ToolKey::Builtin(ToolId::Exec)));
        assert!(!tools.contains(ToolKey::Builtin(ToolId::Run)));
        for name in ["base", "implicit"] {
            assert!(config.resolve(name, ToolId::WriteFile).is_ok());
            assert!(config.resolve(name, ToolId::Exec).is_err());
        }
        assert!(config.resolve("reader", ToolId::ReadFile).is_ok());
        assert!(config.resolve("reader", ToolId::WriteFile).is_err());
        assert!(config.resolve("actions", ToolId::ReadFile).is_err());
        tools.retain(|id| id != ToolKey::Builtin(ToolId::Stat));
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        let rows = discovery["targets"].as_array().unwrap();
        let operations = |name: &str| &rows.iter().find(|row| row["name"] == name).unwrap()["permitted_operations"];
        assert_eq!(
            operations("base"),
            &serde_json::json!(["b-list", "c-write", "n-read"])
        );
        assert_eq!(operations("implicit"), operations("base"));
        assert_eq!(
            operations("reader"),
            &serde_json::json!(["b-list", "n-read"])
        );
        assert_eq!(operations("actions"), &serde_json::json!([]));
    }

    #[test]
    fn restrictive_targets_do_not_hide_baseline_routes_or_authorize_sudo() {
        let config = load_text(
            &format!(
                "{}\n[targets.reader]\nssh_host='private-reader'\n{}\n\
                 [targets.reader.sudo]\nmode='separate-identity'\nssh_host='private-elevated'\n\
                 [targets.files]\nssh_host='private-files'\n{}\n\
                 [targets.files.sudo]\nmode='same-account'\n\
                 [targets.actions]\nssh_host='private-actions'\n{}\n\
                 [targets.actions.sudo]\nmode='same-account'\n\
                 [targets.disabled]\nssh_host='private-disabled'\n{}\n\
                 [targets.empty]\nssh_host='private-empty'\n{}\n\
                 [targets.empty.sudo]\nmode='same-account'\nprograms=[]",
                super::super::test_support::capabilities_toml("baseline"),
                super::super::test_support::capabilities_toml("read-only-files"),
                super::super::test_support::capabilities_toml("files-only"),
                super::super::test_support::capabilities_toml("actions-only"),
                super::super::test_support::capabilities_toml("baseline"),
                super::super::test_support::capabilities_toml("baseline"),
            ),
            &[],
        )
        .unwrap();
        assert!(config.tool_enabled(ToolId::Exec));
        assert!(config.tool_enabled(ToolId::Run));
        assert!(config.tool_enabled(ToolId::Sudo));
        for name in ["reader", "files", "actions", "disabled", "empty"] {
            let error = config.resolve_sudo(name, "root", "/bin/sh").err().unwrap();
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(!error.remote_state_unknown);
        }
        for name in ["reader", "files", "actions"] {
            assert!(config.resolve(name, ToolId::Exec).is_err());
            assert!(config.resolve(name, ToolId::Run).is_err());
        }
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        for row in discovery["targets"].as_array().unwrap() {
            assert!(
                !row["permitted_operations"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("m-elevate"))
            );
        }
    }

    #[test]
    fn profile_policy_preserves_open_validation_closed_targets_and_resolver_boundaries() {
        let open = load_text(
            &format!(
                "destination_policy='open'\n{}",
                super::super::test_support::capabilities_toml("read-only-files")
            ),
            &[],
        )
        .unwrap();
        let resolved = open.resolve("user@example", ToolId::ReadFile).unwrap();
        assert_eq!(resolved.destination, "user@example");
        assert_eq!(resolved.role, IdentityRole::Ordinary);
        assert_eq!(
            open.resolve("-option", ToolId::ReadFile)
                .err()
                .unwrap()
                .code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            open.resolve("user@example", ToolId::WriteFile)
                .err()
                .unwrap()
                .code(),
            ErrorCode::PolicyDenied
        );
        let closed = load_text(
            &format!(
                "{}\n[targets.logical]\nssh_host='private-alias'",
                super::super::test_support::capabilities_toml("read-only-files")
            ),
            &[],
        )
        .unwrap();
        assert!(closed.resolve("logical", ToolId::ReadFile).is_ok());
        assert!(closed.resolve("private-alias", ToolId::ReadFile).is_err());
        let empty = load_text(
            &format!(
                "{}\n[targets]",
                super::super::test_support::capabilities_toml("files-only")
            ),
            &[],
        )
        .unwrap();
        assert!(empty.tool_enabled(ToolId::WriteFile));
        assert!(empty.tool_enabled(ToolId::Targets));
        assert!(empty.resolve("anything", ToolId::ReadFile).is_err());
        let baseline_empty = load_text(
            &format!(
                "{}\n[targets]",
                super::super::test_support::capabilities_toml("baseline")
            ),
            &[],
        )
        .unwrap();
        assert!(baseline_empty.tool_enabled(ToolId::Exec));
        assert!(baseline_empty.tool_enabled(ToolId::WriteFile));
        assert!(!baseline_empty.tool_enabled(ToolId::Sudo));
        for tool in [ToolId::Targets, ToolId::Sudo] {
            assert_eq!(
                closed.resolve("logical", tool).err().unwrap().code(),
                ErrorCode::PolicyDenied
            );
            assert_eq!(
                load_text("", &[])
                    .unwrap()
                    .resolve("host", tool)
                    .err()
                    .unwrap()
                    .code(),
                ErrorCode::PolicyDenied
            );
        }
        let discovery = serde_json::to_value(open.targets(&catalog())).unwrap();
        assert_eq!(discovery["mode"], "open");
        assert_eq!(discovery["targets"], serde_json::json!([]));
    }

    #[test]
    fn controller_activation_uses_global_profile_without_target_capabilities() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"abc").unwrap();
        let definition = format!(
            r#"
[controller]
workspace_root={root:?}
[targets.server]
ssh_host="never-used"
capabilities = {{ file_read = true }}
[tools.local]
description="Controller observation"
revision="1"
authority="controller"
effects=["read"]
execution={{kind="controller_script",source={{path={source:?},content_sha256="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},interpreter={{program="/bin/sh",argv=[]}}}}
input_schema={{type="object",additionalProperties=false,required=[],properties={{}}}}
result={{kind="controller_command"}}
"#,
            root = dir.path().to_str().unwrap(),
            source = source.to_str().unwrap()
        );
        for profile in ["baseline", "actions-only"] {
            let caps = super::super::test_support::capabilities_toml(profile);
            let config = load_text(
                &format!("{caps}\nenabled_tools=['local']\n{definition}"),
                &[],
            )
            .unwrap();
            assert!(config.controller_enabled(BindingId(0)));
            assert!(config.resolve_binding("server", BindingId(0)).is_err());
            let catalog = ToolCatalog::new(vec![ToolEntry {
                id: ToolKey::Binding(BindingId(0)),
                name: "local".into(),
            }])
            .unwrap();
            let discovery = serde_json::to_value(config.targets(&catalog)).unwrap();
            assert_eq!(
                discovery["targets"][0]["permitted_operations"],
                serde_json::json!([])
            );
        }
        std::fs::remove_file(source).unwrap();
        for profile in ["files-only", "read-only-files"] {
            let caps = super::super::test_support::capabilities_toml(profile);
            let config = load_text(
                &format!("{caps}\nenabled_tools=['local']\n{definition}"),
                &[],
            )
            .unwrap();
            assert!(!config.binding_enabled(BindingId(0)));
            assert!(!config.controller_enabled(BindingId(0)));
        }
        assert!(load_text(&definition, &[]).is_ok());
        assert!(load_text(&format!("enabled_tools=['local']\n{definition}"), &[]).is_err());
    }

    #[test]
    fn missing_and_empty_targets_are_closed_and_open_mode_is_explicit() {
        for source in ["", "[targets]", "destination_policy='configured'"] {
            let config = load_text(source, &[]).unwrap();
            let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
            assert_eq!(discovery["mode"], "configured", "{source}");
            assert_eq!(discovery["targets"], serde_json::json!([]), "{source}");
            assert_eq!(
                config
                    .resolve("user@example", ToolId::Exec)
                    .err()
                    .unwrap()
                    .code(),
                ErrorCode::PolicyDenied,
                "{source}"
            );
        }
        let open = load_text(
            &format!(
                "{}\ndestination_policy='open'",
                super::super::test_support::capabilities_toml("baseline")
            ),
            &[],
        )
        .unwrap();
        assert!(open.resolve("user@example", ToolId::Exec).is_ok());
        let discovery = serde_json::to_value(open.targets(&catalog())).unwrap();
        assert_eq!(discovery["mode"], "open");
        for source in [
            "destination_policy='open'\n[targets]",
            "destination_policy='open'\n[targets.one]\nssh_host='one'",
            "destination_policy='unknown'",
            "destination_policy=true",
        ] {
            assert!(load_text(source, &[]).is_err(), "{source}");
        }
    }

    #[test]
    fn automation_environment_reference_is_validated_only_when_requested() {
        let config = load_text("", &[]).unwrap();
        assert_eq!(
            config
                .automation_bundle_with(|key| {
                    assert_eq!(key, "ESTUS_ANSIBLE_BUNDLE");
                    Some("/nonexistent-private-bundle".into())
                })
                .unwrap(),
            Some(PathBuf::from("/nonexistent-private-bundle"))
        );
        for value in [
            String::new(),
            "private-relative-bundle".to_owned(),
            "/private\0bundle".to_owned(),
            format!("/{}", "x".repeat(4096)),
        ] {
            let error = config
                .automation_bundle_with(|_| Some(value.into()))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "automation.bundle: must be a bounded absolute path"
            );
        }
        let boundary = format!("/{}", "x".repeat(4095));
        assert_eq!(
            config
                .automation_bundle_with(|_| Some(boundary.clone().into()))
                .unwrap(),
            Some(PathBuf::from(boundary))
        );
    }

    #[cfg(unix)]
    #[test]
    fn automation_non_unicode_environment_reference_is_sanitized_on_use() {
        use std::os::unix::ffi::OsStringExt;
        let config = load_text("", &[]).unwrap();
        let error = config
            .automation_bundle_with(|_| Some(OsString::from_vec(vec![b'/', 0xff])))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "automation.bundle: must be a bounded absolute path"
        );
    }

    #[test]
    fn configured_dispatch_never_accepts_aliases_and_open_dispatch_is_validated() {
        let config = load_text(
            &format!(
                "{}\n[targets.logical]\nssh_host='ordinary-alias'",
                super::super::test_support::capabilities_toml("baseline")
            ),
            &[],
        )
        .unwrap();
        let resolved = config.resolve("logical", ToolId::Exec).unwrap();
        assert_eq!(
            (resolved.name, resolved.destination, resolved.role),
            ("logical", "ordinary-alias", IdentityRole::Ordinary)
        );
        for host in ["ordinary-alias", "unknown", ""] {
            assert_eq!(
                config.resolve(host, ToolId::Exec).err().unwrap().code(),
                ErrorCode::PolicyDenied
            );
        }
        let empty = load_text("[targets]", &[]).unwrap();
        assert_eq!(
            empty
                .resolve("anything", ToolId::Exec)
                .err()
                .unwrap()
                .code(),
            ErrorCode::PolicyDenied
        );
        let open = load_text(
            &format!(
                "{}\ndestination_policy='open'",
                super::super::test_support::capabilities_toml("baseline")
            ),
            &[],
        )
        .unwrap();
        let resolved = open.resolve("user@example", ToolId::Exec).unwrap();
        assert_eq!(
            (resolved.name, resolved.destination),
            ("user@example", "user@example")
        );
        for host in ["", "-option", "host name", "host\0name"] {
            assert_eq!(
                open.resolve(host, ToolId::Exec).err().unwrap().code(),
                ErrorCode::InvalidArgument
            );
        }
        assert!(!open.has_sudo());
        assert_eq!(
            open.resolve_sudo("user@example", "root", "/bin/id")
                .err()
                .unwrap()
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn sudo_dispatch_uses_exact_policy_and_the_configured_role() {
        let config = load_text(
            r#"
capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
[targets.same]
ssh_host = "ordinary"
[targets.same.sudo]
mode = "same-account"
programs = ["/usr/bin/id"]
[targets.split]
ssh_host = "reader"
[targets.split.sudo]
mode = "separate-identity"
ssh_host = "operator"
users = ["service"]
programs = ["/usr/bin/printf"]
[targets.empty]
ssh_host = "empty"
[targets.empty.sudo]
mode = "same-account"
programs = []
[targets.unrestricted]
ssh_host = "unrestricted"
[targets.unrestricted.sudo]
mode = "same-account"
"#,
            &[],
        )
        .unwrap();
        assert!(config.has_sudo());
        let same = config.resolve_sudo("same", "root", "/usr/bin/id").unwrap();
        assert_eq!(
            (same.name, same.destination, same.role),
            ("same", "ordinary", IdentityRole::Ordinary)
        );
        let split = config
            .resolve_sudo("split", "service", "/usr/bin/printf")
            .unwrap();
        assert_eq!(
            (split.name, split.destination, split.role),
            ("split", "operator", IdentityRole::Elevated)
        );
        assert_eq!(
            config
                .resolve("split", ToolId::ReadFile)
                .unwrap()
                .destination,
            "reader"
        );
        for (host, user, program) in [
            ("same", "service", "/usr/bin/id"),
            ("same", "root", "/bin/id"),
            ("same", "root", "/usr/bin/id-extra"),
            ("same", "root", "id"),
            ("split", "root", "/usr/bin/printf"),
            ("operator", "service", "/usr/bin/printf"),
            ("empty", "root", "/usr/bin/id"),
        ] {
            assert_eq!(
                config
                    .resolve_sudo(host, user, program)
                    .err()
                    .unwrap()
                    .code(),
                ErrorCode::PolicyDenied,
                "{host}/{user}/{program}"
            );
        }
        assert_eq!(
            config
                .resolve_sudo("unrestricted", "root", "/opt/arbitrary")
                .unwrap()
                .role,
            IdentityRole::Ordinary
        );
        assert_eq!(
            config.timeout(Some(600)).unwrap(),
            std::time::Duration::from_secs(600)
        );
        for seconds in [0, 601] {
            assert_eq!(
                config.timeout(Some(seconds)).err().unwrap().code(),
                ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn capabilities_combine_independently_and_rules_narrow_by_intersection() {
        let config = load_text(
            r#"
mode = "headless"
capabilities = { named = true, file_read = true }
[targets.prod-web-01]
ssh_host = "prod-web-01"
[targets.dev-01]
ssh_host = "dev-01"
[rules."prod-*"]
deny_tiers = ["exec", "change"]
allow_tools = ["observe_stat", "inspect_file", "observe_cpu"]
[rules."*-web-*".constraints.inspect_file.path]
enum = ["/etc/nginx/nginx.conf", "/etc/hosts"]
[rules."prod-web-*"]
allow_tools = ["observe_stat", "inspect_file"]
"#,
            &[],
        )
        .unwrap();
        assert!(config.tool_enabled(ToolId::Stat));
        assert!(config.tool_enabled(ToolId::ReadFile));
        assert!(config.tool_enabled(ToolId::ClearTargetQuarantine));
        assert!(!config.tool_enabled(ToolId::WriteFile));
        assert!(!config.tool_enabled(ToolId::Exec));
        assert!(config.resolve("prod-web-01", ToolId::Stat).is_ok());
        assert!(config.resolve("prod-web-01", ToolId::ReadFile).is_ok());
        assert!(config.resolve("prod-web-01", ToolId::Exec).is_err());
        // Rule intersection on prod-web-01 drops observe_cpu (not in prod-web-* allow_tools).
        assert!(
            rules::check_host_tool(
                &config.rules,
                "prod-web-01",
                "observe_cpu",
                RiskTier::Observe
            )
            .is_err()
        );
        // Parameter constraint on prod-web-01 permits /etc/hosts, denies /etc/shadow.
        let ok_params = serde_json::json!({"path": "/etc/hosts"})
            .as_object()
            .unwrap()
            .clone();
        let bad_params = serde_json::json!({"path": "/etc/shadow"})
            .as_object()
            .unwrap()
            .clone();
        assert!(
            config
                .check_builtin_params("prod-web-01", "inspect_file", ToolId::ReadFile, &ok_params)
                .is_ok()
        );
        assert!(
            config
                .check_builtin_params("prod-web-01", "inspect_file", ToolId::ReadFile, &bad_params,)
                .is_err()
        );
        // Conflicting constraints across overlapping wildcard patterns reject configuration.
        let conflict = load_text(
            r#"
[rules."prod-*".constraints.inspect_file.path]
enum = ["/etc/hosts"]
[rules."*-web".constraints.inspect_file.path]
enum = ["/etc/passwd"]
"#,
            &[],
        );
        assert_eq!(conflict.err().unwrap().field, "rules");
    }

    /// Dynamic workstation tool with an ordinary and a named authority route.
    /// `authority` is either empty or a complete `[automation.authorities.*]`.
    fn dynamic_workstation_text(targets: &str, authority: &str) -> String {
        format!(
            r#"
mode = "workstation"
capabilities = {{ named = true, file_read = true, file_write = true, exec = true, sudo = true }}
destination_policy = "configured"
enabled_tools = ["automation", "catalog"]
{targets}
{authority}
[tools.automation]
description = "Dynamic ordinary automation"
revision = "1"
authority = "automation"
effects = ["read"]
execution = {{ kind = "ansible_module", module = "ansible.builtin.stat" }}
result = {{ kind = "ansible_summary" }}
input_schema = {{ type = "object", additionalProperties = false, required = [], properties = {{}} }}

[tools.catalog]
description = "Dynamic named automation"
revision = "1"
authority = "automation:catalog"
effects = ["read"]
execution = {{ kind = "ansible_module", module = "ansible.builtin.stat" }}
result = {{ kind = "ansible_summary" }}
input_schema = {{ type = "object", additionalProperties = false, required = [], properties = {{}} }}
"#
        )
    }

    fn dynamic_ids(config: &Config) -> (BindingId, BindingId) {
        let mut ordinary = None;
        let mut named = None;
        for (id, binding) in config.bindings.entries() {
            match binding.name.as_str() {
                "automation" => ordinary = Some(id),
                "catalog" => named = Some(id),
                _ => {}
            }
        }
        (
            ordinary.expect("ordinary dynamic binding missing"),
            named.expect("named dynamic binding missing"),
        )
    }

    #[test]
    fn open_destination_policy_never_exposes_or_elevates_privileged_bindings() {
        // Workstation mode without a `[targets]` table carries no per-target sudo
        // grant, so a named (privileged) authority must not be published and must
        // never resolve to the uncontrolled workstation root fallback.
        let text = dynamic_workstation_text("", "").replace(
            "destination_policy = \"configured\"",
            "destination_policy = \"open\"",
        );
        let config = load_text(&text, &[]).unwrap();
        assert!(config.targets.is_none(), "open policy has no targets table");
        assert_eq!(config.capabilities, Capabilities::all());
        let (ordinary, named) = dynamic_ids(&config);
        assert!(config.binding_enabled(ordinary));
        assert!(
            !config.binding_enabled(named),
            "privileged binding must not be published in open mode"
        );
        for host in ["db", "unlisted", "server"] {
            let error = config.automation_target(named, host).err().unwrap();
            assert_eq!(error.code(), ErrorCode::PolicyDenied, "{host}");
        }
        let resolved = config.automation_target(ordinary, "db").unwrap();
        assert_eq!(resolved.target.destination, "db");
        assert!(resolved.r#become.is_none(), "ordinary must not elevate");
    }

    #[test]
    fn empty_targets_table_disables_and_denies_every_dynamic_binding() {
        let config = load_text(&dynamic_workstation_text("[targets]", ""), &[]).unwrap();
        assert!(config.targets.as_ref().is_some_and(BTreeMap::is_empty));
        let (ordinary, named) = dynamic_ids(&config);
        assert!(!config.binding_enabled(ordinary));
        assert!(!config.binding_enabled(named));
        for id in [ordinary, named] {
            for host in ["db", "unlisted", "server"] {
                assert_eq!(
                    config.automation_target(id, host).err().unwrap().code(),
                    ErrorCode::PolicyDenied,
                    "{id:?} {host}"
                );
            }
        }
    }

    #[test]
    fn configured_targets_deny_unlisted_dynamic_hosts() {
        let config = load_text(
            &dynamic_workstation_text("[targets.db]\nssh_host = \"db-ordinary\"", ""),
            &[],
        )
        .unwrap();
        let (ordinary, _) = dynamic_ids(&config);
        assert!(config.binding_enabled(ordinary));
        assert!(config.automation_target(ordinary, "db").is_ok());
        assert_eq!(
            config
                .automation_target(ordinary, "unlisted")
                .err()
                .unwrap()
                .code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn default_disabled_sudo_allows_ordinary_but_denies_named_dynamic_elevation() {
        let config = load_text(
            &dynamic_workstation_text("[targets.db]\nssh_host = \"db-ordinary\"", ""),
            &[],
        )
        .unwrap();
        let (ordinary, named) = dynamic_ids(&config);
        let resolved = config.automation_target(ordinary, "db").unwrap();
        assert_eq!(resolved.target.destination, "db-ordinary");
        assert!(resolved.r#become.is_none());
        assert!(!config.binding_enabled(named));
        assert_eq!(
            config.automation_target(named, "db").err().unwrap().code(),
            ErrorCode::PolicyDenied
        );
    }

    #[test]
    fn unrestricted_root_sudo_permits_named_dynamic_elevation_only() {
        let unrestricted = load_text(
            &dynamic_workstation_text(
                "[targets.db]\nssh_host = \"db-ordinary\"\n[targets.db.sudo]\nmode = \"same-account\"",
                "",
            ),
            &[],
        )
        .unwrap();
        let (_, named) = dynamic_ids(&unrestricted);
        assert!(unrestricted.binding_enabled(named));
        let resolved = unrestricted.automation_target(named, "db").unwrap();
        // Same-account elevation stays on the ordinary SSH destination.
        assert_eq!(resolved.target.destination, "db-ordinary");
        assert!(resolved.r#become.is_some());

        for restricted in [
            "[targets.db]\nssh_host = \"db-ordinary\"\n[targets.db.sudo]\nmode = \"same-account\"\nprograms = [\"/usr/bin/id\"]",
            "[targets.db]\nssh_host = \"db-ordinary\"\n[targets.db.sudo]\nmode = \"same-account\"\nusers = [\"app\"]",
        ] {
            let config = load_text(&dynamic_workstation_text(restricted, ""), &[]).unwrap();
            let (_, named) = dynamic_ids(&config);
            assert!(!config.binding_enabled(named), "{restricted}");
            assert_eq!(
                config.automation_target(named, "db").err().unwrap().code(),
                ErrorCode::PolicyDenied
            );
        }
    }

    #[test]
    fn separate_identity_sudo_routes_dynamic_elevation_to_the_elevated_host() {
        let config = load_text(
            &dynamic_workstation_text(
                "[targets.db]\nssh_host = \"db-ordinary\"\n\
                 [targets.db.sudo]\nmode = \"separate-identity\"\nssh_host = \"db-admin\"",
                "",
            ),
            &[],
        )
        .unwrap();
        let (ordinary, named) = dynamic_ids(&config);
        let elevated = config.automation_target(named, "db").unwrap();
        assert_eq!(elevated.target.destination, "db-admin");
        assert!(elevated.r#become.is_some());
        // Ordinary dynamic bindings never elevate, so they stay on the ordinary host.
        let plain = config.automation_target(ordinary, "db").unwrap();
        assert_eq!(plain.target.destination, "db-ordinary");
        assert!(plain.r#become.is_none());
    }
}
