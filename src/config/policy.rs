use std::ffi::OsString;

use crate::bindings::AutomationAuthority;

use super::{validation::validate_runtime_path, *};

impl Profile {
    pub(super) fn permits(self, tool: ToolId) -> bool {
        // Keep every ID classified explicitly so a new binding requires a policy decision.
        match tool {
            ToolId::Targets | ToolId::ReadOutput => true,
            ToolId::ReadFile | ToolId::Stat | ToolId::ListDirectory => {
                matches!(self, Self::Baseline | Self::ReadOnlyFiles | Self::FilesOnly)
            }
            ToolId::WriteFile
            | ToolId::Mkdir
            | ToolId::Rename
            | ToolId::RemoveFile
            | ToolId::ReplaceFile
            | ToolId::RemoveDirectory => {
                matches!(self, Self::Baseline | Self::FilesOnly)
            }
            ToolId::Exec | ToolId::Run | ToolId::Sudo => matches!(self, Self::Baseline),
        }
    }

    pub(super) fn permits_bindings(self) -> bool {
        matches!(self, Self::Baseline | Self::ActionsOnly)
    }
}

impl Target {
    pub(super) fn permits_binding(&self, name: &str) -> bool {
        self.profile.permits_bindings()
            && self
                .selected_bindings
                .as_ref()
                .is_none_or(|names| names.contains(name))
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
            return Err(ToolError::new(
                "policy_denied",
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
}

impl Config {
    pub(crate) fn output_limits(&self) -> crate::output::Limits {
        self.output
    }

    pub(crate) fn directory_limits(&self) -> crate::filesystem::data::DirectoryLimits {
        self.directory
    }

    /// A startup prerequisite only; this does not enable automation tools.
    pub(crate) fn automation_required(&self) -> bool {
        self.automation.required
    }

    /// Resolve the optional reference only when runtime health is requested.
    /// This validates its shape without inspecting any runtime files.
    pub(crate) fn automation_runtime(&self) -> Result<Option<PathBuf>, ConfigError> {
        self.automation_runtime_with(|key| std::env::var_os(key))
    }

    pub(super) fn automation_runtime_with(
        &self,
        env: impl FnOnce(&str) -> Option<OsString>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        if let Some(path) = &self.automation.runtime {
            return Ok(Some(path.clone()));
        }
        env("ESTUS_ANSIBLE_RUNTIME")
            .map(|value| {
                let value = value.to_str().ok_or_else(|| {
                    invalid("automation.runtime", "must be a bounded absolute path")
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
        let active: Vec<_> = self
            .bindings
            .entries()
            .filter(|(id, binding)| binding.is_automation() && self.binding_enabled(*id))
            .map(|(id, _)| id)
            .collect();
        if active.is_empty() {
            return Ok(false);
        }
        let needs_inherited_runtime = active.iter().any(|id| {
            match self
                .bindings
                .get(*id)
                .and_then(|binding| binding.automation_authority())
            {
                Some(AutomationAuthority::Ordinary) => true,
                Some(AutomationAuthority::Named(name)) => self
                    .automation
                    .authorities
                    .get(name)
                    .is_some_and(|authority| authority.runtime.is_none()),
                None => false,
            }
        });
        let inherited_runtime = if needs_inherited_runtime {
            self.automation_runtime()?
        } else {
            None
        };
        let root = crate::bindings::controller_root(self.automation.workspace_root.as_deref())?;
        let mut inspected = BTreeSet::new();
        for id in active {
            let (runtime, agent_socket) = match self
                .bindings
                .get(id)
                .and_then(|binding| binding.automation_authority())
            {
                Some(AutomationAuthority::Named(name)) => {
                    let (name, authority) = self
                        .automation
                        .authorities
                        .get_key_value(name)
                        .ok_or_else(|| {
                            invalid("tools", "automation authority is not configured")
                        })?;
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
                    (
                        authority
                            .runtime
                            .as_ref()
                            .or(inherited_runtime.as_ref())
                            .cloned(),
                        authority
                            .ssh_auth_sock
                            .as_ref()
                            .map(|path| path.as_os_str().to_owned()),
                    )
                }
                Some(AutomationAuthority::Ordinary) => {
                    (inherited_runtime.clone(), std::env::var_os("SSH_AUTH_SOCK"))
                }
                None => return Err(invalid("tools", "automation authority is not configured")),
            };
            self.bindings
                .activate_automation(id, runtime, root.clone(), agent_socket, ct)
                .await?;
        }
        Ok(true)
    }

    pub(crate) fn automation_concurrency(&self) -> usize {
        self.automation.max_concurrent
    }

    pub(crate) fn automation_scratch(&self) -> (u64, usize) {
        (
            self.automation.max_scratch_bytes,
            self.automation.max_scratch_files,
        )
    }

    pub(crate) fn automation_target(
        &self,
        id: BindingId,
        host: &str,
    ) -> Result<ResolvedAutomation<'_>, ToolError> {
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
        let binding = self.bindings.get(id).ok_or_else(denied)?;
        if !self.binding_enabled(id)
            || !binding.is_automation()
            || !binding.targets.iter().any(|target| target == host)
            || !self
                .targets
                .as_ref()
                .and_then(|targets| targets.get(host))
                .is_some_and(|target| target.permits_binding(&binding.name))
        {
            return Err(denied());
        }
        let ssh_executable = self.ssh_executable();
        match binding.automation_authority() {
            Some(AutomationAuthority::Ordinary) => Ok(ResolvedAutomation {
                target: self.automation.targets.get(host).ok_or_else(denied)?,
                ssh_config: self.ssh_config.as_deref(),
                ssh_executable,
                r#become: None,
                agent: AutomationAgent::Inherit,
            }),
            Some(AutomationAuthority::Named(name)) => {
                let authority = self.automation.authorities.get(name).ok_or_else(denied)?;
                Ok(ResolvedAutomation {
                    target: authority.targets.get(host).ok_or_else(denied)?,
                    ssh_config: Some(&authority.ssh_config_file),
                    ssh_executable,
                    r#become: Some(&authority.r#become),
                    agent: authority
                        .ssh_auth_sock
                        .as_deref()
                        .map_or(AutomationAgent::Disabled, AutomationAgent::Fixed),
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

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) fn bindings(&self) -> &Bindings {
        &self.bindings
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
        match &selected.runtime {
            Some(path) => Ok(Some(path.clone())),
            None => self.automation_runtime(),
        }
    }

    pub(crate) fn binding_enabled(&self, id: BindingId) -> bool {
        self.profile.permits_bindings()
            && self.bindings.get(id).is_some_and(|binding| {
                binding.enabled()
                    && (!binding.is_automation()
                        || binding.targets.iter().any(|name| {
                            self.targets
                                .as_ref()
                                .and_then(|targets| targets.get(name))
                                .is_some_and(|target| target.permits_binding(&binding.name))
                        }))
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
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
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
        match binding.sudo() {
            Some((user, program)) => target.sudo.resolve(host, &target.ssh_host, user, program),
            None => self.resolve_ordinary(host),
        }
    }

    pub(crate) fn tool_enabled(&self, tool: ToolId) -> bool {
        self.profile.permits(tool) && (tool != ToolId::Sudo || self.has_sudo())
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
        let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
        match tool {
            ToolId::Targets | ToolId::ReadOutput | ToolId::Sudo => return Err(denied()),
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
        if !self.profile.permits(tool) {
            return Err(denied());
        }
        if self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .is_some_and(|target| !target.profile.permits(tool))
        {
            return Err(denied());
        }
        self.resolve_ordinary(host)
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
                ToolError::new(
                    "policy_denied",
                    "Host is not a configured logical target",
                    false,
                )
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
                    ToolError::new(
                        "policy_denied",
                        "Host is not a configured logical target",
                        false,
                    )
                })?,
            None => {
                destination(host, "host").map_err(|_| {
                    ToolError::new(
                        "invalid_argument",
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
            ToolError::new(
                "policy_denied",
                "Elevated target, user, or program is not authorized",
                false,
            )
        };
        if !self.profile.permits(ToolId::Sudo) {
            return Err(denied());
        }
        let target = self
            .targets
            .as_ref()
            .and_then(|targets| targets.get(host))
            .ok_or_else(denied)?;
        if !target.profile.permits(ToolId::Sudo) {
            return Err(denied());
        }
        target.sudo.resolve(host, &target.ssh_host, user, program)
    }

    pub(crate) fn timeout(&self, seconds: Option<u64>) -> Result<std::time::Duration, ToolError> {
        let seconds = seconds.unwrap_or(self.limits.operation_timeout_secs);
        if seconds == 0 || seconds > self.limits.max_timeout_secs {
            return Err(ToolError::new(
                "invalid_argument",
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
    use super::*;
    use super::super::test_support::{load_text, named_authority_text, automation_text, catalog, builtin, binding_definition};

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
        let text = named_authority_text("baseline", "baseline", true);
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
                serde_json::json!({"method":"sudo","user":"root"})
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
                assert_eq!(error.code, "policy_denied");
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
            for kind in ["ansible_module", "ansible_role"] {
                let text = automation_text(global, target, enabled).replace("ansible_module", kind);
                let mut config = load_text(&text, &[]).unwrap();
                config
                    .activate_automation(&tokio_util::sync::CancellationToken::new())
                    .await
                    .unwrap();
                assert!(!config.binding_enabled(BindingId(0)));
            }
        }
    }

    #[tokio::test]
    async fn active_automation_requires_real_startup_prerequisites() {
        let mut config = load_text(&automation_text("baseline", "baseline", true), &[]).unwrap();
        let error = config
            .activate_automation(&tokio_util::sync::CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.field, "tools");
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
                assert_eq!(error.code, "policy_denied");
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
        let open = load_text("profile='baseline'\ndestination_policy='open'", &[]).unwrap();
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
                    let config = load_text(
                        &format!(
                            "profile='{global}'\n[targets.one]\n\
                             ssh_host='private-ordinary'\nprofile='{target}'\n{sudo}"
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
                    let text = format!(
                        "profile='{global}'\nenabled_tools={enabled}\n\
                         [targets.one]\nssh_host='ordinary-private'\nprofile='{target}'\n\
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
                        assert_eq!(error.code, "policy_denied");
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
                        let config = load_text(
                            &format!(
                                "profile='{global}'\nenabled_tools={enabled}\n\
                                 [targets.one]\nssh_host='ordinary-private'\nprofile='{profile}'\n\
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
                                assert_eq!(error.code, "policy_denied");
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
            let mut config = load_text(
                &format!(
                    "profile='actions-only'\nenabled_tools=['observe','ordinary']\n\
                     [targets.one]\nssh_host='ordinary-private'\nprofile='actions-only'\n\
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
        for (root, native_allowed) in [("", false), ("profile='baseline'\n", true)] {
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
                            config.resolve("one", builtin(entry.id)).err().unwrap().code,
                            "policy_denied"
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
            let config = load_text(
                &format!(
                    "profile='{profile}'\n[targets.one]\nssh_host='private-alias'\n\
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
                    assert_eq!(error.code, "policy_denied", "{profile}/{:?}", entry.id);
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
                    .code,
                "policy_denied"
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
            "profile='files-only'\n\
             [targets.base]\nssh_host='base-alias'\nprofile='baseline'\n\
             [targets.reader]\nssh_host='reader-alias'\nprofile='read-only-files'\n\
             [targets.actions]\nssh_host='actions-alias'\nprofile='actions-only'\n\
             [targets.implicit]\nssh_host='implicit-alias'",
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
            "profile='baseline'\n[targets.reader]\nssh_host='private-reader'\nprofile='read-only-files'\n\
             [targets.reader.sudo]\nmode='separate-identity'\nssh_host='private-elevated'\n\
             [targets.files]\nssh_host='private-files'\nprofile='files-only'\n\
             [targets.files.sudo]\nmode='same-account'\n\
             [targets.actions]\nssh_host='private-actions'\nprofile='actions-only'\n\
             [targets.actions.sudo]\nmode='same-account'\n\
             [targets.disabled]\nssh_host='private-disabled'\nprofile='baseline'\n\
             [targets.empty]\nssh_host='private-empty'\nprofile='baseline'\n\
             [targets.empty.sudo]\nmode='same-account'\nprograms=[]",
            &[],
        )
        .unwrap();
        assert!(config.tool_enabled(ToolId::Exec));
        assert!(config.tool_enabled(ToolId::Run));
        assert!(config.tool_enabled(ToolId::Sudo));
        for name in ["reader", "files", "actions", "disabled", "empty"] {
            let error = config.resolve_sudo(name, "root", "/bin/sh").err().unwrap();
            assert_eq!(error.code, "policy_denied");
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
        let open = load_text("destination_policy='open'\nprofile='read-only-files'", &[]).unwrap();
        let resolved = open.resolve("user@example", ToolId::ReadFile).unwrap();
        assert_eq!(resolved.destination, "user@example");
        assert_eq!(resolved.role, IdentityRole::Ordinary);
        assert_eq!(
            open.resolve("-option", ToolId::ReadFile)
                .err()
                .unwrap()
                .code,
            "invalid_argument"
        );
        assert_eq!(
            open.resolve("user@example", ToolId::WriteFile)
                .err()
                .unwrap()
                .code,
            "policy_denied"
        );
        let closed = load_text(
            "profile='read-only-files'\n[targets.logical]\nssh_host='private-alias'",
            &[],
        )
        .unwrap();
        assert!(closed.resolve("logical", ToolId::ReadFile).is_ok());
        assert!(closed.resolve("private-alias", ToolId::ReadFile).is_err());
        let empty = load_text("profile='files-only'\n[targets]", &[]).unwrap();
        assert!(empty.tool_enabled(ToolId::WriteFile));
        assert!(empty.tool_enabled(ToolId::Targets));
        assert!(empty.resolve("anything", ToolId::ReadFile).is_err());
        let baseline_empty = load_text("profile='baseline'\n[targets]", &[]).unwrap();
        assert!(baseline_empty.tool_enabled(ToolId::Exec));
        assert!(baseline_empty.tool_enabled(ToolId::WriteFile));
        assert!(!baseline_empty.tool_enabled(ToolId::Sudo));
        for tool in [ToolId::Targets, ToolId::Sudo] {
            assert_eq!(
                closed.resolve("logical", tool).err().unwrap().code,
                "policy_denied"
            );
            assert_eq!(
                load_text("", &[])
                    .unwrap()
                    .resolve("host", tool)
                    .err()
                    .unwrap()
                    .code,
                "policy_denied"
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
profile="read-only-files"
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
            let config = load_text(
                &format!("profile={profile:?}\nenabled_tools=['local']\n{definition}"),
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
            let config = load_text(
                &format!("profile={profile:?}\nenabled_tools=['local']\n{definition}"),
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
                    .code,
                "policy_denied",
                "{source}"
            );
        }
        let open = load_text("profile='baseline'\ndestination_policy='open'", &[]).unwrap();
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
                .automation_runtime_with(|key| {
                    assert_eq!(key, "ESTUS_ANSIBLE_RUNTIME");
                    Some("/nonexistent-private-runtime".into())
                })
                .unwrap(),
            Some(PathBuf::from("/nonexistent-private-runtime"))
        );
        for value in [
            String::new(),
            "private-relative-runtime".to_owned(),
            "/private\0runtime".to_owned(),
            format!("/{}", "x".repeat(4096)),
        ] {
            let error = config
                .automation_runtime_with(|_| Some(value.into()))
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "automation.runtime: must be a bounded absolute path"
            );
        }
        let boundary = format!("/{}", "x".repeat(4095));
        assert_eq!(
            config
                .automation_runtime_with(|_| Some(boundary.clone().into()))
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
            .automation_runtime_with(|_| Some(OsString::from_vec(vec![b'/', 0xff])))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "automation.runtime: must be a bounded absolute path"
        );
    }

    #[test]
    fn configured_dispatch_never_accepts_aliases_and_open_dispatch_is_validated() {
        let config = load_text(
            "profile='baseline'\n[targets.logical]\nssh_host='ordinary-alias'",
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
                config.resolve(host, ToolId::Exec).err().unwrap().code,
                "policy_denied"
            );
        }
        let empty = load_text("[targets]", &[]).unwrap();
        assert_eq!(
            empty.resolve("anything", ToolId::Exec).err().unwrap().code,
            "policy_denied"
        );
        let open = load_text("profile='baseline'\ndestination_policy='open'", &[]).unwrap();
        let resolved = open.resolve("user@example", ToolId::Exec).unwrap();
        assert_eq!(
            (resolved.name, resolved.destination),
            ("user@example", "user@example")
        );
        for host in ["", "-option", "host name", "host\0name"] {
            assert_eq!(
                open.resolve(host, ToolId::Exec).err().unwrap().code,
                "invalid_argument"
            );
        }
        assert!(!open.has_sudo());
        assert_eq!(
            open.resolve_sudo("user@example", "root", "/bin/id")
                .err()
                .unwrap()
                .code,
            "policy_denied"
        );
    }

    #[test]
    fn sudo_dispatch_uses_exact_policy_and_the_configured_role() {
        let config = load_text(
            r#"
profile = "baseline"
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
                config.resolve_sudo(host, user, program).err().unwrap().code,
                "policy_denied",
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
                config.timeout(Some(seconds)).err().unwrap().code,
                "invalid_argument"
            );
        }
    }
}
