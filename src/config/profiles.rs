use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
    process::Command,
    sync::Mutex,
};

use serde::{Deserialize, Serialize};

use super::{
    Capabilities, ConfigError, RiskTier, Selection, Sudo, SudoMode, Target, ToolId, invalid,
    loading::RawCapabilities,
};

const MAX_GROUPS: usize = 64;
const MAX_PROFILES: usize = 64;
const MAX_EXTENDS_DEPTH: usize = 8;
const MAX_PATTERNS_PER_GROUP: usize = 64;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_SSH_HOSTNAME_CACHE: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltInProfile {
    Deny,
    Prod,
    ProdChange,
    Dev,
    Lab,
}

impl BuiltInProfile {
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "deny" => Some(Self::Deny),
            "prod" => Some(Self::Prod),
            "prod-change" => Some(Self::ProdChange),
            "dev" => Some(Self::Dev),
            "lab" => Some(Self::Lab),
            _ => None,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Prod => "prod",
            Self::ProdChange => "prod-change",
            Self::Dev => "dev",
            Self::Lab => "lab",
        }
    }

    fn compile(self) -> CompiledProfile {
        match self {
            Self::Deny => CompiledProfile {
                name: self.as_str().to_owned(),
                allowed: false,
                max_tier: RiskTier::Observe,
                require_preview: true,
                capabilities: Capabilities {
                    named: false,
                    file_read: false,
                    file_write: false,
                    exec: false,
                    sudo: false,
                },
                sudo: Sudo::Disabled,
                allow_ip_literals: false,
                selection: None,
                source_file: None,
            },
            Self::Prod => CompiledProfile {
                name: self.as_str().to_owned(),
                allowed: true,
                max_tier: RiskTier::Inspect,
                require_preview: true,
                capabilities: Capabilities {
                    named: true,
                    file_read: true,
                    file_write: false,
                    exec: false,
                    sudo: false,
                },
                sudo: Sudo::Disabled,
                allow_ip_literals: false,
                selection: None,
                source_file: None,
            },
            Self::ProdChange => CompiledProfile {
                name: self.as_str().to_owned(),
                allowed: true,
                max_tier: RiskTier::Change,
                require_preview: true,
                capabilities: Capabilities {
                    named: true,
                    file_read: true,
                    file_write: false,
                    exec: false,
                    sudo: false,
                },
                sudo: Sudo::Disabled,
                allow_ip_literals: false,
                selection: None,
                source_file: None,
            },
            Self::Dev => CompiledProfile {
                name: self.as_str().to_owned(),
                allowed: true,
                max_tier: RiskTier::Exec,
                require_preview: false,
                capabilities: Capabilities {
                    named: true,
                    file_read: true,
                    file_write: true,
                    exec: true,
                    sudo: false,
                },
                sudo: Sudo::Disabled,
                allow_ip_literals: false,
                selection: None,
                source_file: None,
            },
            Self::Lab => CompiledProfile {
                name: self.as_str().to_owned(),
                allowed: true,
                max_tier: RiskTier::Exec,
                require_preview: false,
                capabilities: Capabilities::all(),
                sudo: Sudo::SameAccount {
                    users: vec!["root".to_owned()],
                    programs: None,
                },
                allow_ip_literals: true,
                selection: None,
                source_file: None,
            },
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct RawProfile {
    pub(super) extends: Option<String>,
    pub(super) max_tier: Option<RiskTier>,
    pub(super) require_preview: Option<bool>,
    pub(super) capabilities: Option<RawCapabilities>,
    pub(super) selection: Option<Selection>,
    pub(super) sudo: Option<Sudo>,
    pub(super) allow_ip_literals: Option<bool>,
    #[serde(skip)]
    pub(super) source_file: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawGroup {
    pub(super) name: String,
    #[serde(default)]
    pub(super) profile: Option<String>,
    #[serde(default)]
    pub(super) match_hosts: Vec<String>,
    #[serde(default)]
    pub(super) match_labels: BTreeMap<String, String>,
    #[serde(skip)]
    pub(super) source_file: Option<String>,
}

#[derive(Clone)]
pub(crate) struct CompiledProfile {
    pub(crate) name: String,
    pub(crate) allowed: bool,
    pub(crate) max_tier: RiskTier,
    pub(crate) require_preview: bool,
    pub(crate) capabilities: Capabilities,
    pub(super) sudo: Sudo,
    pub(crate) allow_ip_literals: bool,
    pub(crate) selection: Option<BTreeSet<String>>,
    pub(crate) source_file: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledGroup {
    pub(crate) name: String,
    pub(crate) profile: String,
    pub(crate) match_hosts: Vec<String>,
    pub(crate) match_labels: BTreeMap<String, String>,
    pub(crate) source_file: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PolicyMatch {
    pub(crate) source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) source_file: Option<String>,
    pub(crate) profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) profile_source_file: Option<String>,
    pub(crate) reason: String,
}
#[derive(Clone, Debug)]
pub(crate) struct EffectivePolicy {
    pub(crate) active: bool,
    pub(crate) allowed: bool,
    pub(crate) max_tier: RiskTier,
    pub(crate) require_preview: bool,
    pub(crate) capabilities: Capabilities,
    pub(super) sudo: Sudo,
    pub(crate) selection: Option<BTreeSet<String>>,
    pub(crate) resolved_ssh_hostname: Option<String>,
    pub(crate) is_ip_literal: bool,
    pub(crate) matched: Vec<PolicyMatch>,
    pub(crate) skipped_ip_groups: Vec<String>,
    pub(crate) max_tier_source: Option<String>,
    pub(crate) require_preview_source: Option<String>,
    pub(crate) denied_source: Option<String>,
}

impl EffectivePolicy {
    pub(crate) fn unconstrained() -> Self {
        Self {
            active: false,
            allowed: true,
            max_tier: RiskTier::Exec,
            require_preview: false,
            capabilities: Capabilities::all(),
            sudo: Sudo::Disabled,
            selection: None,
            resolved_ssh_hostname: None,
            is_ip_literal: false,
            matched: Vec::new(),
            skipped_ip_groups: Vec::new(),
            max_tier_source: None,
            require_preview_source: None,
            denied_source: None,
        }
    }

    pub(crate) fn permits_tier(&self, tier: RiskTier) -> bool {
        !self.active || (self.allowed && tier <= self.max_tier)
    }

    pub(crate) fn permits_builtin(&self, tool: ToolId) -> bool {
        if !self.active {
            return true;
        }
        if !self.allowed {
            return false;
        }
        if !self.capabilities.permits(tool) {
            return false;
        }
        if !self.permits_tier(super::policy::risk_tier_for_builtin(tool)) {
            return false;
        }
        self.selection
            .as_ref()
            .is_none_or(|allowed| allowed.contains(tool.wire_name()))
    }

    pub(crate) fn permits_binding_name(
        &self,
        name: &str,
        tier: RiskTier,
        needs_sudo: bool,
    ) -> bool {
        if !self.active {
            return true;
        }
        if !self.allowed {
            return false;
        }
        if !self.capabilities.named {
            return false;
        }
        if needs_sudo && !self.capabilities.sudo {
            return false;
        }
        if !self.permits_tier(tier) {
            return false;
        }
        self.selection
            .as_ref()
            .is_none_or(|allowed| allowed.contains(name))
    }

    pub(crate) fn permits_open_sudo(&self) -> bool {
        self.active
            && self.allowed
            && self.capabilities.sudo
            && !matches!(self.sudo, Sudo::Disabled)
    }

    pub(crate) fn sudo_mode(&self) -> SudoMode {
        if !self.active || !self.allowed || !self.capabilities.sudo {
            SudoMode::Disabled
        } else {
            self.sudo.mode()
        }
    }
}

pub(crate) struct PolicyEngine {
    pub(crate) active: bool,
    pub(crate) yolo: bool,
    pub(crate) default_profile: Option<String>,
    pub(crate) profiles: BTreeMap<String, CompiledProfile>,
    pub(crate) groups: Vec<CompiledGroup>,
    ssh_hostname_cache: Mutex<BTreeMap<String, Option<String>>>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::inactive()
    }
}

impl PolicyEngine {
    pub(crate) fn inactive() -> Self {
        Self {
            active: false,
            yolo: false,
            default_profile: None,
            profiles: builtin_profiles(),
            groups: Vec::new(),
            ssh_hostname_cache: Mutex::new(BTreeMap::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn compile(
        yolo: bool,
        default_profile: Option<String>,
        raw_profiles: BTreeMap<String, RawProfile>,
        raw_groups: Vec<RawGroup>,
        targets: Option<&BTreeMap<String, Target>>,
        definable: &BTreeSet<String>,
        manifest: Option<&crate::catalog::assets::Manifest>,
        global_tools: &BTreeSet<String>,
        permitted_builtins: &BTreeSet<String>,
    ) -> Result<Self, ConfigError> {
        if raw_profiles.len() > MAX_PROFILES {
            return Err(invalid("profiles", "too many custom profiles declared"));
        }
        if raw_groups.len() > MAX_GROUPS {
            return Err(invalid("groups", "too many groups declared"));
        }

        for name in raw_profiles.keys() {
            validate_identifier(name, "profiles")?;
            if BuiltInProfile::from_name(name).is_some() {
                return Err(invalid(
                    "profiles",
                    "cannot redefine a built-in profile; declare a custom name with extends",
                ));
            }
        }

        let mut compiled = builtin_profiles();
        let mut resolving = BTreeSet::new();
        for name in raw_profiles.keys() {
            resolve_profile(
                name,
                &raw_profiles,
                &mut compiled,
                &mut resolving,
                0,
                definable,
                manifest,
                global_tools,
                permitted_builtins,
            )?;
        }

        if let Some(default_name) = &default_profile
            && !compiled.contains_key(default_name)
        {
            return Err(invalid(
                "default_profile",
                "must name a built-in or declared profile",
            ));
        }

        let mut seen_groups = BTreeSet::new();
        let mut groups = Vec::with_capacity(raw_groups.len());
        for group in raw_groups {
            validate_identifier(&group.name, "groups.*.name")?;
            if !seen_groups.insert(group.name.clone()) {
                return Err(invalid("groups.*.name", "duplicate group name"));
            }
            if group.match_hosts.is_empty() && group.match_labels.is_empty() {
                return Err(invalid(
                    "groups",
                    "each group must specify match_hosts or match_labels",
                ));
            }
            if group.match_hosts.len() > MAX_PATTERNS_PER_GROUP {
                return Err(invalid(
                    "groups.*.match_hosts",
                    "too many host patterns in a group",
                ));
            }
            for pattern in &group.match_hosts {
                validate_host_pattern(pattern)?;
            }
            if group.match_labels.len() > 16 {
                return Err(invalid(
                    "groups.*.match_labels",
                    "too many label matchers in a group",
                ));
            }
            for (k, v) in &group.match_labels {
                if k.is_empty() || k.len() > 64 || v.is_empty() || v.len() > 256 {
                    return Err(invalid(
                        "groups.*.match_labels",
                        "label matcher key and value must be bounded non-empty strings",
                    ));
                }
            }
            // Syntactic sugar: when `profile` is omitted, default to the group's own name
            // (so `[[groups]] name = "prod"` automatically maps to profile "prod").
            let profile = group.profile.unwrap_or_else(|| group.name.clone());
            if !compiled.contains_key(&profile) {
                return Err(invalid(
                    "groups.*.profile",
                    "must name a built-in or declared profile (or match a profile by group name)",
                ));
            }
            groups.push(CompiledGroup {
                name: group.name,
                profile,
                match_hosts: group.match_hosts,
                match_labels: group.match_labels,
                source_file: group.source_file,
            });
        }

        let mut any_target_profile = false;
        if let Some(targets) = targets {
            for target in targets.values() {
                if let Some(profile) = &target.profile {
                    if !compiled.contains_key(profile) {
                        return Err(invalid(
                            "targets.*.profile",
                            "must name a built-in or declared profile",
                        ));
                    }
                    any_target_profile = true;
                }
            }
        }

        let effective_default = if yolo {
            Some("lab".to_owned())
        } else {
            default_profile
        };

        let active = yolo
            || effective_default.is_some()
            || !groups.is_empty()
            || !raw_profiles.is_empty()
            || any_target_profile;

        Ok(Self {
            active,
            yolo,
            default_profile: effective_default,
            profiles: compiled,
            groups,
            ssh_hostname_cache: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn has_open_sudo_route(&self) -> bool {
        if !self.active {
            return false;
        }
        if self.yolo {
            return true;
        }
        if let Some(default_name) = &self.default_profile
            && self.profiles.get(default_name).is_some_and(|p| {
                p.allowed && p.capabilities.sudo && !matches!(p.sudo, Sudo::Disabled)
            })
        {
            return true;
        }
        self.groups.iter().any(|group| {
            self.profiles.get(&group.profile).is_some_and(|p| {
                p.allowed && p.capabilities.sudo && !matches!(p.sudo, Sudo::Disabled)
            })
        })
    }

    /// Evaluate the strictest-wins lattice for one host.
    ///
    /// In open mode (`target.is_none()`) when `groups` has host matchers, runs
    /// `ssh -G` (cached) to discover any OpenSSH config alias target `hostname`
    /// and matches groups against BOTH the caller string and the canonical
    /// hostname so an alias can never bypass a stricter group such as `prod`.
    pub(super) fn evaluate(
        &self,
        host: &str,
        target: Option<&Target>,
        ssh_executable: &Path,
        ssh_config: Option<&Path>,
    ) -> EffectivePolicy {
        if !self.active {
            return EffectivePolicy::unconstrained();
        }

        let has_host_groups = self.groups.iter().any(|g| !g.match_hosts.is_empty());
        let resolved_ssh_hostname = if target.is_none() && has_host_groups {
            self.resolve_ssh_hostname(ssh_executable, ssh_config, host)
                .filter(|resolved| !resolved.eq_ignore_ascii_case(host))
        } else {
            None
        };

        let candidate_ssh_host = target.map(|t| t.ssh_host.as_str());
        let is_ip_literal = is_ip_destination(host)
            || candidate_ssh_host.is_some_and(is_ip_destination)
            || resolved_ssh_hostname
                .as_deref()
                .is_some_and(is_ip_destination);

        let mut matched_entries: Vec<(PolicyMatch, &CompiledProfile)> = Vec::new();
        let mut skipped_ip_groups = Vec::new();

        for group in &self.groups {
            let Some(profile) = self.profiles.get(&group.profile) else {
                continue;
            };
            let Some(reason) = match_group(group, host, target, resolved_ssh_hostname.as_deref())
            else {
                continue;
            };
            if is_ip_literal && !profile.allow_ip_literals {
                skipped_ip_groups.push(group.name.clone());
                continue;
            }
            matched_entries.push((
                PolicyMatch {
                    source: format!("group \"{}\"", group.name),
                    source_file: group.source_file.clone(),
                    profile: group.profile.clone(),
                    profile_source_file: profile.source_file.clone(),
                    reason,
                },
                profile,
            ));
        }

        if let Some(target_ref) = target
            && let Some(profile_name) = &target_ref.profile
            && let Some(profile) = self.profiles.get(profile_name)
        {
            matched_entries.push((
                PolicyMatch {
                    source: format!("target \"{host}\""),
                    source_file: target_ref.source_file.clone(),
                    profile: profile_name.clone(),
                    profile_source_file: profile.source_file.clone(),
                    reason: "explicit target profile".to_owned(),
                },
                profile,
            ));
        }

        if matched_entries.is_empty() {
            if self.yolo {
                if let Some(profile) = self.profiles.get("lab") {
                    matched_entries.push((
                        PolicyMatch {
                            source: "--yolo".to_owned(),
                            source_file: None,
                            profile: "lab".to_owned(),
                            profile_source_file: None,
                            reason: "unrestricted workstation escape hatch".to_owned(),
                        },
                        profile,
                    ));
                }
            } else if let Some(default_name) = &self.default_profile
                && let Some(profile) = self.profiles.get(default_name)
            {
                let reason = if skipped_ip_groups.is_empty() {
                    "no groups matched; applied default_profile".to_owned()
                } else {
                    format!(
                        "raw IP literal rejected by {} (allow_ip_literals = false); fell back to default_profile",
                        skipped_ip_groups.join(", ")
                    )
                };
                matched_entries.push((
                    PolicyMatch {
                        source: "default_profile".to_owned(),
                        source_file: None,
                        profile: default_name.clone(),
                        profile_source_file: profile.source_file.clone(),
                        reason,
                    },
                    profile,
                ));
            } else {
                // Active policy engine with groups configured, no default_profile,
                // and no group matched: fail closed.
                let mut policy = EffectivePolicy::unconstrained();
                policy.active = true;
                policy.allowed = false;
                policy.max_tier = RiskTier::Observe;
                policy.require_preview = true;
                policy.capabilities = Capabilities {
                    named: false,
                    file_read: false,
                    file_write: false,
                    exec: false,
                    sudo: false,
                };
                policy.resolved_ssh_hostname = resolved_ssh_hostname;
                policy.is_ip_literal = is_ip_literal;
                policy.skipped_ip_groups = skipped_ip_groups;
                policy.denied_source =
                    Some("no matching group and no default_profile (fail-closed)".to_owned());
                return policy;
            }
        }

        reduce_lattice(
            matched_entries,
            resolved_ssh_hostname,
            is_ip_literal,
            skipped_ip_groups,
        )
    }

    fn resolve_ssh_hostname(
        &self,
        ssh_executable: &Path,
        ssh_config: Option<&Path>,
        destination: &str,
    ) -> Option<String> {
        if let Ok(cache) = self.ssh_hostname_cache.lock()
            && let Some(cached) = cache.get(destination)
        {
            return cached.clone();
        }
        let resolved = query_ssh_canonical_hostname(ssh_executable, ssh_config, destination);
        if let Ok(mut cache) = self.ssh_hostname_cache.lock() {
            if cache.len() >= MAX_SSH_HOSTNAME_CACHE {
                cache.clear();
            }
            cache.insert(destination.to_owned(), resolved.clone());
        }
        resolved
    }
}

fn reduce_lattice(
    entries: Vec<(PolicyMatch, &CompiledProfile)>,
    resolved_ssh_hostname: Option<String>,
    is_ip_literal: bool,
    skipped_ip_groups: Vec<String>,
) -> EffectivePolicy {
    let mut allowed = true;
    let mut max_tier = RiskTier::Exec;
    let mut require_preview = false;
    let mut capabilities = Capabilities::all();
    let mut sudo: Option<Sudo> = None;
    let mut selection: Option<BTreeSet<String>> = None;
    let mut matched = Vec::with_capacity(entries.len());
    let mut max_tier_source: Option<String> = None;
    let mut require_preview_source: Option<String> = None;
    let mut denied_source: Option<String> = None;

    for (info, profile) in entries {
        let label = format!("{} -> profile \"{}\"", info.source, info.profile);
        if !profile.allowed {
            allowed = false;
            if denied_source.is_none() {
                denied_source = Some(label.clone());
            }
        }
        if max_tier_source.is_none() || profile.max_tier < max_tier {
            max_tier = profile.max_tier;
            max_tier_source = Some(label.clone());
        }
        if profile.require_preview && !require_preview {
            require_preview = true;
            require_preview_source = Some(label.clone());
        }
        capabilities = intersect_capabilities(capabilities, profile.capabilities);
        sudo = Some(match sudo {
            None => profile.sudo.clone(),
            Some(current) => intersect_sudo(current, &profile.sudo),
        });
        if let Some(profile_sel) = &profile.selection {
            selection = Some(match selection {
                None => profile_sel.clone(),
                Some(current) => current.intersection(profile_sel).cloned().collect(),
            });
        }
        matched.push(info);
    }

    EffectivePolicy {
        active: true,
        allowed,
        max_tier,
        require_preview,
        capabilities,
        sudo: sudo.unwrap_or(Sudo::Disabled),
        selection,
        resolved_ssh_hostname,
        is_ip_literal,
        matched,
        skipped_ip_groups,
        max_tier_source,
        require_preview_source,
        denied_source,
    }
}

fn intersect_capabilities(a: Capabilities, b: Capabilities) -> Capabilities {
    Capabilities {
        named: a.named && b.named,
        file_read: a.file_read && b.file_read,
        file_write: a.file_write && b.file_write,
        exec: a.exec && b.exec,
        sudo: a.sudo && b.sudo,
    }
}

fn intersect_sudo(a: Sudo, b: &Sudo) -> Sudo {
    match (a, b) {
        (
            Sudo::SameAccount {
                users: users_a,
                programs: progs_a,
            },
            Sudo::SameAccount {
                users: users_b,
                programs: progs_b,
            },
        ) => {
            let users: Vec<String> = users_a
                .into_iter()
                .filter(|u| users_b.contains(u))
                .collect();
            if users.is_empty() {
                return Sudo::Disabled;
            }
            let programs = match (progs_a, progs_b) {
                (None, None) => None,
                (Some(p), None) => Some(p),
                (None, Some(p)) => Some(p.clone()),
                (Some(pa), Some(pb)) => Some(pa.into_iter().filter(|p| pb.contains(p)).collect()),
            };
            Sudo::SameAccount { users, programs }
        }
        (
            Sudo::SeparateIdentity {
                ssh_host: host_a,
                users: users_a,
                programs: progs_a,
            },
            Sudo::SeparateIdentity {
                ssh_host: host_b,
                users: users_b,
                programs: progs_b,
            },
        ) if host_a == *host_b => {
            let users: Vec<String> = users_a
                .into_iter()
                .filter(|u| users_b.contains(u))
                .collect();
            if users.is_empty() {
                return Sudo::Disabled;
            }
            let programs = match (progs_a, progs_b) {
                (None, None) => None,
                (Some(p), None) => Some(p),
                (None, Some(p)) => Some(p.clone()),
                (Some(pa), Some(pb)) => Some(pa.into_iter().filter(|p| pb.contains(p)).collect()),
            };
            Sudo::SeparateIdentity {
                ssh_host: host_a,
                users,
                programs,
            }
        }
        _ => Sudo::Disabled,
    }
}

fn match_group(
    group: &CompiledGroup,
    host: &str,
    target: Option<&Target>,
    resolved_ssh_hostname: Option<&str>,
) -> Option<String> {
    let mut reasons = Vec::new();

    if !group.match_labels.is_empty() {
        let target = target?;
        let labels_ok = group
            .match_labels
            .iter()
            .all(|(k, v)| target.labels.get(k).is_some_and(|tv| tv == v));
        if !labels_ok {
            return None;
        }
        let pairs: Vec<String> = group
            .match_labels
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect();
        reasons.push(format!("labels {{{}}}", pairs.join(", ")));
    }

    if !group.match_hosts.is_empty() {
        let host_part = strip_ssh_user(host);
        let target_host_part = target.map(|t| strip_ssh_user(&t.ssh_host));
        let resolved_part = resolved_ssh_hostname.map(strip_ssh_user);

        let host_reason = group.match_hosts.iter().find_map(|pattern| {
            if glob_match(pattern, host_part) {
                Some(format!("host pattern \"{pattern}\""))
            } else if let Some(th) = target_host_part
                && th != host_part
                && glob_match(pattern, th)
            {
                Some(format!("target ssh_host \"{th}\" matched \"{pattern}\""))
            } else if let Some(rh) = resolved_part
                && glob_match(pattern, rh)
            {
                Some(format!("ssh -G hostname \"{rh}\" matched \"{pattern}\""))
            } else {
                None
            }
        })?;
        reasons.push(host_reason);
    }

    Some(reasons.join(" and "))
}

fn builtin_profiles() -> BTreeMap<String, CompiledProfile> {
    [
        BuiltInProfile::Deny,
        BuiltInProfile::Prod,
        BuiltInProfile::ProdChange,
        BuiltInProfile::Dev,
        BuiltInProfile::Lab,
    ]
    .into_iter()
    .map(|profile| (profile.as_str().to_owned(), profile.compile()))
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_profile(
    name: &str,
    raw_profiles: &BTreeMap<String, RawProfile>,
    compiled: &mut BTreeMap<String, CompiledProfile>,
    resolving: &mut BTreeSet<String>,
    depth: usize,
    definable: &BTreeSet<String>,
    manifest: Option<&crate::catalog::assets::Manifest>,
    global_tools: &BTreeSet<String>,
    permitted_builtins: &BTreeSet<String>,
) -> Result<(), ConfigError> {
    if compiled.contains_key(name) {
        return Ok(());
    }
    if depth >= MAX_EXTENDS_DEPTH {
        return Err(invalid(
            "profiles.*.extends",
            "profile inheritance chain exceeds maximum depth",
        ));
    }
    if !resolving.insert(name.to_owned()) {
        return Err(invalid(
            "profiles.*.extends",
            "cyclic profile inheritance detected",
        ));
    }
    let raw = raw_profiles
        .get(name)
        .ok_or_else(|| invalid("profiles.*.extends", "references an unknown profile"))?;

    let mut base = if let Some(parent) = &raw.extends {
        if !compiled.contains_key(parent) {
            if raw_profiles.contains_key(parent) {
                resolve_profile(
                    parent,
                    raw_profiles,
                    compiled,
                    resolving,
                    depth + 1,
                    definable,
                    manifest,
                    global_tools,
                    permitted_builtins,
                )?;
            } else {
                return Err(invalid(
                    "profiles.*.extends",
                    "must name a built-in or declared profile",
                ));
            }
        }
        compiled
            .get(parent)
            .cloned()
            .ok_or_else(|| invalid("profiles.*.extends", "references an unknown profile"))?
    } else {
        // Standalone custom profile defaults to restrictive prod-like baseline.
        BuiltInProfile::Prod.compile()
    };

    base.name = name.to_owned();
    base.source_file = raw.source_file.clone();
    if let Some(tier) = raw.max_tier {
        base.max_tier = tier;
    }
    if let Some(rp) = raw.require_preview {
        base.require_preview = rp;
    }
    if let Some(caps) = &raw.capabilities {
        base.capabilities = caps.resolve_ref(base.capabilities);
    }
    if let Some(sudo) = &raw.sudo {
        super::validation::validate_sudo_policy(sudo, "profiles.*.sudo")?;
        base.sudo = sudo.clone();
    }
    if let Some(ip) = raw.allow_ip_literals {
        base.allow_ip_literals = ip;
    }
    if let Some(selection) = &raw.selection {
        let mut names = if selection.presets.is_empty() && selection.allow.is_empty() {
            global_tools.clone()
        } else {
            let mut set = permitted_builtins.clone();
            set.extend(
                crate::catalog::selection::expand(
                    definable,
                    manifest,
                    &selection.allow,
                    &selection.presets,
                    &[],
                )
                .map_err(|reason| invalid("profiles.*.selection", reason))?,
            );
            set
        };
        if selection.presets.is_empty() && selection.allow.is_empty() && selection.deny.is_empty() {
            names.clear();
        }
        names.retain(|tool| !selection.deny.contains(tool));
        base.selection = Some(names);
    }

    resolving.remove(name);
    compiled.insert(name.to_owned(), base);
    Ok(())
}

fn validate_identifier(name: &str, field: &'static str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(invalid(
            field,
            "must be a non-empty identifier of ASCII letters, digits, '-', '_' or '.'",
        ));
    }
    Ok(())
}

fn validate_host_pattern(pattern: &str) -> Result<(), ConfigError> {
    if pattern.is_empty()
        || pattern.len() > MAX_PATTERN_BYTES
        || pattern
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(invalid(
            "groups.*.match_hosts",
            "host pattern must be a bounded non-empty string without whitespace or control characters",
        ));
    }
    Ok(())
}

/// Linear-time case-insensitive ASCII glob matcher supporting `*` and `?`.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

pub(crate) fn strip_ssh_user(destination: &str) -> &str {
    let host = destination.rsplit_once('@').map_or(destination, |(_, h)| h);
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

pub(crate) fn is_ip_destination(destination: &str) -> bool {
    let host = strip_ssh_user(destination);
    let without_zone = host.split('%').next().unwrap_or(host);
    without_zone.parse::<IpAddr>().is_ok()
}

fn query_ssh_canonical_hostname(
    ssh_executable: &Path,
    ssh_config: Option<&Path>,
    destination: &str,
) -> Option<String> {
    if destination.is_empty() || destination.starts_with('-') {
        return None;
    }
    let mut cmd = Command::new(ssh_executable);
    cmd.arg("-G");
    if let Some(config) = ssh_config {
        cmd.arg("-F").arg(config);
    }
    cmd.arg("--").arg(destination);
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("hostname ") {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matcher_is_case_insensitive_and_linear() {
        assert!(glob_match("*.prod.internal", "DB-01.PROD.INTERNAL"));
        assert!(glob_match("prod-??", "prod-01"));
        assert!(!glob_match("prod-??", "prod-001"));
        assert!(glob_match("*-prd-*", "eu-prd-db01"));
        assert!(!glob_match("*.dev.internal", "web01.prod.internal"));
        // Degenerate repeated-star input still resolves immediately without backtracking blowup.
        let evil_pat = "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let evil_txt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(!glob_match(evil_pat, evil_txt));
    }

    #[test]
    fn ip_literal_detection_handles_v4_v6_and_user_prefix() {
        assert!(is_ip_destination("10.42.0.15"));
        assert!(is_ip_destination("ops@10.42.0.15"));
        assert!(is_ip_destination("fd00::1"));
        assert!(is_ip_destination("root@[fd00::1]"));
        assert!(is_ip_destination("fe80::1%eth0"));
        assert!(!is_ip_destination("db01.prod.internal"));
        assert!(!is_ip_destination("ops@dev-01"));
    }

    #[test]
    fn groups_name_sugar_and_strictest_wins_lattice_are_order_independent() {
        use super::super::test_support::load_text;
        // Group name "lab", "dev", "prod" automatically maps to built-in profiles
        // without repeating `profile = ...`.
        let text_a = r#"
mode = "workstation"
default_profile = "prod"

[[groups]]
name = "lab"
match_hosts = ["*.lab.internal", "lab-*"]

[[groups]]
name = "dev"
match_hosts = ["eu-*", "*.dev.internal"]

[[groups]]
name = "prod"
match_hosts = ["*-prd-*", "*.prod.internal"]
"#;
        let text_b = r#"
mode = "workstation"
default_profile = "prod"

[[groups]]
name = "prod"
match_hosts = ["*-prd-*", "*.prod.internal"]

[[groups]]
name = "dev"
match_hosts = ["eu-*", "*.dev.internal"]

[[groups]]
name = "lab"
match_hosts = ["*.lab.internal", "lab-*"]
"#;
        for text in [text_a, text_b] {
            let config = load_text(text, &[]).expect("load groups config");
            // Overlapping host matches BOTH dev ("eu-*") and prod ("*-prd-*"):
            // strictest-wins must always yield prod regardless of TOML order.
            let overlap = config.evaluate_host_policy("eu-prd-db01");
            assert!(overlap.allowed);
            assert_eq!(overlap.max_tier, RiskTier::Inspect);
            assert!(overlap.require_preview);
            assert!(!overlap.capabilities.exec);
            assert!(!overlap.capabilities.file_write);
            assert!(overlap.capabilities.file_read);
            assert!(config.resolve("eu-prd-db01", ToolId::Exec).is_err());
            assert!(config.resolve("eu-prd-db01", ToolId::ReadFile).is_ok());

            // Dev host gets exec/file_write, no sudo.
            assert!(config.resolve("app01.dev.internal", ToolId::Exec).is_ok());
            assert!(
                config
                    .resolve_sudo("app01.dev.internal", "root", "/usr/bin/id")
                    .is_err()
            );

            // Lab host gets exec + same-account root sudo.
            assert!(config.resolve("lab-01", ToolId::Exec).is_ok());
            assert!(config.resolve_sudo("lab-01", "root", "/usr/bin/id").is_ok());

            // Unmatched host falls back to default_profile = "prod".
            assert!(config.resolve("mystery-host", ToolId::Exec).is_err());
            assert!(config.resolve("mystery-host", ToolId::ReadFile).is_ok());
        }
    }

    #[test]
    fn ip_literals_cannot_bypass_into_non_ip_groups() {
        use super::super::test_support::load_text;
        let text = r#"
mode = "workstation"
default_profile = "deny"

[[groups]]
name = "dev"
match_hosts = ["*"]

[[groups]]
name = "lab"
match_hosts = ["10.99.*"]
"#;
        let config = load_text(text, &[]).expect("load config");
        // Raw IP 10.42.0.15 cannot enter `dev` (allow_ip_literals = false), so it falls back to `deny`.
        let denied = config.evaluate_host_policy("10.42.0.15");
        assert!(!denied.allowed);
        assert_eq!(denied.skipped_ip_groups, vec!["dev".to_owned()]);
        assert!(config.resolve("10.42.0.15", ToolId::ReadFile).is_err());

        // Lab explicitly has allow_ip_literals = true, so 10.99.0.5 matches lab.
        let lab = config.evaluate_host_policy("10.99.0.5");
        assert!(lab.allowed);
        assert_eq!(lab.max_tier, RiskTier::Exec);
        assert!(config.resolve("10.99.0.5", ToolId::Exec).is_ok());
    }

    #[test]
    fn custom_profiles_extend_validate_cycles_and_match_labels() {
        use super::super::test_support::load_text;
        // Cannot redefine built-in profiles.
        assert!(load_text("[profiles.prod]\nmax_tier = 'exec'\n", &[]).is_err());
        // Cycle detection.
        assert!(
            load_text(
                "[profiles.a]\nextends = 'b'\n[profiles.b]\nextends = 'a'\n",
                &[]
            )
            .is_err()
        );
        // Group with unknown name and no explicit profile fails closed.
        assert!(
            load_text(
                "[[groups]]\nname = 'unknown-tier'\nmatch_hosts = ['*']\n",
                &[]
            )
            .is_err()
        );
        // Empty matcher group fails closed.
        assert!(load_text("[[groups]]\nname = 'prod'\n", &[]).is_err());

        // Custom profile extending prod + match_labels on configured targets.
        let text = r#"
mode = "headless"
capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = false }
default_profile = "deny"

[profiles.prod-db]
extends = "prod"
max_tier = "observe"

[[groups]]
name = "prod-databases"
match_labels = { env = "prod", role = "db" }
profile = "prod-db"

[targets.eu-db-01]
ssh_host = "eu-db-01.prod.internal"
labels = { env = "prod", role = "db" }

[targets.unlabeled]
ssh_host = "mystery.internal"
"#;
        let config = load_text(text, &[]).expect("load configured label groups");
        assert!(config.resolve("eu-db-01", ToolId::Stat).is_ok());
        assert!(config.resolve("eu-db-01", ToolId::ReadFile).is_err());
        assert!(config.resolve("unlabeled", ToolId::Stat).is_err());
    }

    #[test]
    fn yolo_flag_is_standalone_emits_warning_and_enables_open_sudo() {
        use super::super::{Cli, Config, test_support::cli};
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("operator.toml");
        std::fs::write(&cfg_path, "mode = 'workstation'\n").unwrap();

        // --yolo cannot be combined with --config.
        assert!(
            Config::load_with(
                Cli {
                    config: Some(cfg_path),
                    yolo: true,
                    ..cli()
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );
        // --include-lab requires --yolo.
        assert!(
            Config::load_with(
                Cli {
                    include_lab: true,
                    ..cli()
                },
                dir.path(),
                |_| None
            )
            .is_err()
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let config = Config::load_with(
            Cli {
                yolo: true,
                ..cli()
            },
            dir.path(),
            |key| (key == "ESTUS_CATALOG_ROOT").then(|| root.as_os_str().to_owned()),
        )
        .expect("load yolo");
        assert!(config.is_yolo());
        assert!(config.startup_warnings().contains(&"yolo_mode_active"));
        assert!(config.has_sudo());
        assert!(config.resolve("any-host", ToolId::Exec).is_ok());
        assert!(
            config
                .resolve_sudo("any-host", "root", "/usr/bin/id")
                .is_ok()
        );
    }
}
