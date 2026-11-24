use std::process::ExitCode;

use serde::Serialize;

use crate::{
    bindings::{AutomationAuthority, CompiledBinding},
    config::{
        AuthArgs, AuthCommand, Capabilities, Config, RiskTier, SudoMode, ToolId, destination,
        profiles::{EffectivePolicy, PolicyMatch},
        risk_tier_for_binding, risk_tier_for_builtin,
    },
};

#[derive(Serialize)]
struct TierCounts {
    observe: usize,
    inspect: usize,
    preview: usize,
    change: usize,
    exec: usize,
}

#[derive(Serialize)]
struct ExplainReport {
    host: String,
    mode: &'static str,
    yolo: bool,
    configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_source_file: Option<String>,
    ssh_host: Option<String>,
    resolved_ssh_hostname: Option<String>,
    is_ip_literal: bool,
    allowed: bool,
    reason: Option<String>,
    matched: Vec<PolicyMatch>,
    skipped_ip_groups: Vec<String>,
    effective: EffectiveSummary,
    tools: ToolsSummary,
}

#[derive(Serialize)]
struct EffectiveSummary {
    max_tier: RiskTier,
    max_tier_source: Option<String>,
    require_preview: bool,
    require_preview_source: Option<String>,
    capabilities: Capabilities,
    sudo_mode: SudoMode,
}

#[derive(Serialize)]
struct ToolsSummary {
    total: usize,
    by_tier: TierCounts,
    permitted: Vec<String>,
}

#[derive(Serialize)]
struct CanIReport {
    allowed: bool,
    tool: String,
    host: String,
    tier: Option<RiskTier>,
    requires_preview: bool,
    reason: String,
    resolved_ssh_hostname: Option<String>,
    matched: Vec<PolicyMatch>,
}

struct ToolDecision {
    allowed: bool,
    tier: Option<RiskTier>,
    requires_preview: bool,
    reason: String,
}

pub(crate) fn run(config: &Config, args: AuthArgs) -> ExitCode {
    match args.command {
        AuthCommand::Explain { host, json } => run_explain(config, &host, json),
        AuthCommand::CanI { tool, host, json } => run_can_i(config, &tool, &host, json),
    }
}

fn run_explain(config: &Config, host: &str, json: bool) -> ExitCode {
    let report = build_explain(config, host);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => return ExitCode::from(2),
        }
    } else {
        print_explain_text(&report);
    }
    if report.allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_can_i(config: &Config, tool: &str, host: &str, json: bool) -> ExitCode {
    let report = build_can_i(config, tool, host);
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => return ExitCode::from(2),
        }
    } else if report.allowed {
        if report.requires_preview {
            println!("yes  ({})", report.reason);
        } else {
            println!("yes");
        }
    } else {
        println!("no   ({})", report.reason);
    }
    if report.allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn build_explain(config: &Config, host: &str) -> ExplainReport {
    let configured = config.target_ssh_host(host).is_some();
    let target_source_file = config.target_source_file(host).map(str::to_owned);
    let ssh_host = config.target_ssh_host(host).map(str::to_owned);
    let effective = config.evaluate_host_policy(host);

    let (host_ok, host_reason) = check_host_reachable(config, host, &effective);

    let effective_caps = intersect_caps(
        config.global_capabilities(),
        if effective.active {
            effective.capabilities
        } else {
            Capabilities::all()
        },
    );

    let target_tier = config.target_max_tier(host);
    let (max_tier, max_tier_source) = match (target_tier, effective.active) {
        (Some(t), true) if t < effective.max_tier => {
            (t, Some(format!("target \"{host}\" max_tier")))
        }
        (Some(t), false) => (t, Some(format!("target \"{host}\" max_tier"))),
        (_, true) => (effective.max_tier, effective.max_tier_source.clone()),
        (None, false) => (RiskTier::Exec, Some("unconstrained".to_owned())),
    };

    let require_preview = config.requires_preview(host);
    let require_preview_source = if require_preview {
        effective
            .require_preview_source
            .clone()
            .or_else(|| Some("config/target require_preview".to_owned()))
    } else {
        None
    };

    let sudo_mode = config.sudo_mode(host);

    let mut permitted = Vec::new();
    let mut counts = TierCounts {
        observe: 0,
        inspect: 0,
        preview: 0,
        change: 0,
        exec: 0,
    };

    if host_ok {
        for tool_id in ToolId::ALL {
            if matches!(
                tool_id,
                ToolId::Targets | ToolId::ReadOutput | ToolId::ClearTargetQuarantine
            ) {
                continue;
            }
            let decision = decide_builtin(config, tool_id, host, &effective);
            if decision.allowed {
                permitted.push(tool_id.wire_name().to_owned());
                if let Some(tier) = decision.tier {
                    bump_tier(&mut counts, tier);
                }
            }
        }
        for (id, binding) in config.bindings().entries() {
            if !config.binding_enabled(id) || binding.is_controller() {
                continue;
            }
            let decision = decide_binding(config, binding, host, &effective);
            if decision.allowed {
                permitted.push(binding.name.clone());
                if let Some(tier) = decision.tier {
                    bump_tier(&mut counts, tier);
                }
            }
        }
    }
    permitted.sort();

    ExplainReport {
        host: host.to_owned(),
        mode: if config.has_configured_targets() {
            "configured"
        } else {
            "open"
        },
        yolo: config.is_yolo(),
        configured,
        target_source_file,
        ssh_host,
        resolved_ssh_hostname: effective.resolved_ssh_hostname.clone(),
        is_ip_literal: effective.is_ip_literal,
        allowed: host_ok,
        reason: host_reason,
        matched: effective.matched,
        skipped_ip_groups: effective.skipped_ip_groups,
        effective: EffectiveSummary {
            max_tier,
            max_tier_source,
            require_preview,
            require_preview_source,
            capabilities: effective_caps,
            sudo_mode,
        },
        tools: ToolsSummary {
            total: permitted.len(),
            by_tier: counts,
            permitted,
        },
    }
}

fn build_can_i(config: &Config, tool_name: &str, host: &str) -> CanIReport {
    let effective = config.evaluate_host_policy(host);
    let (host_ok, host_reason) = check_host_reachable(config, host, &effective);
    if !host_ok {
        return CanIReport {
            allowed: false,
            tool: tool_name.to_owned(),
            host: host.to_owned(),
            tier: lookup_tier(config, tool_name),
            requires_preview: false,
            reason: host_reason.unwrap_or_else(|| "host is not authorized".to_owned()),
            resolved_ssh_hostname: effective.resolved_ssh_hostname,
            matched: effective.matched,
        };
    }

    let decision =
        if let Some(tool_id) = ToolId::ALL.into_iter().find(|t| t.wire_name() == tool_name) {
            decide_builtin(config, tool_id, host, &effective)
        } else if let Some((id, binding)) = config
            .bindings()
            .entries()
            .find(|(_, b)| b.name == tool_name)
        {
            if !config.binding_enabled(id) {
                ToolDecision {
                    allowed: false,
                    tier: Some(risk_tier_for_binding(binding)),
                    requires_preview: false,
                    reason: "tool is not published under the current configuration".to_owned(),
                }
            } else {
                decide_binding(config, binding, host, &effective)
            }
        } else {
            ToolDecision {
                allowed: false,
                tier: None,
                requires_preview: false,
                reason: "unknown or unpublished tool".to_owned(),
            }
        };

    CanIReport {
        allowed: decision.allowed,
        tool: tool_name.to_owned(),
        host: host.to_owned(),
        tier: decision.tier,
        requires_preview: decision.requires_preview,
        reason: decision.reason,
        resolved_ssh_hostname: effective.resolved_ssh_hostname,
        matched: effective.matched,
    }
}

fn check_host_reachable(
    config: &Config,
    host: &str,
    effective: &EffectivePolicy,
) -> (bool, Option<String>) {
    if config.has_configured_targets() {
        if config.target_ssh_host(host).is_none() {
            return (
                false,
                Some(format!(
                    "host \"{host}\" is not a configured logical target under [targets]"
                )),
            );
        }
    } else if destination(host, "host").is_err() {
        return (
            false,
            Some("host must be a safe non-empty SSH destination".to_owned()),
        );
    }
    if effective.active && !effective.allowed {
        let detail = effective
            .denied_source
            .clone()
            .unwrap_or_else(|| "denied by policy".to_owned());
        return (false, Some(format!("host denied by {detail}")));
    }
    (true, None)
}

fn decide_builtin(
    config: &Config,
    tool: ToolId,
    host: &str,
    effective: &EffectivePolicy,
) -> ToolDecision {
    let tier = risk_tier_for_builtin(tool);
    if matches!(
        tool,
        ToolId::Targets | ToolId::ReadOutput | ToolId::ClearTargetQuarantine
    ) {
        return ToolDecision {
            allowed: config.tool_enabled(tool),
            tier: Some(tier),
            requires_preview: false,
            reason: "global control tool".to_owned(),
        };
    }

    if !config.global_capabilities().permits(tool) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "disabled by global [capabilities] (requires {})",
                required_cap_name(tool)
            ),
        };
    }
    if !config.global_builtins().contains(tool.wire_name()) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: "excluded by global [selection]".to_owned(),
        };
    }
    if effective.active && !effective.capabilities.permits(tool) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "capability \"{}\" disabled by matched profile(s){}",
                required_cap_name(tool),
                format_match_hint(effective)
            ),
        };
    }
    if effective.active && tier > effective.max_tier {
        let src = effective
            .max_tier_source
            .as_deref()
            .unwrap_or("matched profile");
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "tier \"{}\" exceeds max_tier \"{}\" from {src}{}",
                tier_name(tier),
                tier_name(effective.max_tier),
                format_ssh_hint(effective)
            ),
        };
    }
    if let Some(target_tier) = config.target_max_tier(host)
        && tier > target_tier
    {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "tier \"{}\" exceeds target max_tier \"{}\"",
                tier_name(tier),
                tier_name(target_tier)
            ),
        };
    }
    if !config.target_permits_tool_name(host, tool.wire_name()) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: "excluded by target [targets.*.selection]".to_owned(),
        };
    }
    if effective
        .selection
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(tool.wire_name()))
    {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "excluded by profile selection{}",
                format_match_hint(effective)
            ),
        };
    }
    if tool == ToolId::Sudo
        && !config.target_sudo_permits_programs(host)
        && !effective.permits_open_sudo()
    {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "sudo is disabled for host \"{host}\"{}",
                format_match_hint(effective)
            ),
        };
    }
    if matches!(tier, RiskTier::Change | RiskTier::Exec) && config.requires_preview(host) {
        let src = effective
            .require_preview_source
            .as_deref()
            .unwrap_or("require_preview policy");
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: true,
            reason: format!(
                "builtin {} tool has no qualified preview path under require_preview = true ({src})",
                tier_name(tier)
            ),
        };
    }
    ToolDecision {
        allowed: true,
        tier: Some(tier),
        requires_preview: false,
        reason: "authorized".to_owned(),
    }
}

fn decide_binding(
    config: &Config,
    binding: &CompiledBinding,
    host: &str,
    effective: &EffectivePolicy,
) -> ToolDecision {
    let tier = risk_tier_for_binding(binding);
    let native_sudo = binding.sudo().is_some();
    let named_authority = matches!(
        binding.automation_authority(),
        Some(AutomationAuthority::Named(_))
    );
    let needs_sudo = native_sudo || named_authority;

    if !config.global_capabilities().named {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: "disabled by global capabilities.named = false".to_owned(),
        };
    }
    if effective.active && !effective.capabilities.named {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "capabilities.named disabled by matched profile(s){}",
                format_match_hint(effective)
            ),
        };
    }
    // A native sudo route is gated by the target's sudo policy and the active
    // profile, not by the global capability (see `Config::resolve_binding`).
    // Only a named automation authority needs `capabilities.sudo`.
    if named_authority && !config.global_capabilities().sudo {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: "disabled by global capabilities.sudo = false".to_owned(),
        };
    }
    if needs_sudo && effective.active && !effective.capabilities.sudo {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "elevation (capabilities.sudo) disabled by matched profile(s){}",
                format_match_hint(effective)
            ),
        };
    }
    if effective.active && tier > effective.max_tier {
        let src = effective
            .max_tier_source
            .as_deref()
            .unwrap_or("matched profile");
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "tier \"{}\" exceeds max_tier \"{}\" from {src}{}",
                tier_name(tier),
                tier_name(effective.max_tier),
                format_ssh_hint(effective)
            ),
        };
    }
    if let Some(target_tier) = config.target_max_tier(host)
        && tier > target_tier
    {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "tier \"{}\" exceeds target max_tier \"{}\"",
                tier_name(tier),
                tier_name(target_tier)
            ),
        };
    }
    if !binding.has_dynamic_targets() && !binding.permits_host(host) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!("tool targets list does not include \"{host}\""),
        };
    }
    if !config.target_permits_tool_name(host, &binding.name) {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: "excluded by target [targets.*.selection]".to_owned(),
        };
    }
    if effective
        .selection
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&binding.name))
    {
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: false,
            reason: format!(
                "excluded by profile selection{}",
                format_match_hint(effective)
            ),
        };
    }

    if let Some(AutomationAuthority::Named(auth_name)) = binding.automation_authority() {
        let has_named = config.has_named_automation_authority(auth_name, host);
        let workstation_sudo = binding.has_dynamic_targets()
            && (config.target_permits_workstation_sudo(host) || effective.permits_open_sudo());
        if !has_named && !workstation_sudo {
            return ToolDecision {
                allowed: false,
                tier: Some(tier),
                requires_preview: false,
                reason: format!(
                    "requires elevated authority \"automation:{auth_name}\" or unrestricted root sudo on \"{host}\""
                ),
            };
        }
    }

    let preview_required =
        matches!(tier, RiskTier::Change | RiskTier::Exec) && config.requires_preview(host);
    if preview_required {
        if is_preview_paired_binding(&binding.name) {
            return ToolDecision {
                allowed: true,
                tier: Some(tier),
                requires_preview: true,
                reason: "requires a matching preview before execution (require_preview = true)"
                    .to_owned(),
            };
        }
        let src = effective
            .require_preview_source
            .as_deref()
            .unwrap_or("require_preview policy");
        return ToolDecision {
            allowed: false,
            tier: Some(tier),
            requires_preview: true,
            reason: format!("no qualified preview pairing under require_preview = true ({src})"),
        };
    }

    ToolDecision {
        allowed: true,
        tier: Some(tier),
        requires_preview: false,
        reason: "authorized".to_owned(),
    }
}

fn is_preview_paired_binding(name: &str) -> bool {
    crate::server::preview::PREVIEW_PAIRED_CHANGES.contains(&name)
}

fn lookup_tier(config: &Config, tool_name: &str) -> Option<RiskTier> {
    if let Some(tool_id) = ToolId::ALL.into_iter().find(|t| t.wire_name() == tool_name) {
        return Some(risk_tier_for_builtin(tool_id));
    }
    config
        .bindings()
        .entries()
        .find(|(_, b)| b.name == tool_name)
        .map(|(_, b)| risk_tier_for_binding(b))
}

fn required_cap_name(tool: ToolId) -> &'static str {
    match tool {
        ToolId::ReadFile | ToolId::Stat | ToolId::ListDirectory => "file_read",
        ToolId::WriteFile
        | ToolId::Mkdir
        | ToolId::Rename
        | ToolId::RemoveFile
        | ToolId::RemoveDirectory
        | ToolId::ReplaceFile => "file_write",
        ToolId::Exec | ToolId::Run => "exec",
        ToolId::Sudo => "sudo",
        ToolId::Targets | ToolId::ReadOutput | ToolId::ClearTargetQuarantine => "global",
    }
}

fn tier_name(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::Observe => "observe",
        RiskTier::Inspect => "inspect",
        RiskTier::Preview => "preview",
        RiskTier::Change => "change",
        RiskTier::Exec => "exec",
    }
}

fn sudo_mode_name(mode: SudoMode) -> &'static str {
    match mode {
        SudoMode::Disabled => "disabled",
        SudoMode::SameAccount => "same-account",
        SudoMode::SeparateIdentity => "separate-identity",
    }
}

fn format_caps(caps: Capabilities) -> String {
    let mut parts = Vec::new();
    if caps.named {
        parts.push("named");
    }
    if caps.file_read {
        parts.push("file_read");
    }
    if caps.file_write {
        parts.push("file_write");
    }
    if caps.exec {
        parts.push("exec");
    }
    if caps.sudo {
        parts.push("sudo");
    }
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(", ")
    }
}

fn intersect_caps(a: Capabilities, b: Capabilities) -> Capabilities {
    Capabilities {
        named: a.named && b.named,
        file_read: a.file_read && b.file_read,
        file_write: a.file_write && b.file_write,
        exec: a.exec && b.exec,
        sudo: a.sudo && b.sudo,
    }
}

fn bump_tier(counts: &mut TierCounts, tier: RiskTier) {
    match tier {
        RiskTier::Observe => counts.observe += 1,
        RiskTier::Inspect => counts.inspect += 1,
        RiskTier::Preview => counts.preview += 1,
        RiskTier::Change => counts.change += 1,
        RiskTier::Exec => counts.exec += 1,
    }
}

fn format_ssh_hint(effective: &EffectivePolicy) -> String {
    match &effective.resolved_ssh_hostname {
        Some(resolved) => format!("; matched via ssh -G hostname \"{resolved}\""),
        None => String::new(),
    }
}

fn format_match_hint(effective: &EffectivePolicy) -> String {
    if effective.matched.is_empty() {
        return format_ssh_hint(effective);
    }
    let summary: Vec<String> = effective
        .matched
        .iter()
        .map(|m| format!("{} -> profile \"{}\"", m.source, m.profile))
        .collect();
    format!(" ({}){}", summary.join(", "), format_ssh_hint(effective))
}

fn print_explain_text(report: &ExplainReport) {
    let mut target_meta = vec![format!("{} mode", report.mode)];
    if report.yolo {
        target_meta.push("--yolo".to_owned());
    }
    if let Some(source) = &report.target_source_file {
        target_meta.push(format!("from {source}"));
    }
    if let Some(ssh_host) = &report.ssh_host
        && ssh_host != &report.host
    {
        target_meta.push(format!("ssh_host: {ssh_host}"));
    }
    if let Some(resolved) = &report.resolved_ssh_hostname {
        target_meta.push(format!("ssh -G hostname: {resolved}"));
    }
    if report.is_ip_literal {
        target_meta.push("IP literal".to_owned());
    }
    println!(
        "Target:          {} ({})",
        report.host,
        target_meta.join("; ")
    );
    if report.matched.is_empty() {
        println!("Matched groups:  (none)");
    } else {
        println!("Matched groups:");
        for entry in &report.matched {
            let src = match &entry.source_file {
                Some(file) => format!("{} ({file})", entry.source),
                None => entry.source.clone(),
            };
            let prof = match &entry.profile_source_file {
                Some(file) => format!("\"{}\" ({file})", entry.profile),
                None => format!("\"{}\"", entry.profile),
            };
            println!("  - {src} -> profile {prof} ({})", entry.reason);
        }
    }
    if !report.skipped_ip_groups.is_empty() {
        println!(
            "Skipped groups:  {} (raw IP literal rejected by allow_ip_literals = false)",
            report.skipped_ip_groups.join(", ")
        );
    }
    println!(
        "Effective policy (strictest-wins across {} match{}):",
        report.matched.len(),
        if report.matched.len() == 1 { "" } else { "es" }
    );
    if report.allowed {
        println!("  allowed:         yes");
    } else {
        println!(
            "  allowed:         no ({})",
            report.reason.as_deref().unwrap_or("denied")
        );
    }
    match &report.effective.max_tier_source {
        Some(src) => println!(
            "  max_tier:        {:<10} ({src})",
            tier_name(report.effective.max_tier)
        ),
        None => println!(
            "  max_tier:        {}",
            tier_name(report.effective.max_tier)
        ),
    }
    match &report.effective.require_preview_source {
        Some(src) => println!(
            "  require_preview: {:<10} ({src})",
            report.effective.require_preview
        ),
        None => println!("  require_preview: {}", report.effective.require_preview),
    }
    println!(
        "  capabilities:    {}",
        format_caps(report.effective.capabilities)
    );
    println!(
        "  sudo:            {}",
        sudo_mode_name(report.effective.sudo_mode)
    );
    println!(
        "  tools:           {} permitted (observe: {}, inspect: {}, preview: {}, change: {}, exec: {})",
        report.tools.total,
        report.tools.by_tier.observe,
        report.tools.by_tier.inspect,
        report.tools.by_tier.preview,
        report.tools.by_tier.change,
        report.tools.by_tier.exec,
    );
}
