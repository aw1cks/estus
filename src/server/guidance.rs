use rmcp::{
    ErrorData,
    model::{
        GetPromptRequestParams, GetPromptResult, ListPromptsResult, ListResourceTemplatesResult,
        ListResourcesResult, Prompt, PromptArgument, PromptMessage, ReadResourceRequestParams,
        ReadResourceResult, Resource, ResourceContents, ResourceTemplate, Role,
    },
};
use serde_json::Value;

use super::Estus;

pub(super) const INSTRUCTIONS: &str = "\
Estus exposes structured SSH operations organized by risk tier:
- observe_*: read-only system telemetry; safe starting tier.
- inspect_*: sensitive reads (logs, processes, files, sockets) or active probes.
- preview_*: read-only pre-change dependency/plan checks; review before applying changes.
- change_*: structured single-purpose mutations and quarantine reset; never automatically replayed.
- exec_*: generic remote command/argv/sudo execution; escalate only when structured tools cannot express the task.

Uncertainty & Quarantine:
- Interrupted or timed-out writes may report remote_state_unknown=true and quarantine further writes on that logical target.
- When quarantined, read/observe tools remain available to inspect actual target state; clear quarantine explicitly via change_target_quarantine_clear only after independent reconciliation.
- Operations are never retried or replayed automatically.

Continuation & Output Handles:
- Paginated tools (inspect_directory, inspect_journal, inspect_journal_record) return explicit single-use cursors or byte offsets; pass the new token/offset to continue.
- Command/controller tools support retain_output=true to retain bounded stdout/stderr handles readable via inspect_output for the current session.";

const GUIDE_SYSTEMD: &str = "\
# Estus Runbook: Systemd Triage & Service Changes

1. Start read-only: call `observe_systemd_units`, `observe_systemd_unit`, `observe_systemd_jobs`, `observe_systemd_timers`, or `observe_systemd_sockets`.
2. Inspect configuration and logs only when needed: `inspect_systemd_unit_config`, `inspect_journal` (with optional `unit`, `contains`, `direction`, `limit`), and `inspect_journal_record` for long multiline records.
3. Active/inactive/failed manager states are state data, not application health proof.
4. For service mutations (`change_systemd_*`), verify `constraints.allowed_units` and target policy first.
5. Never auto-replay an interrupted or timed-out service mutation; inspect unit state and journal before deciding next steps.";

const GUIDE_LINUX_MEMORY: &str = "\
# Estus Runbook: Linux CPU, Memory & Pressure Triage

1. Collect non-sensitive telemetry first: `observe_cpu`, `observe_memory`, `observe_pressure`, `observe_cgroup_tree`, `observe_cgroup_stats`, `observe_cgroup_sample`.
2. Escalate to sensitive process inspection only when needed: `inspect_processes`, `inspect_process`, `inspect_process_fds`, `inspect_cgroup_processes`.
3. Missing fields are reported in `unavailable` rather than coerced to zero; interpret counter deltas only when `delta` is present and `counter_decrease`/`identity_changed` are false.";

const GUIDE_NETWORKING: &str = "\
# Estus Runbook: Linux Networking & NIC Triage

1. Observe interfaces, addresses, routes, rules, neighbors, and stats first: `observe_network_links`, `observe_network_addresses`, `observe_network_routes`, `observe_network_route_lookup`, `observe_network_neighbors`, `observe_network_interface_stats`, `observe_nic_*`.
2. Escalate to active probes or socket tables deliberately: `inspect_sockets`, `inspect_dns_lookup`, `inspect_icmp_probe`, `inspect_tcp_connect_probe`, `inspect_network_path_probe`.
3. NIC/link/route mutations (`change_network_*`, `change_nic_*`) can disrupt connectivity and trigger target write quarantine if interrupted.";

const GUIDE_UNCERTAINTY: &str = "\
# Estus Runbook: Uncertainty & Quarantine Reconciliation

1. Any mutating binding or write operation whose acknowledgement is lost or whose owner is interrupted after dispatch sets `remote_state_unknown=true` and quarantines writes on that logical host.
2. Quarantine blocks subsequent write/mutating calls with `target_quarantined`; read/observe/inspect tools stay open so you can verify actual remote state.
3. Never replay a failed write blindly. Inspect target state (e.g. `observe_stat`, `inspect_file`, `observe_systemd_unit`, `inspect_journal`) until remote state is understood.
4. Only after independent reconciliation, call `change_target_quarantine_clear` with `acknowledge_remote_state_reconciled=true`.";

struct StaticGuide {
    uri: &'static str,
    name: &'static str,
    title: &'static str,
    description: &'static str,
    body: &'static str,
}

const STATIC_GUIDES: &[StaticGuide] = &[
    StaticGuide {
        uri: "estus://guides/systemd",
        name: "systemd-guide",
        title: "Systemd Triage & Service Changes",
        description: "Safe observation-first workflow for systemd units, logs, and unit mutations.",
        body: GUIDE_SYSTEMD,
    },
    StaticGuide {
        uri: "estus://guides/linux-memory",
        name: "linux-memory-guide",
        title: "Linux CPU, Memory & Pressure Triage",
        description: "Telemetry-first workflow for CPU, memory, PSI pressure, cgroups, and processes.",
        body: GUIDE_LINUX_MEMORY,
    },
    StaticGuide {
        uri: "estus://guides/networking",
        name: "networking-guide",
        title: "Linux Networking & NIC Triage",
        description: "Observation, active probing, and connectivity-safe mutation workflow.",
        body: GUIDE_NETWORKING,
    },
    StaticGuide {
        uri: "estus://guides/uncertainty-reconciliation",
        name: "uncertainty-reconciliation-guide",
        title: "Uncertainty & Quarantine Reconciliation",
        description: "How to investigate remote_state_unknown=true and reconcile quarantined targets.",
        body: GUIDE_UNCERTAINTY,
    },
];

fn validate_arg(value: &str, max_len: usize) -> Result<(), ErrorData> {
    if value.is_empty()
        || value.len() > max_len
        || value.chars().any(|c| c.is_control() && c != ' ')
    {
        return Err(ErrorData::invalid_params("Invalid prompt argument", None));
    }
    Ok(())
}

fn require_string_arg<'a>(
    args: &'a Option<rmcp::model::JsonObject>,
    name: &str,
    required: bool,
) -> Result<Option<&'a str>, ErrorData> {
    let Some(map) = args.as_ref() else {
        return if required {
            Err(ErrorData::invalid_params(
                "Missing required prompt argument",
                None,
            ))
        } else {
            Ok(None)
        };
    };
    match map.get(name) {
        Some(Value::String(s)) => {
            validate_arg(s, 256)?;
            Ok(Some(s.as_str()))
        }
        Some(_) => Err(ErrorData::invalid_params(
            "Prompt argument must be a string",
            None,
        )),
        None if required => Err(ErrorData::invalid_params(
            "Missing required prompt argument",
            None,
        )),
        None => Ok(None),
    }
}

fn check_allowed_keys(
    args: &Option<rmcp::model::JsonObject>,
    allowed: &[&str],
) -> Result<(), ErrorData> {
    if let Some(map) = args.as_ref()
        && map.keys().any(|key| !allowed.contains(&key.as_str()))
    {
        return Err(ErrorData::invalid_params("Unknown prompt argument", None));
    }
    Ok(())
}

pub(super) fn list_prompts() -> ListPromptsResult {
    ListPromptsResult::with_all_items(vec![
        Prompt::new(
            "triage_host",
            Some(
                "Structured host triage plan with resolved capabilities, constraints, and quarantine state",
            ),
            Some(vec![
                PromptArgument::new("host")
                    .with_description("Logical target host (or destination in workstation mode)")
                    .with_required(true),
                PromptArgument::new("symptom")
                    .with_description("Optional observed symptom to guide telemetry selection")
                    .with_required(false),
            ]),
        ),
        Prompt::new(
            "diagnose_service",
            Some(
                "Systemd service diagnosis plan with host capabilities, constraints, and quarantine state",
            ),
            Some(vec![
                PromptArgument::new("host")
                    .with_description("Logical target host")
                    .with_required(true),
                PromptArgument::new("unit")
                    .with_description("Systemd unit name to diagnose")
                    .with_required(true),
            ]),
        ),
        Prompt::new(
            "safe_change",
            Some(
                "Pre-change verification, preview, and uncertainty/quarantine checklist for a target host",
            ),
            Some(vec![
                PromptArgument::new("host")
                    .with_description("Logical target host")
                    .with_required(true),
                PromptArgument::new("operation")
                    .with_description("Intended change operation or tool")
                    .with_required(true),
                PromptArgument::new("target_object")
                    .with_description("Affected remote object (unit, path, sysctl key, interface)")
                    .with_required(true),
            ]),
        ),
        Prompt::new(
            "network_triage",
            Some(
                "Observation-first network and probe plan with host capabilities and quarantine state",
            ),
            Some(vec![
                PromptArgument::new("host")
                    .with_description("Logical target host")
                    .with_required(true),
                PromptArgument::new("peer")
                    .with_description("Optional peer hostname or address for targeted probes")
                    .with_required(false),
            ]),
        ),
    ])
}

fn format_available(
    permitted: &std::collections::BTreeSet<&str>,
    candidates: &[&str],
    fallback: &str,
) -> String {
    let available: Vec<String> = candidates
        .iter()
        .copied()
        .filter(|tool| permitted.contains(tool))
        .map(|tool| format!("`{tool}`"))
        .collect();
    if available.is_empty() {
        fallback.to_owned()
    } else {
        available.join(", ")
    }
}

pub(super) fn get_prompt(
    server: &Estus,
    request: GetPromptRequestParams,
) -> Result<GetPromptResult, ErrorData> {
    let args = &request.arguments;
    let host = match request.name.as_str() {
        "triage_host" => {
            check_allowed_keys(args, &["host", "symptom"])?;
            require_string_arg(args, "host", true)?.expect("required host")
        }
        "diagnose_service" => {
            check_allowed_keys(args, &["host", "unit"])?;
            require_string_arg(args, "host", true)?.expect("required host")
        }
        "safe_change" => {
            check_allowed_keys(args, &["host", "operation", "target_object"])?;
            require_string_arg(args, "host", true)?.expect("required host")
        }
        "network_triage" => {
            check_allowed_keys(args, &["host", "peer"])?;
            require_string_arg(args, "host", true)?.expect("required host")
        }
        _ => return Err(ErrorData::invalid_params("Unknown prompt name", None)),
    };
    let policy = server
        .state
        .config
        .target_policy_summary(
            host,
            &server.state.tools,
            server.state.admission.quarantine_info(host),
        )
        .ok_or_else(|| ErrorData::invalid_params("Unknown or invalid host for prompt", None))?;
    let permitted: std::collections::BTreeSet<&str> = policy["permitted_operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect();

    let (description, body) = match request.name.as_str() {
        "triage_host" => {
            let symptom = require_string_arg(args, "symptom", false)?;
            let symptom_line = symptom.map_or_else(
                || "Symptom: general host health triage.".to_owned(),
                |s| format!("Symptom: {s}"),
            );
            let observe_list = format_available(
                &permitted,
                &[
                    "observe_host_summary",
                    "observe_cpu",
                    "observe_memory",
                    "observe_pressure",
                    "observe_systemd_units",
                    "observe_filesystem_usage",
                    "observe_stat",
                ],
                "permitted `observe_*` tools from the policy below",
            );
            let inspect_list = format_available(
                &permitted,
                &[
                    "inspect_journal",
                    "inspect_processes",
                    "inspect_sockets",
                    "inspect_file",
                    "inspect_directory",
                ],
                "permitted `inspect_*` tools from the policy below",
            );
            (
                "Structured host triage plan",
                format!(
                    "Perform structured read-only triage for host `{host}`.\n{symptom_line}\n\
                     1. Start with `observe_*` tools ({observe_list}).\n\
                     2. Escalate to `inspect_*` ({inspect_list}) only where initial telemetry narrows the scope.\n\
                     3. Avoid mutations or generic `exec_*` during triage."
                ),
            )
        }
        "diagnose_service" => {
            let unit = require_string_arg(args, "unit", true)?.expect("required unit");
            let observe_step = format_available(
                &permitted,
                &[
                    "observe_systemd_unit",
                    "observe_systemd_unit_dependencies",
                    "observe_systemd_units",
                    "observe_stat",
                ],
                "permitted `observe_*` tools in `permitted_operations` below",
            );
            let inspect_step = format_available(
                &permitted,
                &[
                    "inspect_systemd_unit_config",
                    "inspect_journal",
                    "inspect_journal_record",
                    "inspect_file",
                ],
                "permitted `inspect_*` tools in `permitted_operations` below",
            );
            (
                "Systemd service diagnosis plan",
                format!(
                    "Diagnose systemd unit `{unit}` on host `{host}`.\n\
                     1. Read unit and host state with {observe_step}.\n\
                     2. Inspect unit configuration and recent logs for `{unit}` via {inspect_step}.\n\
                     3. Stay within `permitted_operations` listed below; avoid mutations during diagnosis."
                ),
            )
        }
        "safe_change" => {
            let operation =
                require_string_arg(args, "operation", true)?.expect("required operation");
            let target_object =
                require_string_arg(args, "target_object", true)?.expect("required target_object");
            let previews: Vec<String> = permitted
                .iter()
                .copied()
                .filter(|tool| tool.starts_with("preview_"))
                .map(|tool| format!("`{tool}`"))
                .collect();
            let preview_step = if previews.is_empty() {
                "2. No `preview_*` tool is registered for this host; verify target paths/units carefully before mutating.".to_owned()
            } else {
                format!("2. Run matching preview first ({}).", previews.join(", "))
            };
            let clear_note = if permitted.contains("change_target_quarantine_clear") {
                "clear quarantine explicitly via `change_target_quarantine_clear` only after reconciliation"
            } else {
                "escalate to the operator after reconciling actual host state"
            };
            (
                "Safe change and reconciliation checklist",
                format!(
                    "Plan safe change `{operation}` on `{target_object}` for host `{host}`.\n\
                     1. Capture pre-change baseline with permitted `observe_*` / `inspect_*` tools.\n\
                     {preview_step}\n\
                     3. Confirm the host is not quarantined before applying `{operation}`.\n\
                     4. Never auto-replay on timeout/interruption; if `remote_state_unknown=true`, inspect actual state and {clear_note}."
                ),
            )
        }
        "network_triage" => {
            let peer = require_string_arg(args, "peer", false)?;
            let net_observe = format_available(
                &permitted,
                &[
                    "observe_network_links",
                    "observe_network_addresses",
                    "observe_network_routes",
                    "observe_network_interface_stats",
                    "observe_network_neighbors",
                    "observe_network_rules",
                ],
                "permitted `observe_*` tools from `permitted_operations` below",
            );
            let peer_tools = format_available(
                &permitted,
                &[
                    "inspect_sockets",
                    "inspect_dns_lookup",
                    "inspect_tcp_connect_probe",
                    "inspect_icmp_probe",
                    "inspect_network_path_probe",
                ],
                "permitted `inspect_*` tools from `permitted_operations` below",
            );
            let peer_step = peer.map_or_else(
                || format!("2. Inspect active sockets and endpoints via {peer_tools}."),
                |p| format!("2. Inspect sockets and targeted reachability toward `{p}` via {peer_tools}."),
            );
            (
                "Observation-first network triage plan",
                format!(
                    "Perform network triage on host `{host}`.\n\
                     1. Collect link, address, route, and interface state ({net_observe}).\n\
                     {peer_step}"
                ),
            )
        }
        _ => unreachable!(),
    };

    let policy_json = serde_json::to_string_pretty(&policy)
        .map_err(|_| ErrorData::internal_error("Failed to format target policy", None))?;
    let full = format!("{body}\n\nResolved target policy:\n```json\n{policy_json}\n```");
    Ok(
        GetPromptResult::new(vec![PromptMessage::new_text(Role::User, full)])
            .with_description(description),
    )
}

pub(super) fn list_resources(server: &Estus) -> ListResourcesResult {
    let mut resources: Vec<Resource> = STATIC_GUIDES
        .iter()
        .map(|guide| {
            Resource::new(guide.uri, guide.name)
                .with_title(guide.title)
                .with_description(guide.description)
                .with_mime_type("text/markdown")
        })
        .collect();
    for host in server.state.config.configured_target_names() {
        resources.push(
            Resource::new(
                format!("estus://targets/{host}/policy"),
                format!("target-policy-{host}"),
            )
            .with_title(format!("Resolved Policy: {host}"))
            .with_description(
                "Resolved host capabilities, rules, permitted operations, and quarantine state.",
            )
            .with_mime_type("application/json"),
        );
    }
    ListResourcesResult::with_all_items(resources)
}

pub(super) fn list_resource_templates() -> ListResourceTemplatesResult {
    ListResourceTemplatesResult::with_all_items(vec![
        ResourceTemplate::new("estus://targets/{host}/policy", "target-policy")
            .with_title("Target Policy Summary")
            .with_description("Resolved capabilities, host rules, permitted operations, and quarantine state for a target host.")
            .with_mime_type("application/json"),
    ])
}

pub(super) fn read_resource(
    server: &Estus,
    request: ReadResourceRequestParams,
) -> Result<ReadResourceResult, ErrorData> {
    let uri = request.uri.as_str();
    if let Some(guide) = STATIC_GUIDES.iter().find(|guide| guide.uri == uri) {
        return Ok(ReadResourceResult::new(vec![
            ResourceContents::text(guide.body, uri).with_mime_type("text/markdown"),
        ]));
    }
    if let Some(host) = uri
        .strip_prefix("estus://targets/")
        .and_then(|rest| rest.strip_suffix("/policy"))
        && !host.is_empty()
        && !host.contains('/')
        && let Some(summary) = server.state.config.target_policy_summary(
            host,
            &server.state.tools,
            server.state.admission.quarantine_info(host),
        )
    {
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|_| ErrorData::internal_error("Failed to format target policy", None))?;
        return Ok(ReadResourceResult::new(vec![
            ResourceContents::text(json, uri).with_mime_type("application/json"),
        ]));
    }
    Err(ErrorData::resource_not_found("Resource not found", None))
}
