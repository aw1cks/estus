use serde::Serializer;

use crate::{command::MAX_COMMAND_BYTES, wire::MAX_RESPONSE_BYTES};

use super::*;

#[derive(Clone, Copy, Default, Serialize, schemars::JsonSchema)]
pub(crate) struct CleanupDiagnostics {
    pub capacity: usize,
    pub child_reap: usize,
    pub workspace_remove: usize,
}

#[derive(Serialize, schemars::JsonSchema)]
pub(crate) struct TargetDiscovery<'a> {
    mode: TargetMode,
    #[schemars(with = "Vec<TargetSummary<'a>>")]
    targets: TargetSummaries<'a>,
    limits: DiscoveryLimits,
    pub(crate) cleanup_quarantine: CleanupDiagnostics,
}

#[derive(Serialize, schemars::JsonSchema)]
struct TargetSummary<'a> {
    name: &'a str,
    sudo_mode: SudoMode,
    description: Option<&'a str>,
    labels: &'a BTreeMap<String, String>,
    #[schemars(with = "Vec<&'a str>")]
    permitted_operations: PermittedOperations<'a>,
    observed_capabilities: ObservedCapabilities,
}

// Select only public fields as each row is serialized. In particular, do not
// allocate a summary Vec before the shared response-budget guard is applied.
struct TargetSummaries<'a> {
    targets: Option<&'a BTreeMap<String, Target>>,
    tools: &'a ToolCatalog,
    capabilities: Capabilities,
    builtins: &'a BTreeSet<String>,
    bindings: &'a Bindings,
}

impl Serialize for TargetSummaries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.targets.iter().flat_map(|targets| targets.iter()).map(
            |(name, target)| TargetSummary {
                name,
                sudo_mode: target.sudo.mode(),
                description: target.description.as_deref(),
                labels: &target.labels,
                permitted_operations: PermittedOperations {
                    tools: self.tools,
                    bindings: self.bindings,
                    target_name: name,
                    capabilities: self.capabilities,
                    builtins: self.builtins,
                    target: Some(target),
                },
                observed_capabilities: ObservedCapabilities::Unknown,
            },
        ))
    }
}

/// The published answer for one host. It repeats the dispatch decision with
/// the same per-target test, so an operator and an agent read one policy.
struct PermittedOperations<'a> {
    tools: &'a ToolCatalog,
    bindings: &'a Bindings,
    target_name: &'a str,
    /// The global `[capabilities]` ceiling is the only capability gate.
    capabilities: Capabilities,
    /// Builtin names the global selection published.
    builtins: &'a BTreeSet<String>,
    /// `None` is raw-destination mode: no configured target, hence no sudo
    /// grant and no selection or tier narrowing.
    target: Option<&'a Target>,
}

impl Serialize for PermittedOperations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.tools
                .entries
                .iter()
                .filter(|entry| match entry.id {
                    ToolKey::Builtin(id) => {
                        // The test catalogue renames builtins, so match by ID
                        // rather than by published name.
                        let callable = self.capabilities.permits(id)
                            && self.builtins.contains(id.wire_name())
                            && match id {
                                ToolId::Targets
                                | ToolId::ReadOutput
                                | ToolId::ClearTargetQuarantine => false,
                                ToolId::Sudo => self
                                    .target
                                    .is_some_and(|target| target.sudo.permits_programs()),
                                _ => true,
                            };
                        callable
                            && self.target.is_none_or(|target| {
                                target.permits(id.wire_name())
                                    && target.permits_tier(super::policy::risk_tier_for_builtin(id))
                            })
                    }
                    ToolKey::Binding(id) => self.bindings.get(id).is_some_and(|binding| {
                        self.capabilities.permits_bindings()
                            && binding.enabled()
                            && !binding.is_controller()
                            && binding.permits_host(self.target_name)
                            && self.target.is_none_or(|target| {
                                target.permits_binding(binding)
                                    && binding.sudo().is_none_or(|(user, program)| {
                                        target.sudo.permits(user, program)
                                    })
                            })
                    }),
                })
                .map(|entry| entry.name.as_ref()),
        )
    }
}

#[derive(Serialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ObservedCapabilities {
    Unknown,
}

/// Resolved policy ceilings; escaping and JSON framing may reduce usable bytes.
#[derive(Serialize, schemars::JsonSchema)]
struct DiscoveryLimits {
    connect_timeout_secs: u64,
    operation_timeout_secs: u64,
    max_timeout_secs: u64,
    max_output_bytes: u64,
    max_file_bytes: u64,
    max_stdin_bytes: u64,
    max_command_bytes: usize,
    max_encoded_command_bytes: usize,
    max_response_bytes: usize,
    max_directory_page_bytes: usize,
}

impl Config {
    pub(crate) fn targets<'a>(&'a self, tools: &'a ToolCatalog) -> TargetDiscovery<'a> {
        TargetDiscovery {
            mode: if self.targets.is_some() {
                TargetMode::Configured
            } else {
                TargetMode::Open
            },
            targets: TargetSummaries {
                targets: self.targets.as_ref(),
                tools,
                capabilities: self.capabilities,
                builtins: &self.builtins,
                bindings: &self.bindings,
            },
            limits: DiscoveryLimits {
                connect_timeout_secs: self.limits.connect_timeout_secs,
                operation_timeout_secs: self.limits.operation_timeout_secs,
                max_timeout_secs: self.limits.max_timeout_secs,
                max_output_bytes: self.limits.max_output_bytes,
                max_file_bytes: self.limits.max_file_bytes,
                max_stdin_bytes: self.limits.max_file_bytes,
                max_command_bytes: MAX_COMMAND_BYTES,
                max_encoded_command_bytes: MAX_COMMAND_BYTES,
                max_response_bytes: MAX_RESPONSE_BYTES,
                max_directory_page_bytes: crate::filesystem::data::DIRECTORY_PAGE_BYTES,
            },
            cleanup_quarantine: CleanupDiagnostics {
                capacity: crate::controller::QUARANTINE_CAPACITY,
                child_reap: 0,
                workspace_remove: 0,
            },
        }
    }
    pub(crate) fn configured_target_names(&self) -> Vec<&str> {
        self.targets
            .as_ref()
            .map(|targets| targets.keys().map(String::as_str).collect())
            .unwrap_or_default()
    }

    pub(crate) fn target_policy_summary(
        &self,
        host: &str,
        tools: &ToolCatalog,
        quarantine: Option<(String, &'static str, &'static str)>,
    ) -> Option<serde_json::Value> {
        let target = match self.targets.as_ref() {
            Some(targets) => Some(targets.get(host)?),
            None => {
                if !self.allows_dynamic_hosts() || destination(host, "host").is_err() {
                    return None;
                }
                None
            }
        };
        static EMPTY_LABELS: BTreeMap<String, String> = BTreeMap::new();
        let (configured, description, labels) = match target {
            Some(target) => (true, target.description.as_deref(), &target.labels),
            None => (false, None, &EMPTY_LABELS),
        };
        let sudo_ref = target.map(|target| &target.sudo);
        let permitted = PermittedOperations {
            tools,
            bindings: &self.bindings,
            target_name: host,
            capabilities: self.capabilities,
            builtins: &self.builtins,
            target,
        };
        let capabilities = self.capabilities;
        let sudo_mode = sudo_ref.map_or(SudoMode::Disabled, Sudo::mode);
        let mut summary = serde_json::json!({
            "host": host,
            "mode": self.mode,
            "configured": configured,
            "description": description,
            "labels": labels,
            "capabilities": {
                "named": capabilities.named,
                "file_read": capabilities.file_read,
                "file_write": capabilities.file_write,
                "exec": capabilities.exec,
                "sudo": capabilities.sudo,
            },
            "max_tier": target.and_then(|target| target.max_tier),
            "require_preview": self.requires_preview(host),
            "sudo_mode": sudo_mode,
            "permitted_operations": permitted,
            "quarantine": match quarantine {
                Some((authority, executor, cause)) => serde_json::json!({
                    "quarantined": true,
                    "authority": authority,
                    "executor": executor,
                    "cause": cause,
                }),
                None => serde_json::json!({"quarantined": false}),
            }
        });
        if let Some(obj) = summary.as_object_mut() {
            match (self.disclose_sudo_policy, sudo_ref) {
                (_, None | Some(Sudo::Disabled)) => {
                    obj.insert("sudo_policy".into(), serde_json::json!("disabled"));
                }
                (false, Some(Sudo::SameAccount { .. } | Sudo::SeparateIdentity { .. })) => {
                    obj.insert("sudo_policy".into(), serde_json::json!("redacted"));
                }
                (
                    true,
                    Some(
                        Sudo::SameAccount { users, programs }
                        | Sudo::SeparateIdentity {
                            users, programs, ..
                        },
                    ),
                ) => {
                    obj.insert("sudo_policy".into(), serde_json::json!("disclosed"));
                    obj.insert("sudo_users".into(), serde_json::json!(users));
                    obj.insert("sudo_programs".into(), serde_json::json!(programs));
                }
            }
        }
        Some(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{builtin, catalog, load_text};
    use super::*;
    use crate::reply::ErrorCode;

    #[test]
    fn discovery_intersects_target_policy_with_enabled_catalog() {
        let config = load_text(
            "capabilities={named=true,file_read=true,file_write=true,exec=true,sudo=true}\n[targets.one]\nssh_host='private'\n[targets.one.sudo]\nmode='same-account'",
            &[],
        )
        .unwrap();
        let mut tools = catalog();
        tools.retain(|id| matches!(builtin(id), ToolId::Targets | ToolId::Exec | ToolId::Run));
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!(["a-run", "z-exec"])
        );
        tools.retain(|_| false);
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!([])
        );
    }

    #[test]
    fn empty_program_policy_keeps_global_sudo_but_excludes_target_permission() {
        let config = load_text(
            "capabilities={named=true,file_read=true,file_write=true,exec=true,sudo=true}\n[targets.one]\nssh_host='private'\n[targets.one.sudo]\n\
             mode='same-account'\nprograms=[]",
            &[],
        )
        .unwrap();
        let tools = catalog();
        let discovery = serde_json::to_value(config.targets(&tools)).unwrap();
        assert_eq!(discovery["targets"][0]["sudo_mode"], "same-account");
        assert_eq!(
            discovery["targets"][0]["permitted_operations"],
            serde_json::json!(["a-run", "b-list", "c-write", "n-read", "q-stat", "z-exec"])
        );
    }

    #[test]
    fn discovery_sorts_supplied_names_and_targets_without_exposing_aliases() {
        let config = load_text(
            r#"
capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
[targets.zebra]
ssh_host = "ordinary-secret"
[targets.zebra.sudo]
mode = "separate-identity"
ssh_host = "privileged-secret"
[targets.alpha]
ssh_host = "other-secret"
[targets.alpha.sudo]
mode = "same-account"
"#,
            &[],
        )
        .unwrap();
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        assert_eq!(discovery["mode"], "configured");
        assert_eq!(
            discovery["targets"],
            serde_json::json!([
                {
                    "name":"alpha", "sudo_mode":"same-account",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "a-run", "b-list", "c-write", "m-elevate",
                        "n-read", "q-stat", "z-exec"
                    ],
                    "observed_capabilities":"unknown"
                },
                {
                    "name":"zebra", "sudo_mode":"separate-identity",
                    "description":null, "labels":{},
                    "permitted_operations":[
                        "a-run", "b-list", "c-write", "m-elevate",
                        "n-read", "q-stat", "z-exec"
                    ],
                    "observed_capabilities":"unknown"
                }
            ])
        );
        assert!(!discovery.to_string().contains("secret"));
        match &config.targets.as_ref().unwrap()["alpha"].sudo {
            Sudo::SameAccount { users, programs } => {
                assert_eq!(users, &["root"]);
                assert!(programs.is_none());
            }
            _ => panic!("incorrect sudo mode"),
        }
    }

    #[test]
    fn metadata_is_advisory_and_empty_program_allowlists_do_not_advertise_sudo() {
        let config = load_text(
            r#"
capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
[targets.disabled]
ssh_host='private-ordinary'
description='sudo is available'
labels={sudo='enabled'}
[targets.empty_same]
ssh_host='private-same'
[targets.empty_same.sudo]
mode='same-account'
programs=[]
[targets.empty_split]
ssh_host='private-reader'
[targets.empty_split.sudo]
mode='separate-identity'
ssh_host='private-elevated'
users=['private_user']
programs=[]
[targets.allowed]
ssh_host='private-allowed'
[targets.allowed.sudo]
mode='same-account'
users=['private_user']
programs=['/private/program']
"#,
            &[],
        )
        .unwrap();
        let discovery = serde_json::to_value(config.targets(&catalog())).unwrap();
        let rows = discovery["targets"].as_array().unwrap();
        for (name, mode) in [
            ("disabled", "disabled"),
            ("empty_same", "same-account"),
            ("empty_split", "separate-identity"),
        ] {
            let row = rows.iter().find(|row| row["name"] == name).unwrap();
            assert_eq!(row["sudo_mode"], mode);
            assert_eq!(
                row["permitted_operations"],
                serde_json::json!(["a-run", "b-list", "c-write", "n-read", "q-stat", "z-exec"])
            );
            assert_eq!(row["observed_capabilities"], "unknown");
            assert_eq!(
                config
                    .resolve_sudo(name, "private_user", "/private/program")
                    .err()
                    .unwrap()
                    .code(),
                ErrorCode::PolicyDenied
            );
        }
        let disabled = rows.iter().find(|row| row["name"] == "disabled").unwrap();
        assert_eq!(disabled["description"], "sudo is available");
        assert_eq!(disabled["labels"], serde_json::json!({"sudo":"enabled"}));
        let allowed = rows.iter().find(|row| row["name"] == "allowed").unwrap();
        assert!(
            allowed["permitted_operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| operation == "m-elevate")
        );
        assert!(!discovery.to_string().contains("private"));
    }

    #[test]
    fn discovery_limits_report_resolved_toml_and_environment_policy_without_clamping() {
        let text = "[limits]\nconnect_timeout_secs=2\noperation_timeout_secs=3\n\
                    max_timeout_secs=4\nmax_output_bytes=5\nmax_file_bytes=6";
        let config = load_text(text, &[]).unwrap();
        let limits = serde_json::to_value(config.targets(&catalog())).unwrap()["limits"].clone();
        assert_eq!(
            limits,
            serde_json::json!({
                "connect_timeout_secs":2, "operation_timeout_secs":3, "max_timeout_secs":4,
                "max_output_bytes":5, "max_file_bytes":6, "max_stdin_bytes":6,
                "max_command_bytes":MAX_COMMAND_BYTES,
                "max_encoded_command_bytes":MAX_COMMAND_BYTES,
                "max_response_bytes":MAX_RESPONSE_BYTES,
                "max_directory_page_bytes":1_048_576
            })
        );
        let config = load_text(
            text,
            &[
                ("ESTUS_CONNECT_TIMEOUT_SECS", "7"),
                ("ESTUS_OPERATION_TIMEOUT_SECS", "8"),
                ("ESTUS_MAX_TIMEOUT_SECS", "9"),
                ("ESTUS_MAX_OUTPUT_BYTES", "20000000"),
                ("ESTUS_MAX_FILE_BYTES", "30000000"),
            ],
        )
        .unwrap();
        let limits = serde_json::to_value(config.targets(&catalog())).unwrap()["limits"].clone();
        assert_eq!(
            limits,
            serde_json::json!({
                "connect_timeout_secs":7, "operation_timeout_secs":8, "max_timeout_secs":9,
                "max_output_bytes":20000000, "max_file_bytes":30000000,
                "max_stdin_bytes":30000000, "max_command_bytes":MAX_COMMAND_BYTES,
                "max_encoded_command_bytes":MAX_COMMAND_BYTES,
                "max_response_bytes":MAX_RESPONSE_BYTES,
                "max_directory_page_bytes":1_048_576
            })
        );
    }

    #[test]
    fn discovery_schema_describes_public_summary_array_not_private_target_map() {
        fn resolve<'a>(
            document: &'a serde_json::Value,
            node: &'a serde_json::Value,
        ) -> &'a serde_json::Value {
            match node["$ref"].as_str() {
                Some(reference) => document
                    .pointer(reference.strip_prefix('#').unwrap())
                    .unwrap(),
                None => node,
            }
        }
        let schema = serde_json::to_value(schemars::schema_for!(TargetDiscovery<'_>)).unwrap();
        let targets = &schema["properties"]["targets"];
        assert_eq!(targets["type"], "array");
        let summary = &resolve(&schema, &targets["items"])["properties"];
        for field in [
            "description",
            "labels",
            "name",
            "observed_capabilities",
            "permitted_operations",
            "sudo_mode",
        ] {
            assert!(summary.get(field).is_some(), "missing public field {field}");
        }
        let limits = resolve(&schema, &schema["properties"]["limits"]);
        assert_eq!(limits["type"], "object");
        assert!(limits["properties"].get("max_response_bytes").is_some());
        let encoded = schema.to_string();
        for private_field in ["ssh_host", "config_file", "\"users\"", "\"programs\""] {
            assert!(!encoded.contains(private_field), "{private_field}");
        }
    }
}
