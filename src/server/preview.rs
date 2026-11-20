use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use serde_json::json;

use crate::config::{AutomationAgent, ResolvedAutomation};

pub(crate) const MAX_ENTRIES: usize = 256;
pub(crate) const TTL: Duration = Duration::from_secs(300);

const QUALIFIED_MODULES: &[&str] = &[
    "ansible.builtin.systemd_service",
    "ansible.posix.sysctl",
    "ansible.builtin.apt",
    "ansible.builtin.dnf",
    "ansible.builtin.dnf5",
    "ansible.builtin.package",
];

pub(crate) fn is_qualified_module(module: &str) -> bool {
    QUALIFIED_MODULES.contains(&module)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PreviewKey {
    pub(crate) target: String,
    pub(crate) authority_identity: [u8; 32],
    pub(crate) domain: &'static str,
    pub(crate) intent_digest: [u8; 32],
    pub(crate) pre_state_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct PreviewSpec {
    pub(crate) domain: &'static str,
    pub(crate) prestate_module: &'static str,
    pub(crate) prestate_args: Value,
    pub(crate) intent_digest: [u8; 32],
}
pub(crate) struct PreviewStore {
    entries: Mutex<VecDeque<(PreviewKey, Instant)>>,
}

impl Default for PreviewStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PreviewStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
        }
    }

    pub(crate) fn insert(&self, key: PreviewKey) {
        self.insert_at(key, Instant::now());
    }

    pub(crate) fn insert_at(&self, key: PreviewKey, now: Instant) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut entries, now);
        if let Some(pos) = entries.iter().position(|(existing, _)| existing == &key) {
            entries.remove(pos);
        }
        while entries.len() >= MAX_ENTRIES {
            entries.pop_front();
        }
        entries.push_back((key, now));
    }

    pub(crate) fn consume(&self, key: &PreviewKey) -> bool {
        self.consume_at(key, Instant::now())
    }

    pub(crate) fn consume_at(&self, key: &PreviewKey, now: Instant) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut entries, now);
        if let Some(pos) = entries.iter().position(|(existing, _)| existing == key) {
            entries.remove(pos);
            true
        } else {
            false
        }
    }
}

fn prune(entries: &mut VecDeque<(PreviewKey, Instant)>, now: Instant) {
    entries.retain(|(_, recorded_at)| now.saturating_duration_since(*recorded_at) < TTL);
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<String, Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_value(v)))
                .collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

pub(crate) fn canonical_json_sha256(value: &Value) -> Result<[u8; 32], &'static str> {
    let canonical = canonicalize_value(value);
    let bytes = serde_json::to_vec(&canonical).map_err(|_| "invalid_preview_key")?;
    Ok(Sha256::digest(&bytes).into())
}

pub(crate) fn authority_identity_digest(
    authority_label: &str,
    target: &ResolvedAutomation<'_>,
) -> Result<[u8; 32], &'static str> {
    let agent = match target.agent {
        AutomationAgent::Inherit => {
            std::env::var_os("SSH_AUTH_SOCK").map(|socket| socket.to_string_lossy().into_owned())
        }
        AutomationAgent::Disabled => None,
        AutomationAgent::Fixed(socket) => Some(socket.to_string_lossy().into_owned()),
    };
    let identity = serde_json::json!({
        "authority": authority_label,
        "destination": target.target.destination,
        "python": target.target.python,
        "ssh_config": target.ssh_config,
        "ssh_executable": target.ssh_executable,
        "become": target.r#become,
        "agent": agent,
    });
    canonical_json_sha256(&identity)
}

fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Injective catalog file slug for a sysctl key matching `[a-z0-9_.-]+`:
/// `_` doubles and `.` becomes `_`, so distinct keys can never share a file
/// (`br_0` -> `br__0`, `br-0` -> `br-0`).
fn sysctl_config_slug(key: &str) -> String {
    key.replace('_', "__").replace('.', "_")
}

fn sorted_names(raw: Option<&Value>) -> Option<Vec<String>> {
    let mut names = match raw? {
        Value::String(s) if !s.is_empty() => vec![s.clone()],
        Value::Array(items) => {
            let mut v = Vec::with_capacity(items.len());
            for item in items {
                let s = item.as_str()?;
                if !s.is_empty() {
                    v.push(s.to_owned());
                }
            }
            v
        }
        _ => return None,
    };
    names.sort_unstable();
    names.dedup();
    if names.is_empty() { None } else { Some(names) }
}

fn canonical_package_state(raw: Option<&str>) -> Option<&'static str> {
    match raw.unwrap_or("present") {
        "present" | "installed" => Some("present"),
        "absent" | "removed" => Some("absent"),
        "latest" => Some("latest"),
        _ => None,
    }
}

impl PreviewSpec {
    pub(crate) fn for_ansible(module: &str, args: &Value) -> Option<Self> {
        match module {
            "ansible.posix.sysctl" => {
                let key = args.get("name").and_then(Value::as_str)?;
                let state = args
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("present");
                let value = scalar_string(args.get("value"));
                let sysctl_set = args
                    .get("sysctl_set")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                // Bind the same file the native executors pin, so one preview
                // authorizes the config and runtime payloads alike.
                let sysctl_file = match args.get("sysctl_file").and_then(Value::as_str) {
                    Some(explicit) => Value::String(explicit.to_owned()),
                    // `change_sysctl_runtime` never reads or writes
                    // `/etc/sysctl.conf`, so a runtime preview binds a null file.
                    None if sysctl_set => Value::Null,
                    None => Value::String(format!(
                        "/etc/sysctl.d/90-estus-catalog-{}.conf",
                        sysctl_config_slug(key)
                    )),
                };
                // The catalog fixes reload=false for preview; defaulting to true
                // would make a bare preview digest unmatchable.
                let reload = args.get("reload").and_then(Value::as_bool).unwrap_or(false);
                let intent = json!({
                    "key": key,
                    "value": value,
                    "sysctl_file": sysctl_file.clone(),
                    "sysctl_set": sysctl_set,
                    "reload": reload,
                    "state": state,
                });
                Some(Self {
                    domain: "ansible.posix.sysctl",
                    prestate_module: "ansible.posix.sysctl",
                    prestate_args: json!({"name": key, "sysctl_file": sysctl_file}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                })
            }
            "ansible.builtin.systemd_service" => {
                let unit = args.get("name").and_then(Value::as_str)?;
                let scope = args
                    .get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or("system");
                let intent = json!({
                    "unit": unit,
                    "scope": scope,
                    "state": args.get("state").and_then(Value::as_str),
                    "enabled": args.get("enabled").and_then(Value::as_bool),
                    "masked": args.get("masked").and_then(Value::as_bool),
                    "daemon_reload": args.get("daemon_reload").and_then(Value::as_bool).unwrap_or(false),
                });
                Some(Self {
                    domain: "ansible.builtin.systemd_service",
                    prestate_module: "ansible.builtin.systemd_service",
                    prestate_args: json!({"name": unit, "scope": scope}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                })
            }
            "ansible.builtin.package"
            | "ansible.builtin.apt"
            | "ansible.builtin.dnf"
            | "ansible.builtin.dnf5" => {
                let names = sorted_names(args.get("name"))?;
                let state = canonical_package_state(args.get("state").and_then(Value::as_str))?;
                let version = args
                    .get("version")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty());
                let mut options = args.as_object()?.clone();
                options.remove("name");
                options.remove("state");
                options.remove("version");
                // Internal safety flags are not caller intent and would make an
                // otherwise identical preview and change digest disagree.
                options.remove("auto_install_module_deps");
                // Normalize the cache toggle so omitted and `false` agree while
                // `true` still changes the digest.
                let update_cache = options
                    .remove("update_cache")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false);
                options.insert("update_cache".into(), Value::Bool(update_cache));
                let intent = json!({
                    "module": module,
                    "names": names,
                    "state": state,
                    "version": version,
                    "options": options,
                });
                let prestate_module = match module {
                    "ansible.builtin.apt" => "ansible.builtin.apt",
                    "ansible.builtin.dnf" | "ansible.builtin.dnf5" => "ansible.builtin.dnf",
                    _ => "estus.packages",
                };
                Some(Self {
                    domain: "estus.packages",
                    prestate_module,
                    prestate_args: json!({"name": names}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                })
            }
            _ => None,
        }
    }

    pub(crate) fn for_payload(binding_name: &str, is_preview: bool, args: &Value) -> Option<Self> {
        if is_preview {
            if binding_name == "preview_kernel_module_load" || args.get("name").is_some() {
                let name = args.get("name").and_then(Value::as_str)?;
                let canonical_name = name.replace('-', "_");
                let intent = json!({
                    "name": canonical_name,
                    "parameters": {},
                });
                return Some(Self {
                    domain: "estus.kernel_module",
                    prestate_module: "estus.kernel_module",
                    prestate_args: json!({"name": canonical_name}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                });
            }
            return None;
        }
        if binding_name == "change_kernel_module_load"
            || (binding_name.starts_with("change_")
                && args.get("name").is_some()
                && args.get("parameters").is_some())
        {
            let name = args.get("name").and_then(Value::as_str)?;
            let params = args.get("parameters").and_then(Value::as_object)?;
            if !params.is_empty() {
                return None;
            }
            let canonical_name = name.replace('-', "_");
            let intent = json!({
                "name": canonical_name,
                "parameters": {},
            });
            return Some(Self {
                domain: "estus.kernel_module",
                prestate_module: "estus.kernel_module",
                prestate_args: json!({"name": canonical_name}),
                intent_digest: canonical_json_sha256(&intent).ok()?,
            });
        }
        match binding_name {
            "change_sysctl_config" | "change_sysctl_runtime" => {
                let key = args.get("key").and_then(Value::as_str)?;
                let value = scalar_string(args.get("value"))?;
                let (sysctl_file, sysctl_set) = if binding_name == "change_sysctl_config" {
                    (
                        Value::String(format!(
                            "/etc/sysctl.d/90-estus-catalog-{}.conf",
                            sysctl_config_slug(key)
                        )),
                        false,
                    )
                } else {
                    // The runtime payload rewrites the live kernel value and never
                    // touches `/etc/sysctl.conf`; a null file keeps both sides equal.
                    (Value::Null, true)
                };
                let intent = json!({
                    "key": key,
                    "value": value,
                    "sysctl_file": sysctl_file.clone(),
                    "sysctl_set": sysctl_set,
                    "reload": false,
                    "state": "present",
                });
                Some(Self {
                    domain: "ansible.posix.sysctl",
                    prestate_module: "ansible.posix.sysctl",
                    prestate_args: json!({"name": key, "sysctl_file": sysctl_file}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                })
            }
            "change_systemd_start"
            | "change_systemd_stop"
            | "change_systemd_restart"
            | "change_systemd_reload"
            | "change_systemd_enable"
            | "change_systemd_disable"
            | "change_systemd_mask"
            | "change_systemd_unmask" => {
                let unit = args.get("unit").and_then(Value::as_str)?;
                let scope = args
                    .get("manager_scope")
                    .and_then(Value::as_str)
                    .unwrap_or("system");
                let state = match binding_name {
                    "change_systemd_start" => Some("started"),
                    "change_systemd_stop" => Some("stopped"),
                    "change_systemd_restart" => Some("restarted"),
                    "change_systemd_reload" => Some("reloaded"),
                    _ => None,
                };
                let enabled = match binding_name {
                    "change_systemd_enable" => Some(true),
                    "change_systemd_disable" => Some(false),
                    _ => None,
                };
                let masked = match binding_name {
                    "change_systemd_mask" => Some(true),
                    "change_systemd_unmask" => Some(false),
                    _ => None,
                };
                let intent = json!({
                    "unit": unit,
                    "scope": scope,
                    "state": state,
                    "enabled": enabled,
                    "masked": masked,
                    "daemon_reload": false,
                });
                Some(Self {
                    domain: "ansible.builtin.systemd_service",
                    prestate_module: "ansible.builtin.systemd_service",
                    prestate_args: json!({"name": unit, "scope": scope}),
                    intent_digest: canonical_json_sha256(&intent).ok()?,
                })
            }
            _ => None,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> PreviewKey {
        PreviewKey {
            target: "server".into(),
            authority_identity: [1; 32],
            domain: "ansible.posix.sysctl",
            intent_digest: [3; 32],
            pre_state_digest: [tag; 32],
        }
    }

    #[test]
    fn preview_is_consumed_once_and_expires_after_ttl() {
        let store = PreviewStore::new();
        let t0 = Instant::now();
        let k = key(7);
        store.insert_at(k.clone(), t0);

        assert!(store.consume_at(&k, t0 + Duration::from_secs(299)));
        assert!(!store.consume_at(&k, t0 + Duration::from_secs(299)));

        store.insert_at(k.clone(), t0);
        assert!(!store.consume_at(&k, t0 + TTL));
    }

    #[test]
    fn preview_key_distinguishes_every_component() {
        let store = PreviewStore::new();
        let t0 = Instant::now();
        let base = key(9);
        store.insert_at(base.clone(), t0);

        let mut alt = base.clone();
        alt.target = "other".into();
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.authority_identity = [99; 32];
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.domain = "estus.kernel_module";
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.intent_digest = [99; 32];
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.pre_state_digest = [99; 32];
        assert!(!store.consume_at(&alt, t0));

        assert!(store.consume_at(&base, t0));
    }

    #[test]
    fn preview_store_enforces_256_entry_bound() {
        let store = PreviewStore::new();
        let t0 = Instant::now();
        for i in 0..=MAX_ENTRIES {
            let mut k = key(0);
            k.target = format!("host-{i}");
            store.insert_at(k, t0);
        }
        let mut evicted = key(0);
        evicted.target = "host-0".into();
        assert!(!store.consume_at(&evicted, t0));

        let mut retained = key(0);
        retained.target = "host-1".into();
        assert!(store.consume_at(&retained, t0));
    }

    #[test]
    fn preview_specs_match_across_ansible_and_native_executors() {
        let ansible_systemd = PreviewSpec::for_ansible(
            "ansible.builtin.systemd_service",
            &json!({"name": "sshd.service", "state": "restarted", "daemon_reload": false}),
        )
        .unwrap();
        let native_systemd = PreviewSpec::for_payload(
            "change_systemd_restart",
            false,
            &json!({"unit": "sshd.service", "manager_scope": "system"}),
        )
        .unwrap();
        assert_eq!(ansible_systemd.domain, native_systemd.domain);
        assert_eq!(ansible_systemd.intent_digest, native_systemd.intent_digest);

        let preview_pkg = PreviewSpec::for_ansible(
            "ansible.builtin.package",
            &json!({"name": ["htop"], "state": "present"}),
        )
        .unwrap();
        let ansible_dnf = PreviewSpec::for_ansible(
            "ansible.builtin.dnf",
            &json!({"name": ["htop"], "state": "present"}),
        )
        .unwrap();
        assert_eq!(preview_pkg.domain, ansible_dnf.domain);
        assert_ne!(preview_pkg.intent_digest, ansible_dnf.intent_digest);
        let different_options = PreviewSpec::for_ansible(
            "ansible.builtin.package",
            &json!({"name": ["htop"], "state": "present", "update_cache": true}),
        )
        .unwrap();
        assert_ne!(preview_pkg.intent_digest, different_options.intent_digest);
        let preview_kmod = PreviewSpec::for_payload(
            "preview_kernel_module_load",
            true,
            &json!({"name": "nf-conntrack"}),
        )
        .unwrap();
        let apply_kmod = PreviewSpec::for_payload(
            "change_kernel_module_load",
            false,
            &json!({"name": "nf_conntrack", "parameters": {}}),
        )
        .unwrap();
        assert_eq!(preview_kmod.domain, apply_kmod.domain);
        assert_eq!(preview_kmod.intent_digest, apply_kmod.intent_digest);
    }

    #[test]
    fn preview_sysctl_default_file_authorizes_change_sysctl_config() {
        let key = "kernel.printk_ratelimit";
        let preview = PreviewSpec::for_ansible(
            "ansible.posix.sysctl",
            &json!({"name": key, "value": "10", "state": "present"}),
        )
        .unwrap();
        let change = PreviewSpec::for_payload(
            "change_sysctl_config",
            false,
            &json!({"key": key, "value": 10}),
        )
        .unwrap();

        assert_eq!(preview.domain, "ansible.posix.sysctl");
        assert_eq!(preview.domain, change.domain);
        assert_eq!(preview.prestate_module, change.prestate_module);
        assert_eq!(
            preview.prestate_args,
            json!({
                "name": key,
                "sysctl_file": "/etc/sysctl.d/90-estus-catalog-kernel_printk__ratelimit.conf",
            })
        );
        assert_eq!(preview.prestate_args, change.prestate_args);
        assert_eq!(preview.intent_digest, change.intent_digest);
    }

    #[test]
    fn preview_sysctl_runtime_flag_authorizes_change_sysctl_runtime() {
        let key = "kernel.printk_ratelimit";
        let preview = PreviewSpec::for_ansible(
            "ansible.posix.sysctl",
            &json!({
                "name": key,
                "value": "10",
                "state": "present",
                "sysctl_set": true,
            }),
        )
        .unwrap();
        let runtime = PreviewSpec::for_payload(
            "change_sysctl_runtime",
            false,
            &json!({"key": key, "value": 10}),
        )
        .unwrap();
        let config = PreviewSpec::for_payload(
            "change_sysctl_config",
            false,
            &json!({"key": key, "value": 10}),
        )
        .unwrap();

        assert_eq!(preview.domain, "ansible.posix.sysctl");
        assert_eq!(preview.domain, runtime.domain);
        assert_eq!(
            preview.prestate_args,
            json!({"name": key, "sysctl_file": null})
        );
        assert_eq!(preview.prestate_args, runtime.prestate_args);
        assert_eq!(preview.intent_digest, runtime.intent_digest);
        // One preview must not authorize both the runtime and persistent payloads.
        assert_ne!(preview.intent_digest, config.intent_digest);
    }

    #[test]
    fn explicit_sysctl_file_still_binds_that_exact_path() {
        let explicit = PreviewSpec::for_ansible(
            "ansible.posix.sysctl",
            &json!({
                "name": "kernel.printk_ratelimit",
                "value": "10",
                "state": "present",
                "sysctl_file": "/etc/sysctl.d/99-site.conf",
                "reload": true,
            }),
        )
        .unwrap();
        assert_eq!(
            explicit.prestate_args,
            json!({"name": "kernel.printk_ratelimit", "sysctl_file": "/etc/sysctl.d/99-site.conf"})
        );
        let config = PreviewSpec::for_payload(
            "change_sysctl_config",
            false,
            &json!({"key": "kernel.printk_ratelimit", "value": 10}),
        )
        .unwrap();
        assert_ne!(explicit.intent_digest, config.intent_digest);
        assert_eq!(
            sysctl_config_slug("kernel.printk_ratelimit"),
            "kernel_printk__ratelimit"
        );
        assert_eq!(sysctl_config_slug("vm.swappiness"), "vm_swappiness");
        // The encoding must never collapse distinct keys onto one file.
        assert_ne!(
            sysctl_config_slug("net.ipv4.conf.br_0.forwarding"),
            sysctl_config_slug("net.ipv4.conf.br-0.forwarding")
        );
        assert_eq!(
            sysctl_config_slug("net.ipv4.conf.br_0.forwarding"),
            "net_ipv4_conf_br__0_forwarding"
        );
        assert_eq!(
            sysctl_config_slug("net.ipv4.conf.br-0.forwarding"),
            "net_ipv4_conf_br-0_forwarding"
        );
    }

    #[test]
    fn preview_apt_matches_change_apt_after_option_normalization() {
        let preview = PreviewSpec::for_ansible(
            "ansible.builtin.apt",
            &json!({
                "name": ["htop"],
                "state": "present",
                "update_cache": false,
                "auto_install_module_deps": false,
            }),
        )
        .unwrap();
        let change = PreviewSpec::for_ansible(
            "ansible.builtin.apt",
            &json!({"name": ["htop"], "state": "present", "auto_install_module_deps": false}),
        )
        .unwrap();
        assert_eq!(preview.intent_digest, change.intent_digest);

        let cached = PreviewSpec::for_ansible(
            "ansible.builtin.apt",
            &json!({"name": ["htop"], "state": "present", "update_cache": true}),
        )
        .unwrap();
        assert_ne!(preview.intent_digest, cached.intent_digest);
    }

    #[test]
    fn preview_dnf_normalizes_update_cache_and_keeps_distinct_options() {
        let bare = PreviewSpec::for_ansible(
            "ansible.builtin.dnf",
            &json!({"name": ["htop"], "state": "present", "update_cache": false}),
        )
        .unwrap();
        let change = PreviewSpec::for_ansible(
            "ansible.builtin.dnf",
            &json!({"name": ["htop"], "state": "present"}),
        )
        .unwrap();
        assert_eq!(bare.intent_digest, change.intent_digest);

        let cached = PreviewSpec::for_ansible(
            "ansible.builtin.dnf",
            &json!({"name": ["htop"], "state": "present", "update_cache": true}),
        )
        .unwrap();
        assert_ne!(bare.intent_digest, cached.intent_digest);

        let repo = PreviewSpec::for_ansible(
            "ansible.builtin.dnf",
            &json!({"name": ["htop"], "state": "present", "enablerepo": ["epel"]}),
        )
        .unwrap();
        assert_ne!(bare.intent_digest, repo.intent_digest);
    }

    #[test]
    fn preview_sysctl_authorizes_both_native_executors_without_a_runtime_file() {
        let key = "net.ipv4.conf.br_0.forwarding";
        let preview = PreviewSpec::for_ansible(
            "ansible.posix.sysctl",
            &json!({"name": key, "value": "1", "state": "present"}),
        )
        .unwrap();
        let config = PreviewSpec::for_payload(
            "change_sysctl_config",
            false,
            &json!({"key": key, "value": 1}),
        )
        .unwrap();
        assert_eq!(preview.intent_digest, config.intent_digest);
        assert_eq!(preview.prestate_args, config.prestate_args);

        let runtime_preview = PreviewSpec::for_ansible(
            "ansible.posix.sysctl",
            &json!({"name": key, "value": "1", "state": "present", "sysctl_set": true}),
        )
        .unwrap();
        let runtime = PreviewSpec::for_payload(
            "change_sysctl_runtime",
            false,
            &json!({"key": key, "value": 1}),
        )
        .unwrap();
        assert_eq!(runtime_preview.intent_digest, runtime.intent_digest);
        assert_eq!(runtime_preview.prestate_args, runtime.prestate_args);
        assert_eq!(
            runtime.prestate_args,
            json!({"name": key, "sysctl_file": null})
        );
        assert_ne!(runtime_preview.intent_digest, config.intent_digest);
    }
}
