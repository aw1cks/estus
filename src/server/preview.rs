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

fn sysctl_slug(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut prev_underscore = false;
    for byte in key.bytes() {
        let lower = byte.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(char::from(lower));
            prev_underscore = false;
        } else if !prev_underscore && !out.is_empty() {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
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
                let sysctl_file = args
                    .get("sysctl_file")
                    .and_then(Value::as_str)
                    .unwrap_or("/etc/sysctl.conf");
                let sysctl_set = args
                    .get("sysctl_set")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let reload = args.get("reload").and_then(Value::as_bool).unwrap_or(true);
                let intent = json!({
                    "key": key,
                    "value": value,
                    "sysctl_file": sysctl_file,
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
            "ansible.builtin.apt" | "ansible.builtin.dnf" => {
                let names = sorted_names(args.get("name"))?;
                let state = canonical_package_state(args.get("state").and_then(Value::as_str))?;
                let prestate_module = if module == "ansible.builtin.apt" {
                    "ansible.builtin.apt"
                } else {
                    "ansible.builtin.dnf"
                };
                let intent = json!({
                    "names": names,
                    "state": state,
                });
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
                        format!("/etc/sysctl.d/90-estus-catalog-{}.conf", sysctl_slug(key)),
                        false,
                    )
                } else {
                    ("/etc/sysctl.conf".to_owned(), true)
                };
                let intent = json!({
                    "key": key,
                    "value": value,
                    "sysctl_file": sysctl_file,
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
            "change_packages_install" | "change_packages_remove" | "change_packages_upgrade" => {
                if args.get("version").is_some_and(|v| !v.is_null()) {
                    return None;
                }
                let pkg = args.get("package").and_then(Value::as_str)?;
                let state = match binding_name {
                    "change_packages_install" => "present",
                    "change_packages_remove" => "absent",
                    "change_packages_upgrade" => "latest",
                    _ => unreachable!(),
                };
                let intent = json!({
                    "names": [pkg],
                    "state": state,
                });
                Some(Self {
                    domain: "estus.packages",
                    prestate_module: "estus.packages",
                    prestate_args: json!({"name": [pkg]}),
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

        let ansible_apt = PreviewSpec::for_ansible(
            "ansible.builtin.apt",
            &json!({"name": ["htop"], "state": "present"}),
        )
        .unwrap();
        let native_pkg = PreviewSpec::for_payload(
            "change_packages_install",
            false,
            &json!({"package": "htop"}),
        )
        .unwrap();
        assert_eq!(ansible_apt.domain, native_pkg.domain);
        assert_eq!(ansible_apt.intent_digest, native_pkg.intent_digest);

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
}
