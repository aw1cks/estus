use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    config::{AutomationAgent, ResolvedAutomation},
    contracts::schema_import::ReviewedModule,
};

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
    pub(crate) catalog_revision: [u8; 32],
    pub(crate) binding_revision: String,
    pub(crate) canonical_arguments: [u8; 32],
    pub(crate) pre_state_digest: [u8; 32],
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

pub(crate) fn catalog_revision_digest(
    catalog_version: Option<&str>,
    reviewed: &ReviewedModule,
) -> Result<[u8; 32], &'static str> {
    let revision = serde_json::json!({
        "catalog_version": catalog_version,
        "module": reviewed.module,
        "content_sha256": reviewed.content_sha256,
        "collection": reviewed.collection,
        "runtime": reviewed.runtime,
    });
    canonical_json_sha256(&revision)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(tag: u8) -> PreviewKey {
        PreviewKey {
            target: "server".into(),
            authority_identity: [1; 32],
            catalog_revision: [2; 32],
            binding_revision: "1".into(),
            canonical_arguments: [3; 32],
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
        alt.catalog_revision = [99; 32];
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.binding_revision = "2".into();
        assert!(!store.consume_at(&alt, t0));

        let mut alt = base.clone();
        alt.canonical_arguments = [99; 32];
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
            k.binding_revision = format!("rev-{i}");
            store.insert_at(k, t0);
        }
        let mut evicted = key(0);
        evicted.binding_revision = "rev-0".into();
        assert!(!store.consume_at(&evicted, t0));

        let mut retained = key(0);
        retained.binding_revision = "rev-1".into();
        assert!(store.consume_at(&retained, t0));
    }
}
