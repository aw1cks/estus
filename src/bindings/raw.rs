use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::compiled::Effect;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawBinding {
    pub(super) description: String,
    pub(super) revision: String,
    pub(super) targets: Option<Vec<String>>,
    pub(super) authority: toml::Value,
    pub(super) effects: Vec<Effect>,
    pub(super) execution: RawExecution,
    pub(super) input_schema: Option<toml::Value>,
    pub(super) fixed_args: Option<toml::Value>,
    pub(super) input_map: Option<BTreeMap<String, String>>,
    pub(super) argument_types: Option<toml::Value>,
    pub(super) result: RawResult,
    pub(super) limits: Option<RawLimits>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RawExecution {
    NativeArgv {
        program: String,
        argv: Vec<RawSlot>,
        cwd: Option<String>,
    },
    RemoteScript {
        source: RawScriptSource,
        interpreter: RawInterpreter,
        argv: Vec<RawSlot>,
        cwd: Option<String>,
    },
    ControllerScript {
        source: RawScriptSource,
        interpreter: RawInterpreter,
        environment: Option<BTreeMap<String, String>>,
        cwd: Option<String>,
    },
    NativePayload {
        snapshot: String,
        source: String,
        #[serde(default)]
        no_log: bool,
    },
    AnsibleGeneric {
        policy: crate::automation::generic::RawPolicy,
    },
    AnsibleModule {
        snapshot: String,
        #[serde(default)]
        no_log: bool,
    },
    AnsibleRole {
        snapshot: String,
        role_path: Option<String>,
        #[serde(default)]
        no_log: bool,
    },
    AnsiblePlaybook {
        snapshot: String,
        project_root: String,
        #[serde(default)]
        no_log: bool,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawScriptSource {
    pub(super) path: String,
    pub(super) content_sha256: String,
    pub(super) max_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawInterpreter {
    pub(super) program: String,
    pub(super) argv: Vec<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum RawSlot {
    Fixed(String),
    Input(InputSlot),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InputSlot {
    pub(super) input: String,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RawResult {
    // Empty struct variants keep unknown-option rejection for tagged records.
    Command {},
    ControllerCommand {},
    AnsibleSummary {},
    CapabilityProjection {
        fields: BTreeMap<String, Vec<String>>,
        schema: toml::Value,
        max_bytes: usize,
        max_items: usize,
        max_depth: usize,
    },
    AnsibleProjection {
        fields: BTreeMap<String, Vec<String>>,
        schema: toml::Value,
        max_bytes: usize,
        max_items: usize,
        max_depth: usize,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawLimits {
    pub(super) timeout_secs: Option<u64>,
    pub(super) max_output_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSchema {
    #[serde(rename = "type")]
    pub(super) kind: String,
    #[serde(rename = "additionalProperties")]
    pub(super) additional_properties: bool,
    pub(super) required: Vec<String>,
    pub(super) properties: BTreeMap<String, RawProperty>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawProperty {
    #[serde(rename = "type")]
    pub(super) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) description: Option<String>,
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub(super) min_length: Option<u64>,
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub(super) max_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) minimum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) maximum: Option<i64>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub(super) choices: Option<Vec<Value>>,
}
