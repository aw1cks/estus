use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use rmcp::{ErrorData, model::JsonObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    config::{ConfigError, Limits, account_name},
    reply::ToolError,
};

use super::raw::{RawBinding, RawExecution, RawResult, RawSchema, RawSlot, SiteConstraints};
pub(crate) use payload::ActivatedPayload;
pub(crate) use plans::{ActivatedAutomation, ControllerPlan, PreparedController};

mod payload;
mod plans;

pub(crate) const EXECUTOR_KIND: &str = "native_argv";
pub(crate) const RESULT_KIND: &str = "command";

const MAX_SCHEMA_BYTES: usize = 16 * 1024;
pub(crate) const MAX_BINDINGS: usize = 256;

fn valid_unit_name(unit: &str) -> bool {
    !unit.is_empty()
        && unit.len() <= 128
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@.:-".contains(&byte))
}

fn valid_sysctl_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn valid_package_name(pkg: &str) -> bool {
    !pkg.is_empty()
        && pkg.len() <= 128
        && pkg
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._-".contains(&byte))
}

fn unique_bounded(list: &[String], check: impl Fn(&str) -> bool) -> bool {
    !list.is_empty()
        && list.len() <= 32
        && list.iter().all(|item| check(item))
        && list.iter().collect::<BTreeSet<_>>().len() == list.len()
}

/// The literal overlay a definition's `[tools.<name>]` table compiles to:
/// catalog policy (`constraints`) folded in, nothing inferred.
#[cfg(test)]
pub(crate) fn definition_overlay(text: &str, name: &str) -> Result<Value, &'static str> {
    let document: toml::Table = text.parse().map_err(|_| "invalid definition TOML")?;
    let table = document
        .get("tools")
        .and_then(|tools| tools.get(name))
        .and_then(toml::Value::as_table)
        .ok_or("definition has no such tool")?;
    let mut input_schema = serde_json::to_value(
        table
            .get("input_schema")
            .ok_or("definition lacks an input schema")?,
    )
    .map_err(|_| "invalid definition")?;
    let mut fixed_args = serde_json::to_value(
        table
            .get("fixed_args")
            .ok_or("definition lacks fixed arguments")?,
    )
    .map_err(|_| "invalid definition")?;
    let input_map = serde_json::to_value(
        table
            .get("input_map")
            .unwrap_or(&toml::Value::Table(toml::Table::new())),
    )
    .map_err(|_| "invalid definition")?;
    let constraints: Option<SiteConstraints> = table
        .get("constraints")
        .cloned()
        .map(|value| value.try_into())
        .transpose()
        .map_err(|_| "invalid site constraints")?;
    apply_site_constraints(&mut input_schema, &mut fixed_args, constraints.as_ref())?;
    Ok(json!({
        "input_schema": input_schema,
        "fixed_args": fixed_args,
        "input_map": input_map,
    }))
}

pub(crate) fn apply_site_constraints(
    input_schema: &mut Value,
    fixed_args: &mut Value,
    constraints: Option<&SiteConstraints>,
) -> Result<(), &'static str> {
    let Some(fixed_obj) = fixed_args.as_object_mut() else {
        return Err("Fixed module arguments must be an object");
    };
    let existing_fixed = fixed_obj.get("allowed_units").cloned();
    let existing_enum = input_schema
        .get("properties")
        .and_then(|props| props.get("unit"))
        .and_then(|unit| unit.get("enum"))
        .cloned();
    let Some(constraints) = constraints else {
        if let (Some(fixed_units), Some(enum_units)) = (existing_fixed, existing_enum)
            && fixed_units != enum_units
        {
            return Err(
                "Inconsistent fixed_args.allowed_units and input_schema.properties.unit.enum",
            );
        }
        return Ok(());
    };
    if let Some(units) = &constraints.allowed_units {
        if !unique_bounded(units, valid_unit_name) {
            return Err("Invalid site unit constraints");
        }
        if existing_fixed.is_some() || existing_enum.is_some() {
            return Err(
                "constraints.allowed_units cannot be combined with manual allowed_units or unit enum",
            );
        }
        let unit_prop = input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .and_then(|props| props.get_mut("unit"))
            .and_then(Value::as_object_mut)
            .ok_or("constraints.allowed_units requires input_schema.properties.unit")?;
        let units_value = Value::Array(units.iter().cloned().map(Value::String).collect());
        unit_prop.insert("enum".into(), units_value.clone());
        fixed_obj.insert("allowed_units".into(), units_value);
    }
    if let Some(keys) = &constraints.allowed_keys {
        if !unique_bounded(keys, valid_sysctl_key) {
            return Err("Invalid site sysctl key constraints");
        }
        let keys_value = Value::Array(keys.iter().cloned().map(Value::String).collect());
        let props = input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .ok_or("constraints.allowed_keys requires input_schema.properties")?;
        if let Some(key_prop) = props.get_mut("key").and_then(Value::as_object_mut) {
            key_prop.insert("enum".into(), keys_value.clone());
            fixed_obj.insert("approved_keys".into(), keys_value);
        } else if let Some(items_prop) = props
            .get_mut("keys")
            .and_then(Value::as_object_mut)
            .and_then(|k| k.get_mut("items"))
            .and_then(Value::as_object_mut)
        {
            items_prop.insert("enum".into(), keys_value.clone());
            fixed_obj.insert("approved_keys".into(), keys_value);
        } else if let Some(name_prop) = props.get_mut("name").and_then(Value::as_object_mut) {
            name_prop.insert("enum".into(), keys_value);
        } else {
            return Err("constraints.allowed_keys requires key, keys.items, or name property");
        }
    }
    if let Some(interfaces) = &constraints.allowed_interfaces {
        if !unique_bounded(interfaces, valid_interface_name) {
            return Err("Invalid site interface constraints");
        }
        let ifaces_value = Value::Array(interfaces.iter().cloned().map(Value::String).collect());
        let mut matched = false;
        if let Some(iface_prop) = input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .and_then(|props| props.get_mut("interface"))
            .and_then(Value::as_object_mut)
        {
            iface_prop.insert("enum".into(), ifaces_value.clone());
            matched = true;
        }
        if let Some(policy) = fixed_obj
            .get_mut("operator_policy")
            .and_then(Value::as_object_mut)
            && policy.contains_key("interfaces")
        {
            policy.insert("interfaces".into(), ifaces_value);
            matched = true;
        }
        if !matched {
            return Err(
                "constraints.allowed_interfaces requires interface schema or operator_policy.interfaces",
            );
        }
    }
    if let Some(packages) = &constraints.allowed_packages {
        if !unique_bounded(packages, valid_package_name) {
            return Err("Invalid site package constraints");
        }
        let pkgs_value = Value::Array(packages.iter().cloned().map(Value::String).collect());
        let mut matched = false;
        if let Some(props) = input_schema
            .get_mut("properties")
            .and_then(Value::as_object_mut)
        {
            if let Some(pkg_prop) = props.get_mut("package").and_then(Value::as_object_mut) {
                pkg_prop.insert("enum".into(), pkgs_value.clone());
                fixed_obj.insert("approved_packages".into(), pkgs_value.clone());
                matched = true;
            } else if let Some(items_prop) = props
                .get_mut("name")
                .and_then(Value::as_object_mut)
                .and_then(|n| n.get_mut("items"))
                .and_then(Value::as_object_mut)
            {
                items_prop.insert("enum".into(), pkgs_value.clone());
                matched = true;
            }
        }
        if !matched && fixed_obj.contains_key("approved_packages") {
            fixed_obj.insert("approved_packages".into(), pkgs_value);
            matched = true;
        }
        if !matched {
            return Err(
                "constraints.allowed_packages requires package, name.items, or approved_packages",
            );
        }
    }
    Ok(())
}
const RESERVED: &[&str] = &[
    "host",
    "timeout_secs",
    "retain_output",
    "argv",
    "program",
    "cwd",
    "stdin",
    "user",
    "role",
    "authority",
    "execution",
    "profile",
    "env",
    "shell",
    "sudo",
    "command",
    "revision",
    "effects",
    "result",
    "input_schema",
    "enabled_tools",
];

struct SchemaCounter(usize);
impl io::Write for SchemaCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_SCHEMA_BYTES)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "schema exceeds limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn schema_fits(value: &impl Serialize) -> bool {
    serde_json::to_writer(SchemaCounter(0), value).is_ok()
}

fn integral_number(value: &Value) -> bool {
    value.as_number().is_some_and(|number| {
        number.as_i64().is_some()
            || number.as_u64().is_some()
            || number
                .as_f64()
                .is_some_and(|value| value.is_finite() && value.fract() == 0.0)
    })
}
fn canonical_integer(value: Value) -> Value {
    let integer = value.as_i64().or_else(|| {
        let number = value.as_f64()?;
        // Strict upper bound avoids saturating i64::MAX after float rounding.
        (number.is_finite()
            && number.fract() == 0.0
            && number >= i64::MIN as f64
            && number < -(i64::MIN as f64))
            .then_some(number as i64)
    });
    integer.map(Value::from).unwrap_or(value)
}
fn unsigned_integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let number = value.as_f64()?;
        (number.is_finite() && number.fract() == 0.0 && number >= 0.0 && number < u64::MAX as f64)
            .then_some(number as u64)
    })
}

fn invalid(reason: &'static str) -> ConfigError {
    ConfigError::new("tools", reason)
}
fn bound(reason: &'static str) -> ToolError {
    ToolError::invalid_argument(reason, false)
}
fn shape() -> ErrorData {
    ErrorData::invalid_params("Invalid named tool argument shape", None)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn parameter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !RESERVED.contains(&value)
}
fn absolute(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 4096 && !value.contains('\0')
}

fn controller_environment(
    configured: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut bytes = 0usize;
    if configured.len() > 32 {
        return Err(invalid("Controller environment exceeds entry bound"));
    }
    for (name, value) in &configured {
        let application = name.strip_prefix("MCP_").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        });
        bytes += name.len() + value.len();
        if name.len() > 64
            || (!application && !matches!(name.as_str(), "PATH" | "LANG" | "LC_ALL" | "TZ"))
            || value.len() > 4096
            || value.contains('\0')
            || bytes > 8192
        {
            return Err(invalid("Invalid controller environment"));
        }
    }
    let mut environment = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("TZ".into(), "UTC".into()),
    ]);
    environment.extend(configured);
    Ok(environment)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BindingId(pub(crate) usize);

#[derive(Debug)]
pub(crate) struct Bindings {
    entries: Vec<CompiledBinding>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Effect {
    Read,
    SensitiveRead,
    Probe,
    RuntimeWrite,
    PersistentWrite,
    Availability,
    Unknown,
}
#[derive(Debug)]
enum Domain {
    String { minimum: u64, maximum: u64 },
    Integer { minimum: i64, maximum: i64 },
    Boolean,
}
#[derive(Debug)]
struct Input {
    name: String,
    domain: Domain,
    choices: Option<Vec<Value>>,
}
impl Input {
    fn matches_type(&self, value: &Value) -> bool {
        match self.domain {
            Domain::String { .. } => value.is_string(),
            Domain::Integer { .. } => integral_number(value),
            Domain::Boolean => value.is_boolean(),
        }
    }
    fn validate(&self, value: &Value) -> Result<(), ToolError> {
        let constraint = match self.domain {
            Domain::String { minimum, maximum } => match value.as_str() {
                None => Some("invalid_type"),
                Some(v) if v.contains('\0') => Some("pattern_mismatch"),
                Some(v) => {
                    let count = v.chars().count() as u64;
                    if count < minimum {
                        Some("too_short")
                    } else if count > maximum {
                        Some("too_long")
                    } else {
                        None
                    }
                }
            },
            Domain::Integer { minimum, maximum } => match value.as_i64() {
                None => Some("invalid_type"),
                Some(v) if v < minimum => Some("below_minimum"),
                Some(v) if v > maximum => Some("above_maximum"),
                Some(_) => None,
            },
            Domain::Boolean => (!value.is_boolean()).then_some("invalid_type"),
        }
        .or_else(|| {
            self.choices
                .as_ref()
                .is_some_and(|choices| !choices.contains(value))
                .then_some("invalid_enum")
        });
        if let Some(constraint) = constraint {
            return Err(ToolError::invalid_argument_owned(format!(
                "Named tool input '{}' violates {constraint} constraint",
                self.name
            )));
        }
        Ok(())
    }
    fn option_safe(&self) -> bool {
        self.choices.is_some()
            || matches!(
                self.domain,
                Domain::Boolean | Domain::Integer { minimum: 0.., .. }
            )
    }
}
#[derive(Debug)]
enum Slot {
    Fixed(String),
    Input(usize),
}
#[derive(Debug)]
enum Authority {
    Ordinary,
    Sudo(String),
    Controller,
}

#[derive(Debug)]
pub(crate) struct ScriptSource {
    pub(crate) path: String,
    pub(crate) content_sha256: [u8; 32],
    pub(crate) max_bytes: usize,
}

#[derive(Debug)]
enum ControllerState {
    Disabled,
    Activated(Arc<ControllerPlan>),
}

#[derive(Debug)]
enum PayloadState {
    Unactivated(payload::UnactivatedPayload),
    Activated(Arc<ActivatedPayload>),
}

#[derive(Debug)]
enum AnsibleState {
    Unactivated(plans::UnactivatedAutomation),
    Activated(Arc<ActivatedAutomation>),
}

#[derive(Debug)]
enum Execution {
    NativeArgv {
        program: String,
        cwd: Option<String>,
        authority: Authority,
    },
    ControllerScript(ControllerState),
    Payload(PayloadState),
    Ansible(AnsibleState),
}

#[derive(Clone, Debug)]
pub(crate) enum AutomationAuthority {
    Ordinary,
    Named(String),
}

impl AutomationAuthority {
    fn parse(value: &toml::Value) -> Result<Self, ConfigError> {
        match value.as_str() {
            Some("automation") => Ok(Self::Ordinary),
            Some(value) => {
                let name = value
                    .strip_prefix("automation:")
                    .ok_or_else(|| invalid("Invalid automation authority"))?;
                if name.is_empty()
                    || name.len() > 64
                    || !name.bytes().enumerate().all(|(index, byte)| {
                        byte.is_ascii_alphabetic()
                            || byte == b'_'
                            || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
                    })
                {
                    return Err(invalid("Invalid automation authority"));
                }
                Ok(Self::Named(name.to_owned()))
            }
            None => Err(invalid("Invalid automation authority")),
        }
    }

    pub(crate) fn identity_role(&self) -> crate::config::IdentityRole {
        match self {
            Self::Ordinary => crate::config::IdentityRole::Ordinary,
            Self::Named(_) => crate::config::IdentityRole::Automation,
        }
    }

    pub(crate) fn label(&self) -> Cow<'static, str> {
        match self {
            Self::Ordinary => Cow::Borrowed("automation"),
            Self::Named(name) => Cow::Owned(format!("automation:{name}")),
        }
    }
}

impl Serialize for AutomationAuthority {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Ordinary => serializer.serialize_str("automation"),
            Self::Named(name) => serializer.collect_str(&format_args!("automation:{name}")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledBinding {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) revision: String,
    pub(crate) targets: Vec<String>,
    pub(crate) dynamic_targets: bool,
    pub(crate) input_schema: Arc<JsonObject>,
    enabled: bool,
    effects: Vec<Effect>,
    inputs: Vec<Input>,
    execution: Execution,
    argv: Vec<Slot>,
    timeout_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}
pub(crate) struct BindingRequest {
    pub(crate) host: String,
    pub(crate) timeout_secs: Option<u64>,
    pub retain_output: bool,
    values: Vec<Value>,
}
#[cfg(test)]
pub(crate) enum BindingCall {
    Remote(BindingRequest),
    Controller(ControllerRequest),
    Automation(AutomationRequest),
    Payload,
}

#[derive(Clone, Debug)]
pub(crate) enum ActivatedExecution {
    NativeArgv,
    Controller(Arc<ControllerPlan>),
    Payload(Arc<ActivatedPayload>),
    Automation(Arc<ActivatedAutomation>),
}

pub(crate) enum ActivatedCall {
    Remote(BindingRequest),
    Controller {
        plan: Arc<ControllerPlan>,
        request: ControllerRequest,
    },
    Automation {
        activated: Arc<ActivatedAutomation>,
        request: AutomationRequest,
    },
    Payload {
        activated: Arc<ActivatedPayload>,
        request: AutomationRequest,
    },
}

pub(crate) struct AutomationRequest {
    pub(crate) host: String,
    timeout_secs: Option<u64>,
    inputs: Value,
}

pub(crate) struct ControllerRequest {
    timeout_secs: Option<u64>,
    pub retain_output: bool,
    values: Vec<Value>,
}
struct ControllerActivation<'a> {
    workspace_root: Option<&'a str>,
    permitted: bool,
    canonical_root: Option<Arc<Path>>,
}

impl Bindings {
    #[cfg(test)]
    pub(crate) fn compile(
        raw: BTreeMap<String, toml::Value>,
        enabled: &[String],
        limits: &Limits,
        target_exists: impl Fn(&str) -> bool,
        workspace_root: Option<&str>,
        active_profile: bool,
    ) -> Result<Self, ConfigError> {
        Self::compile_with_mode(
            raw,
            enabled,
            limits,
            target_exists,
            workspace_root,
            active_profile,
            false,
        )
    }

    pub(crate) fn compile_with_mode(
        raw: BTreeMap<String, toml::Value>,
        enabled: &[String],
        limits: &Limits,
        target_exists: impl Fn(&str) -> bool,
        workspace_root: Option<&str>,
        active_profile: bool,
        workstation: bool,
    ) -> Result<Self, ConfigError> {
        if raw.len() > MAX_BINDINGS {
            return Err(invalid("At most 256 named tools are allowed"));
        }
        let selected: BTreeSet<_> = enabled.iter().map(String::as_str).collect();
        if selected.len() != enabled.len() || enabled.iter().any(|name| !raw.contains_key(name)) {
            return Err(ConfigError::new(
                "enabled_tools",
                "Enabled tool names must exist and be unique",
            ));
        }
        let mut activation = ControllerActivation {
            workspace_root,
            permitted: active_profile,
            canonical_root: None,
        };
        let entries = raw
            .into_iter()
            .map(|(name, value)| {
                if !identifier(&name) {
                    return Err(invalid("Invalid named tool identifier"));
                }
                let raw: RawBinding = value
                    .try_into()
                    .map_err(|_| invalid("Invalid named tool definition"))?;
                let enabled = selected.contains(name.as_str());
                CompiledBinding::compile(
                    name,
                    raw,
                    enabled,
                    limits,
                    &target_exists,
                    &mut activation,
                    workstation,
                )
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    pub(crate) fn push_dynamic_payload(
        &mut self,
        name: String,
        raw_toml: toml::Value,
        source: Vec<u8>,
        manifest_bytes: &[u8],
        limits: &Limits,
    ) -> Result<BindingId, ConfigError> {
        if self.entries.len() >= MAX_BINDINGS {
            return Err(invalid("At most 256 named tools are allowed"));
        }
        if !identifier(&name) || self.entries.iter().any(|b| b.name == name) {
            return Err(invalid("Invalid or duplicate bundled tool identifier"));
        }
        let mut raw: RawBinding = raw_toml
            .try_into()
            .map_err(|_| invalid("Invalid bundled tool definition"))?;
        raw.targets = None;
        let mut compiled =
            CompiledBinding::compile_payload(name, raw, true, limits, &|_| false, true)?;
        compiled.activate_bundled_payload(source, manifest_bytes)?;
        let id = BindingId(self.entries.len());
        self.entries.push(compiled);
        Ok(id)
    }
    pub(crate) fn push_dynamic_ansible_module(
        &mut self,
        name: String,
        raw_toml: toml::Value,
        limits: &Limits,
    ) -> Result<BindingId, ConfigError> {
        if self.entries.len() >= MAX_BINDINGS {
            return Err(invalid("At most 256 named tools are allowed"));
        }
        if !identifier(&name) || self.entries.iter().any(|b| b.name == name) {
            return Err(invalid("Invalid or duplicate bundled tool identifier"));
        }
        let mut raw: RawBinding = raw_toml
            .try_into()
            .map_err(|_| invalid("Invalid bundled module definition"))?;
        raw.targets = None;
        let compiled =
            CompiledBinding::compile_automation(name, raw, true, limits, &|_| false, true)?;
        let id = BindingId(self.entries.len());
        self.entries.push(compiled);
        Ok(id)
    }

    pub(crate) fn disable(&mut self, id: BindingId) {
        if let Some(binding) = self.entries.get_mut(id.0) {
            binding.enabled = false;
        }
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (BindingId, &CompiledBinding)> {
        self.entries
            .iter()
            .enumerate()
            .map(|(i, entry)| (BindingId(i), entry))
    }
    pub(crate) fn get(&self, id: BindingId) -> Option<&CompiledBinding> {
        self.entries.get(id.0)
    }
}

fn validate_risk_prefix_effects(name: &str, effects: &[Effect]) -> Result<(), ConfigError> {
    let has_mutating = effects.iter().any(|effect| {
        matches!(
            effect,
            Effect::RuntimeWrite | Effect::PersistentWrite | Effect::Availability | Effect::Unknown
        )
    });
    if name.starts_with("observe_") {
        if effects.is_empty() || !effects.iter().all(|effect| matches!(effect, Effect::Read)) {
            return Err(invalid("observe_* tools may only declare read effects"));
        }
    } else if name.starts_with("inspect_") {
        if has_mutating
            || !effects
                .iter()
                .any(|effect| matches!(effect, Effect::SensitiveRead | Effect::Probe))
        {
            return Err(invalid(
                "inspect_* tools must declare read-only inspection or probe effects",
            ));
        }
    } else if name.starts_with("preview_") {
        if has_mutating || effects.is_empty() {
            return Err(invalid(
                "preview_* tools may not declare mutating or unknown effects",
            ));
        }
    } else if name.starts_with("change_") && !has_mutating {
        return Err(invalid(
            "change_* tools must declare mutating or unknown effects",
        ));
    }
    Ok(())
}
impl CompiledBinding {
    fn compile_automation(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
        workstation: bool,
    ) -> Result<Self, ConfigError> {
        let RawExecution::AnsibleModule {
            module,
            bundle,
            no_log,
            check_mode,
            diff,
        } = raw.execution
        else {
            unreachable!("automation execution selected");
        };
        if !crate::contracts::module_schema::valid_fqcn(&module) {
            return Err(invalid("Invalid Ansible module FQCN"));
        }
        if let Some(ref b) = bundle
            && !absolute(b)
        {
            return Err(invalid("Invalid Ansible bundle path"));
        }
        if check_mode && !name.starts_with("preview_") {
            return Err(invalid(
                "check_mode is only supported on preview_* ansible_module bindings",
            ));
        }
        if diff && (!check_mode || no_log) {
            return Err(invalid("diff requires preview check_mode without no_log"));
        }
        let authority = AutomationAuthority::parse(&raw.authority)?;
        let dynamic_targets = raw.targets.is_none() && workstation;
        let targets = raw.targets.unwrap_or_default();
        if !matches!(
            &raw.result,
            RawResult::AnsibleSummary {} | RawResult::AnsibleProjection { .. }
        ) || raw.description.is_empty()
            || raw.description.len() > 1024
            || !identifier(&raw.revision)
            || (!dynamic_targets
                && (targets.is_empty()
                    || targets.len() > 32
                    || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
                    || targets.iter().any(|target| !target_exists(target))))
            || raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid(
                "Invalid automation binding authority or definition",
            ));
        }
        let projection = match raw.result {
            RawResult::AnsibleSummary {} => {
                if diff {
                    return Err(invalid("diff requires a disclosure-approved projection"));
                }
                None
            }
            RawResult::AnsibleProjection {
                fields,
                schema,
                max_bytes,
                max_items,
                max_depth,
            } => {
                if diff
                    && !fields
                        .values()
                        .any(|path| path.first().map(String::as_str) == Some("diff"))
                {
                    return Err(invalid(
                        "diff requires explicit approval in projection fields",
                    ));
                }
                let schema = serde_json::to_value(schema)
                    .map_err(|_| invalid("Invalid projection schema"))?;
                Some(Arc::new(
                    crate::contracts::projection::compile_with_diff(
                        json!({
                            "fields": fields, "schema": schema, "max_bytes": max_bytes,
                            "max_items": max_items, "max_depth": max_depth
                        }),
                        diff,
                    )
                    .map_err(invalid)?,
                ))
            }
            _ => unreachable!("module result checked"),
        };
        let mut schema = serde_json::to_value(
            raw.input_schema
                .ok_or_else(|| invalid("Input schema is required"))?,
        )
        .map_err(|_| invalid("Invalid module schema"))?;
        let mut fixed = raw
            .fixed_args
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| invalid("Invalid fixed module arguments"))?
            .unwrap_or_else(|| json!({}));
        if !fixed.is_object() {
            return Err(invalid("Fixed module arguments must be an object"));
        }
        apply_site_constraints(&mut schema, &mut fixed, raw.constraints.as_ref())
            .map_err(invalid)?;
        let mut overlay = json!({"input_schema":schema,"fixed_args":fixed,"input_map":raw.input_map.unwrap_or_default()});
        if let Some(argument_types) = raw.argument_types {
            overlay["argument_types"] = serde_json::to_value(argument_types)
                .map_err(|_| invalid("Invalid opaque argument representations"))?;
        }
        crate::contracts::module_schema::validate_overlay(&overlay).map_err(invalid)?;
        let timeout_secs = raw.limits.as_ref().and_then(|limits| limits.timeout_secs);
        if timeout_secs.is_some_and(|value| value == 0 || value > limits.max_timeout_secs)
            || raw
                .limits
                .as_ref()
                .and_then(|limits| limits.max_output_bytes)
                .is_some()
        {
            return Err(invalid("Module limits only support a bounded timeout"));
        }
        let host_schema = if dynamic_targets {
            json!({"type": "string", "minLength": 1, "maxLength": 256})
        } else {
            json!({"type": "string", "enum": targets})
        };
        let published = json!({
            "type":"object","additionalProperties":false,
            "required":["host","inputs"],
            "properties":{
                "host":host_schema,
                "inputs":overlay["input_schema"],
                "timeout_secs":{"type":"integer","minimum":1,"maximum":timeout_secs.unwrap_or(limits.max_timeout_secs)}
            }
        }).as_object().cloned().ok_or_else(||invalid("Invalid module metadata"))?;
        if !schema_fits(&published) || !schema_fits(&overlay) {
            return Err(invalid("Module metadata exceeds bound"));
        }
        Ok(Self {
            name,
            description: raw.description,
            revision: raw.revision,
            targets,
            dynamic_targets,
            input_schema: Arc::new(published),
            enabled,
            effects: raw.effects,
            inputs: Vec::new(),
            execution: Execution::Ansible(AnsibleState::Unactivated(
                plans::UnactivatedAutomation {
                    module,
                    bundle: bundle.map(PathBuf::from),
                    authority,
                    overlay,
                    no_log,
                    check_mode,
                    diff,
                    projection,
                },
            )),
            argv: Vec::new(),
            timeout_secs,
            max_output_bytes: None,
        })
    }

    fn compile(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
        activation: &mut ControllerActivation<'_>,
        workstation: bool,
    ) -> Result<Self, ConfigError> {
        validate_risk_prefix_effects(&name, &raw.effects)?;
        if matches!(&raw.execution, RawExecution::NativePayload { .. }) {
            return Self::compile_payload(name, raw, enabled, limits, target_exists, workstation);
        }
        if matches!(&raw.execution, RawExecution::AnsibleModule { .. }) {
            return Self::compile_automation(
                name,
                raw,
                enabled,
                limits,
                target_exists,
                workstation,
            );
        }
        if raw.fixed_args.is_some()
            || raw.input_map.is_some()
            || raw.argument_types.is_some()
            || raw.constraints.is_some()
        {
            return Err(invalid(
                "Module overlay fields require ansible_module execution",
            ));
        }
        if raw.description.is_empty() || raw.description.len() > 1024 || !identifier(&raw.revision)
        {
            return Err(invalid("Invalid description or revision"));
        }
        let authority = match raw.authority {
            toml::Value::String(value) if value == "ordinary" => Authority::Ordinary,
            toml::Value::String(value) if value == "controller" => Authority::Controller,
            toml::Value::Table(mut value) if value.len() == 1 => match value.remove("sudo") {
                Some(toml::Value::String(user)) if user.len() <= 64 && account_name(&user) => {
                    Authority::Sudo(user)
                }
                _ => return Err(invalid("Invalid fixed sudo account")),
            },
            _ => return Err(invalid("Invalid fixed tool authority")),
        };
        let controller = matches!(&raw.execution, RawExecution::ControllerScript { .. });
        if controller != matches!(authority, Authority::Controller)
            || !matches!(
                (&raw.result, controller),
                (RawResult::ControllerCommand {}, true) | (RawResult::Command {}, false)
            )
        {
            return Err(invalid("Execution, authority and result kinds must agree"));
        }
        if controller && raw.targets.is_some() {
            return Err(invalid("Controller tools must omit targets"));
        }
        let targets = raw.targets.unwrap_or_default();
        if !controller
            && (targets.is_empty()
                || targets.len() > 32
                || targets.iter().collect::<BTreeSet<_>>().len() != targets.len()
                || targets.iter().any(|v| !target_exists(v)))
        {
            return Err(invalid("Targets must be unique configured logical targets"));
        }
        if raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid("Effects must be nonempty and unique"));
        }
        let (execution, raw_argv, mut separator) = match raw.execution {
            RawExecution::NativeArgv { program, argv, cwd } => {
                if !absolute(&program)
                    || program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || argv.len() > 64
                {
                    return Err(invalid("Invalid fixed executable layout"));
                }
                if matches!(authority, Authority::Sudo(_)) && cwd.is_some() {
                    return Err(invalid("Elevated bindings do not support cwd"));
                }
                (
                    Execution::NativeArgv {
                        program,
                        cwd,
                        authority,
                    },
                    argv,
                    false,
                )
            }
            RawExecution::ControllerScript {
                source,
                interpreter,
                environment,
                cwd,
            } => {
                if !absolute(&source.path)
                    || source.path.ends_with('/')
                    || !absolute(&interpreter.program)
                    || interpreter.program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || interpreter.argv.len() > 64
                    || interpreter
                        .argv
                        .iter()
                        .any(|v| v.len() > 4096 || v.contains('\0'))
                {
                    return Err(invalid("Invalid fixed controller script layout"));
                }
                let mut digest = [0; 32];
                if source.content_sha256.len() != 64
                    || hex::decode_to_slice(&source.content_sha256, &mut digest).is_err()
                {
                    return Err(invalid("Invalid script content_sha256"));
                }
                let ceiling = limits.max_file_bytes.min(1_048_576);
                let max_bytes = source.max_bytes.unwrap_or(ceiling);
                if max_bytes == 0 || max_bytes > ceiling {
                    return Err(invalid("Invalid script byte bound"));
                }
                let environment = controller_environment(environment.unwrap_or_default())?;
                let plan = activation.prepare(
                    enabled,
                    ScriptSource {
                        path: source.path,
                        content_sha256: digest,
                        max_bytes: max_bytes as usize,
                    },
                    interpreter,
                    environment,
                    cwd,
                )?;
                let state = plan.map_or(ControllerState::Disabled, ControllerState::Activated);
                (Execution::ControllerScript(state), Vec::new(), false)
            }
            RawExecution::NativePayload { .. } | RawExecution::AnsibleModule { .. } => {
                unreachable!("compiled separately")
            }
        };
        let timeout_secs = raw.limits.as_ref().and_then(|v| v.timeout_secs);
        let max_output_bytes = raw.limits.as_ref().and_then(|v| v.max_output_bytes);
        if timeout_secs.is_some_and(|v| v == 0 || v > limits.max_timeout_secs)
            || max_output_bytes.is_some_and(|v| v == 0 || v > limits.max_output_bytes)
        {
            return Err(invalid(
                "Tool limits must be positive and no greater than server ceilings",
            ));
        }
        if !schema_fits(&(&raw.input_schema, &targets)) {
            return Err(invalid("Input schema exceeds metadata bound"));
        }
        let schema: RawSchema = raw
            .input_schema
            .ok_or_else(|| invalid("Input schema is required"))?
            .try_into()
            .map_err(|_| invalid("Unsupported input schema"))?;
        if schema.kind != "object"
            || schema.additional_properties
            || schema.properties.len() > 16
            || schema.required.len() != schema.properties.len()
            || schema.required.iter().collect::<BTreeSet<_>>().len() != schema.required.len()
            || schema
                .required
                .iter()
                .any(|v| !schema.properties.contains_key(v))
        {
            return Err(invalid(
                "Input schema must be a closed flat required object",
            ));
        }
        let mut inputs = Vec::with_capacity(schema.properties.len());
        let mut properties = JsonObject::new();
        for (name, mut property) in schema.properties {
            if !parameter(&name) || property.description.as_ref().is_some_and(|v| v.len() > 512) {
                return Err(invalid("Invalid input identifier or description"));
            }
            let domain = match property.kind.as_str() {
                "string" if property.minimum.is_none() && property.maximum.is_none() => {
                    let minimum = property.min_length.unwrap_or(0);
                    let maximum = property
                        .max_length
                        .ok_or_else(|| invalid("Strings require maxLength"))?;
                    if minimum > maximum || maximum > 4096 {
                        return Err(invalid("Invalid string length bounds"));
                    }
                    Domain::String { minimum, maximum }
                }
                "integer" if property.min_length.is_none() && property.max_length.is_none() => {
                    let minimum = property
                        .minimum
                        .ok_or_else(|| invalid("Integers require minimum"))?;
                    let maximum = property
                        .maximum
                        .ok_or_else(|| invalid("Integers require maximum"))?;
                    if minimum > maximum {
                        return Err(invalid("Invalid integer bounds"));
                    }
                    Domain::Integer { minimum, maximum }
                }
                "boolean"
                    if property.min_length.is_none()
                        && property.max_length.is_none()
                        && property.minimum.is_none()
                        && property.maximum.is_none() =>
                {
                    Domain::Boolean
                }
                _ => return Err(invalid("Unsupported property schema")),
            };
            if matches!(domain, Domain::Integer { .. })
                && let Some(choices) = &mut property.choices
            {
                for value in choices {
                    *value = canonical_integer(std::mem::take(value));
                }
            }
            let input = Input {
                name: name.clone(),
                domain,
                choices: property.choices.clone(),
            };
            if let Some(choices) = &input.choices
                && (choices.is_empty()
                    || choices.len() > 32
                    || choices.iter().enumerate().any(|(i, v)| {
                        choices[..i].contains(v)
                            || !input.matches_type(v)
                            || input.validate(v).is_err()
                    }))
            {
                return Err(invalid("Invalid input enumeration"));
            }
            properties.insert(
                name,
                serde_json::to_value(property).map_err(|_| invalid("Invalid property metadata"))?,
            );
            inputs.push(input);
        }
        let mut used = vec![false; inputs.len()];
        let mut argv = Vec::with_capacity(raw_argv.len());
        for slot in raw_argv {
            argv.push(match slot {
                RawSlot::Fixed(value) => {
                    if value.len() > 4096 || value.contains('\0') {
                        return Err(invalid("Invalid fixed argv literal"));
                    }
                    if value == "--" {
                        separator = true;
                    }
                    Slot::Fixed(value)
                }
                RawSlot::Input(slot) => {
                    let index = inputs
                        .iter()
                        .position(|v| v.name == slot.input)
                        .ok_or_else(|| invalid("Unknown input mapping"))?;
                    if !separator && !inputs[index].option_safe() {
                        return Err(invalid(
                            "Unrestricted inputs require a preceding fixed option separator",
                        ));
                    }
                    used[index] = true;
                    Slot::Input(index)
                }
            });
        }
        if !controller && used.contains(&false) {
            return Err(invalid("Every input must occupy an argv slot"));
        }
        let ceiling = timeout_secs.unwrap_or(limits.max_timeout_secs);
        if !controller {
            properties.insert("host".into(), json!({"type":"string", "enum":targets}));
        }
        properties.insert(
            "timeout_secs".into(),
            json!({"type":"integer", "minimum":1, "maximum":ceiling}),
        );
        properties.insert(
            "retain_output".into(),
            json!({"type":"boolean", "default":false}),
        );
        let mut required = schema.required;
        if !controller {
            required.push("host".into());
        }
        let metadata = json!({"type":"object", "additionalProperties":false, "properties":properties, "required":required});
        let Value::Object(metadata) = metadata else {
            return Err(invalid("Invalid schema metadata"));
        };
        if !schema_fits(&metadata) {
            return Err(invalid("Generated input schema exceeds metadata bound"));
        }
        let input_schema = Arc::new(metadata);
        let binding = Self {
            name,
            description: raw.description,
            revision: raw.revision,
            targets,
            dynamic_targets: false,
            input_schema,
            enabled,
            effects: raw.effects,
            inputs,
            execution,
            argv,
            timeout_secs,
            max_output_bytes,
        };
        if !controller {
            let arguments = binding
                .argv
                .iter()
                .filter_map(|v| match v {
                    Slot::Fixed(value) => Some(Cow::Borrowed(value.as_str())),
                    Slot::Input(_) => None,
                })
                .collect();
            binding
                .invocation(arguments)
                .encoded_len()
                .map_err(|_| invalid("Fixed command exceeds encoded command bound"))?;
        }
        Ok(binding)
    }
    pub(crate) fn public_authority(&self) -> Value {
        if let Some(authority) = self.automation_authority() {
            serde_json::json!(authority)
        } else if self.is_controller() {
            serde_json::json!("controller")
        } else {
            self.sudo().map_or_else(
                || serde_json::json!("ordinary"),
                |(user, _)| serde_json::json!({"sudo": user}),
            )
        }
    }

    pub(crate) fn execution_location(&self) -> &'static str {
        if self.is_controller() {
            "controller"
        } else {
            "remote"
        }
    }

    pub(crate) fn trusted_controller_code(&self) -> bool {
        self.is_controller()
    }

    pub(crate) fn restriction_boundary(&self) -> Value {
        serde_json::json!({
            "mcp":"request_policy",
            "os":if self.is_controller() { "service_account" } else { "service_account_and_remote_identity" },
            "service_account_separation":"operator_managed_not_observed",
            "sandbox":"not_provided_by_estus",
        })
    }

    pub(crate) fn executor_kind(&self) -> &'static str {
        match &self.execution {
            Execution::NativeArgv { .. } => EXECUTOR_KIND,
            Execution::ControllerScript(_) => "controller_script",
            Execution::Payload(_) => "native_payload",
            Execution::Ansible(_) => "ansible_module",
        }
    }

    pub(crate) fn bundle_override(&self) -> Option<&Path> {
        match &self.execution {
            Execution::Ansible(state) => state.bundle_override(),
            _ => None,
        }
    }

    pub(crate) fn is_controller(&self) -> bool {
        matches!(self.execution, Execution::ControllerScript(_))
    }

    pub(crate) fn is_automation(&self) -> bool {
        matches!(self.execution, Execution::Ansible(_))
    }

    pub(crate) fn is_payload(&self) -> bool {
        matches!(self.execution, Execution::Payload(_))
    }

    pub(crate) fn automation_authority(&self) -> Option<&AutomationAuthority> {
        match &self.execution {
            Execution::Ansible(state) => Some(state.authority()),
            Execution::Payload(state) => Some(state.authority()),
            _ => None,
        }
    }

    pub(crate) fn automation_activated(&self) -> bool {
        matches!(
            self.execution,
            Execution::Ansible(AnsibleState::Activated(_))
        )
    }

    pub(crate) fn activated_execution(&self) -> Option<ActivatedExecution> {
        match &self.execution {
            Execution::NativeArgv { .. } => Some(ActivatedExecution::NativeArgv),
            Execution::ControllerScript(ControllerState::Activated(plan)) => {
                Some(ActivatedExecution::Controller(Arc::clone(plan)))
            }
            Execution::Payload(PayloadState::Activated(activated)) => {
                Some(ActivatedExecution::Payload(Arc::clone(activated)))
            }
            Execution::Ansible(AnsibleState::Activated(activated)) => {
                Some(ActivatedExecution::Automation(Arc::clone(activated)))
            }
            Execution::ControllerScript(ControllerState::Disabled)
            | Execution::Payload(PayloadState::Unactivated(_))
            | Execution::Ansible(AnsibleState::Unactivated(_)) => None,
        }
    }

    pub(crate) fn projection(&self) -> Option<&Arc<crate::contracts::projection::Plan>> {
        match &self.execution {
            Execution::Ansible(state) => state.projection(),
            Execution::Payload(state) => Some(state.projection()),
            _ => None,
        }
    }

    pub(crate) fn result_kind(&self) -> &'static str {
        if self.is_payload() {
            "capability_projection"
        } else if self.projection().is_some() {
            "ansible_projection"
        } else if self.is_automation() {
            "ansible_summary"
        } else if self.is_controller() {
            "controller_command"
        } else {
            RESULT_KIND
        }
    }

    pub(crate) fn sudo(&self) -> Option<(&str, &str)> {
        match &self.execution {
            Execution::NativeArgv {
                program,
                authority: Authority::Sudo(user),
                ..
            } => Some((user, program)),
            _ => None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
    pub(crate) fn has_dynamic_targets(&self) -> bool {
        self.dynamic_targets
    }
    pub(crate) fn permits_host(&self, host: &str) -> bool {
        if self.dynamic_targets {
            crate::config::destination(host, "host").is_ok()
        } else {
            self.targets.iter().any(|target| target == host)
        }
    }
    pub(crate) fn read_only(&self) -> bool {
        self.effects
            .iter()
            .all(|v| matches!(v, Effect::Read | Effect::SensitiveRead))
    }
    pub(crate) fn effects(&self) -> &[Effect] {
        &self.effects
    }
    pub(crate) fn is_shared_read(&self) -> bool {
        self.read_only()
            && !self.effects.is_empty()
            && !self
                .effects
                .iter()
                .any(|effect| matches!(effect, Effect::Probe | Effect::Unknown))
    }
    pub(crate) fn is_probe_only(&self) -> bool {
        !self.is_shared_read()
            && !self.effects.is_empty()
            && self.effects.iter().all(|effect| {
                matches!(effect, Effect::Read | Effect::SensitiveRead | Effect::Probe)
            })
    }
    #[cfg(test)]
    pub(crate) fn parse_request(&self, arguments: JsonObject) -> Result<BindingCall, ErrorData> {
        self.parse_request_ref(&arguments)
    }

    pub(crate) fn parse_activated_call(
        &self,
        activated: &ActivatedExecution,
        arguments: &JsonObject,
    ) -> Result<ActivatedCall, ErrorData> {
        match activated {
            ActivatedExecution::NativeArgv => {
                let inputs = self.parse_native_inputs(false, arguments)?;
                let Some(host) = inputs.host else {
                    return Err(shape());
                };
                Ok(ActivatedCall::Remote(BindingRequest {
                    host,
                    timeout_secs: inputs.timeout_secs,
                    retain_output: inputs.retain_output,
                    values: inputs.values,
                }))
            }
            ActivatedExecution::Controller(plan) => {
                let inputs = self.parse_native_inputs(true, arguments)?;
                Ok(ActivatedCall::Controller {
                    plan: Arc::clone(plan),
                    request: ControllerRequest {
                        timeout_secs: inputs.timeout_secs,
                        retain_output: inputs.retain_output,
                        values: inputs.values,
                    },
                })
            }
            ActivatedExecution::Automation(activated) => {
                let request = Self::parse_automation_inputs(&activated.overlay, arguments)?;
                Ok(ActivatedCall::Automation {
                    activated: Arc::clone(activated),
                    request,
                })
            }
            ActivatedExecution::Payload(activated) => {
                let request = Self::parse_automation_inputs(&activated.overlay, arguments)?;
                Ok(ActivatedCall::Payload {
                    activated: Arc::clone(activated),
                    request,
                })
            }
        }
    }

    fn parse_automation_inputs(
        overlay: &Value,
        arguments: &JsonObject,
    ) -> Result<AutomationRequest, ErrorData> {
        let mut matched = 1;
        let Some(Value::String(host)) = arguments.get("host") else {
            return Err(shape());
        };
        let timeout_secs = match arguments.get("timeout_secs") {
            Some(value) => {
                matched += 1;
                Some(unsigned_integer(value).ok_or_else(shape)?)
            }
            None => None,
        };
        let inputs = arguments.get("inputs").ok_or_else(shape)?;
        matched += 1;
        if arguments.len() != matched {
            return Err(shape());
        }
        crate::contracts::module_schema::validate_input_shape(&overlay["input_schema"], inputs)
            .map_err(|_| shape())?;
        Ok(AutomationRequest {
            host: host.clone(),
            timeout_secs,
            inputs: inputs.clone(),
        })
    }

    fn parse_native_inputs(
        &self,
        controller: bool,
        arguments: &JsonObject,
    ) -> Result<NativeInputs, ErrorData> {
        let mut matched = 0;
        let host = if controller {
            None
        } else {
            matched += 1;
            match arguments.get("host") {
                Some(Value::String(host)) => Some(host.clone()),
                _ => return Err(shape()),
            }
        };
        let timeout_secs = match arguments.get("timeout_secs") {
            Some(value) => {
                matched += 1;
                Some(unsigned_integer(value).ok_or_else(shape)?)
            }
            None => None,
        };
        let retain_output = match arguments.get("retain_output") {
            Some(value) => {
                matched += 1;
                value.as_bool().ok_or_else(shape)?
            }
            None => false,
        };
        let values = self
            .inputs
            .iter()
            .map(|input| {
                let value = arguments.get(&input.name).ok_or_else(shape)?;
                matched += 1;
                if !input.matches_type(value) {
                    return Err(shape());
                }
                Ok(if matches!(input.domain, Domain::Integer { .. }) {
                    canonical_integer(value.clone())
                } else {
                    value.clone()
                })
            })
            .collect::<Result<_, _>>()?;
        if arguments.len() != matched {
            return Err(shape());
        }
        Ok(NativeInputs {
            host,
            timeout_secs,
            retain_output,
            values,
        })
    }

    #[cfg(test)]
    pub(crate) fn parse_request_ref(
        &self,
        arguments: &JsonObject,
    ) -> Result<BindingCall, ErrorData> {
        if let Execution::Payload(state) = &self.execution {
            Self::parse_automation_inputs(state.overlay(), arguments)?;
            return Ok(BindingCall::Payload);
        }
        if let Execution::Ansible(state) = &self.execution {
            return Self::parse_automation_inputs(state.overlay(), arguments)
                .map(BindingCall::Automation);
        }
        let inputs = self.parse_native_inputs(self.is_controller(), arguments)?;
        Ok(match inputs.host {
            Some(host) => BindingCall::Remote(BindingRequest {
                host,
                timeout_secs: inputs.timeout_secs,
                retain_output: inputs.retain_output,
                values: inputs.values,
            }),
            None => BindingCall::Controller(ControllerRequest {
                timeout_secs: inputs.timeout_secs,
                retain_output: inputs.retain_output,
                values: inputs.values,
            }),
        })
    }
}

struct NativeInputs {
    host: Option<String>,
    timeout_secs: Option<u64>,
    retain_output: bool,
    values: Vec<Value>,
}

#[cfg(test)]
mod tests;
