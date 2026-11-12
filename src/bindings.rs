use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    io,
    sync::Arc,
    time::Duration,
};

use rmcp::{ErrorData, model::JsonObject};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    command::Invocation,
    config::{ConfigError, Limits},
    reply::ToolError,
};
pub(crate) const EXECUTOR_KIND: &str = "native_argv";
pub(crate) const RESULT_KIND: &str = "command";

const MAX_SCHEMA_BYTES: usize = 16 * 1024;
const RESERVED: &[&str] = &[
    "host",
    "timeout_secs",
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
    ToolError::new("invalid_argument", reason, false)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BindingId(pub(crate) usize);

#[derive(Debug)]
pub(crate) struct Bindings {
    entries: Vec<CompiledBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBinding {
    description: String,
    revision: String,
    targets: Vec<String>,
    authority: String,
    effects: Vec<Effect>,
    execution: RawExecution,
    input_schema: toml::Value,
    result: RawResult,
    limits: Option<RawLimits>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExecution {
    kind: String,
    program: String,
    argv: Vec<RawSlot>,
    cwd: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum RawSlot {
    Fixed(String),
    Input(InputSlot),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputSlot {
    input: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResult {
    kind: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    timeout_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSchema {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
    required: Vec<String>,
    properties: BTreeMap<String, RawProperty>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawProperty {
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    min_length: Option<u64>,
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    max_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maximum: Option<i64>,
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    choices: Option<Vec<Value>>,
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
        let valid = match self.domain {
            Domain::String { minimum, maximum } => value.as_str().is_some_and(|v| {
                !v.contains('\0') && (minimum..=maximum).contains(&(v.chars().count() as u64))
            }),
            Domain::Integer { minimum, maximum } => value
                .as_i64()
                .is_some_and(|v| (minimum..=maximum).contains(&v)),
            Domain::Boolean => value.is_boolean(),
        };
        if !valid
            || self
                .choices
                .as_ref()
                .is_some_and(|choices| !choices.contains(value))
        {
            return Err(bound("Named tool input violates its declared bounds"));
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
pub(crate) struct CompiledBinding {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) revision: String,
    pub(crate) targets: Vec<String>,
    pub(crate) input_schema: Arc<JsonObject>,
    enabled: bool,
    effects: Vec<Effect>,
    inputs: Vec<Input>,
    program: String,
    argv: Vec<Slot>,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
    max_output_bytes: Option<u64>,
}
pub(crate) struct BindingRequest {
    pub(crate) host: String,
    pub(crate) timeout_secs: Option<u64>,
    values: Vec<Value>,
}
pub(crate) struct PreparedBinding<'a> {
    pub(crate) invocation: Invocation<'a>,
    pub(crate) duration: Duration,
    pub(crate) max_output_bytes: u64,
}

impl Bindings {
    pub(crate) fn compile(
        raw: BTreeMap<String, toml::Value>,
        enabled: &[String],
        limits: &Limits,
        target_exists: impl Fn(&str) -> bool,
    ) -> Result<Self, ConfigError> {
        if raw.len() > 32 {
            return Err(invalid("At most 32 named tools are allowed"));
        }
        let selected: BTreeSet<_> = enabled.iter().map(String::as_str).collect();
        if selected.len() != enabled.len() || enabled.iter().any(|name| !raw.contains_key(name)) {
            return Err(ConfigError::new(
                "enabled_tools",
                "Enabled tool names must exist and be unique",
            ));
        }
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
                CompiledBinding::compile(name, raw, enabled, limits, &target_exists)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
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
impl CompiledBinding {
    fn compile(
        name: String,
        raw: RawBinding,
        enabled: bool,
        limits: &Limits,
        target_exists: &impl Fn(&str) -> bool,
    ) -> Result<Self, ConfigError> {
        if raw.description.is_empty() || raw.description.len() > 1024 || !identifier(&raw.revision)
        {
            return Err(invalid("Invalid description or revision"));
        }
        if raw.authority != "ordinary"
            || raw.execution.kind != EXECUTOR_KIND
            || raw.result.kind != RESULT_KIND
        {
            return Err(invalid(
                "Only ordinary native argv command tools are supported",
            ));
        }
        if raw.targets.is_empty()
            || raw.targets.len() > 32
            || raw.targets.iter().collect::<BTreeSet<_>>().len() != raw.targets.len()
            || raw.targets.iter().any(|v| !target_exists(v))
        {
            return Err(invalid("Targets must be unique configured logical targets"));
        }
        if raw.effects.is_empty()
            || raw.effects.iter().collect::<BTreeSet<_>>().len() != raw.effects.len()
        {
            return Err(invalid("Effects must be nonempty and unique"));
        }
        let execution = raw.execution;
        if !absolute(&execution.program)
            || execution.program.ends_with('/')
            || execution.cwd.as_deref().is_some_and(|v| !absolute(v))
            || execution.argv.len() > 64
        {
            return Err(invalid("Invalid fixed executable layout"));
        }
        let timeout_secs = raw.limits.as_ref().and_then(|v| v.timeout_secs);
        let max_output_bytes = raw.limits.as_ref().and_then(|v| v.max_output_bytes);
        if timeout_secs.is_some_and(|v| v == 0 || v > limits.max_timeout_secs)
            || max_output_bytes.is_some_and(|v| v == 0 || v > limits.max_output_bytes)
        {
            return Err(invalid(
                "Tool limits must be positive and no greater than server ceilings",
            ));
        }
        if !schema_fits(&(&raw.input_schema, &raw.targets)) {
            return Err(invalid("Input schema exceeds metadata bound"));
        }
        let schema: RawSchema = raw
            .input_schema
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
        let mut separator = false;
        let mut used = vec![false; inputs.len()];
        let mut argv = Vec::with_capacity(execution.argv.len());
        for slot in execution.argv {
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
        if used.contains(&false) {
            return Err(invalid("Every input must occupy an argv slot"));
        }
        let ceiling = timeout_secs.unwrap_or(limits.max_timeout_secs);
        properties.insert("host".into(), json!({"type":"string", "enum":raw.targets}));
        properties.insert(
            "timeout_secs".into(),
            json!({"type":"integer", "minimum":1, "maximum":ceiling}),
        );
        let mut required = schema.required;
        required.push("host".into());
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
            targets: raw.targets,
            input_schema,
            enabled,
            effects: raw.effects,
            inputs,
            program: execution.program,
            argv,
            cwd: execution.cwd,
            timeout_secs,
            max_output_bytes,
        };
        let fixed = Invocation::BoundArgv {
            program: &binding.program,
            arguments: binding
                .argv
                .iter()
                .filter_map(|v| match v {
                    Slot::Fixed(value) => Some(Cow::Borrowed(value.as_str())),
                    Slot::Input(_) => None,
                })
                .collect(),
            cwd: binding.cwd.as_deref(),
        };
        fixed
            .encoded_len()
            .map_err(|_| invalid("Fixed command exceeds encoded command bound"))?;
        Ok(binding)
    }
    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }
    pub(crate) fn read_only(&self) -> bool {
        self.effects
            .iter()
            .all(|v| matches!(v, Effect::Read | Effect::SensitiveRead))
    }
    pub(crate) fn effects(&self) -> &[Effect] {
        &self.effects
    }
    pub(crate) fn parse_request(
        &self,
        mut arguments: JsonObject,
    ) -> Result<BindingRequest, ErrorData> {
        let host = match arguments.remove("host") {
            Some(Value::String(host)) => host,
            _ => return Err(shape()),
        };
        let timeout_secs = arguments
            .remove("timeout_secs")
            .map(|v| unsigned_integer(&v).ok_or_else(shape))
            .transpose()?;
        let values = self
            .inputs
            .iter()
            .map(|input| {
                let value = arguments.remove(&input.name).ok_or_else(shape)?;
                if !input.matches_type(&value) {
                    return Err(shape());
                }
                Ok(if matches!(input.domain, Domain::Integer { .. }) {
                    canonical_integer(value)
                } else {
                    value
                })
            })
            .collect::<Result<_, _>>()?;
        if !arguments.is_empty() {
            return Err(shape());
        }
        Ok(BindingRequest {
            host,
            timeout_secs,
            values,
        })
    }
    pub(crate) fn prepare<'a>(
        &'a self,
        request: &'a BindingRequest,
        limits: &Limits,
    ) -> Result<PreparedBinding<'a>, ToolError> {
        if !self.targets.contains(&request.host) {
            return Err(bound("Host is not a declared tool target"));
        }
        let ceiling = self.timeout_secs.unwrap_or(limits.max_timeout_secs);
        let timeout = request
            .timeout_secs
            .unwrap_or(self.timeout_secs.unwrap_or(limits.operation_timeout_secs));
        if timeout == 0 || timeout > ceiling || timeout > limits.max_timeout_secs {
            return Err(bound("Timeout exceeds named tool ceiling"));
        }
        if request.values.len() != self.inputs.len() {
            return Err(bound("Invalid named tool inputs"));
        }
        for (input, value) in self.inputs.iter().zip(&request.values) {
            input.validate(value)?;
        }
        let mut arguments: Vec<Cow<'a, str>> = Vec::with_capacity(self.argv.len());
        // Reused integer slots copy their already formatted bounded representation, never reformat.
        let mut numeric_slots: [Option<usize>; 16] = [None; 16];
        for slot in &self.argv {
            let value = match slot {
                Slot::Fixed(value) => Cow::Borrowed(value.as_str()),
                Slot::Input(index) => match &request.values[*index] {
                    Value::String(value) => Cow::Borrowed(value.as_str()),
                    Value::Bool(value) => Cow::Borrowed(if *value { "true" } else { "false" }),
                    Value::Number(value) => {
                        if let Some(previous) = numeric_slots[*index] {
                            arguments[previous].clone()
                        } else {
                            numeric_slots[*index] = Some(arguments.len());
                            Cow::Owned(value.to_string())
                        }
                    }
                    _ => return Err(bound("Invalid named tool inputs")),
                },
            };
            arguments.push(value);
        }
        let invocation = Invocation::BoundArgv {
            program: &self.program,
            arguments,
            cwd: self.cwd.as_deref(),
        };
        invocation.encoded_len()?;
        Ok(PreparedBinding {
            invocation,
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }
}

