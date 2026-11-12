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
    config::{ConfigError, Limits, account_name},
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
    authority: toml::Value,
    effects: Vec<Effect>,
    execution: RawExecution,
    input_schema: toml::Value,
    result: RawResult,
    limits: Option<RawLimits>,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawExecution {
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
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScriptSource {
    path: String,
    content_sha256: String,
    max_bytes: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterpreter {
    program: String,
    argv: Vec<String>,
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
enum Authority {
    Ordinary,
    Sudo(String),
}

#[derive(Debug)]
pub(crate) struct ScriptSource {
    pub(crate) path: String,
    pub(crate) content_sha256: [u8; 32],
    pub(crate) max_bytes: usize,
}

#[derive(Debug)]
enum Execution {
    NativeArgv {
        program: String,
        cwd: Option<String>,
        authority: Authority,
    },
    RemoteScript {
        source: ScriptSource,
        program: String,
        prefix: Vec<String>,
        cwd: Option<String>,
    },
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
    execution: Execution,
    argv: Vec<Slot>,
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
    pub(crate) script: Option<&'a ScriptSource>,
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
        let authority = match raw.authority {
            toml::Value::String(value) if value == "ordinary" => Authority::Ordinary,
            toml::Value::Table(mut value) if value.len() == 1 => match value.remove("sudo") {
                Some(toml::Value::String(user)) if user.len() <= 64 && account_name(&user) => {
                    Authority::Sudo(user)
                }
                _ => return Err(invalid("Invalid fixed sudo account")),
            },
            _ => return Err(invalid("Invalid fixed tool authority")),
        };
        if raw.result.kind != RESULT_KIND {
            return Err(invalid("Only command tool results are supported"));
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
            RawExecution::RemoteScript {
                source,
                interpreter,
                argv,
                cwd,
            } => {
                if !matches!(authority, Authority::Ordinary) {
                    return Err(invalid("Remote scripts require ordinary authority"));
                }
                if !absolute(&source.path)
                    || source.path.ends_with('/')
                    || !absolute(&interpreter.program)
                    || interpreter.program.ends_with('/')
                    || cwd.as_deref().is_some_and(|v| !absolute(v))
                    || interpreter.argv.len() > 64
                    || argv.len() > 64 - interpreter.argv.len()
                    || interpreter
                        .argv
                        .iter()
                        .any(|v| v.len() > 4096 || v.contains('\0'))
                {
                    return Err(invalid("Invalid fixed remote script layout"));
                }
                let mut content_sha256 = [0; 32];
                if source.content_sha256.len() != 64
                    || hex::decode_to_slice(&source.content_sha256, &mut content_sha256).is_err()
                {
                    return Err(invalid(
                        "Script content_sha256 requires exactly 64 hexadecimal ASCII characters",
                    ));
                }
                let ceiling = limits.max_file_bytes.min(1_048_576);
                let max_bytes = source.max_bytes.unwrap_or(ceiling);
                if max_bytes == 0 || max_bytes > ceiling {
                    return Err(invalid(
                        "Script byte bound must be positive and within the server and 1 MiB ceilings",
                    ));
                }
                let separator = interpreter.argv.iter().any(|v| v == "--");
                (
                    Execution::RemoteScript {
                        source: ScriptSource {
                            path: source.path,
                            content_sha256,
                            max_bytes: max_bytes as usize,
                        },
                        program: interpreter.program,
                        prefix: interpreter.argv,
                        cwd,
                    },
                    argv,
                    separator,
                )
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
            execution,
            argv,
            timeout_secs,
            max_output_bytes,
        };
        let mut arguments = binding.arguments();
        arguments.extend(binding.argv.iter().filter_map(|v| match v {
            Slot::Fixed(value) => Some(Cow::Borrowed(value.as_str())),
            Slot::Input(_) => None,
        }));
        let fixed = binding.invocation(arguments);
        fixed
            .encoded_len()
            .map_err(|_| invalid("Fixed command exceeds encoded command bound"))?;
        Ok(binding)
    }
    pub(crate) fn executor_kind(&self) -> &'static str {
        match self.execution {
            Execution::NativeArgv { .. } => EXECUTOR_KIND,
            Execution::RemoteScript { .. } => "remote_script",
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

    fn arguments(&self) -> Vec<Cow<'_, str>> {
        let prefix = match &self.execution {
            Execution::NativeArgv { .. } => &[][..],
            Execution::RemoteScript { prefix, .. } => prefix.as_slice(),
        };
        let mut arguments = Vec::with_capacity(prefix.len() + self.argv.len());
        arguments.extend(prefix.iter().map(|v| Cow::Borrowed(v.as_str())));
        arguments
    }

    fn invocation<'a>(&'a self, arguments: Vec<Cow<'a, str>>) -> Invocation<'a> {
        match &self.execution {
            Execution::NativeArgv {
                program,
                authority: Authority::Sudo(user),
                ..
            } => Invocation::BoundSudo {
                program,
                arguments,
                user,
            },
            Execution::NativeArgv {
                program,
                cwd,
                authority: Authority::Ordinary,
            }
            | Execution::RemoteScript { program, cwd, .. } => Invocation::BoundArgv {
                program,
                arguments,
                cwd: cwd.as_deref(),
            },
        }
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
        let mut arguments = self.arguments();
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
        let invocation = self.invocation(arguments);
        invocation.encoded_len()?;
        Ok(PreparedBinding {
            invocation,
            script: match &self.execution {
                Execution::RemoteScript { source, .. } => Some(source),
                Execution::NativeArgv { .. } => None,
            },
            duration: Duration::from_secs(timeout),
            max_output_bytes: self.max_output_bytes.unwrap_or(limits.max_output_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> toml::Value {
        toml::from_str(r#"
description = "Literal observation"
revision = "review-1"
targets = ["server"]
authority = "ordinary"
effects = ["read"]
execution = { kind = "native_argv", program = "/usr/bin/printf", argv = ["--", { input = "value" }] }
input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 4096 } } }
result = { kind = "command" }
"#).unwrap()
    }
    fn compile(value: toml::Value) -> Result<Bindings, ConfigError> {
        Bindings::compile(
            BTreeMap::from([("observe".into(), value)]),
            &["observe".into()],
            &Limits::default(),
            |v| v == "server",
        )
    }
    fn request(binding: &CompiledBinding, value: Value) -> BindingRequest {
        binding
            .parse_request(
                json!({"host":"server", "value":value})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap()
    }
    fn property(raw: &mut toml::Value) -> &mut toml::Value {
        &mut raw["input_schema"]["properties"]["value"]
    }
    fn put(table: &mut toml::Value, key: &str, value: toml::Value) {
        table.as_table_mut().unwrap().insert(key.into(), value);
    }

    #[test]
    fn fixed_sudo_borrows_literal_inputs_without_exposing_authority_controls() {
        let mut raw = definition();
        raw["authority"] = toml::from_str("sudo = 'root'").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(binding.read_only());
        let text = "-n ' \"$();\\\n雪";
        let request = request(binding, json!(text));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        match prepared.invocation {
            Invocation::BoundSudo {
                program,
                arguments,
                user,
            } => {
                assert_eq!(program, "/usr/bin/printf");
                assert_eq!(user, "root");
                assert_eq!(arguments, [Cow::Borrowed("--"), Cow::Borrowed(text)]);
                assert!(arguments.iter().all(|v| matches!(v, Cow::Borrowed(_))));
            }
            _ => panic!("Expected fixed sudo invocation"),
        }
        for key in ["user", "authority", "program"] {
            let mut arguments = json!({"host":"server", "value":"ok"})
                .as_object()
                .unwrap()
                .clone();
            arguments.insert(key.into(), json!("root"));
            assert_eq!(
                binding.parse_request(arguments).err().unwrap().code,
                rmcp::model::ErrorCode::INVALID_PARAMS
            );
        }
    }

    #[test]
    fn literal_slots_borrow_and_preserve_adversarial_text() {
        let mut raw = definition();
        put(
            &mut raw["execution"],
            "cwd",
            "/tmp/quotes ' and spaces".into(),
        );
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .insert(1, "fixed '$()`;\n".into());
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let text = "-a ' \"$()`;\\\n雪";
        let request = request(binding, json!(text));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        match prepared.invocation {
            Invocation::BoundArgv {
                program,
                arguments,
                cwd,
            } => {
                assert_eq!(program, "/usr/bin/printf");
                assert_eq!(cwd, Some("/tmp/quotes ' and spaces"));
                assert_eq!(
                    arguments.iter().map(Cow::as_ref).collect::<Vec<_>>(),
                    ["--", "fixed '$()`;\n", text]
                );
            }
            _ => panic!("Expected bound argv"),
        }
    }

    #[test]
    fn closed_shape_and_types_reject_before_preparation() {
        let bindings = compile(definition()).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for arguments in [
            json!({"host":"server"}),
            json!({"host":42, "value":"ok"}),
            json!({"host":"server", "value":1}),
            json!({"host":"server", "value":"ok", "program":"/bin/sh"}),
            json!({"host":"server", "value":"ok", "timeout_secs":-1}),
            json!({"host":"server", "value":"ok", "timeout_secs":null}),
            json!({"host":"server", "value":"ok", "env":{}}),
        ] {
            let error = binding
                .parse_request(arguments.as_object().unwrap().clone())
                .err()
                .unwrap();
            assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        }
    }

    #[test]
    fn string_bounds_count_characters_and_enum_is_enforced() {
        let mut raw = definition();
        *property(&mut raw) = toml::from_str("type='string'\nminLength=1\nmaxLength=2").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for (text, accepted) in [
            ("", false),
            ("雪", true),
            ("雪雪", true),
            ("雪雪雪", false),
            ("\0", false),
        ] {
            let request = request(binding, json!(text));
            let result = binding.prepare(&request, &Limits::default());
            assert_eq!(result.is_ok(), accepted, "{text:?}");
            if let Err(error) = result {
                assert_eq!(error.code, "invalid_argument");
                assert!(!error.remote_state_unknown);
            }
        }
        let mut raw = definition();
        put(
            property(&mut raw),
            "enum",
            toml::Value::Array(vec!["approved".into()]),
        );
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        assert!(
            binding
                .prepare(&request(binding, json!("approved")), &Limits::default())
                .is_ok()
        );
        assert!(
            binding
                .prepare(&request(binding, json!("other")), &Limits::default())
                .is_err()
        );
    }

    #[test]
    fn integer_and_boolean_domains_render_exactly() {
        for (schema, values) in [
            (
                "type='integer'\nminimum=-2\nmaximum=2",
                vec![
                    (json!(-2), Some("-2")),
                    (json!(2), Some("2")),
                    (json!(3), None),
                ],
            ),
            (
                "type='boolean'\nenum=[true]",
                vec![(json!(true), Some("true")), (json!(false), None)],
            ),
            (
                "type='integer'\nminimum=-9223372036854775808\nmaximum=9223372036854775807",
                vec![
                    (json!(i64::MIN), Some("-9223372036854775808")),
                    (json!(i64::MAX), Some("9223372036854775807")),
                ],
            ),
        ] {
            let mut raw = definition();
            *property(&mut raw) = toml::from_str(schema).unwrap();
            let bindings = compile(raw).unwrap();
            let binding = bindings.get(BindingId(0)).unwrap();
            for (value, expected) in values {
                let request = request(binding, value);
                let result = binding.prepare(&request, &Limits::default());
                if let Some(expected) = expected {
                    match result.unwrap().invocation {
                        Invocation::BoundArgv { arguments, .. } => {
                            assert_eq!(arguments[1], expected)
                        }
                        _ => panic!("Expected bound argv"),
                    }
                } else {
                    assert!(result.is_err());
                }
            }
            for wrong in [json!("1"), json!(1.5), json!([])] {
                assert!(
                    binding
                        .parse_request(
                            json!({"host":"server","value":wrong})
                                .as_object()
                                .unwrap()
                                .clone()
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn option_safety_depends_on_fixed_separator_or_closed_domain() {
        for (schema, accepted) in [
            ("type='string'\nmaxLength=32", false),
            ("type='string'\nmaxLength=32\nenum=['--version']", true),
            ("type='integer'\nminimum=-1\nmaximum=5", false),
            ("type='integer'\nminimum=-1\nmaximum=5\nenum=[-1,2]", true),
            ("type='integer'\nminimum=0\nmaximum=5", true),
            ("type='boolean'", true),
        ] {
            let mut raw = definition();
            raw["execution"]["argv"].as_array_mut().unwrap().remove(0);
            *property(&mut raw) = toml::from_str(schema).unwrap();
            assert_eq!(compile(raw).is_ok(), accepted, "{schema}");
        }
        let mut raw = definition();
        raw["execution"]["argv"].as_array_mut().unwrap().swap(0, 1);
        assert!(
            compile(raw).is_err(),
            "A later separator must not authorize an earlier free slot"
        );
    }

    #[test]
    fn unsupported_schemas_and_bad_mappings_fail_even_when_disabled() {
        for schema in [
            "type='string'",
            "type='string'\nmaxLength=4097",
            "type='string'\nmaxLength=2\nminLength=3",
            "type='string'\nmaxLength=2\npattern='.*'",
            "type='string'\nmaxLength=2\ndefault='x'",
            "type='object'\nproperties={}",
            "type='integer'\nminimum=0",
            "type='integer'\nminimum=2\nmaximum=1",
            "type='integer'\nminimum=0\nmaximum=2\nenum=['1']",
            "type='boolean'\nenum=[]",
            "type='boolean'\nenum=[true,true]",
            "type='boolean'\nmaximum=2",
        ] {
            let mut raw = definition();
            *property(&mut raw) = toml::from_str(schema).unwrap();
            assert!(
                Bindings::compile(
                    BTreeMap::from([("observe".into(), raw)]),
                    &[],
                    &Limits::default(),
                    |_| true
                )
                .is_err(),
                "{schema}"
            );
        }
        for name in RESERVED
            .iter()
            .copied()
            .chain(["_hidden", "bad-name", "1value"])
        {
            let mut raw = definition();
            let properties = raw["input_schema"]["properties"].as_table_mut().unwrap();
            let value = properties.remove("value").unwrap();
            properties.insert(name.into(), value);
            raw["input_schema"]["required"] = toml::Value::Array(vec![name.into()]);
            raw["execution"]["argv"][1]["input"] = name.into();
            assert!(compile(raw).is_err(), "{name}");
        }
        for argv in [
            vec![],
            vec![toml::Value::String("--".into())],
            vec![toml::from_str("input='unknown'").unwrap()],
            vec![toml::from_str("input='value'\nfixed='override'").unwrap()],
        ] {
            let mut raw = definition();
            raw["execution"]["argv"] = toml::Value::Array(argv);
            assert!(compile(raw).is_err());
        }
        for required in [vec![], vec!["value", "value"], vec!["missing"]] {
            let mut raw = definition();
            raw["input_schema"]["required"] =
                toml::Value::Array(required.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
    }

    #[test]
    fn limits_targets_revision_and_enablement_are_enforced() {
        let mut raw = definition();
        put(
            &mut raw,
            "limits",
            toml::from_str("timeout_secs=3\nmax_output_bytes=7").unwrap(),
        );
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let mut request = request(binding, json!("ok"));
        let prepared = binding.prepare(&request, &Limits::default()).unwrap();
        assert_eq!(prepared.duration, Duration::from_secs(3));
        assert_eq!(prepared.max_output_bytes, 7);
        for timeout in [0, 4] {
            request.timeout_secs = Some(timeout);
            assert!(binding.prepare(&request, &Limits::default()).is_err());
        }
        request.timeout_secs = Some(2);
        assert_eq!(
            binding
                .prepare(&request, &Limits::default())
                .unwrap()
                .duration,
            Duration::from_secs(2)
        );
        request.host = "arbitrary.example".into();
        assert!(binding.prepare(&request, &Limits::default()).is_err());
        for revision in ["", "not secret!", "☃"] {
            let mut raw = definition();
            raw["revision"] = revision.into();
            assert!(compile(raw).is_err());
        }
        for targets in [vec![], vec!["server", "server"], vec!["unknown"]] {
            let mut raw = definition();
            raw["targets"] = toml::Value::Array(targets.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
        for limits in [
            "timeout_secs=0",
            "timeout_secs=601",
            "max_output_bytes=0",
            "max_output_bytes=1048577",
        ] {
            let mut raw = definition();
            put(&mut raw, "limits", toml::from_str(limits).unwrap());
            assert!(compile(raw).is_err());
        }
        for enabled in [
            vec!["missing".into()],
            vec!["observe".into(), "observe".into()],
        ] {
            assert!(
                Bindings::compile(
                    BTreeMap::from([("observe".into(), definition())]),
                    &enabled,
                    &Limits::default(),
                    |_| true
                )
                .is_err()
            );
        }
        let disabled = Bindings::compile(
            BTreeMap::from([("observe".into(), definition())]),
            &[],
            &Limits::default(),
            |_| true,
        )
        .unwrap();
        assert!(!disabled.get(BindingId(0)).unwrap().enabled());
    }

    #[test]
    fn actual_expansion_obeys_exact_encoded_command_boundary() {
        // The fixed prefix "command -- /x --" is 16 bytes; sixteen references
        // contribute 65504 bytes at 4093 bytes each plus their leading spaces.
        // A 15-byte literal plus its leading space reaches exactly 65536.
        let mut raw = definition();
        raw["execution"]["program"] = "/x".into();
        let mut argv = vec![
            toml::Value::String("--".into()),
            toml::Value::String("x".repeat(15)),
        ];
        argv.extend((0..16).map(|_| toml::from_str("input='value'").unwrap()));
        raw["execution"]["argv"] = toml::Value::Array(argv);
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        let exact = request(binding, json!("x".repeat(4093)));
        let prepared = binding.prepare(&exact, &Limits::default()).unwrap();
        assert_eq!(prepared.invocation.encoded_len().unwrap(), 65536);
        let over = request(binding, json!("x".repeat(4094)));
        let error = binding.prepare(&over, &Limits::default()).err().unwrap();
        assert_eq!(error.code, "invalid_argument");
        assert!(!error.remote_state_unknown);
    }

    #[test]
    fn static_layout_and_metadata_bounds_reject_overflow() {
        for (field, value) in [
            ("program", Value::String("relative".into())),
            ("program", Value::String("/bin/".into())),
            ("program", Value::String("/".to_owned() + &"x".repeat(4096))),
            ("cwd", Value::String("relative".into())),
        ] {
            let mut raw = definition();
            put(&mut raw["execution"], field, value.as_str().unwrap().into());
            assert!(compile(raw).is_err());
        }
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .push("x".repeat(4097).into());
        assert!(compile(raw).is_err());
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .extend((0..63).map(|_| "x".into()));
        assert!(compile(raw).is_err(), "More than 64 slots");
        let mut raw = definition();
        raw["execution"]["argv"]
            .as_array_mut()
            .unwrap()
            .extend((0..32).map(|_| "x".repeat(4096).into()));
        assert!(
            compile(raw).is_err(),
            "Fixed-only command must fit before any request"
        );
        let mut raw = definition();
        put(
            property(&mut raw),
            "enum",
            toml::Value::Array(
                (0..5)
                    .map(|i| format!("{i}{}", "x".repeat(4000)).into())
                    .collect(),
            ),
        );
        assert!(compile(raw).is_err(), "Aggregate enum text is bounded");
        let raw = (0..33)
            .map(|i| (format!("tool_{i}"), definition()))
            .collect();
        assert!(Bindings::compile(raw, &[], &Limits::default(), |_| true).is_err());
    }

    #[test]
    fn effect_annotations_are_conservative_and_unique() {
        for (effects, read_only) in [
            (vec!["read", "sensitive_read"], true),
            (vec!["read", "probe"], false),
            (vec!["runtime_write"], false),
            (vec!["persistent_write"], false),
            (vec!["availability"], false),
            (vec!["unknown"], false),
        ] {
            let mut raw = definition();
            raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
            let bindings = compile(raw).unwrap();
            assert_eq!(bindings.get(BindingId(0)).unwrap().read_only(), read_only);
        }
        for effects in [vec![], vec!["read", "read"], vec!["invented"]] {
            let mut raw = definition();
            raw["effects"] = toml::Value::Array(effects.into_iter().map(Into::into).collect());
            assert!(compile(raw).is_err());
        }
    }

    #[test]
    fn integer_schema_normalizes_integral_numbers_without_truncating() {
        let mut raw = definition();
        *property(&mut raw) =
            toml::from_str("type='integer'\nminimum=-2\nmaximum=2\nenum=[1,2]").unwrap();
        let bindings = compile(raw).unwrap();
        let binding = bindings.get(BindingId(0)).unwrap();
        for (token, expected) in [("1", "1"), ("1.0", "1"), ("1e0", "1"), ("2.0", "2")] {
            let value: Value = serde_json::from_str(token).unwrap();
            let request = binding
                .parse_request(
                    json!({
                        "host":"server", "value":value, "timeout_secs":1.0
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                )
                .unwrap();
            let prepared = binding.prepare(&request, &Limits::default()).unwrap();
            assert_eq!(prepared.duration, Duration::from_secs(1));
            match prepared.invocation {
                Invocation::BoundArgv { arguments, .. } => assert_eq!(arguments[1], expected),
                _ => panic!("wrong native invocation"),
            }
        }
        for token in ["1.5", "1e100", "3.0"] {
            let value: Value = serde_json::from_str(token).unwrap();
            if let Ok(request) = binding.parse_request(
                json!({
                    "host":"server", "value":value
                })
                .as_object()
                .unwrap()
                .clone(),
            ) {
                assert!(binding.prepare(&request, &Limits::default()).is_err());
            }
        }
        let mut raw = definition();
        *property(&mut raw) =
            toml::from_str("type='integer'\nminimum=0\nmaximum=2\nenum=[1,1.0]").unwrap();
        assert!(
            compile(raw).is_err(),
            "numeric enum aliases must not become distinct choices"
        );
    }

    #[test]
    fn generated_host_enums_share_the_complete_input_schema_budget() {
        for (target, choices) in [
            ("x".repeat(MAX_SCHEMA_BYTES + 1), None),
            (
                "x".repeat(MAX_SCHEMA_BYTES - 1024),
                Some(vec!["a".repeat(1000), "b".repeat(1000)]),
            ),
        ] {
            let mut raw = definition();
            raw["targets"] = toml::Value::Array(vec![target.into()]);
            if let Some(choices) = choices {
                put(
                    property(&mut raw),
                    "enum",
                    toml::Value::Array(choices.into_iter().map(toml::Value::String).collect()),
                );
            }
            let result = Bindings::compile(
                BTreeMap::from([("observe".into(), raw)]),
                &["observe".into()],
                &Limits::default(),
                |_| true,
            );
            assert!(
                result.is_err(),
                "generated host choices escaped the schema cap"
            );
        }
    }
}
