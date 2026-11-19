use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value as JsonValue;

use super::{ConfigError, RiskTier, invalid};
use crate::reply::ToolError;

const MAX_RULES: usize = 64;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_ENUM_VALUES: usize = 64;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ParameterConstraint {
    #[serde(default, rename = "enum")]
    pub(crate) allowed_values: Option<Vec<toml::Value>>,
    #[serde(default, rename = "const")]
    pub(crate) exact_value: Option<toml::Value>,
    #[serde(default)]
    pub(crate) min_length: Option<usize>,
    #[serde(default)]
    pub(crate) max_length: Option<usize>,
    #[serde(default)]
    pub(crate) minimum: Option<i64>,
    #[serde(default)]
    pub(crate) maximum: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHostRule {
    #[serde(default)]
    pub(crate) deny_tiers: Vec<RiskTier>,
    #[serde(default)]
    pub(crate) allow_tools: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) constraints: BTreeMap<String, BTreeMap<String, ParameterConstraint>>,
}

#[derive(Clone, Debug)]
pub(crate) struct HostRule {
    pub(crate) pattern: String,
    pub(crate) deny_tiers: Vec<RiskTier>,
    pub(crate) allow_tools: Option<BTreeSet<String>>,
    pub(crate) constraints: BTreeMap<String, BTreeMap<String, ParameterConstraint>>,
}

fn valid_scalar(value: &toml::Value) -> bool {
    matches!(
        value,
        toml::Value::String(_) | toml::Value::Integer(_) | toml::Value::Boolean(_)
    )
}

fn scalar_matches_json(toml_val: &toml::Value, json_val: &JsonValue) -> bool {
    match (toml_val, json_val) {
        (toml::Value::String(a), JsonValue::String(b)) => a == b,
        (toml::Value::Integer(a), JsonValue::Number(b)) => b.as_i64() == Some(*a),
        (toml::Value::Boolean(a), JsonValue::Bool(b)) => a == b,
        _ => false,
    }
}

impl ParameterConstraint {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.allowed_values.is_none()
            && self.exact_value.is_none()
            && self.min_length.is_none()
            && self.max_length.is_none()
            && self.minimum.is_none()
            && self.maximum.is_none()
        {
            return Err("host rule parameter constraint must not be empty");
        }
        if let Some(values) = &self.allowed_values
            && (values.is_empty()
                || values.len() > MAX_ENUM_VALUES
                || !values.iter().all(valid_scalar))
        {
            return Err("host rule enum constraint must be a bounded list of scalars");
        }
        if let Some(value) = &self.exact_value
            && !valid_scalar(value)
        {
            return Err("host rule const constraint must be a scalar");
        }
        if let (Some(min), Some(max)) = (self.min_length, self.max_length)
            && min > max
        {
            return Err("conflicting host rule length bounds");
        }
        if let (Some(min), Some(max)) = (self.minimum, self.maximum)
            && min > max
        {
            return Err("conflicting host rule numeric bounds");
        }
        if let Some(allowed) = self.effective_allowed_set()?
            && !allowed
                .iter()
                .any(|value| self.satisfies_bounds_toml(value))
        {
            return Err("conflicting host rule parameter constraints");
        }
        Ok(())
    }

    fn effective_allowed_set(&self) -> Result<Option<Vec<toml::Value>>, &'static str> {
        match (&self.allowed_values, &self.exact_value) {
            (None, None) => Ok(None),
            (Some(values), None) => Ok(Some(values.clone())),
            (None, Some(exact)) => Ok(Some(vec![exact.clone()])),
            (Some(values), Some(exact)) => {
                if values.contains(exact) {
                    Ok(Some(vec![exact.clone()]))
                } else {
                    Err("conflicting host rule parameter constraints")
                }
            }
        }
    }

    fn satisfies_bounds_toml(&self, value: &toml::Value) -> bool {
        match value {
            toml::Value::String(text) => {
                let len = text.chars().count();
                self.min_length.is_none_or(|min| len >= min)
                    && self.max_length.is_none_or(|max| len <= max)
                    && self.minimum.is_none()
                    && self.maximum.is_none()
            }
            toml::Value::Integer(num) => {
                self.minimum.is_none_or(|min| *num >= min)
                    && self.maximum.is_none_or(|max| *num <= max)
                    && self.min_length.is_none()
                    && self.max_length.is_none()
            }
            toml::Value::Boolean(_) => {
                self.min_length.is_none()
                    && self.max_length.is_none()
                    && self.minimum.is_none()
                    && self.maximum.is_none()
            }
            _ => false,
        }
    }

    pub(crate) fn intersect(&self, other: &Self) -> Result<Self, &'static str> {
        let min_length = match (self.min_length, other.min_length) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let max_length = match (self.max_length, other.max_length) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let (Some(min), Some(max)) = (min_length, max_length)
            && min > max
        {
            return Err("conflicting host rule parameter constraints");
        }
        let minimum = match (self.minimum, other.minimum) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let maximum = match (self.maximum, other.maximum) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let (Some(min), Some(max)) = (minimum, maximum)
            && min > max
        {
            return Err("conflicting host rule parameter constraints");
        }
        let left = self.effective_allowed_set()?;
        let right = other.effective_allowed_set()?;
        let allowed_values = match (left, right) {
            (None, None) => None,
            (Some(v), None) | (None, Some(v)) => Some(v),
            (Some(a), Some(b)) => {
                let intersected: Vec<_> = a.into_iter().filter(|v| b.contains(v)).collect();
                if intersected.is_empty() {
                    return Err("conflicting host rule parameter constraints");
                }
                Some(intersected)
            }
        };
        let merged = Self {
            allowed_values,
            exact_value: None,
            min_length,
            max_length,
            minimum,
            maximum,
        };
        if let Some(values) = &merged.allowed_values
            && !values
                .iter()
                .any(|value| merged.satisfies_bounds_toml(value))
        {
            return Err("conflicting host rule parameter constraints");
        }
        Ok(merged)
    }

    pub(crate) fn permits(&self, value: &JsonValue) -> bool {
        if let Some(exact) = &self.exact_value
            && !scalar_matches_json(exact, value)
        {
            return false;
        }
        if let Some(allowed) = &self.allowed_values
            && !allowed
                .iter()
                .any(|candidate| scalar_matches_json(candidate, value))
        {
            return false;
        }
        if let Some(min) = self.min_length
            && value.as_str().is_none_or(|text| text.chars().count() < min)
        {
            return false;
        }
        if let Some(max) = self.max_length
            && value.as_str().is_none_or(|text| text.chars().count() > max)
        {
            return false;
        }
        if let Some(min) = self.minimum
            && value.as_i64().is_none_or(|num| num < min)
        {
            return false;
        }
        if let Some(max) = self.maximum
            && value.as_i64().is_none_or(|num| num > max)
        {
            return false;
        }
        true
    }
}

/// Literal characters plus `*` wildcard only (`*` matches zero or more chars).
pub(crate) fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut match_ti) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] && p[pi] != b'*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            match_ti = ti;
            pi += 1;
        } else if let Some(star) = star_pi {
            pi = star + 1;
            match_ti += 1;
            ti = match_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// True when there exists at least one string matching both literal+`*` patterns.
pub(crate) fn patterns_overlap(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let m = a.len();
    let n = b.len();
    let mut prev = vec![false; n + 1];
    let mut curr = vec![false; n + 1];
    prev[0] = true;
    for j in 1..=n {
        if b[j - 1] == b'*' {
            prev[j] = prev[j - 1];
        }
    }
    for i in 1..=m {
        curr.fill(false);
        if a[i - 1] == b'*' {
            curr[0] = prev[0];
        }
        for j in 1..=n {
            let ca = a[i - 1];
            let cb = b[j - 1];
            curr[j] = if ca == b'*' && cb == b'*' {
                prev[j] || curr[j - 1] || prev[j - 1]
            } else if ca == b'*' || cb == b'*' {
                prev[j] || curr[j - 1]
            } else {
                ca == cb && prev[j - 1]
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

pub(super) fn compile_rules(
    raw: BTreeMap<String, RawHostRule>,
) -> Result<Vec<HostRule>, ConfigError> {
    if raw.len() > MAX_RULES {
        return Err(invalid("rules", "exceeds maximum host rule count"));
    }
    let mut compiled = Vec::with_capacity(raw.len());
    for (pattern, rule) in raw {
        if pattern.is_empty()
            || pattern.len() > MAX_PATTERN_BYTES
            || pattern.chars().any(char::is_control)
        {
            return Err(invalid(
                "rules",
                "host rule pattern must be nonempty, bounded, and contain no control characters",
            ));
        }
        let allow_tools = match rule.allow_tools {
            Some(tools) => {
                if tools.iter().any(String::is_empty) {
                    return Err(invalid(
                        "rules.*.allow_tools",
                        "tool names must be nonempty",
                    ));
                }
                Some(tools.into_iter().collect())
            }
            None => None,
        };
        for (tool, params) in &rule.constraints {
            if tool.is_empty() {
                return Err(invalid(
                    "rules.*.constraints",
                    "tool names must be nonempty",
                ));
            }
            for (param, constraint) in params {
                if param.is_empty() {
                    return Err(invalid(
                        "rules.*.constraints",
                        "parameter names must be nonempty",
                    ));
                }
                constraint
                    .validate()
                    .map_err(|reason| invalid("rules.*.constraints", reason))?;
            }
        }
        compiled.push(HostRule {
            pattern,
            deny_tiers: rule.deny_tiers,
            allow_tools,
            constraints: rule.constraints,
        });
    }
    for (i, left) in compiled.iter().enumerate() {
        for right in &compiled[i + 1..] {
            if !patterns_overlap(&left.pattern, &right.pattern) {
                continue;
            }
            for (tool, left_params) in &left.constraints {
                let Some(right_params) = right.constraints.get(tool) else {
                    continue;
                };
                for (param, left_constraint) in left_params {
                    let Some(right_constraint) = right_params.get(param) else {
                        continue;
                    };
                    left_constraint
                        .intersect(right_constraint)
                        .map_err(|reason| invalid("rules", reason))?;
                }
            }
        }
    }
    Ok(compiled)
}

pub(crate) fn check_host_tool(
    rules: &[HostRule],
    host: &str,
    tool: &str,
    tier: RiskTier,
) -> Result<(), ToolError> {
    let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
    for rule in rules {
        if !wildcard_match(&rule.pattern, host) {
            continue;
        }
        if rule.deny_tiers.contains(&tier) {
            return Err(denied());
        }
        if let Some(allowed) = &rule.allow_tools
            && !allowed.contains(tool)
        {
            return Err(denied());
        }
    }
    Ok(())
}

pub(crate) fn check_host_params(
    rules: &[HostRule],
    host: &str,
    tool: &str,
    tier: RiskTier,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<(), ToolError> {
    check_host_tool(rules, host, tool, tier)?;
    let denied = || ToolError::new("policy_denied", "Operation is not authorized", false);
    let nested_inputs = params.get("inputs").and_then(JsonValue::as_object);
    for rule in rules {
        if !wildcard_match(&rule.pattern, host) {
            continue;
        }
        if let Some(tool_constraints) = rule.constraints.get(tool) {
            for (param, constraint) in tool_constraints {
                if let Some(value) = params
                    .get(param)
                    .or_else(|| nested_inputs.and_then(|inputs| inputs.get(param)))
                    && !constraint.permits(value)
                {
                    return Err(denied());
                }
            }
        }
    }
    Ok(())
}
