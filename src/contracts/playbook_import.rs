//! Explicit reviewed playbook contracts; importing never parses or executes YAML.
use std::path::{Path, PathBuf};

use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    module_schema, role_import,
    schema_import::{Report, bounded_json, read_json, stopped, write_document},
};
use crate::{
    automation::{self, RuntimeContext, RuntimeIdentity},
    config::Config,
};

const SNAPSHOT_LIMIT: usize = 1_048_576;
const INPUT_LIMIT: usize = 65_536;

#[derive(Args)]
pub(crate) struct ImportArgs {
    playbook: String,
    #[arg(long)]
    project_root: PathBuf,
    /// Explicit closed JSON Schema; never inferred from project content.
    #[arg(long)]
    input_schema: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    overlay: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    snapshot: PathBuf,
    #[arg(long)]
    project_root: PathBuf,
    #[arg(long)]
    overlay: Option<PathBuf>,
    #[arg(long)]
    input: Option<PathBuf>,
}

pub(crate) enum Command {
    Import(ImportArgs),
    Verify(VerifyArgs),
}

pub(crate) fn valid_playbook(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with(['/', '-'])
        && !["\0", "\\", "$", "{{", "{%", "{#"]
            .iter()
            .any(|token| value.contains(token))
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && (value.ends_with(".yml") || value.ends_with(".yaml"))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    playbook: String,
    runtime: RuntimeIdentity,
    content_sha256: String,
    contract: Value,
    schema_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<Value>,
}

fn digest(snapshot: &Snapshot) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(&(
        snapshot.schema,
        &snapshot.playbook,
        &snapshot.runtime,
        &snapshot.content_sha256,
        &snapshot.contract,
        &snapshot.binding,
    ))
    .map_err(|_| "invalid_schema_snapshot")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_contract(contract: &Value) -> Result<(), &'static str> {
    // Only an explicit-schema contract can be approved: no injected defaults,
    // invented aliases, or documentation-derived semantics at reload/startup.
    if module_schema::import_explicit_schema(&contract["schema"])? != *contract {
        return Err("invalid_schema_snapshot");
    }
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<Snapshot, &'static str> {
    let snapshot: Snapshot = serde_json::from_value(read_json(path, SNAPSHOT_LIMIT)?)
        .map_err(|_| "invalid_schema_snapshot")?;
    if snapshot.schema != 1
        || !valid_playbook(&snapshot.playbook)
        || !automation::valid_identity(&snapshot.runtime)
        || snapshot.content_sha256.len() != 64
        || !snapshot
            .content_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || snapshot.schema_sha256 != digest(&snapshot)?
    {
        return Err("invalid_schema_snapshot");
    }
    validate_contract(&snapshot.contract)?;
    if let Some(binding) = &snapshot.binding {
        compile_binding(&snapshot.contract, binding)?;
    }
    Ok(snapshot)
}

pub(crate) struct ReviewedPlaybook {
    pub playbook: String,
    pub runtime: RuntimeIdentity,
    pub content_sha256: String,
    pub contract: Value,
    pub binding: Option<Value>,
    snapshot: PathBuf,
}

pub(crate) fn load_reviewed(path: &Path) -> Result<ReviewedPlaybook, &'static str> {
    let snapshot = read_snapshot(path)?;
    Ok(ReviewedPlaybook {
        playbook: snapshot.playbook,
        runtime: snapshot.runtime,
        content_sha256: snapshot.content_sha256,
        contract: snapshot.contract,
        binding: snapshot.binding,
        snapshot: std::fs::canonicalize(path).map_err(|_| "schema_file_unavailable")?,
    })
}

pub(crate) async fn verify_reviewed(
    reviewed: &ReviewedPlaybook,
    project_root: &Path,
    runtime: Option<PathBuf>,
    context: RuntimeContext<'_>,
) -> Result<(), &'static str> {
    validate_contract(&reviewed.contract)?;
    let observed = automation::import_playbook(
        runtime,
        &reviewed.playbook,
        project_root,
        Some(&reviewed.snapshot),
        context,
    )
    .await?;
    if reviewed.runtime != observed.identity
        || reviewed.content_sha256 != observed.content_sha256
        || observed.document["playbook"].as_str() != Some(&reviewed.playbook)
    {
        return Err("schema_drift");
    }
    Ok(())
}

fn playbook_variable(name: &str) -> bool {
    !matches!(
        name,
        "playbook"
            | "project_root"
            | "playbook_path"
            | "import_playbook"
            | "limit"
            | "extra_vars"
            | "extravars"
    )
}

pub(crate) fn validate_overlay(overlay: &Value) -> Result<(), &'static str> {
    role_import::validate_overlay(overlay)?;
    for field in ["fixed_args", "input_map"] {
        if overlay[field]
            .as_object()
            .is_some_and(|values| values.keys().any(|name| !playbook_variable(name)))
        {
            return Err("invalid_binding_schema");
        }
    }
    Ok(())
}

pub(crate) fn compile_binding(
    contract: &Value,
    overlay: &Value,
) -> Result<module_schema::CapabilityBinding, &'static str> {
    validate_overlay(overlay)?;
    for field in ["fixed_args", "input_map"] {
        for name in overlay[field]
            .as_object()
            .ok_or("invalid_binding_schema")?
            .keys()
        {
            let canonical = contract["aliases"]["aliases"][name]
                .as_str()
                .unwrap_or(name);
            if !playbook_variable(canonical) {
                return Err("invalid_binding_schema");
            }
        }
    }
    role_import::compile_binding(contract, overlay)
}

fn output_path(path: &Path) -> Result<PathBuf, &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|_| "schema_output_failed")?;
    let output = parent.join(path.file_name().ok_or("schema_output_failed")?);
    if output
        .to_str()
        .is_none_or(|value| value.len() > 4096 || value.contains('\0'))
    {
        return Err("schema_output_failed");
    }
    Ok(output)
}

struct Prepared {
    playbook: String,
    project_root: PathBuf,
    guarded_path: PathBuf,
    output: bool,
    previous: Option<(RuntimeIdentity, String)>,
    contract: Value,
    binding: Option<Value>,
    input: Option<Value>,
}

fn prepare(command: Command, phase: &mut &'static str) -> Result<Prepared, &'static str> {
    let prepared = match command {
        Command::Import(args) => Prepared {
            playbook: args.playbook,
            project_root: args.project_root,
            guarded_path: output_path(&args.output)?,
            output: true,
            previous: None,
            contract: module_schema::import_explicit_schema(&read_json(
                &args.input_schema,
                INPUT_LIMIT,
            )?)?,
            binding: args
                .overlay
                .map(|path| read_json(&path, INPUT_LIMIT))
                .transpose()?,
            input: None,
        },
        Command::Verify(args) => {
            let previous = read_snapshot(&args.snapshot)?;
            Prepared {
                playbook: previous.playbook,
                project_root: args.project_root,
                guarded_path: std::fs::canonicalize(&args.snapshot)
                    .map_err(|_| "schema_file_unavailable")?,
                output: false,
                previous: Some((previous.runtime, previous.content_sha256)),
                contract: previous.contract,
                binding: match args.overlay {
                    Some(path) => Some(read_json(&path, INPUT_LIMIT)?),
                    None => previous.binding,
                },
                input: args
                    .input
                    .map(|path| read_json(&path, INPUT_LIMIT))
                    .transpose()?,
            }
        }
    };
    if !valid_playbook(&prepared.playbook) {
        return Err("invalid_playbook");
    }
    if let Some(binding) = &prepared.binding {
        *phase = "binding_validation";
        let compiled = compile_binding(&prepared.contract, binding)?;
        if let Some(input) = &prepared.input {
            *phase = "input_validation";
            compiled.prepare(input)?;
        }
    } else if prepared.input.is_some() {
        *phase = "binding_validation";
        return Err("schema_binding_required");
    }
    Ok(prepared)
}

pub(crate) async fn perform(
    config: Config,
    command: Command,
    timeout_secs: Option<u64>,
    shutdown: CancellationToken,
) -> Report {
    let mut phase = "schema_validation";
    match perform_tracked(config, command, timeout_secs, shutdown, &mut phase).await {
        Ok(report) => report,
        Err(code) => Report::failed(code, phase),
    }
}

async fn perform_tracked(
    config: Config,
    command: Command,
    timeout_secs: Option<u64>,
    shutdown: CancellationToken,
    phase: &mut &'static str,
) -> Result<Report, &'static str> {
    let deadline = tokio::time::Instant::now()
        .checked_add(
            config
                .timeout(timeout_secs)
                .map_err(|_| "invalid_timeout")?,
        )
        .ok_or("invalid_timeout")?;
    let runtime = config
        .automation_runtime()
        .map_err(|_| "runtime_unavailable")?;
    *phase = "schema_preparation";
    let (prepared, preparation_phase) = tokio::task::spawn_blocking(move || {
        let mut phase = "schema_preparation";
        let result = prepare(command, &mut phase);
        (result, phase)
    })
    .await
    .map_err(|_| "schema_file_unavailable")?;
    *phase = preparation_phase;
    let prepared = prepared?;
    stopped(&shutdown, deadline)?;
    *phase = "runtime_import";
    let observed = automation::import_playbook(
        runtime,
        &prepared.playbook,
        &prepared.project_root,
        Some(&prepared.guarded_path),
        RuntimeContext {
            deadline,
            ct: &shutdown,
            shutdown: &shutdown,
        },
    )
    .await?;
    stopped(&shutdown, deadline)?;
    *phase = "schema_verification";
    if observed.document["playbook"].as_str() != Some(&prepared.playbook) {
        return Err("runtime_protocol_error");
    }
    if let Some((identity, content)) = &prepared.previous
        && (*identity != observed.identity || *content != observed.content_sha256)
    {
        return Err("schema_drift");
    }
    let report = Report::validated(prepared.binding.is_some(), prepared.input.is_some());
    if prepared.output {
        *phase = "schema_write";
        let mut snapshot = Snapshot {
            schema: 1,
            playbook: prepared.playbook,
            runtime: observed.identity,
            content_sha256: observed.content_sha256,
            contract: prepared.contract,
            schema_sha256: String::new(),
            binding: prepared.binding,
        };
        snapshot.schema_sha256 = digest(&snapshot)?;
        let mut remaining = 16_384 - 64;
        for value in [Some(&snapshot.contract), snapshot.binding.as_ref()]
            .into_iter()
            .flatten()
        {
            if !bounded_json(value, 1, &mut remaining) {
                return Err("schema_file_limit");
            }
        }
        stopped(&shutdown, deadline)?;
        tokio::task::spawn_blocking(move || write_document(&prepared.guarded_path, &snapshot))
            .await
            .map_err(|_| "schema_output_failed")??;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn playbook_path_is_canonical_and_bounded() {
        assert!(valid_playbook("nested/部署.yaml"));
        for value in [
            "/site.yml",
            "-site.yml",
            "a//b.yml",
            "./site.yml",
            "a/../site.yml",
            "a\\b.yml",
            "$HOME/site.yml",
            "{{name}}.yml",
            "site.json",
            "site.yml\0",
        ] {
            assert!(!valid_playbook(value), "{value:?}");
        }
        assert!(!valid_playbook(&format!("{}.yml", "a".repeat(4093))));
    }

    #[test]
    fn explicit_playbook_conditionals_validate_before_execution() {
        let schema = json!({
            "type":"object", "additionalProperties":false,
            "properties":{"mode":{"type":"string"}, "payload":{"type":"string"}},
            "required":["mode"],
            "if":{"properties":{"mode":{"const":"write"}},"required":["mode"]},
            "then":{"required":["payload"]},
            "else":{"not":{"required":["payload"]}}
        });
        let contract = module_schema::import_explicit_schema(&schema).unwrap();
        let overlay = json!({
            "input_schema":schema, "fixed_args":{},
            "input_map":{"mode":"mode","payload":"payload"}
        });
        let binding = compile_binding(&contract, &overlay).unwrap();
        assert!(binding.prepare(&json!({"mode":"write"})).is_err());
        assert!(
            binding
                .prepare(&json!({"mode":"read","payload":"forbidden"}))
                .is_err()
        );
        assert!(
            binding
                .prepare(&json!({"mode":"write","payload":"literal {{ text }}"}))
                .is_ok()
        );
    }
}
