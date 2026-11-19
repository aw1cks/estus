//! Explicit, offline authoring commands. Importing never registers or executes a tool.
//! Failed CLI reports retain a fixed cause code and the last entered authoring phase;
//! successful reports omit diagnostic fields. File parsing is `schema_preparation`,
//! distinct from semantic binding/input validation, and never renders source errors.
use std::fs::{OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::automation::{self, RuntimeCollection, RuntimeContext, RuntimeIdentity};
use crate::config::Config;
use crate::contracts::module_schema;

const SNAPSHOT_LIMIT: usize = 1_048_576;
const INPUT_LIMIT: usize = 65_536;

#[derive(Args)]
pub(crate) struct SchemaArgs {
    #[command(subcommand)]
    command: SchemaCommand,
    /// Deadline for the entire offline import/verification.
    #[arg(long, global = true)]
    timeout_secs: Option<u64>,
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Explicitly approve the selected runtime's canonical generic module inventory.
    ImportInventory {
        #[arg(long)]
        output: PathBuf,
    },
    /// Import installed public ansible-doc metadata into a new reviewable snapshot.
    Import {
        module: String,
        #[arg(long)]
        output: PathBuf,
        /// Reviewed JSON input_schema, fixed_args and input_map.
        #[arg(long)]
        overlay: Option<PathBuf>,
    },
    /// Detect runtime/content/schema drift and validate an optional binding/input.
    Verify {
        snapshot: PathBuf,
        /// Validate this overlay instead of the snapshot's stored overlay.
        #[arg(long)]
        overlay: Option<PathBuf>,
        /// Validate request JSON without executing it or printing argument values.
        #[arg(long)]
        input: Option<PathBuf>,
    },
    /// Import one reviewed role entry point; never execute its tasks or dependencies.
    ImportRole(crate::contracts::role_import::ImportArgs),
    /// Detect role/runtime/content drift and validate reviewed inputs offline.
    VerifyRole(crate::contracts::role_import::VerifyArgs),
    /// Review one fixed project/playbook with an explicit input contract, without executing it.
    ImportPlaybook(crate::contracts::playbook_import::ImportArgs),
    /// Detect reviewed project/runtime drift and validate inputs without execution.
    VerifyPlaybook(crate::contracts::playbook_import::VerifyArgs),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    module: String,
    runtime: RuntimeIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<RuntimeCollection>,
    content_sha256: String,
    contract: Value,
    schema_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<Value>,
}

/// Reviewed backend metadata. Loading never regenerates or refreshes approval.
#[derive(Debug)]
pub(crate) struct ReviewedModule {
    pub module: String,
    pub runtime: RuntimeIdentity,
    pub collection: Option<RuntimeCollection>,
    pub content_sha256: String,
    pub contract: Value,
    pub binding: Option<Value>,
}

pub(crate) fn load_reviewed(path: &Path) -> Result<ReviewedModule, &'static str> {
    let snapshot = read_snapshot(path)?;
    Ok(ReviewedModule {
        module: snapshot.module,
        runtime: snapshot.runtime,
        collection: snapshot.collection,
        content_sha256: snapshot.content_sha256,
        contract: snapshot.contract,
        binding: snapshot.binding,
    })
}

/// Return the verified logical source path for subsequent content-only checks.
pub(crate) async fn verify_reviewed(
    reviewed: &ReviewedModule,
    runtime: Option<PathBuf>,
    context: RuntimeContext<'_>,
) -> Result<String, &'static str> {
    let observed = automation::import_module(runtime, &reviewed.module, context).await?;
    if reviewed.runtime != observed.identity
        || reviewed.collection != observed.collection
        || reviewed.content_sha256 != observed.content_sha256
        || reviewed.contract != module_schema::import_document(&observed.document)?
    {
        return Err("schema_drift");
    }
    let source = observed.document["doc"]["filename"]
        .as_str()
        .filter(|source| {
            source.len() <= 4096
                && !source.contains('\0')
                && Path::new(source)
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
        })
        .ok_or("invalid_schema_snapshot")?;
    Ok(source.to_owned())
}

#[derive(Serialize)]
pub(crate) struct Report {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_validated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_validated: Option<bool>,
}

impl Report {
    pub(crate) fn validated(binding: bool, input: bool) -> Self {
        Self {
            ok: true,
            error_code: None,
            phase: None,
            binding_validated: Some(binding),
            input_validated: Some(input),
        }
    }

    pub(crate) fn failed(code: &'static str, phase: &'static str) -> Self {
        Self {
            ok: false,
            error_code: Some(code),
            phase: Some(phase),
            binding_validated: None,
            input_validated: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<(&'static str, &'static str)> {
        self.error_code.zip(self.phase)
    }

    pub(crate) async fn publish(self) -> u8 {
        // Only fixed keys, booleans, error codes and phases enter this report.
        let Ok(mut bytes) = serde_json::to_vec(&self) else {
            return 1;
        };
        bytes.push(b'\n');
        let output = async {
            let mut stdout = tokio::io::stdout();
            stdout.write_all(&bytes).await?;
            stdout.flush().await
        };
        match tokio::time::timeout(Duration::from_secs(1), output).await {
            Ok(Ok(())) => u8::from(!self.ok),
            _ => {
                crate::audit::emit(
                    &serde_json::json!({"event":"error","code":"schema_output_failed","phase":"schema_output"}),
                );
                1
            }
        }
    }
}

pub(crate) fn bounded_json(value: &Value, depth: usize, remaining: &mut usize) -> bool {
    if depth > 32 || *remaining == 0 {
        return false;
    }
    *remaining -= 1;
    match value {
        Value::Array(values) => values.iter().all(|v| bounded_json(v, depth + 1, remaining)),
        Value::Object(values) => values
            .values()
            .all(|v| bounded_json(v, depth + 1, remaining)),
        _ => true,
    }
}

pub(crate) fn read_json(path: &Path, limit: usize) -> Result<Value, &'static str> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "schema_file_unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "schema_file_unavailable")?
        .is_file()
    {
        return Err("invalid_schema_file");
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "schema_file_unavailable")?;
    if bytes.len() > limit {
        return Err("schema_file_limit");
    }
    let value = crate::strict_json::parse(&bytes).map_err(|_| "invalid_schema_json")?;
    if !bounded_json(&value, 0, &mut 16_384) {
        return Err("schema_file_limit");
    }
    Ok(value)
}

fn digest(snapshot: &Snapshot) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(&(
        snapshot.schema,
        &snapshot.module,
        &snapshot.runtime,
        &snapshot.collection,
        &snapshot.content_sha256,
        &snapshot.contract,
        &snapshot.binding,
    ))
    .map_err(|_| "invalid_schema_snapshot")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn read_snapshot(path: &Path) -> Result<Snapshot, &'static str> {
    let snapshot: Snapshot = serde_json::from_value(read_json(path, SNAPSHOT_LIMIT)?)
        .map_err(|_| "invalid_schema_snapshot")?;
    if snapshot.schema != 1
        || !automation::valid_identity(&snapshot.runtime)
        || snapshot.content_sha256.len() != 64
        || !snapshot
            .content_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !module_schema::valid_fqcn(&snapshot.module)
        || snapshot.schema_sha256 != digest(&snapshot)?
    {
        return Err("invalid_schema_snapshot");
    }
    Ok(snapshot)
}

fn write_snapshot(path: &Path, snapshot: &Snapshot) -> Result<(), &'static str> {
    // Leave room for the fixed, identity-validated envelope and walk borrowed
    // values at their persisted depth. Never publish a snapshot we cannot read.
    let mut remaining = 16_384 - 64;
    if !bounded_json(&snapshot.contract, 1, &mut remaining)
        || snapshot
            .binding
            .as_ref()
            .is_some_and(|binding| !bounded_json(binding, 1, &mut remaining))
    {
        return Err("schema_file_limit");
    }
    write_document(path, snapshot)
}

pub(crate) fn write_document(path: &Path, document: &impl Serialize) -> Result<(), &'static str> {
    let mut bytes = serde_json::to_vec_pretty(document).map_err(|_| "invalid_schema_snapshot")?;
    bytes.push(b'\n');
    if bytes.len() > SNAPSHOT_LIMIT {
        return Err("schema_file_limit");
    }
    write_document_bytes(path, &bytes)
}

fn write_document_bytes(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".estus-schema-")
        .permissions(Permissions::from_mode(0o600))
        .tempfile_in(parent)
        .map_err(|_| "schema_output_failed")?;
    file.write_all(bytes).map_err(|_| "schema_output_failed")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "schema_output_failed")?;
    file.persist_noclobber(path)
        .map_err(|_| "schema_output_exists_or_failed")?;
    Ok(())
}

pub(crate) fn stopped(
    shutdown: &CancellationToken,
    deadline: tokio::time::Instant,
) -> Result<(), &'static str> {
    if shutdown.is_cancelled() {
        Err("cancelled")
    } else if tokio::time::Instant::now() >= deadline {
        Err("timeout")
    } else {
        Ok(())
    }
}

pub(crate) async fn run(config: Config, args: SchemaArgs, shutdown: CancellationToken) -> Report {
    let mut phase = "schema_validation";
    match perform(config, args, shutdown, &mut phase).await {
        Ok(report) => report,
        Err(code) => Report::failed(code, phase),
    }
}

async fn perform(
    config: Config,
    args: SchemaArgs,
    shutdown: CancellationToken,
    phase: &mut &'static str,
) -> Result<Report, &'static str> {
    let command = match args.command {
        SchemaCommand::ImportInventory { output } => {
            *phase = "runtime_import";
            let reference = config
                .automation_runtime()
                .map_err(|_| "runtime_unavailable")?;
            let duration = config
                .timeout(args.timeout_secs)
                .map_err(|_| "invalid_timeout")?;
            let deadline = tokio::time::Instant::now()
                .checked_add(duration)
                .ok_or("invalid_timeout")?;
            let inventory = automation::import_inventory(
                reference,
                RuntimeContext {
                    deadline,
                    ct: &shutdown,
                    shutdown: &shutdown,
                },
            )
            .await?;
            stopped(&shutdown, deadline)?;
            *phase = "schema_write";
            tokio::task::spawn_blocking(move || {
                let mut bytes =
                    serde_json::to_vec(&inventory).map_err(|_| "invalid_generic_inventory")?;
                bytes.push(b'\n');
                if bytes.len() as u64 > crate::automation::generic::INVENTORY_BYTES {
                    return Err("schema_file_limit");
                }
                write_document_bytes(&output, &bytes)
            })
            .await
            .map_err(|_| "schema_output_failed")??;
            return Ok(Report {
                ok: true,
                error_code: None,
                phase: None,
                binding_validated: None,
                input_validated: None,
            });
        }
        SchemaCommand::ImportRole(role) => {
            return Ok(crate::contracts::role_import::perform(
                config,
                crate::contracts::role_import::Command::Import(role),
                args.timeout_secs,
                shutdown,
            )
            .await);
        }
        SchemaCommand::VerifyRole(role) => {
            return Ok(crate::contracts::role_import::perform(
                config,
                crate::contracts::role_import::Command::Verify(role),
                args.timeout_secs,
                shutdown,
            )
            .await);
        }
        SchemaCommand::ImportPlaybook(playbook) => {
            return Ok(crate::contracts::playbook_import::perform(
                config,
                crate::contracts::playbook_import::Command::Import(playbook),
                args.timeout_secs,
                shutdown,
            )
            .await);
        }
        SchemaCommand::VerifyPlaybook(playbook) => {
            return Ok(crate::contracts::playbook_import::perform(
                config,
                crate::contracts::playbook_import::Command::Verify(playbook),
                args.timeout_secs,
                shutdown,
            )
            .await);
        }
        command => command,
    };
    let duration = config
        .timeout(args.timeout_secs)
        .map_err(|_| "invalid_timeout")?;
    let deadline = tokio::time::Instant::now()
        .checked_add(duration)
        .ok_or("invalid_timeout")?;
    let reference = config
        .automation_runtime()
        .map_err(|_| "runtime_unavailable")?;
    // Join filesystem work even when interrupted: dropping blocking I/O is not cancellation.
    *phase = "schema_preparation";
    let command = tokio::task::spawn_blocking(move || -> Result<_, &'static str> {
        match command {
            SchemaCommand::Import {
                module,
                output,
                overlay,
            } => {
                if !module_schema::valid_fqcn(&module) {
                    return Err("invalid_module_name");
                }
                let binding = overlay
                    .map(|path| read_json(&path, INPUT_LIMIT))
                    .transpose()?;
                Ok((module, Some(output), None, binding, None))
            }
            SchemaCommand::Verify {
                snapshot,
                overlay,
                input,
            } => {
                let snapshot = read_snapshot(&snapshot)?;
                let binding = overlay
                    .map(|path| read_json(&path, INPUT_LIMIT))
                    .transpose()?;
                let input = input
                    .map(|path| read_json(&path, INPUT_LIMIT))
                    .transpose()?;
                Ok((
                    snapshot.module.clone(),
                    None,
                    Some(snapshot),
                    binding,
                    input,
                ))
            }
            SchemaCommand::ImportInventory { .. }
            | SchemaCommand::ImportRole(_)
            | SchemaCommand::VerifyRole(_)
            | SchemaCommand::ImportPlaybook(_)
            | SchemaCommand::VerifyPlaybook(_) => {
                unreachable!("workflow commands are dispatched before module preparation")
            }
        }
    })
    .await
    .map_err(|_| "schema_file_unavailable")??;
    let (module, output, previous, binding, input) = command;
    stopped(&shutdown, deadline)?;
    *phase = "runtime_import";
    let observed = automation::import_module(
        reference,
        &module,
        RuntimeContext {
            deadline,
            ct: &shutdown,
            shutdown: &shutdown,
        },
    )
    .await?;
    stopped(&shutdown, deadline)?;
    *phase = "schema_conversion";
    let contract = module_schema::import_document(&observed.document)?;
    *phase = "schema_verification";
    if let Some(previous) = &previous
        && (previous.runtime != observed.identity
            || previous.collection != observed.collection
            || previous.content_sha256 != observed.content_sha256
            || previous.contract != contract)
    {
        return Err("schema_drift");
    }
    let binding = binding.or_else(|| previous.and_then(|p| p.binding));
    if let Some(overlay) = &binding {
        *phase = "binding_validation";
        let compiled = module_schema::compile_binding(&contract, overlay)?;
        if let Some(input) = &input {
            *phase = "input_validation";
            compiled.prepare(input)?;
        }
    } else if input.is_some() {
        *phase = "binding_validation";
        return Err("schema_binding_required");
    }
    let report = Report {
        ok: true,
        error_code: None,
        phase: None,
        binding_validated: Some(binding.is_some()),
        input_validated: Some(input.is_some()),
    };
    if let Some(output) = output {
        *phase = "schema_write";
        let mut snapshot = Snapshot {
            schema: 1,
            module,
            runtime: observed.identity,
            collection: observed.collection,
            content_sha256: observed.content_sha256,
            schema_sha256: String::new(),
            contract,
            binding,
        };
        snapshot.schema_sha256 = digest(&snapshot)?;
        stopped(&shutdown, deadline)?;
        tokio::task::spawn_blocking(move || write_snapshot(&output, &snapshot))
            .await
            .map_err(|_| "schema_output_failed")??;
    }
    Ok(report)
}

pub(crate) async fn author_module(
    runtime: Option<PathBuf>,
    module: &str,
    overlay: &Value,
    output: &Path,
    context: RuntimeContext<'_>,
) -> Result<(), &'static str> {
    let observed = automation::import_module(runtime, module, context).await?;
    let contract = module_schema::import_document(&observed.document)?;
    module_schema::compile_binding(&contract, overlay)?;
    let mut snapshot = Snapshot {
        schema: 1,
        module: module.to_owned(),
        runtime: observed.identity,
        collection: observed.collection,
        content_sha256: observed.content_sha256,
        contract,
        schema_sha256: String::new(),
        binding: Some(overlay.clone()),
    };
    snapshot.schema_sha256 = digest(&snapshot)?;
    let output = output.to_path_buf();
    tokio::task::spawn_blocking(move || write_snapshot(&output, &snapshot))
        .await
        .map_err(|_| "schema_output_failed")?
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_and_nonregular_or_oversized_authoring_inputs_reject() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("input.json");
        for text in [
            r#"{"state":"present","state":"absent"}"#,
            r#"{"x":{"a":1,"a":2}}"#,
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(read_json(&path, INPUT_LIMIT), Err("invalid_schema_json"));
        }
        std::fs::write(&path, vec![b' '; INPUT_LIMIT + 1]).unwrap();
        assert_eq!(read_json(&path, INPUT_LIMIT), Err("schema_file_limit"));
        assert!(read_json(root.path(), INPUT_LIMIT).is_err());
    }
}
