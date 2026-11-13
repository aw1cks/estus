//! Offline role authoring. Snapshots approve metadata, never publish or execute a role.
use std::path::{Path, PathBuf};

use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::{
    automation::{self, RuntimeCollection, RuntimeContext, RuntimeIdentity},
    config::Config,
    module_schema, role_schema,
    schema_import::{Report, bounded_json, read_json, stopped, write_document},
};

const SNAPSHOT_LIMIT: usize = 1_048_576;
const INPUT_LIMIT: usize = 65_536;

#[derive(Args)]
pub(crate) struct ImportArgs {
    role: String,
    #[arg(long, default_value = "main")]
    entry_point: String,
    /// Exact standalone role directory; collection roles use the selected runtime.
    #[arg(long)]
    role_path: Option<PathBuf>,
    #[arg(long)]
    output: PathBuf,
    /// Explicit closed JSON Schema, required only for a role without argument specs.
    #[arg(long = "schema")]
    explicit_schema: Option<PathBuf>,
    /// Reviewed JSON input_schema, fixed_args and input_map.
    #[arg(long)]
    overlay: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    snapshot: PathBuf,
    /// Repeat the exact standalone source reference; no ambient role lookup.
    #[arg(long)]
    role_path: Option<PathBuf>,
    #[arg(long)]
    overlay: Option<PathBuf>,
    /// Validate request JSON without executing or printing it.
    #[arg(long)]
    input: Option<PathBuf>,
}

pub(crate) enum Command {
    Import(ImportArgs),
    Verify(VerifyArgs),
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    Collection,
    Directory,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u32,
    role: String,
    entry_point: String,
    source: Source,
    runtime: RuntimeIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<RuntimeCollection>,
    content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    explicit_schema: Option<Value>,
    contract: Value,
    schema_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<Value>,
}

fn digest(snapshot: &Snapshot) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(&(
        snapshot.schema,
        &snapshot.role,
        &snapshot.entry_point,
        snapshot.source,
        &snapshot.runtime,
        &snapshot.collection,
        &snapshot.content_sha256,
        &snapshot.explicit_schema,
        &snapshot.contract,
        &snapshot.binding,
    ))
    .map_err(|_| "invalid_schema_snapshot")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_snapshot(path: &Path) -> Result<Snapshot, &'static str> {
    let snapshot: Snapshot = serde_json::from_value(read_json(path, SNAPSHOT_LIMIT)?)
        .map_err(|_| "invalid_schema_snapshot")?;
    if snapshot.schema != 1
        || !role_schema::valid_role(&snapshot.role)
        || !role_schema::valid_entry_point(&snapshot.entry_point)
        || (snapshot.source == Source::Collection)
            != role_schema::is_collection_role(&snapshot.role)
        || !automation::valid_identity(&snapshot.runtime)
        || !hash(&snapshot.content_sha256)
        || snapshot
            .collection
            .as_ref()
            .is_some_and(|c| !automation::valid_collection(c))
        || (snapshot.source == Source::Collection) != snapshot.collection.is_some()
        || snapshot.schema_sha256 != digest(&snapshot)?
    {
        return Err("invalid_schema_snapshot");
    }
    Ok(snapshot)
}

fn source(role: &str, entry_point: &str, path: Option<&Path>) -> Result<Source, &'static str> {
    if !role_schema::valid_role(role) {
        return Err("invalid_role_name");
    }
    if !role_schema::valid_entry_point(entry_point) {
        return Err("invalid_role_entry_point");
    }
    match (role_schema::is_collection_role(role), path) {
        (true, None) => Ok(Source::Collection),
        (true, Some(_)) => Err("invalid_role_source"),
        (false, None) => Err("role_source_required"),
        (false, Some(path)) => {
            let text = path.to_str().ok_or("invalid_role_source")?;
            if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
                return Err("invalid_role_source");
            }
            Ok(Source::Directory)
        }
    }
}

struct Previous {
    runtime: RuntimeIdentity,
    collection: Option<RuntimeCollection>,
    content_sha256: String,
    contract: Value,
}

struct Prepared {
    role: String,
    entry_point: String,
    source: Source,
    role_path: Option<PathBuf>,
    output: Option<PathBuf>,
    previous: Option<Previous>,
    explicit_schema: Option<Value>,
    binding: Option<Value>,
    input: Option<Value>,
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

fn prepare(command: Command) -> Result<Prepared, &'static str> {
    match command {
        Command::Import(args) => {
            let source = source(&args.role, &args.entry_point, args.role_path.as_deref())?;
            Ok(Prepared {
                role: args.role,
                entry_point: args.entry_point,
                source,
                role_path: args.role_path,
                output: Some(output_path(&args.output)?),
                previous: None,
                explicit_schema: args
                    .explicit_schema
                    .map(|p| read_json(&p, INPUT_LIMIT))
                    .transpose()?,
                binding: args
                    .overlay
                    .map(|p| read_json(&p, INPUT_LIMIT))
                    .transpose()?,
                input: None,
            })
        }
        Command::Verify(args) => {
            let previous = read_snapshot(&args.snapshot)?;
            let source = source(
                &previous.role,
                &previous.entry_point,
                args.role_path.as_deref(),
            )?;
            let binding = match args.overlay {
                Some(path) => Some(read_json(&path, INPUT_LIMIT)?),
                None => previous.binding,
            };
            Ok(Prepared {
                role: previous.role,
                entry_point: previous.entry_point,
                source,
                role_path: args.role_path,
                output: None,
                explicit_schema: previous.explicit_schema,
                previous: Some(Previous {
                    runtime: previous.runtime,
                    collection: previous.collection,
                    content_sha256: previous.content_sha256,
                    contract: previous.contract,
                }),
                binding,
                input: args.input.map(|p| read_json(&p, INPUT_LIMIT)).transpose()?,
            })
        }
    }
}

pub(crate) async fn perform(
    config: Config,
    command: Command,
    timeout_secs: Option<u64>,
    shutdown: CancellationToken,
) -> Result<Report, &'static str> {
    let deadline = tokio::time::Instant::now()
        .checked_add(
            config
                .timeout(timeout_secs)
                .map_err(|_| "invalid_timeout")?,
        )
        .ok_or("invalid_timeout")?;
    let reference = config
        .automation_runtime()
        .map_err(|_| "runtime_unavailable")?;
    // Started file work is joined even on interruption, like module authoring.
    let prepared = tokio::task::spawn_blocking(move || prepare(command))
        .await
        .map_err(|_| "schema_file_unavailable")??;
    stopped(&shutdown, deadline)?;
    let observed = automation::import_role(
        reference,
        &prepared.role,
        &prepared.entry_point,
        prepared.role_path.as_deref(),
        prepared.output.as_deref(),
        RuntimeContext {
            deadline,
            ct: &shutdown,
            shutdown: &shutdown,
        },
    )
    .await?;
    stopped(&shutdown, deadline)?;
    let contract = role_schema::import_document(
        &observed.document,
        &prepared.entry_point,
        prepared.explicit_schema.as_ref(),
    )?;
    if let Some(previous) = &prepared.previous
        && (previous.runtime != observed.identity
            || previous.collection != observed.collection
            || previous.content_sha256 != observed.content_sha256
            || previous.contract != contract)
    {
        return Err("schema_drift");
    }
    if let Some(binding) = &prepared.binding {
        let compiled = module_schema::compile_binding(&contract, binding)?;
        if let Some(input) = &prepared.input {
            compiled.prepare(input)?;
        }
    } else if prepared.input.is_some() {
        return Err("schema_binding_required");
    }
    let report = Report::validated(prepared.binding.is_some(), prepared.input.is_some());
    if let Some(output) = prepared.output {
        let mut snapshot = Snapshot {
            schema: 1,
            role: prepared.role,
            entry_point: prepared.entry_point,
            source: prepared.source,
            runtime: observed.identity,
            collection: observed.collection,
            content_sha256: observed.content_sha256,
            explicit_schema: prepared.explicit_schema,
            contract,
            schema_sha256: String::new(),
            binding: prepared.binding,
        };
        snapshot.schema_sha256 = digest(&snapshot)?;
        // Check all borrowed subtrees at their persisted depth before writing.
        let mut remaining = 16_384 - 64;
        for value in [
            Some(&snapshot.contract),
            snapshot.explicit_schema.as_ref(),
            snapshot.binding.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !bounded_json(value, 1, &mut remaining) {
                return Err("schema_file_limit");
            }
        }
        stopped(&shutdown, deadline)?;
        tokio::task::spawn_blocking(move || write_document(&output, &snapshot))
            .await
            .map_err(|_| "schema_output_failed")??;
    }
    Ok(report)
}
