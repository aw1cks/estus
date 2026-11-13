//! Explicit, offline authoring commands. Importing never registers or executes a tool.
use std::fs::{OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::automation::{self, RuntimeCollection, RuntimeContext, RuntimeIdentity};
use crate::config::Config;
use crate::module_schema;

const SNAPSHOT_LIMIT: usize = 1_048_576;
#[cfg(test)]
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
    /// Import installed public ansible-doc metadata into a new reviewable snapshot.
    Import {
        module: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Detect runtime/content/schema drift and validate an optional binding/input.
    Verify { snapshot: PathBuf },
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

#[derive(Serialize)]
pub(crate) struct Report {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_validated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_validated: Option<bool>,
}

impl Report {
    fn failed(code: &'static str) -> Self {
        Self {
            ok: false,
            error_code: Some(code),
            binding_validated: None,
            input_validated: None,
        }
    }

    pub(crate) async fn publish(self) -> u8 {
        // Only fixed keys, booleans and fixed error codes enter this report.
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
                    &serde_json::json!({"event":"error","code":"schema_output_failed"}),
                );
                1
            }
        }
    }
}

// serde_json::Value normally accepts duplicate keys. Authoring inputs must not
// acquire different meanings when read by another JSON implementation.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn bounded_json(value: &Value, depth: usize, remaining: &mut usize) -> bool {
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

fn read_json(path: &Path, limit: usize) -> Result<Value, &'static str> {
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
    let Unique(value) = serde_json::from_slice(&bytes).map_err(|_| "invalid_schema_json")?;
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
    let mut bytes = serde_json::to_vec_pretty(snapshot).map_err(|_| "invalid_schema_snapshot")?;
    bytes.push(b'\n');
    if bytes.len() > SNAPSHOT_LIMIT {
        return Err("schema_file_limit");
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::Builder::new()
        .prefix(".ssh-mcp-schema-")
        .permissions(Permissions::from_mode(0o600))
        .tempfile_in(parent)
        .map_err(|_| "schema_output_failed")?;
    file.write_all(&bytes).map_err(|_| "schema_output_failed")?;
    file.as_file()
        .sync_all()
        .map_err(|_| "schema_output_failed")?;
    file.persist_noclobber(path)
        .map_err(|_| "schema_output_exists_or_failed")?;
    Ok(())
}

fn stopped(
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
    match perform(config, args, shutdown).await {
        Ok(report) => report,
        Err(code) => Report::failed(code),
    }
}

async fn perform(
    config: Config,
    args: SchemaArgs,
    shutdown: CancellationToken,
) -> Result<Report, &'static str> {
    let duration = config
        .timeout(args.timeout_secs)
        .map_err(|_| "invalid_timeout")?;
    let deadline = tokio::time::Instant::now()
        .checked_add(duration)
        .ok_or("invalid_timeout")?;
    let reference = config
        .automation_runtime()
        .map_err(|_| "runtime_unavailable")?;
    let (module, output, previous) =
        tokio::task::spawn_blocking(move || -> Result<_, &'static str> {
            match args.command {
                SchemaCommand::Import { module, output } => {
                    if !module_schema::valid_fqcn(&module) {
                        return Err("invalid_module_name");
                    }
                    Ok((module, Some(output), None))
                }
                SchemaCommand::Verify { snapshot } => {
                    let snapshot = read_snapshot(&snapshot)?;
                    if snapshot.binding.is_some() {
                        return Err("invalid_schema_snapshot");
                    }
                    Ok((snapshot.module.clone(), None, Some(snapshot)))
                }
            }
        })
        .await
        .map_err(|_| "schema_file_unavailable")??;
    stopped(&shutdown, deadline)?;
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
    let contract = module_schema::import_document(&observed.document)?;
    if let Some(previous) = &previous
        && (previous.runtime != observed.identity
            || previous.collection != observed.collection
            || previous.content_sha256 != observed.content_sha256
            || previous.contract != contract)
    {
        return Err("schema_drift");
    }
    if let Some(output) = output {
        let mut snapshot = Snapshot {
            schema: 1,
            module,
            runtime: observed.identity,
            collection: observed.collection,
            content_sha256: observed.content_sha256,
            contract,
            schema_sha256: String::new(),
            binding: None,
        };
        snapshot.schema_sha256 = digest(&snapshot)?;
        stopped(&shutdown, deadline)?;
        tokio::task::spawn_blocking(move || write_snapshot(&output, &snapshot))
            .await
            .map_err(|_| "schema_output_failed")??;
    }
    Ok(Report {
        ok: true,
        error_code: None,
        binding_validated: None,
        input_validated: None,
    })
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
