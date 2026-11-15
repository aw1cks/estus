//! Reviewed role contracts for offline authoring and fixed execution activation.
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

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
    /// Standalone source role. Its complete parent is copied into a reviewed bundle.
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
    #[arg(skip)]
    reviewed_bundle: bool,
}

impl ImportArgs {
    pub(crate) fn reviewed(
        role: String,
        role_path: PathBuf,
        output: PathBuf,
        overlay: PathBuf,
    ) -> Self {
        Self {
            role,
            entry_point: "main".into(),
            role_path: Some(role_path),
            output,
            explicit_schema: None,
            overlay: Some(overlay),
            reviewed_bundle: true,
        }
    }
}

#[derive(Args)]
pub(crate) struct VerifyArgs {
    snapshot: PathBuf,
    /// Exact role inside the persisted reviewed bundle, not the original authoring source.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_root: Option<PathBuf>,
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
        &snapshot.bundle_root,
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
    let value = read_json(path, SNAPSHOT_LIMIT)?;
    if value.get("schema").and_then(Value::as_u64) != Some(2) {
        return Err("role_snapshot_reimport_required");
    }
    let snapshot: Snapshot =
        serde_json::from_value(value).map_err(|_| "invalid_schema_snapshot")?;
    if !role_schema::valid_role(&snapshot.role)
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
        || (snapshot.source == Source::Directory) != snapshot.bundle_root.is_some()
        || snapshot.bundle_root.as_ref().is_some_and(|root| {
            !root.is_absolute()
                || root.to_str().is_none_or(|s| {
                    s.len() > 4096
                        || s.contains('\0')
                        || [":", "$", "{{", "{%", "{#"]
                            .iter()
                            .any(|token| s.contains(token))
                })
        })
        || snapshot.schema_sha256 != digest(&snapshot)?
    {
        return Err("invalid_schema_snapshot");
    }
    Ok(snapshot)
}

/// Reviewed role metadata; source selection is snapshot-owned and never refreshed.
pub(crate) struct ReviewedRole {
    pub role: String,
    pub entry_point: String,
    pub runtime: RuntimeIdentity,
    pub collection: Option<RuntimeCollection>,
    pub content_sha256: String,
    pub bundle_root: Option<PathBuf>,
    pub contract: Value,
    pub binding: Option<Value>,
    source: Source,
    explicit_schema: Option<Value>,
}

pub(crate) fn load_reviewed(path: &Path) -> Result<ReviewedRole, &'static str> {
    let snapshot = read_snapshot(path)?;
    Ok(ReviewedRole {
        role: snapshot.role,
        entry_point: snapshot.entry_point,
        runtime: snapshot.runtime,
        collection: snapshot.collection,
        content_sha256: snapshot.content_sha256,
        bundle_root: snapshot.bundle_root,
        contract: snapshot.contract,
        binding: snapshot.binding,
        source: snapshot.source,
        explicit_schema: snapshot.explicit_schema,
    })
}

pub(crate) async fn verify_reviewed(
    reviewed: &ReviewedRole,
    role_path: Option<&Path>,
    runtime: Option<PathBuf>,
    context: RuntimeContext<'_>,
) -> Result<(), &'static str> {
    if source(&reviewed.role, &reviewed.entry_point, role_path)? != reviewed.source {
        return Err("invalid_role_source");
    }
    let approved_path = reviewed
        .bundle_root
        .as_ref()
        .map(|root| root.join(&reviewed.role));
    if role_path != approved_path.as_deref() {
        return Err("role_bundle_source_mismatch");
    }
    let observed = automation::import_role(
        runtime,
        &reviewed.role,
        &reviewed.entry_point,
        approved_path.as_deref(),
        None,
        context,
    )
    .await?;
    let contract = role_schema::import_document(
        &observed.document,
        &reviewed.entry_point,
        reviewed.explicit_schema.as_ref(),
    )?;
    if reviewed.runtime != observed.identity
        || reviewed.collection != observed.collection
        || reviewed.content_sha256 != observed.content_sha256
        || reviewed.contract != contract
    {
        return Err("schema_drift");
    }
    Ok(())
}

fn role_variable(name: &str) -> bool {
    !name.starts_with("estus_")
        && !name.starts_with("ansible_")
        && !name.starts_with("become")
        && !name.starts_with("inventory_")
        && !name.starts_with("callback_")
        && !matches!(
            name,
            "mcp_result"
                | "host"
                | "hosts"
                | "hostvars"
                | "groups"
                | "group_names"
                | "inventory"
                | "connection"
                | "remote_user"
                | "port"
                | "password"
                | "private_key_file"
                | "ssh_args"
                | "ssh_common_args"
                | "ssh_extra_args"
                | "environment"
                | "executable"
                | "interpreter"
                | "runtime"
                | "collections"
                | "roles"
                | "role"
                | "role_name"
                | "role_path"
                | "entry_point"
                | "tasks"
                | "tasks_from"
                | "handlers_from"
                | "vars_from"
                | "defaults_from"
                | "tags"
                | "skip_tags"
                | "start_at_task"
                | "check_mode"
                | "diff"
                | "delegate_to"
                | "delegate_facts"
                | "run_once"
                | "serial"
                | "strategy"
                | "execution"
                | "authority"
                | "program"
                | "command"
                | "shell"
                | "sudo"
                | "action"
                | "local_action"
                | "module_defaults"
                | "module"
                | "module_name"
                | "async"
                | "poll"
                | "until"
                | "retries"
                | "delay"
                | "timeout"
                | "when"
                | "loop"
                | "loop_control"
                | "with_items"
                | "block"
                | "rescue"
                | "always"
                | "ignore_errors"
                | "ignore_unreachable"
                | "any_errors_fatal"
                | "failed_when"
                | "changed_when"
                | "register"
                | "vars"
                | "vars_files"
                | "vars_prompt"
                | "include_role"
                | "import_role"
                | "include_tasks"
                | "import_tasks"
                | "playbook_dir"
                | "inventory_dir"
                | "inventory_file"
                | "inventory_hostname"
                | "inventory_hostname_short"
                | "omit"
                | "role_names"
                | "play_hosts"
                | "gather_facts"
                | "no_log"
                | "notify"
                | "listen"
                | "allow_duplicates"
                | "public"
                | "rolespec_validate"
        )
}

/// Add role variable restrictions to the existing shared overlay validator.
pub(crate) fn validate_overlay(overlay: &Value) -> Result<(), &'static str> {
    module_schema::validate_overlay(overlay)?;
    for field in ["fixed_args", "input_map"] {
        if overlay[field]
            .as_object()
            .is_some_and(|values| values.keys().any(|name| !role_variable(name)))
        {
            return Err("invalid_binding_schema");
        }
    }
    Ok(())
}

pub(crate) fn compile_binding(
    contract: &Value,
    overlay: &Value,
) -> Result<module_schema::CompiledModuleBinding, &'static str> {
    validate_overlay(overlay)?;
    // Aliases must not turn a harmless-looking configured name into a control.
    for field in ["fixed_args", "input_map"] {
        for name in overlay[field]
            .as_object()
            .ok_or("invalid_binding_schema")?
            .keys()
        {
            let canonical = contract["aliases"]["aliases"][name]
                .as_str()
                .unwrap_or(name);
            if !role_variable(canonical) {
                return Err("invalid_binding_schema");
            }
        }
    }
    module_schema::compile_binding(contract, overlay)
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
    bundle: Option<RoleBundle>,
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
    if output.to_str().is_none_or(|value| {
        value.len() > 4096
            || value.contains('\0')
            || [":", "$", "{{", "{%", "{#"]
                .iter()
                .any(|token| value.contains(token))
    }) {
        return Err("schema_output_failed");
    }
    Ok(output)
}

/// An authoring-only copy. Failed imports remove only the directory they created.
struct RoleBundle {
    root: PathBuf,
    published: bool,
}

impl Drop for RoleBundle {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn bundle_root(snapshot: &Path) -> PathBuf {
    snapshot.with_extension("roles")
}
pub(crate) fn author_bundle(
    role: &str,
    source: &Path,
    snapshot: &Path,
) -> Result<PathBuf, &'static str> {
    let mut bundle = copy_bundle(role, source, snapshot)?;
    bundle.published = true;
    Ok(bundle.root.clone())
}

fn copy_bundle(role: &str, source: &Path, output: &Path) -> Result<RoleBundle, &'static str> {
    let selected = fs::canonicalize(source).map_err(|_| "invalid_role_source")?;
    let parent = selected.parent().ok_or("invalid_role_source")?;
    if selected.file_name().and_then(|name| name.to_str()) != Some(role)
        || !selected.is_dir()
        || parent.to_str().is_none_or(|s| {
            [":", "$", "{{", "{%", "{#"]
                .iter()
                .any(|token| s.contains(token))
        })
    {
        return Err("invalid_role_source");
    }
    if output.starts_with(parent) {
        return Err("role_output_inside_source");
    }
    let root = bundle_root(output);
    DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|_| "role_bundle_output_exists_or_failed")?;
    let bundle = RoleBundle {
        root,
        published: false,
    };
    let mut entries = 0usize;
    let mut bytes = 0u64;
    copy_role_tree(parent, &bundle.root, 0, &mut entries, &mut bytes)?;
    Ok(bundle)
}

fn copy_role_tree(
    source: &Path,
    destination: &Path,
    depth: usize,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), &'static str> {
    if depth > 32 {
        return Err("role_content_limit");
    }
    for entry in fs::read_dir(source).map_err(|_| "role_content_failed")? {
        let entry = entry.map_err(|_| "role_content_failed")?;
        *entries += 1;
        if *entries > 50_000 {
            return Err("role_content_limit");
        }
        let kind = entry.file_type().map_err(|_| "role_content_failed")?;
        let target = destination.join(entry.file_name());
        if kind.is_symlink() {
            return Err("role_content_symlink");
        }
        if kind.is_dir() {
            DirBuilder::new()
                .mode(0o700)
                .create(&target)
                .map_err(|_| "role_bundle_output_failed")?;
            copy_role_tree(&entry.path(), &target, depth + 1, entries, bytes)?;
        } else if kind.is_file() {
            let mut input = OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
                .open(entry.path())
                .map_err(|_| "role_content_failed")?;
            let metadata = input.metadata().map_err(|_| "role_content_failed")?;
            if !metadata.is_file() {
                return Err("role_content_failed");
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600 | (metadata.permissions().mode() & 0o100))
                .open(target)
                .map_err(|_| "role_bundle_output_failed")?;
            let mut size = 0u64;
            let mut buffer = [0u8; 65_536];
            loop {
                let read = input.read(&mut buffer).map_err(|_| "role_content_failed")?;
                if read == 0 {
                    break;
                }
                size += read as u64;
                *bytes += read as u64;
                if size > 32 * 1024 * 1024 || *bytes > 256 * 1024 * 1024 {
                    return Err("role_content_limit");
                }
                output
                    .write_all(&buffer[..read])
                    .map_err(|_| "role_bundle_output_failed")?;
            }
        } else {
            return Err("role_content_failed");
        }
    }
    Ok(())
}

fn prepare(command: Command) -> Result<Prepared, &'static str> {
    match command {
        Command::Import(args) => {
            let source = source(&args.role, &args.entry_point, args.role_path.as_deref())?;
            let output = output_path(&args.output)?;
            if fs::symlink_metadata(&output).is_ok() {
                return Err("schema_output_exists_or_failed");
            }
            let bundle = if args.reviewed_bundle {
                None
            } else {
                args.role_path
                    .as_deref()
                    .map(|path| copy_bundle(&args.role, path, &output))
                    .transpose()?
            };
            let role_path = match &bundle {
                Some(bundle) => Some(bundle.root.join(&args.role)),
                None => args.role_path,
            };
            Ok(Prepared {
                bundle,
                role: args.role,
                entry_point: args.entry_point,
                source,
                role_path,
                output: Some(output),
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
            let approved_path = previous
                .bundle_root
                .as_ref()
                .map(|root| root.join(&previous.role));
            if args.role_path != approved_path {
                return Err("role_bundle_source_mismatch");
            }
            Ok(Prepared {
                bundle: None,
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
) -> Report {
    let reference = match config.automation_runtime() {
        Ok(reference) => reference,
        Err(_) => return Report::failed("runtime_unavailable", "runtime_selection"),
    };
    perform_with_reference(&config, command, timeout_secs, shutdown, reference).await
}

pub(crate) async fn perform_with_reference(
    config: &Config,
    command: Command,
    timeout_secs: Option<u64>,
    shutdown: CancellationToken,
    reference: Option<PathBuf>,
) -> Report {
    let mut phase = "schema_validation";
    match perform_tracked(
        config,
        command,
        timeout_secs,
        shutdown,
        reference,
        &mut phase,
    )
    .await
    {
        Ok(report) => report,
        Err(code) => Report::failed(code, phase),
    }
}

// CLI and catalog callers receive the same retained failure phase.
async fn perform_tracked(
    config: &Config,
    command: Command,
    timeout_secs: Option<u64>,
    shutdown: CancellationToken,
    reference: Option<PathBuf>,
    phase: &mut &'static str,
) -> Result<Report, &'static str> {
    let deadline = tokio::time::Instant::now()
        .checked_add(
            config
                .timeout(timeout_secs)
                .map_err(|_| "invalid_timeout")?,
        )
        .ok_or("invalid_timeout")?;
    // Started file work is joined even on interruption, like module authoring.
    *phase = "schema_preparation";
    let mut prepared = tokio::task::spawn_blocking(move || prepare(command))
        .await
        .map_err(|_| "schema_file_unavailable")??;
    stopped(&shutdown, deadline)?;
    *phase = "runtime_import";
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
    *phase = "schema_conversion";
    let contract = role_schema::import_document(
        &observed.document,
        &prepared.entry_point,
        prepared.explicit_schema.as_ref(),
    )?;
    *phase = "schema_verification";
    if let Some(previous) = &prepared.previous
        && (previous.runtime != observed.identity
            || previous.collection != observed.collection
            || previous.content_sha256 != observed.content_sha256
            || previous.contract != contract)
    {
        return Err("schema_drift");
    }
    if let Some(binding) = &prepared.binding {
        *phase = "binding_validation";
        let compiled = compile_binding(&contract, binding)?;
        if let Some(input) = &prepared.input {
            *phase = "input_validation";
            compiled.prepare(input)?;
        }
    } else if prepared.input.is_some() {
        *phase = "binding_validation";
        return Err("schema_binding_required");
    }
    let report = Report::validated(prepared.binding.is_some(), prepared.input.is_some());
    if let Some(output) = prepared.output {
        *phase = "schema_write";
        let mut snapshot = Snapshot {
            schema: 2,
            role: prepared.role,
            entry_point: prepared.entry_point,
            source: prepared.source,
            runtime: observed.identity,
            collection: observed.collection,
            bundle_root: prepared
                .role_path
                .as_ref()
                .and_then(|path| path.parent())
                .map(Path::to_path_buf),
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
        if let Some(bundle) = &mut prepared.bundle {
            bundle.published = true;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_role_alias_cannot_restore_a_reserved_control() {
        let overlay = json!({
            "input_schema": {"type":"object", "additionalProperties":false,
                "required":[], "properties":{}},
            "fixed_args": {"approved_name":"literal"},
            "input_map": {}
        });
        validate_overlay(&overlay).unwrap();
        let contract = json!({"aliases":{"aliases":{"approved_name":"mcp_result"}}});
        assert_eq!(
            compile_binding(&contract, &overlay).err(),
            Some("invalid_binding_schema")
        );
    }

    #[test]
    fn role_variable_policy_does_not_interpret_nested_domain_data() {
        let overlay = json!({
            "input_schema": {"type":"object", "additionalProperties":false,
                "required":[], "properties":{}},
            "fixed_args": {"configuration":{
                "connection":"{{ lookup('env', 'PRIVATE') }}",
                "mcp_result":{"estus_arguments":"ordinary nested data"}
            }},
            "input_map": {}
        });
        validate_overlay(&overlay).unwrap();
    }

    #[test]
    fn old_role_approval_requires_explicit_reimport() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot = directory.path().join("reviewed.json");
        fs::write(&snapshot, br#"{"schema":1}"#).unwrap();
        assert_eq!(
            read_snapshot(&snapshot).err(),
            Some("role_snapshot_reimport_required")
        );
    }

    #[test]
    fn authoring_copies_siblings_once_and_failure_removes_only_owned_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("sources");
        fs::create_dir_all(source.join("entry/tasks")).unwrap();
        fs::create_dir_all(source.join("dependency/tasks")).unwrap();
        fs::write(source.join("entry/tasks/main.yml"), "[]\n").unwrap();
        fs::write(
            source.join("dependency/tasks/main.yml"),
            "[]\n# dependency\n",
        )
        .unwrap();
        let output = directory.path().join("reviewed.json");
        let bundle = copy_bundle("entry", &source.join("entry"), &output).unwrap();
        assert_eq!(
            fs::read(bundle.root.join("dependency/tasks/main.yml")).unwrap(),
            b"[]\n# dependency\n",
        );
        fs::write(source.join("dependency/tasks/main.yml"), "changed\n").unwrap();
        assert_eq!(
            fs::read(bundle.root.join("dependency/tasks/main.yml")).unwrap(),
            b"[]\n# dependency\n",
        );
        assert_eq!(
            copy_bundle("entry", &source.join("entry"), &output).err(),
            Some("role_bundle_output_exists_or_failed"),
        );
        drop(bundle);
        assert!(!bundle_root(&output).exists());
        std::os::unix::fs::symlink(
            source.join("entry/tasks/main.yml"),
            source.join("dependency/linked.yml"),
        )
        .unwrap();
        assert_eq!(
            copy_bundle("entry", &source.join("entry"), &output).err(),
            Some("role_content_symlink"),
        );
        assert!(!bundle_root(&output).exists());
        assert!(source.join("entry/tasks/main.yml").exists());
    }
}
