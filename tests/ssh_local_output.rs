//! Command output retention: ranges, permissions, quotas and argv/native routes.
#[path = "support/ssh_local.rs"]
#[allow(dead_code)]
mod sshl;
#[path = "support/core.rs"]
#[allow(dead_code)]
// Shared support items used by other suites are inert here.
mod support;
use sshl::*;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use indoc::formatdoc;
use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use support::Fixture;
use support::WireServer;
use support::assert_masters_gone;
use support::masters;
use support::quote;
use tokio::time::sleep;
use tokio::time::timeout;

// Output artifacts are observed only through public receipts/reads and the
// test-owned TMPDIR, never through an implementation-specific pathname.
fn output_entries(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?)
}

fn output_handle(data: &Value) -> Result<String> {
    let receipt = &data["output"];
    ensure!(receipt["status"] == "ready", "retention receipt: {receipt}");
    let handle = receipt["handle"].as_str().context("output handle")?;
    ensure!(
        handle.len() == 32
            && handle
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "handle is not an opaque lowercase capability"
    );
    Ok(handle.to_owned())
}

async fn output_range(
    server: &mut WireServer,
    id: u64,
    handle: &str,
    stream: &str,
    (offset, limit): (u64, u64),
    (bytes, eof): (&[u8], bool),
    encoding: &str,
) -> Result<()> {
    let reply = script_wire_call(
        server,
        id,
        "inspect_output",
        json!({
            "handle":handle,"stream":stream,"offset":offset,"max_bytes":limit,"encoding":encoding,
        }),
    )
    .await?;
    let content = if encoding == "base64" {
        STANDARD.encode(bytes)
    } else {
        std::str::from_utf8(bytes)?.to_owned()
    };
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":content,"encoding":encoding,"bytes_read":bytes.len(),
                "next_offset":offset + bytes.len() as u64,"eof":eof,
                "content_sha256":hex::encode(Sha256::digest(bytes)),
            }),
        "retained range mismatch: {reply}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_exact_ranges_permissions_and_local_reads() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let artifacts = fixture.root.path().join("output-tmp");
        let runtime = fixture.root.path().join("output-runtime");
        fs::create_dir(&artifacts)?;
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        let config = fixture.root.path().join("output.toml");
        fs::write(&config, format!(
            "capabilities = {{ named = true, file_read = true, file_write = true, exec = true, sudo = true }}\n[ssh]\nconfig_file = {}\n[limits]\nmax_output_bytes = 4\n[output]\nper_stream_bytes = 64\ntotal_bytes = 128\nmax_handles = 1\n[targets.plain]\nssh_host = 'plain'\n",
            serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
        ))?;
        let mut command = support::server_command(&config)?;
        command.env("TMPDIR", &artifacts).env("XDG_RUNTIME_DIR", &runtime);
        let mut server = WireServer::start_command(command)?;
        let cases = async {
            server.initialize().await?;
            let reply = script_wire_call(&mut server, 2, "exec_command",
                json!({"host":"plain","command":"printf abc"})).await?;
            ensure!(succeeded(&reply)?.get("output").is_none());
            ensure!(output_entries(&artifacts)?.is_empty(), "default call created artifacts");
            let reply = script_wire_call(&mut server, 3, "exec_command", json!({
                "host":"plain","command":"printf 'abc\\000\\303\\251\\377Z'; printf 'err\\000\\376' >&2",
                "retain_output":true,
            })).await?;
            let data = succeeded(&reply)?;
            let handle = output_handle(data)?;
            ensure!(data["stdout"] == "abc\0" && data["stderr"] == "err\0");
            ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
            ensure!(data["output"]["stdout"] == json!({"bytes_retained":8,"total_bytes":8,"truncated":false}));
            ensure!(data["output"]["stderr"] == json!({"bytes_retained":5,"total_bytes":5,"truncated":false}));
            let directories = output_entries(&artifacts)?;
            ensure!(directories.len() == 1, "expected one private artifact owner: {directories:?}");
            ensure!(fs::metadata(&directories[0])?.permissions().mode() & 0o777 == 0o700);
            let files = output_entries(&directories[0])?;
            ensure!(files.len() == 2);
            let mut payloads = Vec::new();
            for path in &files {
                ensure!(fs::metadata(path)?.permissions().mode() & 0o777 == 0o600);
                payloads.push(fs::read(path)?);
            }
            ensure!(payloads.contains(&b"abc\0\xc3\xa9\xffZ".to_vec()));
            ensure!(payloads.contains(&b"err\0\xfe".to_vec()));
            let before_masters = masters(&server.log)?;
            let before_auth = fixture.authentications();
            output_range(&mut server, 4, &handle, "stdout", (0, 8), (b"abc\0\xc3\xa9\xffZ", true), "base64").await?;
            output_range(&mut server, 5, &handle, "stderr", (0, 5), (b"err\0\xfe", true), "base64").await?;
            output_range(&mut server, 6, &handle, "stdout", (0, 3), (b"abc", false), "utf8").await?;
            output_range(&mut server, 7, &handle, "stdout", (4, 2), ("é".as_bytes(), false), "utf8").await?;
            output_range(&mut server, 8, &handle, "stdout", (8, 1), (b"", true), "utf8").await?;
            output_range(&mut server, 9, &handle, "stderr", (99, 1), (b"", true), "base64").await?;
            for (id, offset, count) in [(10, 4, 1), (11, 5, 1), (12, 6, 1)] {
                let reply = script_wire_call(&mut server, id, "inspect_output", json!({
                    "handle":handle,"stream":"stdout","offset":offset,"max_bytes":count,
                })).await?;
                failed(&reply, "invalid_encoding")?;
                ensure!(reply["error"]["remote_state_unknown"] == false && reply["data"].is_null());
            }
            // A second, real server has no authority over the first server's handle.
            let mut foreign = WireServer::start(&config)?;
            let foreign_case = async {
                foreign.initialize().await?;
                let reply = script_wire_call(&mut foreign, 2, "inspect_output",
                    json!({"handle":handle,"stream":"stdout"})).await?;
                failed(&reply, "not_found")?;
                ensure!(masters(&foreign.log)?.is_empty());
                Ok::<_, anyhow::Error>(())
            }.await;
            let foreign_stop = foreign.stop(None).await;
            foreign_case?;
            foreign_stop?;
            ensure!(masters(&server.log)? == before_masters);
            ensure!(fixture.authentications() == before_auth, "local reads opened SSH");
            Ok::<_, anyhow::Error>(handle)
        }.await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        let handle = cases?;
        let log = stopped?;
        gone?;
        ensure!(output_entries(&artifacts)?.is_empty(), "shutdown retained private files");
        ensure!(!log.text().contains(&handle), "capability leaked into audit");
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_prefix_quota_disabled_storage_failure_and_expiry() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        for mode in ["quota", "disabled", "storage", "expiry"] {
            let temporary = fixture.root.path().join(format!("output-{mode}"));
            let runtime = fixture.root.path().join(format!("runtime-{mode}"));
            fs::create_dir(&runtime)?;
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
            if mode == "storage" { fs::write(&temporary, b"not a directory")?; }
            else { fs::create_dir(&temporary)?; }
            let config = fixture.root.path().join(format!("output-{mode}.toml"));
            fs::write(&config, format!(
                "capabilities = {{ named = true, file_read = true, file_write = true, exec = true, sudo = true }}\n[ssh]\nconfig_file = {}\n[limits]\nmax_output_bytes = 4\n[output]\nenabled = {}\nper_stream_bytes = 8\ntotal_bytes = 16\nmax_handles = 1\nttl_secs = {}\n[targets.plain]\nssh_host = 'plain'\n",
                serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
                mode != "disabled", if mode == "expiry" { 1 } else { 300 },
            ))?;
            let mut command = support::server_command(&config)?;
            command.env("TMPDIR", &temporary).env("XDG_RUNTIME_DIR", &runtime);
            let mut server = WireServer::start_command(command)?;
            let cases = async {
                server.initialize().await?;
                let reply = script_wire_call(&mut server, 2, "exec_command", json!({
                    "host":"plain","command":"printf 0123456789; printf abcdefghij >&2","retain_output":true,
                })).await?;
                let data = succeeded(&reply)?;
                if matches!(mode, "quota" | "expiry") {
                    let handle = output_handle(data)?;
                    for stream in ["stdout", "stderr"] {
                        ensure!(data["output"][stream] == json!({"bytes_retained":8,"total_bytes":10,"truncated":true}));
                    }
                    output_range(&mut server, 3, &handle, "stdout", (0, 8), (b"01234567", true), "utf8").await?;
                    output_range(&mut server, 4, &handle, "stderr", (0, 8), (b"abcdefgh", true), "utf8").await?;
                    if mode == "expiry" {
                        timeout(Duration::from_secs(5), async {
                            while !output_entries(&temporary)?.is_empty() { sleep(Duration::from_millis(10)).await; }
                            Ok::<_, anyhow::Error>(())
                        }).await??;
                        let reply = script_wire_call(&mut server, 5, "inspect_output",
                            json!({"handle":handle,"stream":"stdout"})).await?;
                        failed(&reply, "not_found")?;
                        return Ok::<_, anyhow::Error>(());
                    }
                } else {
                    ensure!(data["output"] == json!({"status":"unavailable","reason":if mode == "disabled" {"retention_disabled"} else {"io_error"}}));
                }
                // More than pipe capacity on both streams, followed by a real
                // observed nonzero exit: failed retention must keep draining.
                let reply = script_wire_call(&mut server, 6, "exec_command", json!({
                    "host":"plain","retain_output":true,
                    "command":"x=oooooooooooooooo; y=eeeeeeeeeeeeeeee; i=0; while [ \"$i\" -lt 14 ]; do x=$x$x; y=$y$y; i=$((i+1)); done; printf '%s' \"$x\"; printf '%s' \"$y\" >&2; exit 23",
                })).await?;
                failed(&reply, "command_failed")?;
                let data = &reply["data"];
                ensure!(data["exit_code"] == 23 && data["termination"] == "exited");
                ensure!(data["stdout"] == "oooo" && data["stderr"] == "eeee");
                ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
                ensure!(data["output"] == json!({"status":"unavailable","reason":match mode {
                    "quota" => "resource_limit", "disabled" => "retention_disabled", _ => "io_error",
                }}), "retention changed execution failure: {reply}");
                if mode == "disabled" { ensure!(output_entries(&temporary)?.is_empty()); }
                if mode == "storage" { ensure!(fs::read(&temporary)? == b"not a directory"); }
                let finished = fixture.root.path().join(format!("output-timeout-{mode}-done"));
                let sleeper = binding_program("sleep")?;
                let timed = script_wire_call(&mut server, 7, "exec_command", json!({
                    "host":"plain","retain_output":true,"timeout_secs":1,
                    "command":format!("trap '' HUP; printf TIME; printf WAIT >&2; {} 2; printf done > {}",
                        quote(&sleeper.to_string_lossy()), quote(&finished.to_string_lossy())),
                })).await;
                // Observe the finite synchronous remote command's completion
                // even if its channel-deadline response is wrong.
                Fixture::await_file(&finished).await?;
                let timed = timed?;
                failed(&timed, "timeout")?;
                ensure!(timed["data"]["termination"] == "timeout");
                ensure!(timed["data"]["exit_code"].is_null());
                ensure!(timed["data"]["remote_may_still_be_running"] == true);
                ensure!(timed["error"]["remote_state_unknown"] == true);
                ensure!(timed["data"]["output"] == json!({"status":"unavailable","reason":match mode {
                    "quota" => "resource_limit", "disabled" => "retention_disabled", _ => "io_error",
                }}));
                Ok::<_, anyhow::Error>(())
            }.await;
            let owned = masters(&server.log);
            let stopped = server.stop(None).await;
            let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
            cases.with_context(|| mode)?;
            stopped?;
            gone?;
            if mode != "storage" { ensure!(output_entries(&temporary)?.is_empty()); }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_output_argv_and_named_native() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let printf = binding_program("printf")?;
        let config = fixture.root.path().join("output-bindings.toml");
        fs::write(&config, formatdoc! {r#"
            capabilities = {{ named = true, file_read = true, file_write = true, exec = true, sudo = true }}
            [selection]
            allow = ["retained_native"]
            [ssh]
            config_file = {ssh_config}
            [limits]
            max_output_bytes = 4
            [output]
            per_stream_bytes = 64
            total_bytes = 512
            max_handles = 4
            [targets.plain]
            ssh_host = "plain"
            [tools.retained_native]
            description = "Emit fixed native output."
            revision = "output-1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={printf},argv=["--",'%s\000%s',"native","é"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
        "#,
            ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?,
            printf = serde_json::to_string(&printf.to_string_lossy())?,
        })?;
        let mut server = WireServer::start(&config)?;
        let cases = async {
            server.initialize().await?;
            let mut id = 2;
            for (name, args, stdout, stderr) in [
                ("exec_argv", json!({"host":"plain","argv":["/bin/sh","-c","printf 'native\\000\\303\\251'; printf 'error\\000\\377' >&2"],"retain_output":true}), &b"native\0\xc3\xa9"[..], &b"error\0\xff"[..]),
                ("retained_native", json!({"host":"plain","retain_output":true}), &b"native\0\xc3\xa9"[..], &b""[..]),
            ] {
                let reply = script_wire_call(&mut server, id, name, args).await?;
                id += 1;
                let data = succeeded(&reply)?;
                ensure!(data["exit_code"] == 0 && data["termination"] == "exited");
                let handle = output_handle(data)?;
                ensure!(data["stdout"] == "nati" && data["stdout_truncated"] == true);
                for (stream, bytes) in [("stdout", stdout), ("stderr", stderr)] {
                    ensure!(data["output"][stream] == json!({
                        "bytes_retained":bytes.len(),"total_bytes":bytes.len(),"truncated":false,
                    }));
                    output_range(&mut server, id, &handle, stream, (0, 64), (bytes, true), "base64").await?;
                    id += 1;
                }
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        stopped?;
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}
