//! Real MCP file semantics and exec/SFTP multiplexing; root exec is only an oracle.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use indoc::{formatdoc, indoc};
use serde_json::{Value, json};
use tokio::{
    process::Command,
    time::{Duration, sleep, timeout},
};

use crate::{
    command_succeeded, fixture_fingerprints, isolated, observed_authentications,
    observed_master_count, private_boundary, support,
};

const ROOT: &str = "/tmp/v03-files";
const FILE_MARKER: &str = "V03_FILE_PAYLOAD_SECRET";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn succeeded(reply: &Value) -> Result<&Value> {
    ensure!(
        reply["error"].is_null() && reply["data"].is_object(),
        "file operation failed"
    );
    Ok(&reply["data"])
}

fn rejected(reply: &Value, code: &str) -> Result<()> {
    ensure!(
        reply["data"].is_null() && reply["error"]["code"] == code,
        "file operation did not return the expected error"
    );
    ensure!(reply["error"]["remote_state_unknown"] == false);
    Ok(())
}

async fn call(
    wire: &mut support::WireServer,
    id: &mut u64,
    name: &str,
    arguments: Value,
    credentials: &[String],
) -> Result<Value> {
    *id += 1;
    let (mut frame, size) = wire
        .request_with_size(
            json!(*id),
            "tools/call",
            json!({"name":name,"arguments":arguments}),
        )
        .await?;
    ensure!(
        size <= 16_777_216,
        "whole MCP response exceeded the wire bound"
    );
    private_boundary(&serde_json::to_string(&frame)?, credentials)?;
    let result = frame
        .get_mut("result")
        .context("missing tool result")?
        .take();
    support::envelope(serde_json::from_value(result)?)
}

// Hashing and decoding happen in the independent root container oracle, not in
// the application or an SSH command fallback.
async fn digest(fixture: &isolated::Fixture, bytes: &[u8]) -> Result<String> {
    let output = fixture
        .primary_exec(&format!(
            "/bin/printf '%s' {} | /bin/base64 -d | /bin/sha256sum",
            support::quote(&STANDARD.encode(bytes)),
        ))
        .await?;
    let text = String::from_utf8(output)?;
    let hash = text
        .split_ascii_whitespace()
        .next()
        .context("root digest")?;
    ensure!(hash.len() == 64);
    Ok(hash.to_owned())
}

async fn inspect_file(fixture: &isolated::Fixture, path: &str, bytes: &[u8]) -> Result<()> {
    let output = fixture
        .primary_exec(&formatdoc! {"
        /bin/test -f {path}
        /bin/stat -c '%u:%g:%s' -- {path}
        /bin/base64 -w 0 -- {path}
    ", path = support::quote(path)})
        .await?;
    ensure!(
        output == format!("1000:1000:{}\n{}", bytes.len(), STANDARD.encode(bytes)).as_bytes(),
        "independent file bytes or owner differ"
    );
    Ok(())
}

async fn check_master(
    fixture: &isolated::Fixture,
    owned: &[(u32, std::path::PathBuf)],
) -> Result<()> {
    ensure!(owned.len() == 1);
    let output = support::run(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .arg("-S")
            .arg(&owned[0].1)
            .args(["-O", "check", "plain"]),
    )
    .await?;
    ensure!(
        output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(&format!("(pid={})", owned[0].0)),
        "original master PID/socket is not alive"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires exact Nix fixture artifact and explicit Docker-compatible daemon"]
async fn ssh_lossless_files_and_exec_sftp_multiplexing() -> Result<()> {
    let fixture = isolated::Fixture::start(isolated::ImageKind::Native).await?;
    let mut wire = match support::WireServer::start(&fixture.config) {
        Ok(wire) => wire,
        Err(error) => {
            return match fixture.stop().await {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("fixture cleanup also failed: {cleanup:#}")))
                }
            };
        }
    };
    let credentials = fixture.credential_markers();
    let scenario =
        async {
            let mut credentials = credentials?;
            credentials.push("V03_BACKEND_DIAGNOSTIC_SECRET".to_owned());
            wire.initialize().await?;
            fixture.verify_identities().await?;
            let keys = fixture_fingerprints(&fixture).await?;
            observed_authentications(&fixture, &keys, &[("mcp", 3), ("mcp-sudo", 1)]).await?;
            // This namespace belongs solely to this disposable fixture. Root setup
            // does not create an SSH connection and is never the product writer.
            fixture
                .primary_exec(indoc! {r#"
            /bin/mkdir -m 755 /tmp/v03-files
            /bin/chown 1000:1000 /tmp/v03-files
            /bin/printf '%s' ORIGINAL > /tmp/v03-files/preserved
            /bin/chown 1000:1000 /tmp/v03-files/preserved
            /bin/chmod 644 /tmp/v03-files/preserved
        "#})
                .await?;
            let mut id = 10;
            // A valid logical target makes these validation checks meaningful:
            // neither failure may reach SSH, authenticate, create or truncate.
            for (path, content, encoding, code) in [
                (
                    "/tmp/v03-files/preserved",
                    "%%%=".to_owned(),
                    "base64",
                    "invalid_encoding",
                ),
                (
                    "/tmp/v03-files/invalid-new",
                    "%%%=".to_owned(),
                    "base64",
                    "invalid_encoding",
                ),
                (
                    "/tmp/v03-files/preserved",
                    "x".repeat(1_048_577),
                    "utf8",
                    "invalid_argument",
                ),
                (
                    "/tmp/v03-files/oversized-new",
                    STANDARD.encode(vec![0u8; 1_048_577]),
                    "base64",
                    "invalid_argument",
                ),
            ] {
                rejected(&call(&mut wire, &mut id, "change_file_write", json!({
                "host":"plain","path":path,"content":content,"encoding":encoding,"overwrite":true
            }), &credentials).await?, code)?;
            }
            ensure!(
                support::masters(&wire.log)?.is_empty(),
                "invalid writes started a master"
            );
            observed_authentications(&fixture, &keys, &[("mcp", 3), ("mcp-sudo", 1)]).await?;
            inspect_file(&fixture, "/tmp/v03-files/preserved", b"ORIGINAL").await?;
            fixture
                .primary_exec(indoc! {"
            /bin/test ! -e /tmp/v03-files/invalid-new
            /bin/test ! -e /tmp/v03-files/oversized-new
        "})
                .await?;

            let first = call(
                &mut wire,
                &mut id,
                "exec_command",
                json!({"host":"plain",
            "command":"/usr/bin/printf '%s' \"$SSH_CONNECTION\""}),
                &credentials,
            )
            .await?;
            let connection = succeeded(&first)?["stdout"]
                .as_str()
                .context("SSH_CONNECTION")?
                .to_owned();
            ensure!(connection.split_ascii_whitespace().count() == 4);
            command_succeeded(&first, &connection)?;
            let owned = observed_master_count(&wire.log, 1).await?;
            check_master(&fixture, &owned).await?;
            observed_authentications(&fixture, &keys, &[("mcp", 4), ("mcp-sudo", 1)]).await?;

            let utf8 = format!("{FILE_MARKER}:é\0\n'\\");
            let binary = [0, 255, 128, 65, 0, 10];
            for (name, bytes, encoding, content) in [
                ("utf8", utf8.as_bytes(), "utf8", utf8.clone()),
                (
                    "binary",
                    binary.as_slice(),
                    "base64",
                    STANDARD.encode(binary),
                ),
            ] {
                let path = format!("{ROOT}/{name}");
                let written = call(
                    &mut wire,
                    &mut id,
                    "change_file_write",
                    json!({
                        "host":"plain","path":path,"content":content,"encoding":encoding
                    }),
                    &credentials,
                )
                .await?;
                ensure!(succeeded(&written)? == &json!({"bytes_written":bytes.len()}));
                inspect_file(&fixture, &path, bytes).await?;
                let read = call(
                    &mut wire,
                    &mut id,
                    "inspect_file",
                    json!({
                        "host":"plain","path":path,"encoding":encoding
                    }),
                    &credentials,
                )
                .await?;
                ensure!(
                    succeeded(&read)?
                        == &json!({"content":content,"encoding":encoding,
                "bytes_read":bytes.len(),"next_offset":bytes.len(),"eof":true,
                "content_sha256":digest(&fixture, bytes).await?})
                );
            }
            // Root oracle verifies the literal unusual path, not shell evaluation.
            let unusual_name = "space 'quote\"; $(printf NOT_EXECUTED)\n*";
            let unusual_path = format!("{ROOT}/{unusual_name}");
            let unusual = call(
                &mut wire,
                &mut id,
                "change_file_write",
                json!({
                    "host":"plain","path":unusual_path,"content":FILE_MARKER
                }),
                &credentials,
            )
            .await?;
            succeeded(&unusual)?;
            inspect_file(&fixture, &unusual_path, FILE_MARKER.as_bytes()).await?;
            let unusual = call(
                &mut wire,
                &mut id,
                "inspect_file",
                json!({
                    "host":"plain","path":unusual_path
                }),
                &credentials,
            )
            .await?;
            ensure!(succeeded(&unusual)?["content"] == FILE_MARKER);

            for (offset, limit, bytes, next, eof) in [
                (0, 2, &binary[..2], 2, false),
                (2, 3, &binary[2..5], 5, false),
                (5, 1, &binary[5..], 6, true),
                (6, 2, &binary[6..], 6, true),
                (9, 2, &binary[6..], 9, true),
            ] {
                let hash = digest(&fixture, bytes).await?;
                let read = call(&mut wire, &mut id, "inspect_file", json!({
                "host":"plain","path":"/tmp/v03-files/binary","encoding":"base64",
                "offset":offset,"max_bytes":limit,"expected_content_sha256":hash.to_uppercase()
            }), &credentials).await?;
                ensure!(
                    succeeded(&read)?
                        == &json!({"content":STANDARD.encode(bytes),
                "encoding":"base64","bytes_read":bytes.len(),"next_offset":next,
                "eof":eof,"content_sha256":hash}),
                    "range/EOF/raw digest differs"
                );
            }
            let mismatch = call(
                &mut wire,
                &mut id,
                "inspect_file",
                json!({
                    "host":"plain","path":"/tmp/v03-files/binary","encoding":"base64",
                    "offset":2,"max_bytes":3,"expected_content_sha256":EMPTY_SHA256
                }),
                &credentials,
            )
            .await?;
            rejected(&mismatch, "checksum_mismatch")?;
            rejected(
                &call(
                    &mut wire,
                    &mut id,
                    "inspect_file",
                    json!({
                        "host":"plain","path":"/tmp/v03-files/binary"
                    }),
                    &credentials,
                )
                .await?,
                "invalid_encoding",
            )?;
            let unicode_offset = utf8.find('é').context("UTF-8 fixture character")?;
            rejected(
                &call(
                    &mut wire,
                    &mut id,
                    "inspect_file",
                    json!({
                        "host":"plain","path":"/tmp/v03-files/utf8",
                        "offset":unicode_offset,"max_bytes":1
                    }),
                    &credentials,
                )
                .await?,
                "invalid_encoding",
            )?;
            let existing = call(
                &mut wire,
                &mut id,
                "change_file_write",
                json!({
                    "host":"plain","path":"/tmp/v03-files/preserved","content":FILE_MARKER
                }),
                &credentials,
            )
            .await?;
            rejected(&existing, "already_exists")?;
            inspect_file(&fixture, "/tmp/v03-files/preserved", b"ORIGINAL").await?;
            for bytes in [b"xy".as_slice(), b"".as_slice()] {
                let written = call(
                    &mut wire,
                    &mut id,
                    "change_file_write",
                    json!({
                        "host":"plain","path":"/tmp/v03-files/preserved",
                        "content":std::str::from_utf8(bytes)?,"overwrite":true
                    }),
                    &credentials,
                )
                .await?;
                ensure!(succeeded(&written)?["bytes_written"] == bytes.len());
                inspect_file(&fixture, "/tmp/v03-files/preserved", bytes).await?;
                let read = call(
                    &mut wire,
                    &mut id,
                    "inspect_file",
                    json!({
                        "host":"plain","path":"/tmp/v03-files/preserved"
                    }),
                    &credentials,
                )
                .await?;
                ensure!(succeeded(&read)?["content"] == std::str::from_utf8(bytes)?);
                ensure!(succeeded(&read)?["eof"] == true);
            }
            let directories = fixture
                .primary_exec(indoc! {r#"
            /bin/chmod 644 /tmp/v03-files/binary
            /bin/ln -s binary /tmp/v03-files/link
            /bin/chown -h 1000:1000 /tmp/v03-files/link
            /bin/test -L /tmp/v03-files/link
            /bin/test "$(/bin/readlink /tmp/v03-files/link)" = binary
            /bin/test "$(/bin/stat -c '%u:%g:%a:%s' /tmp/v03-files/link)" = 1000:1000:777:6
            /bin/test "$(/bin/stat -c '%u:%g:%a' /tmp/v03-files)" = 1000:1000:755
            /bin/mkdir -m 755 /tmp/v03-files/names /tmp/v03-files/many
            /bin/chown 1000:1000 /tmp/v03-files/names /tmp/v03-files/many
            bad=$(/bin/printf 'bad\377')
            : > "/tmp/v03-files/names/$bad"
            : > "/tmp/v03-files/names/space 'quote"
            /bin/chmod 640 /tmp/v03-files/names/*
            /bin/chown 1000:1000 /tmp/v03-files/names/*
            i=0
            while [ "$i" -lt 201 ]; do
                : > "/tmp/v03-files/many/item-$i"
                i=$((i + 1))
            done
            /bin/chmod 640 /tmp/v03-files/many/*
            /bin/chown 1000:1000 /tmp/v03-files/many/*
            /bin/stat -c '%u:%g:%a' /tmp/v03-files/names /tmp/v03-files/many
            for path in /tmp/v03-files/names/*; do
                /bin/printf '%s' "${path##*/}" | /bin/base64 -w 0
                /bin/printf '\n'
                /bin/stat -c '%u:%g:%a:%s' -- "$path"
            done
            count=0
            for path in /tmp/v03-files/many/*; do
                /bin/test "$(/bin/stat -c '%u:%g:%a:%s' -- "$path")" = 1000:1000:640:0
                count=$((count + 1))
            done
            /bin/printf 'count=%s\n' "$count"
        "#})
                .await
                .context("seeding and independently checking directory fixtures")?;
            ensure!(directories == format!(
            "1000:1000:755\n1000:1000:755\n{}\n1000:1000:640:0\n{}\n1000:1000:640:0\ncount=201\n",
            STANDARD.encode(b"bad\xff"), STANDARD.encode(b"space 'quote")).as_bytes(),
            "independent raw directory names/count/modes differ");
            for follow in [false, true] {
                let args = if follow {
                    json!({"host":"plain","path":"/tmp/v03-files/link","follow_symlinks":true})
                } else {
                    json!({"host":"plain","path":"/tmp/v03-files/link"})
                };
                let stat = call(&mut wire, &mut id, "observe_stat", args, &credentials).await?;
                let data = succeeded(&stat)?;
                ensure!(data["kind"] == if follow { "file" } else { "symlink" });
                ensure!(data["size"] == 6 && data["uid"] == 1000 && data["gid"] == 1000);
                ensure!(data["permissions"] == if follow { 0o644 } else { 0o777 });
            }
            let names = call(
                &mut wire,
                &mut id,
                "inspect_directory",
                json!({
                    "host":"plain","path":"/tmp/v03-files/names"
                }),
                &credentials,
            )
            .await?;
            let data = succeeded(&names)?;
            ensure!(data["truncated"] == false);
            let entries = data["entries"].as_array().context("directory entries")?;
            ensure!(entries.len() == 2);
            for (raw, text) in [
                (b"bad\xff".as_slice(), None),
                (b"space 'quote".as_slice(), Some("space 'quote")),
            ] {
                let entry = entries
                    .iter()
                    .find(|entry| entry["name_base64"] == STANDARD.encode(raw))
                    .context("lossless filename absent")?;
                ensure!(entry["name"] == json!(text));
                ensure!(entry["metadata"]["kind"] == "file" && entry["metadata"]["size"] == 0);
                ensure!(
                    entry["metadata"]["permissions"] == 0o640
                        && entry["metadata"]["uid"] == 1000
                        && entry["metadata"]["gid"] == 1000
                );
            }
            for (limit, expected, truncated) in [
                (None, 200, true),
                (Some(201), 201, false),
                (Some(1), 1, true),
            ] {
                let mut args = json!({"host":"plain","path":"/tmp/v03-files/many"});
                if let Some(limit) = limit {
                    args["max_entries"] = json!(limit);
                }
                let listed =
                    call(&mut wire, &mut id, "inspect_directory", args, &credentials).await?;
                let data = succeeded(&listed)?;
                let entries = data["entries"]
                    .as_array()
                    .context("bounded directory entries")?;
                ensure!(entries.len() == expected && data["truncated"] == truncated);
                let mut unique = std::collections::BTreeSet::new();
                for entry in entries {
                    let name = entry["name"].as_str().context("ASCII filename")?;
                    let index: usize = name
                        .strip_prefix("item-")
                        .context("unexpected entry")?
                        .parse()?;
                    ensure!(index < 201 && unique.insert(index));
                    ensure!(entry["name_base64"] == STANDARD.encode(name));
                }
            }

            // A finite shell waits for a controller-owned release file. Independent
            // root observation proves dispatch; read/stat must reply before release.
            let held_id = id + 1;
            id += 1;
            wire.send(
                json!({"jsonrpc":"2.0","id":held_id,"method":"tools/call","params":{
            "name":"exec_command","arguments":{"host":"plain","timeout_secs":30,
            "command":indoc! {r#"
                /usr/bin/printf '%s' "$SSH_CONNECTION" > /tmp/v03-files/started
                i=0
                while [ ! -e /tmp/v03-files/release ]; do
                    if [ "$i" -ge 20 ]; then
                        /usr/bin/printf '%s' EXPIRED >&2
                        exit 73
                    fi
                    /bin/sleep 1
                    i=$((i + 1))
                done
                /usr/bin/printf '%s' "$SSH_CONNECTION"
            "#}}}}),
            )
            .await?;
            timeout(Duration::from_secs(5), async {
                loop {
                    let marker = fixture
                        .primary_exec(indoc! {"
                    if [ -f /tmp/v03-files/started ]; then
                        /bin/cat /tmp/v03-files/started
                    fi
                "})
                        .await?;
                    if marker == connection.as_bytes() {
                        return Ok::<_, anyhow::Error>(());
                    }
                    ensure!(marker.is_empty(), "held exec has a different transport");
                    sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .context("held exec did not publish its readiness marker")??;
            inspect_file(&fixture, "/tmp/v03-files/started", connection.as_bytes()).await?;
            let read = call(
                &mut wire,
                &mut id,
                "inspect_file",
                json!({
                    "host":"plain","path":"/tmp/v03-files/utf8"
                }),
                &credentials,
            )
            .await?;
            ensure!(succeeded(&read)?["content"] == utf8);
            let stat = call(
                &mut wire,
                &mut id,
                "observe_stat",
                json!({
                    "host":"plain","path":"/tmp/v03-files/binary"
                }),
                &credentials,
            )
            .await?;
            ensure!(succeeded(&stat)?["size"] == binary.len());
            fixture
                .primary_exec(indoc! {r#"
            /bin/test ! -e /tmp/v03-files/release
            /bin/printf '%s' release > /tmp/v03-files/release
            /bin/chmod 644 /tmp/v03-files/release
            /bin/test "$(/bin/stat -c '%u:%g:%a:%s' /tmp/v03-files/release)" = 0:0:644:7
            /bin/test "$(/bin/base64 -w 0 /tmp/v03-files/release)" = cmVsZWFzZQ==
        "#})
                .await?;
            let (mut frame, size) = wire.receive(json!(held_id)).await?;
            ensure!(size <= 16_777_216);
            private_boundary(&serde_json::to_string(&frame)?, &credentials)?;
            let held = support::envelope(serde_json::from_value(frame["result"].take())?)?;
            command_succeeded(&held, &connection)?;
            let after = call(
                &mut wire,
                &mut id,
                "exec_command",
                json!({"host":"plain",
            "command":"/usr/bin/printf '%s' \"$SSH_CONNECTION\""}),
                &credentials,
            )
            .await?;
            command_succeeded(&after, &connection)?;
            ensure!(observed_master_count(&wire.log, 1).await? == owned);
            check_master(&fixture, &owned).await?;
            observed_authentications(&fixture, &keys, &[("mcp", 4), ("mcp-sudo", 1)]).await?;
            let fields = connection.split_ascii_whitespace().collect::<Vec<_>>();
            let peer = format!("from {} port {}", fields[0], fields[1]);
            let primary_logs = fixture.primary_logs().await?;
            let primary_logs = String::from_utf8(primary_logs)?;
            ensure!(
                primary_logs
                    .lines()
                    .any(|line| line.contains("Starting session:")
                        && line.contains("subsystem 'sftp'")
                        && line.contains(&peer)),
                "sshd did not associate SFTP with the exec transport's client port"
            );

            fixture
                .nosftp_exec(indoc! {"
            /bin/mkdir -m 755 /tmp/v03-files
            /bin/chown 1000:1000 /tmp/v03-files
            /bin/printf '%s' NO_SFTP_ORIGINAL > /tmp/v03-files/source
            /bin/chown 1000:1000 /tmp/v03-files/source
            /bin/chmod 644 /tmp/v03-files/source
        "})
                .await?;
            let before = fixture.nosftp_logs().await?;
            for (tool, args) in [
                (
                    "inspect_file",
                    json!({"host":"nosftp","path":"/tmp/v03-files/source"}),
                ),
                (
                    "change_file_write",
                    json!({"host":"nosftp","path":"/tmp/v03-files/upload","content":FILE_MARKER}),
                ),
                (
                    "observe_stat",
                    json!({"host":"nosftp","path":"/tmp/v03-files/source"}),
                ),
                (
                    "inspect_directory",
                    json!({"host":"nosftp","path":"/tmp/v03-files"}),
                ),
            ] {
                let failed = call(&mut wire, &mut id, tool, args, &credentials).await?;
                ensure!(
                    failed["data"].is_null() && failed["error"].is_object(),
                    "missing SFTP unexpectedly succeeded"
                );
            }
            let after = fixture.nosftp_logs().await?;
            let delta = after
                .strip_prefix(before.as_slice())
                .context("nosftp logs lost their snapshot prefix")?;
            let text = String::from_utf8_lossy(delta);
            ensure!(
                text.lines()
                    .filter(|line| line.contains("subsystem request for sftp"))
                    .count()
                    >= 4,
                "no independent evidence of all four SFTP subsystem requests"
            );
            for forbidden in [
                "request exec",
                "request shell",
                "Starting session: command",
                "Starting session: shell",
            ] {
                ensure!(
                    !text.contains(forbidden),
                    "SFTP-disabled operation attempted an SSH command fallback"
                );
            }
            let inspected = fixture
                .nosftp_exec(indoc! {"
            /bin/test ! -e /tmp/v03-files/upload
            set -- /tmp/v03-files/*
            /bin/test \"$#\" -eq 1
            /bin/test \"$1\" = /tmp/v03-files/source
            /bin/stat -c '%u:%g:%a:%s' /tmp/v03-files/source
            /bin/base64 -w 0 /tmp/v03-files/source
        "})
                .await?;
            ensure!(
                inspected
                    == format!("1000:1000:644:16\n{}", STANDARD.encode(b"NO_SFTP_ORIGINAL"))
                        .as_bytes()
            );
            let mut audit_markers = credentials;
            audit_markers.extend([
                FILE_MARKER.to_owned(),
                STANDARD.encode(utf8.as_bytes()),
                STANDARD.encode(binary),
                unusual_name.to_owned(),
                "V03_BACKEND_DIAGNOSTIC_SECRET".to_owned(),
            ]);
            private_boundary(&wire.log.text(), &audit_markers)?;
            for record in wire.log.records()? {
                for field in [
                    "path", "content", "payload", "command", "stdin", "stdout", "stderr",
                ] {
                    ensure!(
                        record.get(field).is_none(),
                        "audit contains a payload field"
                    );
                }
            }
            for tool in [
                "change_file_write",
                "inspect_file",
                "observe_stat",
                "inspect_directory",
            ] {
                ensure!(
                    wire.log
                        .records()?
                        .iter()
                        .any(|record| record["tool"] == tool && record["event"] == "finish"),
                    "missing actual file audit completion"
                );
            }
            Ok::<_, anyhow::Error>(audit_markers)
        }
        .await;
    // Collect every cleanup result before returning a scenario failure. Stopping
    // the container also bounds a still-waiting finite remote barrier on errors.
    let log = wire.log.clone();
    let server_cleanup = wire.stop(None).await.map(|_| ());
    let master_cleanup = match support::masters(&log) {
        Ok(owned) if owned.is_empty() => Ok(()),
        Ok(owned) => support::assert_masters_gone(&owned).await,
        Err(error) => Err(error),
    };
    let container_cleanup = fixture.stop().await;
    let scenario = scenario.and_then(|markers| private_boundary(&log.text(), &markers));
    let errors = [
        ("scenario", scenario),
        ("server cleanup", server_cleanup),
        ("master cleanup", master_cleanup),
        ("container cleanup", container_cleanup),
    ]
    .into_iter()
    .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error:#}")))
    .collect::<Vec<_>>();
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(())
}
