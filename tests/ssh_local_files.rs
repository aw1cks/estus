//! Real SFTP file operations: read, stat, list, write, mkdir, rename, remove, replace.
#[path = "support/replace_relay.rs"]
mod replace_relay;
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
use rmcp::model::CallToolRequest;
use rmcp::model::ClientRequest;
use rmcp::service::PeerRequestOptions;
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::time::Duration;
use support::Client;
use support::Fixture;
use support::WireServer;
use support::assert_masters_gone;
use support::masters;
use support::params;
use support::quote;
use tokio::process::Command;
use tokio::time::sleep;
use tokio::time::timeout;

// Independent local oracle for cases without a published SHA-256 vector.
// find_program canonicalizes Nix multicall applets, so preserve sha256sum argv[0].
async fn local_sha256(bytes: &[u8]) -> Result<String> {
    use std::io::Write;

    ensure!(
        bytes.len() <= 300_000,
        "local hash input exceeds test bound"
    );
    let program = support::find_program("sha256sum")?;
    ensure!(
        program.starts_with("/nix/store"),
        "sha256sum must be Nix-provided"
    );
    let mut input = tempfile::NamedTempFile::new()?;
    input.write_all(bytes)?;
    let output = support::run(
        Command::new(program)
            .arg0("sha256sum")
            .args(["--binary", "--zero", "--"])
            .arg(input.path()),
    )
    .await?;
    ensure!(
        output.status.success() && output.stderr.is_empty(),
        "local SHA-256 oracle failed"
    );
    ensure!(
        output.stdout.len() == 67 + input.path().as_os_str().len()
            && output.stdout[64..66] == *b" *"
            && output.stdout.last() == Some(&0),
        "unexpected bounded SHA-256 oracle output"
    );
    let digest = std::str::from_utf8(&output.stdout[..64])?;
    ensure!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    Ok(digest.to_owned())
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

const MISMATCH_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

async fn read_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let root = fixture.root.path();
    {
        let owned = observed_masters(&client.log, 1).await?;
        live_transport(fixture, client, &owned[0], 1, 3).await?;
    }
    let before_reads = fixture.listeners[0].log.text();
    let text = root.join("read-text");
    fs::write(&text, b"abcdef")?;
    let empty = root.join("read-empty");
    fs::write(&empty, b"")?;
    // Exact metadata also distinguishes lookahead from incorrectly consuming it.
    for (path, offset, limit, content, next, eof) in [
        (&text, 0, None, "abcdef", 6, true),
        (&text, 0, Some(3), "abc", 3, false),
        (&text, 3, Some(3), "def", 6, true),
        (&text, 5, Some(8), "f", 6, true),
        (&text, 6, Some(1), "", 6, true),
        (&text, 99, Some(1), "", 99, true),
        (&text, u64::MAX, Some(1), "", u64::MAX, true),
        (&empty, 0, None, "", 0, true),
    ] {
        let mut args = json!({"host":"plain","path":path,"offset":offset});
        if let Some(limit) = limit {
            args["max_bytes"] = json!(limit);
        }
        // Published empty/abc vectors also exercise case-insensitive verification.
        // The abc read has a fourth byte available: it must not enter the digest.
        let digest = match content {
            "" => EMPTY_SHA256.to_owned(),
            "abc" => ABC_SHA256.to_owned(),
            _ => local_sha256(content.as_bytes()).await?,
        };
        if content == "abc" {
            args["expected_content_sha256"] = json!(ABC_SHA256.to_ascii_uppercase());
        } else if content.is_empty() {
            args["expected_content_sha256"] = json!(EMPTY_SHA256);
        }
        let reply = client.call("inspect_file", args).await?;
        ensure!(
            succeeded(&reply)?
                == &json!({
                    "content":content,"encoding":"utf8","bytes_read":content.len(),
                    "next_offset":next,"eof":eof,"content_sha256":digest
                }),
            "read range offset={offset}, limit={limit:?}: {reply}"
        );
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .context("native prerequisite: current account")?;
    let home = fs::canonicalize(user.dir).context("native prerequisite: usable account home")?;
    let depth = home
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    let mut relative = PathBuf::with_capacity(depth * 3 + root.as_os_str().len() + 16);
    for _ in 0..depth {
        relative.push("..");
    }
    relative.push(root.strip_prefix("/")?);
    relative.push("read-text");
    let reply = client
        .call("inspect_file", json!({"host":"plain","path":relative}))
        .await?;
    ensure!(
        succeeded(&reply)?["content"] == "abcdef",
        "relative SFTP path used the wrong initial directory"
    );

    let large = root.join("read-multiple-packets");
    let contents = "0123456789".repeat(30_001);
    fs::write(&large, contents.as_bytes())?;
    let reply = client
        .call(
            "inspect_file",
            json!({"host":"plain","path":large,"max_bytes":300_000}),
        )
        .await?;
    let data = succeeded(&reply)?;
    ensure!(data["content"].as_str() == Some(&contents[..300_000]));
    ensure!(
        data["bytes_read"] == 300_000 && data["next_offset"] == 300_000 && data["eof"] == false
    );
    ensure!(data["content_sha256"] == local_sha256(&contents.as_bytes()[..300_000]).await?);
    let binary = root.join("read-binary");
    fs::write(&binary, [0, 255, 128, 65])?;
    let binary_digest = local_sha256(&[0, 255, 128, 65]).await?;
    let reply = client
        .call(
            "inspect_file",
            json!({"host":"plain","path":binary,"encoding":"base64",
                "expected_content_sha256":binary_digest}),
        )
        .await?;
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":"AP+AQQ==","encoding":"base64","bytes_read":4,"next_offset":4,"eof":true,
                "content_sha256":binary_digest
            })
    );
    let unicode = root.join("read-unicode");
    fs::write(&unicode, "é!")?;
    for args in [
        json!({"host":"plain","path":unicode,"max_bytes":1}),
        json!({"host":"plain","path":unicode,"offset":1}),
        json!({"host":"plain","path":binary}),
    ] {
        let reply = client.call("inspect_file", args).await?;
        failed(&reply, "invalid_encoding")?;
        ensure!(reply["data"].is_null(), "lossy or partial UTF8 success");
        ensure!(reply["error"]["remote_state_unknown"] == false);
    }
    // Expansion would select a different path; the substitution is side-effect free.
    let unusual = root.join("quote' \" ; $(printf EVALUATED)\n*");
    fs::write(&unusual, b"LITERAL_PATH")?;
    let reply = client
        .call("inspect_file", json!({"host":"plain","path":unusual}))
        .await?;
    ensure!(succeeded(&reply)?["content"] == "LITERAL_PATH");

    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    let before = fixture.listeners[0].log.text();
    let sessions = |text: &str, kind: &str| {
        text.lines()
            .filter(|line| line.contains("Starting session:") && line.contains(kind))
            .count()
    };
    let reply = client
        .call(
            "inspect_file",
            json!({"host":"plain","path":unusual,"expected_content_sha256":MISMATCH_SHA256}),
        )
        .await?;
    failed(&reply, "checksum_mismatch")?;
    ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
    let serialized = serde_json::to_string(&reply)?;
    let actual_digest = local_sha256(b"LITERAL_PATH").await?;
    for secret in ["LITERAL_PATH", MISMATCH_SHA256, actual_digest.as_str()] {
        ensure!(
            !serialized.contains(secret),
            "checksum failure disclosed read payload"
        );
    }
    let audit = await_audit(&client.log, "finish", "checksum_mismatch").await?;
    ensure!(audit["identity_role"] == "ordinary" && audit["remote_state_unknown"] == false);
    ensure!(
        live_transport(fixture, client, &owned[0], 1, 3).await? == transport,
        "checksum mismatch replaced the healthy ordinary master"
    );
    // The transport probe drains listener logs. A mismatch opens exactly one
    // SFTP session, and the only shell command is that explicit health probe.
    let after = fixture.listeners[0].log.text();
    ensure!(
        sessions(&after, "subsystem 'sftp'") == sessions(&before, "subsystem 'sftp'") + 1,
        "checksum mismatch retried its SFTP session"
    );
    ensure!(
        sessions(&after, "command") == sessions(&before, "command") + 1,
        "SFTP verification executed an unexpected remote shell helper"
    );
    for secret in [
        "LITERAL_PATH",
        MISMATCH_SHA256,
        actual_digest.as_str(),
        ABC_SHA256,
        &ABC_SHA256.to_ascii_uppercase(),
        EMPTY_SHA256,
        binary_digest.as_str(),
    ] {
        ensure!(
            !client.log.text().contains(secret),
            "read audit disclosed content or digest"
        );
    }
    ensure!(
        sessions(&after, "command") == sessions(&before_reads, "command") + 2,
        "range hashing or expected-digest verification ran a remote shell helper"
    );

    let denied = root.join("read-denied");
    fs::write(&denied, b"PRIVATE")?;
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    for (path, code) in [
        (root.join("read-missing"), "not_found"),
        (denied, "permission_denied"),
    ] {
        let reply = client
            .call("inspect_file", json!({"host":"plain","path":path}))
            .await?;
        failed(&reply, code)?;
        ensure!(reply["data"].is_null());
        ensure!(reply["error"]["remote_state_unknown"] == false);
    }
    let default_range = root.join("read-default-range");
    fs::write(&default_range, vec![b'a'; 65_537])?;
    let default_digest = local_sha256(&vec![b'a'; 65_536]).await?;
    let reply = client
        .call("inspect_file", json!({"host":"plain","path":default_range}))
        .await?;
    ensure!(
        succeeded(&reply)?
            == &json!({
                "content":"a".repeat(65_536),"encoding":"utf8","bytes_read":65_536,
                "next_offset":65_536,"eof":false,"content_sha256":default_digest
            }),
        "default read must be bounded with one-byte lookahead"
    );
    Ok(())
}

async fn blocked_reads() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-ready");
    let server = Fixture::sftp_server()?;
    for path in [&started, &done, &server] {
        ensure!(
            path.to_str().is_some_and(|path| path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_./+".contains(&byte))),
            "native prerequisite: shell-safe subsystem fixture path"
        );
    }
    // This finite fault delays the real protocol, not readiness observation.
    // Both markers are observed; no test passes merely by sleeping long enough.
    let script = format!(
        concat!(
            "trap \"\" HUP; printf started > {started}; ",
            "sleep 5; printf done > {done}; exec {server}",
        ),
        started = started.display(),
        done = done.display(),
        server = server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf BLOCKED_READ_MASTER").await?)?["stdout"]
                    == "BLOCKED_READ_MASTER"
            );
            let owned = observed_masters(&client.log, 1).await?;
            fixture.await_authentications(3).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let path = fixture.root.path().join("delayed-read");
            fs::write(&path, b"X")?;
            for cancel in [false, true] {
                for marker in [&started, &done] {
                    if marker.exists() {
                        fs::remove_file(marker)?;
                    }
                }
                let args = json!({"host":"plain","path":path,"max_bytes":1,
                    "timeout_secs":if cancel { 10 } else { 1 }});
                let result = async {
                    if cancel {
                        let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
                            "inspect_file",
                            args,
                        )));
                        let handle = timeout(
                            Duration::from_secs(5),
                            client
                                .service
                                .send_cancellable_request(request, PeerRequestOptions::default()),
                        )
                        .await??;
                        Fixture::await_file(&started).await?;
                        ensure!(
                            !done.exists(),
                            "subsystem fault finished before cancellation"
                        );
                        ensure!(
                            succeeded(&exec(&client, "printf SFTP_SIBLING").await?)?["stdout"]
                                == "SFTP_SIBLING"
                        );
                        timeout(
                            Duration::from_secs(5),
                            handle.cancel(Some("native SFTP cancellation".into())),
                        )
                        .await??;
                        let audit = await_audit(&client.log, "finish", "cancelled").await?;
                        ensure!(audit["remote_state_unknown"] == true);
                    } else {
                        let blocked = client.call("inspect_file", args);
                        let sibling = async {
                            Fixture::await_file(&started).await?;
                            let reply = exec(&client, "printf SFTP_SIBLING").await?;
                            ensure!(succeeded(&reply)?["stdout"] == "SFTP_SIBLING");
                            Ok::<_, anyhow::Error>(())
                        };
                        let (reply, sibling) = tokio::join!(blocked, sibling);
                        sibling?;
                        let reply = reply?;
                        failed(&reply, "timeout")?;
                        ensure!(reply["data"].is_null());
                        ensure!(reply["error"]["remote_state_unknown"] == true);
                        await_audit(&client.log, "finish", "timeout").await?;
                    }
                    ensure!(
                        !done.exists(),
                        "cancellation waited for remote startup to finish"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                // The channel close is not proof that the remote prefix ended.
                let completed = Fixture::await_file(&done).await;
                result?;
                completed?;
                ensure!(
                    live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                    "cancelled file read replaced the ordinary master"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_read_file() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf READ_MASTER").await?)?["stdout"] == "READ_MASTER"
            );
            read_cases(&fixture, &client).await?;
            blocked_reads().await?;
            let reply = client
                .call(
                    "inspect_file",
                    json!({
                        "host":"nosftp","path":fixture.root.path().join("read-text")
                    }),
                )
                .await?;
            let code = reply["error"]["code"]
                .as_str()
                .context("subsystem denial must fail")?;
            ensure!(
                matches!(code, "unsupported" | "io_error" | "connection_lost"),
                "untyped subsystem denial must not masquerade as authentication failure: {reply}"
            );
            ensure!(reply["data"].is_null(), "missing subsystem used a fallback");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client
                .call(
                    "exec_command",
                    json!({"host":"nosftp","command":"printf NO_FALLBACK_MASTER_ALIVE"}),
                )
                .await?;
            ensure!(succeeded(&reply)?["stdout"] == "NO_FALLBACK_MASTER_ALIVE");
            ensure!(
                masters(&client.log)? == before,
                "subsystem denial discarded a healthy master"
            );
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        ensure!(
            !log.text().contains("LITERAL_PATH"),
            "requested file content reached audit"
        );
        for record in log
            .final_records()?
            .iter()
            .filter(|record| record["tool"] == "inspect_file")
        {
            ensure!(
                record["identity_role"] == "ordinary",
                "read used a nonordinary identity"
            );
            for field in ["content", "content_sha256", "expected_content_sha256"] {
                ensure!(
                    record.get(field).is_none(),
                    "read audit includes payload field {field}"
                );
            }
        }
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_read_cleanup() -> Result<()> {
    let work = tempfile::tempdir()?;
    let done = work.path().join("channel-close-done");
    let protocol_done = work.path().join("protocol-done");
    let server = Fixture::sftp_server()?;
    for path in [&done, &protocol_done, &server] {
        ensure!(
            path.to_str().is_some_and(|path| path
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_./+".contains(&byte))),
            "native prerequisite: shell-safe subsystem fixture path"
        );
    }
    // The real server exits successfully, then the configured session holds its
    // channel open. Observe both protocol and session completion, not a delay.
    let script = format!(
        "trap \"\" HUP; {server} && printf closed > {protocol_done}; sleep 5; printf done > {done}",
        done = done.display(),
        protocol_done = protocol_done.display(),
        server = server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            ensure!(
                succeeded(&exec(&client, "printf CLEANUP_MASTER").await?)?["stdout"]
                    == "CLEANUP_MASTER"
            );
            let owned = observed_masters(&client.log, 1).await?;
            fixture.await_authentications(3).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let path = fixture.root.path().join("cleanup-read");
            fs::write(&path, b"X")?;
            let reply = client
                .call(
                    "inspect_file",
                    json!({"host":"plain","path":path,"max_bytes":1,"timeout_secs":10}),
                )
                .await?;
            Fixture::await_file(&protocol_done).await?;
            failed(&reply, "io_error")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                !done.exists(),
                "normal cleanup waited for the remote session to finish"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "cleanup failure replaced the shared master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let completed = Fixture::await_file(&done).await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        completed?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

async fn stat_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let root = fixture.root.path();
    let file = root.join("stat-file");
    fs::write(&file, b"STAT_SHARED_MASTER")?;
    // Nonexecutable owned data safely exercises setuid and sticky bits.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o5640))?;
    ensure!(fs::metadata(&file)?.mode() & 0o7777 == 0o5640);
    let directory = root.join("stat-directory");
    fs::create_dir(&directory)?;
    let link = root.join("stat-link");
    symlink(&file, &link)?;
    let dangling = root.join("stat-dangling");
    let missing = root.join("stat-missing");
    symlink(&missing, &dangling)?;
    let unusual = root.join("stat-é quote' \" ; $(printf EVALUATED)\n*");
    fs::write(&unusual, b"LITERAL_STAT_PATH")?;
    let socket_tree = tempfile::Builder::new()
        .prefix("sm-stat-")
        .tempdir_in("/tmp")?;
    let socket = socket_tree.path().join("s");
    let _socket = UnixListener::bind(&socket)?;

    ensure!(succeeded(&exec(client, "printf STAT_MASTER").await?)?["stdout"] == "STAT_MASTER");
    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    let before = fixture.listeners[0].log.text();
    for (path, follow) in [
        (&file, None),
        (&directory, None),
        (&link, None),
        (&link, Some(true)),
        (&dangling, None),
        (&unusual, None),
        (&socket, None),
    ] {
        let mut args = json!({"host":"plain","path":path});
        if let Some(follow) = follow {
            args["follow_symlinks"] = json!(follow);
        }
        let reply = client.call("observe_stat", args).await?;
        ensure!(
            succeeded(&reply)? == &native_stat_data(path, follow.unwrap_or(false))?,
            "native metadata mismatch for {path:?}, follow={follow:?}: {reply}"
        );
    }

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .context("native prerequisite: current account")?;
    let home = fs::canonicalize(user.dir).context("native prerequisite: usable account home")?;
    let mut relative = PathBuf::new();
    for component in home.components() {
        if matches!(component, std::path::Component::Normal(_)) {
            relative.push("..");
        }
    }
    relative.push(file.strip_prefix("/")?);
    let reply = client
        .call("observe_stat", json!({"host":"plain","path":relative}))
        .await?;
    ensure!(
        succeeded(&reply)? == &native_stat_data(&file, false)?,
        "relative stat path used the wrong initial directory"
    );

    let denied = root.join("stat-denied");
    fs::create_dir(&denied)?;
    let child = denied.join("private");
    fs::write(&child, b"PRIVATE_STAT")?;
    let permissions = fs::metadata(&denied)?.permissions();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    let failures = async {
        // A file's mode alone does not deny stat: traversal must be denied.
        ensure!(
            fs::symlink_metadata(&child)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
            "native prerequisite: owned parent must actually deny traversal"
        );
        for (path, follow, code) in [
            (&missing, false, "not_found"),
            (&dangling, true, "not_found"),
            (&child, false, "permission_denied"),
        ] {
            let reply = client
                .call(
                    "observe_stat",
                    json!({"host":"plain","path":path,"follow_symlinks":follow}),
                )
                .await?;
            failed(&reply, code)?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            let serialized = serde_json::to_string(&reply)?;
            ensure!(
                !serialized.contains(path.to_str().context("UTF8 fixture path")?),
                "stat failure disclosed its path"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Restore before propagating any scenario failure or deleting the fixture.
    let restored = fs::set_permissions(&denied, permissions);
    failures?;
    restored?;

    let reply = client
        .call("inspect_file", json!({"host":"plain","path":file}))
        .await?;
    ensure!(succeeded(&reply)?["content"] == "STAT_SHARED_MASTER");
    ensure!(
        live_transport(fixture, client, &owned[0], 1, 3).await? == transport,
        "exec/read/stat did not reuse the same live ordinary master"
    );
    let sessions = |text: &str, kind: &str| {
        text.lines()
            .filter(|line| line.contains("Starting session:") && line.contains(kind))
            .count()
    };
    let after = fixture.listeners[0].log.text();
    ensure!(
        sessions(&after, "command") == sessions(&before, "command") + 1,
        "stat or read ran an unexpected remote shell helper"
    );
    let before = fixture.listeners[1].log.text();
    let reply = client
        .call("observe_stat", json!({"host":"nosftp","path":file}))
        .await?;
    let code = reply["error"]["code"]
        .as_str()
        .context("subsystem denial must fail stat")?;
    ensure!(
        matches!(code, "unsupported" | "io_error" | "connection_lost"),
        "unexpected subsystem failure: {reply}"
    );
    ensure!(
        reply["data"].is_null(),
        "stat used a missing-subsystem fallback"
    );
    let owned = observed_masters(&client.log, 2).await?;
    let reply = client
        .call(
            "exec_command",
            json!({"host":"nosftp","command":"printf STAT_NO_FALLBACK_MASTER_ALIVE"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "STAT_NO_FALLBACK_MASTER_ALIVE");
    ensure!(
        masters(&client.log)? == owned,
        "stat denial replaced a healthy master"
    );
    fixture.await_authentications(4).await?;
    timeout(Duration::from_secs(5), async {
        while sessions(&fixture.listeners[1].log.text(), "command")
            < sessions(&before, "command") + 1
        {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("missing subsystem health-probe log")?;
    ensure!(
        sessions(&fixture.listeners[1].log.text(), "command") == sessions(&before, "command") + 1,
        "missing subsystem ran a stat shell fallback"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_stat() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = stat_cases(&fixture, &client).await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        let records = log.final_records()?;
        let stats: Vec<_> = records
            .iter()
            .filter(|record| record["tool"] == "observe_stat")
            .collect();
        ensure!(!stats.is_empty(), "stat emitted no audit records");
        for record in stats {
            ensure!(
                record["identity_role"] == "ordinary",
                "stat used a nonordinary identity"
            );
            for field in ["path", "filename", "target", "content", "uid", "gid"] {
                ensure!(record.get(field).is_none(), "stat audit disclosed {field}");
            }
        }
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

async fn list_cases(fixture: &Fixture, client: &Client) -> Result<()> {
    let directory = fixture.root.path().join("list-'\";~$*\n");
    fs::create_dir(&directory)?;
    let mut names = vec![
        b"z-last".to_vec(),
        b"a-first".to_vec(),
        "é-雪".as_bytes().to_vec(),
        b"quote'\";~$*\n\t\\control\x01".to_vec(),
    ];
    // APFS rejects invalid UTF-8; the approved Linux smoke covers these bytes.
    #[cfg(target_os = "linux")]
    names.push(b"nonutf8-\xff\xfe".to_vec());
    names.extend((0..201).map(|i| format!("entry-{i:03}").into_bytes()));
    for name in &names {
        fs::write(
            directory.join(std::ffi::OsString::from_vec(name.clone())),
            b"LIST_DATA",
        )?;
    }
    fs::create_dir(directory.join("subdirectory"))?;
    fs::write(
        directory.join("subdirectory/hidden-child"),
        b"NOT_RECURSIVE",
    )?;
    symlink("z-last", directory.join("symlink"))?;
    // Independent local readdir is the static native server's enumeration oracle,
    // not a sorted expectation or a copy of the tool's filename conversion.
    let expected: Vec<_> = fs::read_dir(&directory)?
        .map(|entry| {
            let entry = entry?;
            let name = entry.file_name();
            Ok(json!({
                "name": name.to_str(),
                "name_base64": STANDARD.encode(name.as_bytes()),
                "metadata": native_stat_data(&entry.path(), false)?,
            }))
        })
        .collect::<Result<_>>()?;
    let count = names.len() + 2;
    ensure!(expected.len() == count);
    ensure!(succeeded(&exec(client, "printf LIST_MASTER").await?)?["stdout"] == "LIST_MASTER");
    let owned = observed_masters(&client.log, 1).await?;
    let transport = live_transport(fixture, client, &owned[0], 1, 3).await?;
    for (limit, count, truncated) in [
        (None, 200, true),
        (Some(1), 1, true),
        (Some(count - 1), count - 1, true),
        (Some(count), count, false),
        (Some(1000), count, false),
    ] {
        let mut args = json!({"host":"plain","path":directory});
        if let Some(limit) = limit {
            args["max_entries"] = json!(limit);
        }
        let reply = client.call("inspect_directory", args).await?;
        let data = succeeded(&reply)?;
        ensure!(
            data["entries"] == json!(&expected[..count]) && data["truncated"] == truncated,
            "listing lost bytes, reordered entries, fabricated metadata or misreported truncation"
        );
    }
    let empty = fixture.root.path().join("list-empty");
    fs::create_dir(&empty)?;
    let reply = client
        .call(
            "inspect_directory",
            json!({"host":"plain","path":empty,"max_entries":1}),
        )
        .await?;
    ensure!(succeeded(&reply)? == &json!({"entries":[],"truncated":false}));
    // Exercise a larger directory crossing multiple SFTP READDIR responses.
    for i in 201..1001 {
        fs::write(directory.join(format!("entry-{i:03}")), b"")?;
    }
    let reply = client
        .call(
            "inspect_directory",
            json!({"host":"plain","path":directory,"max_entries":1000}),
        )
        .await?;
    let data = succeeded(&reply)?;
    ensure!(data["truncated"] == true, "entry-count limit must truncate");
    let entries = data["entries"].as_array().context("directory entries")?;
    ensure!(entries.len() == 1000);
    for entry in entries {
        let raw = STANDARD.decode(entry["name_base64"].as_str().context("listed raw name")?)?;
        let position = fs::read_dir(&directory)?
            .flatten()
            .position(|entry| entry.file_name().as_bytes() == raw)
            .context("listed entry absent from local enumeration")?;
        ensure!(position < 1000, "listed entry outside the page prefix");
    }

    let denied = fixture.root.path().join("list-denied");
    fs::create_dir(&denied)?;
    let permissions = fs::metadata(&denied)?.permissions();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000))?;
    let failures = async {
        for (path, code) in [
            (fixture.root.path().join("list-missing"), "not_found"),
            (denied.clone(), "permission_denied"),
        ] {
            let reply = client
                .call("inspect_directory", json!({"host":"plain","path":path}))
                .await?;
            failed(&reply, code)?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let restored = fs::set_permissions(&denied, permissions);
    failures?;
    restored?;
    ensure!(live_transport(fixture, client, &owned[0], 1, 3).await? == transport);
    let reply = client
        .call(
            "inspect_directory",
            json!({"host":"nosftp","path":directory}),
        )
        .await?;
    let code = reply["error"]["code"]
        .as_str()
        .context("subsystem denial must fail listing")?;
    ensure!(matches!(
        code,
        "unsupported" | "io_error" | "connection_lost"
    ));
    ensure!(reply["data"].is_null(), "listing used a subsystem fallback");
    let owned = observed_masters(&client.log, 2).await?;
    let reply = client
        .call(
            "exec_command",
            json!({"host":"nosftp","command":"printf LIST_NO_FALLBACK"}),
        )
        .await?;
    ensure!(succeeded(&reply)?["stdout"] == "LIST_NO_FALLBACK");
    ensure!(masters(&client.log)? == owned);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_list_directory() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = list_cases(&fixture, &client).await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let records = stopped?.final_records()?;
        for record in records.iter().filter(|record| record["tool"] == "inspect_directory") {
            ensure!(record["identity_role"] == "ordinary");
            for field in ["path", "name", "name_base64", "metadata", "entries"] {
                ensure!(record.get(field).is_none(), "listing audit disclosed {field}");
            }
        }
        gone?;

        // An actual near-limit string ID leaves room for only a directory prefix.
        // The raw frame reader measures both SDK representations plus framing.
        let directory = fixture.root.path().join("list-'\";~$*\n");
        let expected: Vec<_> = fs::read_dir(&directory)?
            .map(|entry| Ok(STANDARD.encode(entry?.file_name().as_bytes())))
            .collect::<Result<_>>()?;
        let mut wire = WireServer::start(&fixture.config)?;
        let wire_case = async {
            wire.initialize().await?;
            let (frame, size) = wire.request_with_size(
                json!("x".repeat(16_774_000)),
                "tools/call",
                json!({"name":"inspect_directory","arguments":{"host":"plain","path":directory,"max_entries":1000}}),
            ).await?;
            ensure!(size <= 16_777_216);
            let result = &frame["result"];
            let reply = &result["structuredContent"];
            ensure!(serde_json::from_str::<Value>(result["content"][0]["text"].as_str().context("text result")?)? == *reply);
            let data = succeeded(reply)?;
            ensure!(data["truncated"] == true);
            let entries = data["entries"].as_array().context("wire entries")?;
            ensure!(!entries.is_empty() && entries.len() < 200, "wire budget was not exercised");
            for (entry, expected) in entries.iter().zip(&expected) {
                ensure!(entry["name_base64"] == *expected);
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&wire.log);
        let stopped = wire.stop(None).await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        wire_case?;
        stopped?;
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_startup_file_profiles() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let config = fixture.root.path().join("file-profiles.toml");
        let ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?;
        fs::write(
            &config,
            formatdoc! {"
            capabilities = {{ file_read = true, file_write = true }}
            [ssh]
            config_file = {ssh_config}
            [targets.allowed]
            ssh_host = 'plain'
            [targets.allowed.sudo]
            mode = 'same-account'
            users = ['root']
            programs = ['/usr/bin/true']
            [targets.locked]
            ssh_host = 'plain'
            max_tier = 'inspect'
        "},
        )?;
        let directory = fixture.root.path().join("profile-owned-files");
        fs::create_dir(&directory)?;
        let file = directory.join("preserved");
        fs::write(&file, b"abc")?;
        let client = Client::start(&config).await?;
        let cases =
            async {
                let initial_auth = fixture.authentications();
                let listed =
                    timeout(Duration::from_secs(5), client.service.list_tools(None)).await??;
                let mut names: Vec<_> =
                    listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
                names.sort_unstable();
                ensure!(
                    names
                        == [
                            "change_directory_remove",
                            "change_file_remove",
                            "change_file_replace",
                            "change_file_write",
                            "change_mkdir",
                            "change_rename",
                            "change_target_quarantine_clear",
                            "inspect_directory",
                            "inspect_file",
                            "inspect_output",
                            "observe_stat",
                            "observe_targets",
                        ],
                    "files-only published an unexpected route: {names:?}"
                );

                // These valid payloads must fail routing, not argument validation.
                // The explicit baseline target must not restore global escape routes;
                // configured sudo availability must not restore ssh_sudo either.
                for host in ["allowed", "locked"] {
                    for (name, args) in [
                        ("exec_command", json!({"host":host,"command":"printf NEVER"})),
                        ("exec_argv", json!({"host":host,"argv":["/usr/bin/true"]})),
                        ("exec_sudo", json!({"host":host,"argv":["/usr/bin/true"]})),
                    ] {
                        let result = timeout(
                            Duration::from_secs(5),
                            client.service.call_tool(params(name, args)),
                        )
                        .await?;
                        match result {
                            Err(rmcp::ServiceError::McpError(error)) => {
                                ensure!(
                                    serde_json::to_value(error)?["code"] == -32602,
                                    "{name} did not reject the hidden route"
                                );
                            }
                            other => anyhow::bail!("{name} remained reachable: {other:?}"),
                        }
                    }
                }
                let reply = client.call("change_file_write", json!({
                "host":"locked","path":file,"content":"MUST_NOT_REPLACE","overwrite":true,
            })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    fs::read(&file)? == b"abc",
                    "read-only target changed existing bytes"
                );
                let reply = client.call("change_file_replace", json!({
                    "host":"locked","path":file,"content":"MUST_NOT_REPLACE","overwrite":true,
                })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&file)? == b"abc");
                let denied_directory = directory.join("mkdir-policy-denied");
                let reply = client
                    .call(
                        "change_mkdir",
                        json!({
                            "host":"locked","path":denied_directory,
                        }),
                    )
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    !denied_directory.exists(),
                    "read-only target created a directory"
                );
                let denied_rename = directory.join("rename-policy-denied");
                let reply = client.call("change_rename", json!({
                    "host":"locked","source":file,"destination":denied_rename,"overwrite":true
                })).await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&file)? == b"abc" && !denied_rename.exists());
                let reply = client
                    .call(
                        "change_file_remove",
                        json!({
                            "host":"locked","path":file
                        }),
                    )
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(
                    fs::read(&file)? == b"abc",
                    "read-only target unlinked an entry"
                );
                ensure!(
                    masters(&client.log)?.is_empty(),
                    "profile denial started an SSH master"
                );
                ensure!(
                    fixture.authentications() == initial_auth,
                    "profile denial authenticated to SSH"
                );

                for host in ["locked", "allowed"] {
                    let reply = client
                        .call("inspect_file", json!({"host":host,"path":file}))
                        .await?;
                    ensure!(
                        succeeded(&reply)?
                            == &json!({
                                "content":"abc","encoding":"utf8","bytes_read":3,"next_offset":3,
                                "eof":true,"content_sha256":ABC_SHA256,
                            })
                    );
                    let reply = client
                        .call("observe_stat", json!({"host":host,"path":file}))
                        .await?;
                    ensure!(succeeded(&reply)? == &native_stat_data(&file, false)?);
                    let reply = client
                        .call(
                            "inspect_directory",
                            json!({
                                "host":host,"path":directory,
                            }),
                        )
                        .await?;
                    ensure!(
                        succeeded(&reply)?
                            == &json!({
                                "entries":[{
                                    "name":"preserved","name_base64":STANDARD.encode(b"preserved"),
                                    "metadata":native_stat_data(&file, false)?,
                                }],
                                "truncated":false,
                            })
                    );
                }
                let created_directory = directory.join("mkdir-allowed");
                let reply = client
                    .call(
                        "change_mkdir",
                        json!({
                            "host":"allowed","path":created_directory,
                        }),
                    )
                    .await?;
                succeeded(&reply)?;
                ensure!(
                    fs::symlink_metadata(&created_directory)?
                        .file_type()
                        .is_dir(),
                    "files-only profile did not create the actual allowed directory"
                );
                ensure!(fs::read_dir(&created_directory)?.next().is_none());
                ensure!(fs::read(&file)? == b"abc", "mkdir changed its sibling file");
                let created_inode = fs::symlink_metadata(&created_directory)?.ino();
                let reply = client
                    .call("change_directory_remove", json!({"host":"locked","path":created_directory}))
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::symlink_metadata(&created_directory)?.ino() == created_inode);
                ensure!(fs::read_dir(&created_directory)?.next().is_none());
                let reply = client
                    .call("change_directory_remove", json!({"host":"allowed","path":created_directory}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    matches!(fs::symlink_metadata(&created_directory), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "files-only profile did not remove the actual allowed empty directory"
                );
                ensure!(fs::read(&file)? == b"abc", "rmdir changed its sibling file");
                let payload = "PROFILE_WRITE_é雪\0END";
                let reply = client
                    .call(
                        "change_file_write",
                        json!({
                            "host":"allowed","path":file,"content":payload,"overwrite":true,
                        }),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":payload.len()}));
                ensure!(
                    fs::read(&file)? == payload.as_bytes(),
                    "allowed write lost bytes"
                );
                let reply = client
                    .call("inspect_file", json!({"host":"locked","path":file}))
                    .await?;
                ensure!(
                    succeeded(&reply)?["content"] == payload,
                    "read-only target did not see the real allowed SFTP write"
                );
                let previous_inode = fs::metadata(&file)?.ino();
                let reply = client.call("change_file_replace", json!({
                    "host":"allowed","path":file,"content":payload,"overwrite":true,
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":payload.len()}));
                ensure!(fs::read(&file)? == payload.as_bytes());
                ensure!(fs::metadata(&file)?.ino() != previous_inode);
                ensure!(fs::metadata(&file)?.mode() & 0o7777 == 0o600);
                let reply = client.call("inspect_file", json!({"host":"locked","path":file})).await?;
                ensure!(succeeded(&reply)?["content"] == payload);
                let renamed = directory.join("renamed");
                let before = fs::symlink_metadata(&file)?.ino();
                let reply = client
                    .call(
                        "change_rename",
                        json!({
                            "host":"allowed","source":file,"destination":renamed,"overwrite":true
                        }),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(!file.exists() && fs::symlink_metadata(&renamed)?.ino() == before);
                ensure!(fs::read(&renamed)? == payload.as_bytes());
                let reply = client
                    .call("inspect_file", json!({"host":"locked","path":renamed}))
                    .await?;
                ensure!(succeeded(&reply)?["content"] == payload);
                let reply = client
                    .call("change_file_remove", json!({"host":"locked","path":renamed}))
                    .await?;
                failed(&reply, "policy_denied")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::symlink_metadata(&renamed)?.ino() == before);
                ensure!(fs::read(&renamed)? == payload.as_bytes());
                let reply = client
                    .call("change_file_remove", json!({"host":"allowed","path":renamed}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    fs::symlink_metadata(&renamed).is_err(),
                    "files-only profile did not unlink the actual allowed entry"
                );
                ensure!(fs::read_dir(&directory)?.next().is_none());
                ensure!(
                    !masters(&client.log)?.is_empty(),
                    "successful file calls started no master"
                );
                ensure!(
                    fixture.authentications() > initial_auth,
                    "successful file calls did not authenticate to sshd"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_write_file() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let preserved = fixture.root.path().join("write-invalid-preserved");
            fs::write(&preserved, b"KEEP_INVALID_WRITE")?;
            for (content, encoding, code) in [
                ("x".repeat(1_048_577), "utf8", "invalid_argument"),
                ("YR==".to_owned(), "base64", "invalid_encoding"),
            ] {
                let reply = client.call("change_file_write", json!({
                    "host":"plain","path":preserved,"content":content,"encoding":encoding,"overwrite":true,
                })).await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&preserved)? == b"KEEP_INVALID_WRITE");
                ensure!(masters(&client.log)?.is_empty(), "invalid write acquired SSH");
            }
            fixture.await_authentications(2).await?;
            succeeded(&exec(&client, "printf WRITE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let root = fixture.root.path();
            let payload = "WRITE_PRIVATE_é雪\0END";
            let cap = "x".repeat(1_048_576);
            for (name, content, encoding, expected) in [
                ("write-unicode", payload, "utf8", payload.as_bytes()),
                ("write-empty", "", "utf8", b"".as_slice()),
                ("write-exact-cap", cap.as_str(), "utf8", cap.as_bytes()),
                ("write-binary", "AP+AQQ==", "base64", b"\0\xff\x80A".as_slice()),
                ("write-'\";~$*\n$(printf EVALUATED)", "LITERAL_WRITE", "utf8", b"LITERAL_WRITE".as_slice()),
            ] {
                let path = root.join(name);
                let reply = client.call("change_file_write", json!({
                    "host":"plain","path":path,"content":content,"encoding":encoding
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":expected.len()}), "{name}: {reply}");
                ensure!(fs::read(&path)? == expected, "{name}: native bytes differ");
            }
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
                .context("native prerequisite: current account")?;
            let home = fs::canonicalize(user.dir)?;
            let mut relative = PathBuf::new();
            for component in home.components() {
                if matches!(component, std::path::Component::Normal(_)) {
                    relative.push("..");
                }
            }
            relative.push(root.strip_prefix("/")?);
            relative.push("write-relative");
            let reply = client.call("change_file_write", json!({
                "host":"plain","path":relative,"content":"RELATIVE_WRITE"
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":14}));
            ensure!(fs::read(root.join("write-relative"))? == b"RELATIVE_WRITE");

            let existing = root.join("write-existing");
            fs::write(&existing, b"KEEP_OLD_TAIL")?;
            let link = root.join("write-existing-link");
            symlink(&existing, &link)?;
            let dangling = root.join("write-dangling-link");
            let absent = root.join("write-dangling-target");
            symlink(&absent, &dangling)?;
            for path in [&existing, &link, &dangling] {
                let reply = client.call("change_file_write", json!({
                    "host":"plain","path":path,"content":"MUST_NOT_REPLACE"
                })).await?;
                failed(&reply, "already_exists")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                ensure!(fs::read(&existing)? == b"KEEP_OLD_TAIL");
                ensure!(fs::read_link(&link)? == existing);
                ensure!(fs::read_link(&dangling)? == absent && !absent.exists());
            }
            let reply = client.call("change_file_write", json!({
                "host":"plain","path":existing,"content":"short","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":5}));
            ensure!(fs::read(&existing)? == b"short", "overwrite retained old tail");
            let reply = client.call("change_file_write", json!({
                "host":"plain","path":link,"content":"L","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":1}));
            ensure!(fs::read(&existing)? == b"L" && fs::read_link(&link)? == existing);
            let reply = client.call("change_file_write", json!({
                "host":"plain","path":dangling,"content":"NEW","overwrite":true
            })).await?;
            ensure!(succeeded(&reply)? == &json!({"bytes_written":3}));
            ensure!(fs::read(&absent)? == b"NEW" && fs::read_link(&dangling)? == absent);

            let parent = root.join("write-missing-parent");
            let reply = client.call("change_file_write", json!({
                "host":"plain","path":parent.join("child"),"content":"NO_MKDIR"
            })).await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(!parent.exists(), "write created an implicit parent");
            let denied = root.join("write-denied");
            fs::write(&denied, b"DENIED_OLD_BYTES")?;
            fs::set_permissions(&denied, fs::Permissions::from_mode(0o400))?;
            let attempted = client.call("change_file_write", json!({
                "host":"plain","path":denied,"content":"DENIED_NEW_BYTES","overwrite":true
            })).await;
            let restored = fs::set_permissions(&denied, fs::Permissions::from_mode(0o600));
            let reply = attempted?;
            restored?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::read(&denied)? == b"DENIED_OLD_BYTES");

            let reply = client.call("inspect_file", json!({"host":"plain","path":existing})).await?;
            ensure!(succeeded(&reply)?["content"] == "L");
            let reply = client.call("observe_stat", json!({"host":"plain","path":existing})).await?;
            ensure!(succeeded(&reply)? == &native_stat_data(&existing, false)?);
            ensure!(live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "exec/read/stat/write did not share the ordinary master");

            let unsupported = root.join("write-no-subsystem");
            let reply = client.call("change_file_write", json!({
                "host":"nosftp","path":unsupported,"content":"NO_FALLBACK"
            })).await?;
            ensure!(matches!(reply["error"]["code"].as_str(), Some("unsupported" | "io_error" | "connection_lost")));
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(!unsupported.exists(), "missing subsystem ran a write fallback");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client.call("exec_command", json!({
                "host":"nosftp","command":"printf WRITE_MASTER_HEALTHY"
            })).await?;
            ensure!(succeeded(&reply)?["stdout"] == "WRITE_MASTER_HEALTHY");
            ensure!(masters(&client.log)? == before);
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        for secret in ["WRITE_PRIVATE_", "LITERAL_WRITE", "DENIED_NEW_BYTES", "write-existing",
            "write-dangling", "write-no-subsystem"] {
            ensure!(!log.text().contains(secret), "write audit disclosed path or content");
        }
        let records = log.final_records()?;
        let writes: Vec<_> = records.iter().filter(|record| record["tool"] == "change_file_write").collect();
        ensure!(!writes.is_empty());
        for record in writes {
            ensure!(record["identity_role"] == "ordinary");
            for field in ["path", "content", "payload"] {
                ensure!(record.get(field).is_none(), "write audit disclosed {field}");
            }
        }
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_write_close_and_write_failures() -> Result<()> {
    let server = Fixture::sftp_server()?;
    for (request, expected, code) in [
        ("close", b"NEW".as_slice(), "permission_denied"),
        ("write", b"".as_slice(), "permission_denied"),
    ] {
        // The actual OpenSSH server denies this protocol request; no emulator
        // can accidentally acknowledge a write or close that never happened.
        let subsystem = format!("{} -P {request}", server.display());
        let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
        let scenario = async {
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                succeeded(&exec(&client, "printf WRITE_FAULT_MASTER").await?)?;
                let owned = observed_masters(&client.log, 1).await?;
                let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
                let path = fixture.root.path().join(format!("write-fault-{request}"));
                fs::write(&path, b"OLD_BYTES_LONGER_THAN_NEW")?;
                let reply = client
                    .call(
                        "change_file_write",
                        json!({
                            "host":"plain","path":path,"content":"NEW","overwrite":true
                        }),
                    )
                    .await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(
                    fs::read(&path)? == expected,
                    "{request}: incorrect post-mutation filesystem state"
                );
                let audit = await_audit(&client.log, "finish", code).await?;
                ensure!(
                    audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary"
                );
                ensure!(
                    live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                    "{request} failure discarded the healthy ordinary master"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let owned = masters(&client.log);
            let stopped = client.stop().await;
            let gone = match owned {
                Ok(owned) => assert_masters_gone(&owned).await,
                Err(error) => Err(error),
            };
            cases?;
            stopped?;
            gone
        }
        .await;
        let cleanup = fixture.stop().await;
        scenario?;
        cleanup?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_mkdir() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str("\n[targets.mkdir-locked]\nssh_host = 'plain'\nmax_tier = 'inspect'\n");
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("mkdir-private");
        fs::create_dir(&directory)?;
        let sibling = directory.join("preserved-file");
        fs::write(&sibling, b"MKDIR_KEEP_SIBLING")?;
        let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"mkdir\0invalid"}),
                json!({"host":"plain","path":directory.join("zero"),"timeout_secs":0}),
                json!({"host":"plain","path":directory.join("over-limit"),"timeout_secs":16}),
            ] {
                let reply = client.call("change_mkdir", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let denied = directory.join("policy-denied");
            let reply = client
                .call(
                    "change_mkdir",
                    json!({
                        "host":"mkdir-locked","path":denied
                    }),
                )
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(
                masters(&client.log)?.is_empty(),
                "invalid or denied mkdir acquired SSH"
            );
            ensure!(
                fixture.authentications() == initial_auth,
                "invalid or denied mkdir authenticated"
            );
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "rejected mkdir changed directory entries"
            );

            succeeded(&exec(&client, "printf MKDIR_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let names = [
                "ordinary",
                "  é雪 directory  ",
                "'\";~$*\n$(printf EVALUATED)",
            ];
            for name in names {
                let path = directory.join(name);
                let reply = client
                    .call("change_mkdir", json!({"host":"plain","path":path}))
                    .await?;
                succeeded(&reply)?;
                ensure!(
                    fs::symlink_metadata(&path)?.file_type().is_dir(),
                    "{name:?}: no actual directory"
                );
                ensure!(
                    fs::read_dir(&path)?.next().is_none(),
                    "{name:?}: directory not empty"
                );
                let reply = client
                    .call("observe_stat", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(succeeded(&reply)? == &native_stat_data(&path, false)?);
            }
            let existing = directory.join("ordinary");
            let child = existing.join("keep-child");
            fs::write(&child, b"KEEP_DIRECTORY_CHILD")?;
            let live = directory.join("live-link");
            symlink(&existing, &live)?;
            let dangling = directory.join("dangling-link");
            let absent = directory.join("absent-target");
            symlink(&absent, &dangling)?;
            for path in [&existing, &sibling, &live, &dangling] {
                let before = fs::symlink_metadata(path)?;
                let reply = client
                    .call("change_mkdir", json!({"host":"plain","path":path}))
                    .await?;
                failed(&reply, "already_exists")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                let after = fs::symlink_metadata(path)?;
                ensure!(
                    after.ino() == before.ino() && after.file_type() == before.file_type(),
                    "{}: existing entry replaced",
                    path.display()
                );
                ensure!(fs::read(&child)? == b"KEEP_DIRECTORY_CHILD");
                ensure!(fs::read(&sibling)? == b"MKDIR_KEEP_SIBLING");
                ensure!(fs::read_link(&live)? == existing);
                ensure!(fs::read_link(&dangling)? == absent && !absent.exists());
            }
            let missing = directory.join("missing-parent");
            let reply = client
                .call(
                    "change_mkdir",
                    json!({
                        "host":"plain","path":missing.join("child")
                    }),
                )
                .await?;
            ensure!(
                matches!(
                    reply["error"]["code"].as_str(),
                    Some("not_found" | "permission_denied" | "io_error")
                ),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                !missing.exists(),
                "mkdir recursively created a missing parent"
            );
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = names
                .iter()
                .map(|name| std::ffi::OsString::from(*name))
                .collect::<Vec<_>>();
            expected.extend(
                ["preserved-file", "live-link", "dangling-link"].map(std::ffi::OsString::from),
            );
            expected.sort();
            ensure!(
                entries == expected,
                "mkdir changed sibling entries or expanded a literal path"
            );
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"MKDIR_KEEP_SIBLING");
            let reply = client
                .call("inspect_file", json!({"host":"plain","path":sibling}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "MKDIR_KEEP_SIBLING");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "mkdir discarded the shared healthy master"
            );

            let unsupported = directory.join("no-subsystem");
            let reply = client
                .call("change_mkdir", json!({"host":"nosftp","path":unsupported}))
                .await?;
            ensure!(
                matches!(
                    reply["error"]["code"].as_str(),
                    Some("unsupported" | "io_error" | "connection_lost")
                ),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(
                !unsupported.exists(),
                "unavailable SFTP ran a mkdir fallback"
            );
            let before = observed_masters(&client.log, 2).await?;
            let reply = client
                .call(
                    "exec_command",
                    json!({
                        "host":"nosftp","command":"printf MKDIR_NO_SUBSYSTEM_HEALTHY"
                    }),
                )
                .await?;
            ensure!(succeeded(&reply)?["stdout"] == "MKDIR_NO_SUBSYSTEM_HEALTHY");
            ensure!(
                masters(&client.log)? == before,
                "unavailable SFTP replaced a healthy master"
            );
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        ensure!(
            !log.text().contains("mkdir-private"),
            "mkdir audit disclosed a private path"
        );
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_mkdir_dispatch_failure() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    // This is the real SFTP server's policy denial, not a simulated reply.
    // Its own refusal log counts requests, including retries within one channel.
    let script = format!(
        "echo launch >> {}; exec {} -P mkdir -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MKDIR_FAULT_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("mkdir-fault");
            fs::create_dir(&directory)?;
            let sibling = directory.join("sibling");
            fs::write(&sibling, b"KEEP_FAULT_SIBLING")?;
            let path = directory.join("denied");
            let reply = client
                .call("change_mkdir", json!({"host":"plain","path":path}))
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(!path.exists(), "SFTP denial caused a shell fallback");
            ensure!(fs::read(&sibling)? == b"KEEP_FAULT_SIBLING");
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "SFTP denial changed sibling entries"
            );
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "SFTP mkdir denial discarded a healthy master"
            );
            ensure!(
                fs::read_to_string(&launches)?.lines().count() == 1,
                "mkdir denial replayed the SFTP session"
            );
            let log = fs::read_to_string(&requests)?;
            ensure!(
                log.lines()
                    .filter(|line| line.contains("Refusing") && line.contains("mkdir request"))
                    .count()
                    == 1,
                "expected exactly one actual MKDIR refusal, without replay: {log}"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_mkdir_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let server = Fixture::sftp_server()?;
    // Delay only the handshake; the finite guard is awaited even on assertion
    // failure, before its private filesystem is removed.
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {}",
        started.display(),
        done.display(),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MKDIR_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("mkdir-delay");
            fs::create_dir(&directory)?;
            let sibling = directory.join("sibling");
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let path = directory.join("never-dispatched");
            let reply = client
                .call(
                    "change_mkdir",
                    json!({
                        "host":"plain","path":path,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake interruption discarded a healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "handshake timeout replayed SFTP"
            );
            ensure!(!path.exists(), "handshake timeout ran a mkdir fallback");
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(
                fs::read_dir(&directory)?.count() == 1,
                "handshake timeout changed sibling entries"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // Await the finite remote guard even when the request assertion failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        stopped?;
        completed?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH/coreutils and a non-root local account"]
async fn ssh_named_bindings() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let printf = binding_program("printf")?;
        let id = binding_program("id")?;
        let sleeper = binding_program("sleep")?;
        // `id -u`: the full `id` line lists every supplementary group and can
        // exceed this config's 1024-byte output limit on directory-joined hosts.
        let identity = support::run(Command::new(&id).arg("-u")).await?;
        ensure!(identity.status.success() && identity.stderr.is_empty());
        let identity = String::from_utf8(identity.stdout)?;
        let config = fixture.root.path().join("named-bindings.toml");
        let ssh_config = serde_json::to_string(&fixture.ssh_config.to_string_lossy())?;
        let printf_path = serde_json::to_string(&printf.to_string_lossy())?;
        let id_path = serde_json::to_string(&id.to_string_lossy())?;
        let sleep_path = serde_json::to_string(&sleeper.to_string_lossy())?;
        fs::write(&config, formatdoc! {r#"
            capabilities = {{ named = true }}
            [selection]
            allow = ["literal_values", "ordinary_identity", "missing_account", "bounded_pause"]
            [ssh]
            config_file = {ssh_config}
            [limits]
            operation_timeout_secs = 10
            max_timeout_secs = 15
            max_output_bytes = 1024
            [targets.plain]
            ssh_host = "plain"
            [targets.plain.sudo]
            mode = "same-account"
            users = ["root"]
            programs = [{id_path}]
            [targets.denied]
            ssh_host = "must-never-connect"
            [targets.locked]
            ssh_host = "must-never-connect"
            selection = {{ allow = [] }}
            [tools.literal_values]
            description = "Emit bounded literal data with a fixed format."
            revision = "literal-r1"
            targets = ["plain", "locked"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{ kind = "native_argv", program = {printf_path}, argv = ["--", '%s\000%s\000%s', {{input="text"}}, {{input="number"}}, {{input="flag"}}] }}
            input_schema = {{ type="object", additionalProperties=false, required=["text","number","flag"], properties={{ text={{type="string",maxLength=256}}, number={{type="integer",minimum=-9,maximum=9}}, flag={{type="boolean"}} }} }}
            result = {{kind="command"}}
            [tools.ordinary_identity]
            description = "Observe the ordinary account without caller-selected options."
            revision = "identity-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={id_path},argv=["-u"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            [tools.missing_account]
            description = "Observe a fixed invalid empty account."
            revision = "missing-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["read"]
            execution = {{kind="native_argv",program={id_path},argv=["--",""]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            [tools.bounded_pause]
            description = "A finite fixed native sleep; cancellation is uncertain."
            revision = "pause-r1"
            targets = ["plain"]
            authority = "ordinary"
            effects = ["availability"]
            execution = {{kind="native_argv",program={sleep_path},argv=["--","3"]}}
            input_schema = {{type="object",additionalProperties=false,required=[],properties={{}}}}
            result = {{kind="command"}}
            limits = {{timeout_secs=5,max_output_bytes=128}}
        "#})?;
        let client = Client::start(&config).await?;
        let cases = async {
            let listed = timeout(Duration::from_secs(5), client.service.list_tools(None)).await??;
            let mut names: Vec<_> = listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
            names.sort_unstable();
            ensure!(names == [
                "bounded_pause", "change_target_quarantine_clear", "inspect_output", "literal_values",
                "missing_account", "observe_targets", "ordinary_identity",
            ], "actions-only exposed an unexpected tool: {names:?}");
            let initial_auth = fixture.authentications();
            let valid = json!({"host":"plain","text":"VALID","number":1,"flag":true});
            // Shape errors cannot override operator authority or fixed layout.
            for extra in ["program","argv","cwd","stdin","user","role","authority","shell"] {
                let mut args = valid.clone();
                args[extra] = json!("BINDING_FORBIDDEN_OVERRIDE");
                let result = timeout(
                    Duration::from_secs(5),
                    client.service.call_tool(params("literal_values", args)),
                ).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("binding accepted {extra}: {other:?}"),
                }
            }
            for (name,args) in [
                ("exec_command",json!({"host":"plain","command":"printf NEVER"})),
                ("exec_argv",json!({"host":"plain","argv":[id]})),
                ("exec_sudo",json!({"host":"plain","argv":[id]})),
            ] {
                let result = timeout(Duration::from_secs(5),client.service.call_tool(params(name,args))).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("actions-only raw route remained reachable: {other:?}"),
                }
            }
            for (field, value) in [("number",json!("1")),("flag",json!(1)),("text",json!(false))] {
                let mut args = valid.clone();
                args[field] = value;
                let result = timeout(
                    Duration::from_secs(5),
                    client.service.call_tool(params("literal_values", args)),
                ).await?;
                match result {
                    Err(rmcp::ServiceError::McpError(error)) => {
                        ensure!(serde_json::to_value(error)?["code"] == -32602);
                    }
                    other => anyhow::bail!("binding accepted wrong {field} type: {other:?}"),
                }
            }
            for (field, value, code) in [
                ("host",json!("denied"),"policy_denied"),
                ("host",json!("unknown-target"),"policy_denied"),
                ("host",json!("locked"),"policy_denied"),
                ("text",json!("x".repeat(257)),"invalid_argument"),
                ("text",json!("BINDING_NUL_SECRET\0"),"invalid_argument"),
                ("number",json!(-10),"invalid_argument"),
                ("number",json!(10),"invalid_argument"),
            ] {
                let mut args = valid.clone();
                args[field] = value;
                let reply = client.call("literal_values", args).await?;
                failed(&reply, code)?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client.call("bounded_pause",json!({"host":"plain","timeout_secs":6})).await?;
            failed(&reply,"invalid_argument")?;
            ensure!(masters(&client.log)?.is_empty(), "rejection acquired a master");
            ensure!(fixture.authentications() == initial_auth, "rejection authenticated");
            let injected = fixture.root.path().join("binding-injected");
            let injection = format!("$(touch {}); `touch {}`",quote(&injected.to_string_lossy()),quote(&injected.to_string_lossy()));
            let max_text = "雪".repeat(256);
            let payloads = [
                "", "--help", "-n", "BINDING_PAYLOAD_SECRET_09d2",
                "single' double\" \\ $HOME ; & | < > * ? [ ] { }",
                "日本語 🦀", "control:\n\r\t\u{1b}\u{7f}", &injection, &max_text,
            ];
            for (index, text) in payloads.into_iter().enumerate() {
                let number = if index % 2 == 0 { -9 } else { 9 };
                let flag = index % 2 == 0;
                let reply = client.call("literal_values",json!({
                    "host":"plain","text":text,"number":number,"flag":flag,
                })).await?;
                let data = succeeded(&reply)?;
                ensure!(data["stdout"] == format!("{text}\0{number}\0{flag}"), "literal conversion lost data: {reply}");
                ensure!(data["stderr"] == "" && data["exit_code"] == 0);
                ensure!(data["termination"] == "exited" && data["remote_may_still_be_running"] == false);
                ensure!(data["stdout_lossy"] == false && data["stderr_lossy"] == false);
                ensure!(!injected.exists(), "input interpolated into remote shell syntax");
            }
            let reply = client.call("ordinary_identity",json!({"host":"plain"})).await?;
            let observed = succeeded(&reply)?["stdout"].as_str().context("identity stdout")?.to_owned();
            ensure!(observed == identity, "binding changed account identity: local {identity:?}, remote {observed:?}");
            let reply = client.call("missing_account",json!({"host":"plain"})).await?;
            failed(&reply,"command_failed")?;
            ensure!(reply["data"]["stdout"] == "" && reply["data"]["exit_code"] == 1);
            ensure!(!reply["data"]["stderr"].as_str().context("id stderr")?.is_empty());
            ensure!(reply["data"]["termination"] == "exited");
            ensure!(reply["error"]["remote_state_unknown"] == false);
            let owned = observed_masters(&client.log,1).await?;
            fixture.await_authentications(initial_auth + 1).await?;
            let timed = client.call("bounded_pause",json!({"host":"plain","timeout_secs":1})).await?;
            failed(&timed,"timeout")?;
            ensure!(timed["data"]["termination"] == "timeout" && timed["data"]["exit_code"].is_null());
            ensure!(timed["data"]["remote_may_still_be_running"] == true);
            ensure!(timed["error"]["remote_state_unknown"] == true);
            failed(
                &client.call("bounded_pause", json!({"host":"plain"})).await?,
                "target_quarantined",
            )?;
            ensure!(
                succeeded(
                    &client
                        .call(
                            "change_target_quarantine_clear",
                            json!({"host":"plain","acknowledge_remote_state_reconciled":true}),
                        )
                        .await?
                )?["cleared"]
                    == true
            );
            let session_count = || fixture.listeners[0].log.text().lines()
                .filter(|line| line.contains("Starting session: command")).count();
            let before = session_count();
            let request = ClientRequest::CallToolRequest(CallToolRequest::new(params(
                "bounded_pause",json!({"host":"plain"}),
            )));
            let handle = timeout(Duration::from_secs(5),client.service.send_cancellable_request(
                request,PeerRequestOptions::default(),
            )).await??;
            // Observe real sshd dispatch before cancellation, not a fabricated reply.
            let dispatched = timeout(Duration::from_secs(5),async {
                while session_count() <= before { sleep(Duration::from_millis(20)).await; }
            }).await;
            let cancelled = timeout(Duration::from_secs(5),handle.cancel(Some("named native cancellation".into()))).await;
            dispatched.context("bound sleep was not dispatched")?;
            cancelled??;
            let audit = await_audit(&client.log,"finish","cancelled").await?;
            ensure!(audit["tool"] == "bounded_pause" && audit["exit_code"].is_null());
            ensure!(audit["remote_state_unknown"] == true);
            // A later ordinary binding must still use the original transport.
            let reply = client.call("ordinary_identity",json!({"host":"plain"})).await?;
            ensure!(succeeded(&reply)?["stdout"] == identity);
            let check = support::run(Command::new(&fixture.ssh)
                .arg("-F").arg(&fixture.ssh_config).arg("-S").arg(&owned[0].1)
                .args(["-O","check","plain"])).await?;
            ensure!(check.status.success());
            ensure!(String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={})",owned[0].0)));
            ensure!(masters(&client.log)? == owned, "binding replaced its healthy master");
            fixture.await_authentications(initial_auth + 1).await?;
            Ok::<_,anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        // Fixed sleep is finite. Give dispatched work its bounded settling window
        // even on assertion failure; neither channel teardown nor this wait proves
        // remote termination, and there is no remote process-kill claim.
        sleep(Duration::from_secs(4)).await;
        cases?;
        let log = stopped?;
        gone?;
        let text = log.text();
        for secret in ["BINDING_PAYLOAD_SECRET_09d2","BINDING_NUL_SECRET","BINDING_FORBIDDEN_OVERRIDE"] {
            ensure!(!text.contains(secret), "binding audit leaked caller payload");
        }
        for program in [&printf,&id,&sleeper] {
            ensure!(!text.contains(program.to_string_lossy().as_ref()), "audit leaked fixed executable");
        }
        let records = log.final_records()?;
        for (name,revision) in [
            ("literal_values","literal-r1"),("ordinary_identity","identity-r1"),
            ("missing_account","missing-r1"),("bounded_pause","pause-r1"),
        ] {
            let events: Vec<_> = records.iter().filter(|record| record["tool"] == name
                && ["start","finish"].contains(&record["event"].as_str().unwrap_or(""))).collect();
            ensure!(events.iter().any(|record| record["event"] == "start"));
            ensure!(events.iter().any(|record| record["event"] == "finish"));
            for record in events {
                ensure!(record["identity_role"] == "ordinary");
                ensure!(record["binding_revision"] == revision && record["executor"] == "native_argv");
                for forbidden in ["program","argv","command","stdin","stdout","stderr","user","text","number","flag"] {
                    ensure!(record.get(forbidden).is_none(), "binding audit exposed {forbidden}");
                }
            }
        }
        Ok::<_,anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_rename_moves_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.rename-locked]\nssh_host = 'plain'\nmax_tier = 'inspect'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("rename-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let destination = directory.join("destination");
        fs::write(&source, b"RENAME_SOURCE_BYTES")?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","source":"","destination":destination,"overwrite":true}),
                json!({"host":"plain","source":source,"destination":"","overwrite":true}),
                json!({"host":"plain","source":"source\0invalid","destination":destination,"overwrite":true}),
                json!({"host":"plain","source":source,"destination":"destination\0invalid","overwrite":true}),
                json!({"host":"plain","source":source,"destination":destination,"overwrite":true,"timeout_secs":0}),
                json!({"host":"plain","source":source,"destination":destination,"overwrite":true,"timeout_secs":16}),
            ] {
                let reply = client.call("change_rename", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call(
                    "change_rename",
                    json!({"host":"rename-locked","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected rename acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected rename authenticated");
            ensure!(fs::read(&source)? == b"RENAME_SOURCE_BYTES");
            ensure!(!destination.exists() && fs::read_dir(&directory)?.count() == 1);

            succeeded(&exec(&client, "printf RENAME_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let inode = fs::symlink_metadata(&source)?.ino();
            let reply = client
                .call(
                    "change_rename",
                    json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&source).is_err(), "source survived successful rename");
            ensure!(fs::symlink_metadata(&destination)?.ino() == inode);
            ensure!(fs::read(&destination)? == b"RENAME_SOURCE_BYTES");

            let replacement = directory.join("replacement");
            let retained = directory.join("old-destination-hardlink");
            fs::hard_link(&destination, &retained)?;
            fs::write(&replacement, b"EXPLICIT_OVERWRITE_BYTES")?;
            let replacement_inode = fs::symlink_metadata(&replacement)?.ino();
            let reply = client
                .call(
                    "change_rename",
                    json!({"host":"plain","source":replacement,"destination":destination,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&replacement).is_err());
            ensure!(fs::symlink_metadata(&destination)?.ino() == replacement_inode);
            ensure!(fs::read(&destination)? == b"EXPLICIT_OVERWRITE_BYTES");
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::read(&retained)? == b"RENAME_SOURCE_BYTES");

            let tree = directory.join("tree");
            let moved_tree = directory.join("moved-tree");
            fs::create_dir(&tree)?;
            fs::write(tree.join("child"), b"TREE_CHILD")?;
            let tree_inode = fs::symlink_metadata(&tree)?.ino();
            let child_inode = fs::symlink_metadata(tree.join("child"))?.ino();
            let reply = client
                .call(
                    "change_rename",
                    json!({"host":"plain","source":tree,"destination":moved_tree,"overwrite":true}),
                )
                .await?;
            ensure!(succeeded(&reply)? == &json!({"renamed":true}));
            ensure!(fs::symlink_metadata(&tree).is_err());
            ensure!(fs::symlink_metadata(&moved_tree)?.ino() == tree_inode);
            ensure!(fs::symlink_metadata(moved_tree.join("child"))?.ino() == child_inode);
            ensure!(fs::read(moved_tree.join("child"))? == b"TREE_CHILD");

            let missing_link_target = directory.join("missing-link-target");
            for (index, target) in [&destination, &missing_link_target]
                .into_iter()
                .enumerate()
            {
                let link = directory.join(format!("link-{index}"));
                let moved_link = directory.join(format!("moved-link-{index}"));
                symlink(target, &link)?;
                let link_inode = fs::symlink_metadata(&link)?.ino();
                let reply = client
                    .call(
                        "change_rename",
                        json!({"host":"plain","source":link,"destination":moved_link,"overwrite":true}),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(fs::symlink_metadata(&link).is_err());
                let metadata = fs::symlink_metadata(&moved_link)?;
                ensure!(metadata.file_type().is_symlink() && metadata.ino() == link_inode);
                ensure!(fs::read_link(&moved_link)? == *target);
            }
            ensure!(fs::read(&destination)? == b"EXPLICIT_OVERWRITE_BYTES");
            ensure!(fs::symlink_metadata(&missing_link_target).is_err());

            let literal_names = [
                ("  é雪 source  ", "  雪é destination  "),
                ("'\";~$*\n$(printf EVALUATED)", "${HOME} {{rename}}\n'\";*"),
            ];
            for (from, to) in literal_names {
                let source = directory.join(from);
                let destination = directory.join(to);
                fs::write(&source, b"LITERAL_RENAME_BYTES")?;
                let inode = fs::symlink_metadata(&source)?.ino();
                let reply = client
                    .call(
                        "change_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                    )
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"renamed":true}));
                ensure!(fs::symlink_metadata(&source).is_err(), "{from:?}: source survived");
                ensure!(fs::symlink_metadata(&destination)?.ino() == inode, "{to:?}: inode changed");
                ensure!(fs::read(&destination)? == b"LITERAL_RENAME_BYTES");
            }
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "destination", "old-destination-hardlink", "moved-tree",
                "moved-link-0", "moved-link-1", "  雪é destination  ",
                "${HOME} {{rename}}\n'\";*",
            ]
            .map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "rename expanded a literal name or changed siblings");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "rename replaced the shared healthy master"
            );
            let reply = client
                .call("inspect_file", json!({"host":"plain","path":retained}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "RENAME_SOURCE_BYTES");
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        ensure!(!log.text().contains("rename-private"), "rename audit disclosed private paths");
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_no_overwrite_preserves_entries() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "exec {} -e -l VERBOSE 2>> {}",
        server.display(),
        requests.display()
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let directory = fixture.root.path().join("protected-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let existing = directory.join("existing");
        let tree = directory.join("tree");
        let live = directory.join("live");
        let dangling = directory.join("dangling");
        let absent = directory.join("absent");
        let missing_target = directory.join("missing-target");
        fs::write(&source, b"KEEP_SOURCE")?;
        fs::write(&existing, b"KEEP_DESTINATION")?;
        fs::create_dir(&tree)?;
        fs::write(tree.join("child"), b"KEEP_CHILD")?;
        symlink(&existing, &live)?;
        symlink(&missing_target, &dangling)?;
        let entries = [&source, &existing, &tree, &live, &dangling];
        let inodes = entries
            .iter()
            .map(|path| fs::symlink_metadata(path).map(|metadata| metadata.ino()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf PROTECTED_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            // Existing files, directories, live/dangling links and absent names
            // all require the same conservative pre-dispatch rejection.
            for (source, destination) in [
                (&source, &existing),
                (&source, &tree),
                (&source, &live),
                (&source, &dangling),
                (&source, &absent),
                (&tree, &absent),
                (&live, &absent),
                (&dangling, &absent),
            ] {
                let omitted_err = client
                    .service
                    .call_tool(params(
                        "change_rename",
                        json!({"host":"plain","source":source,"destination":destination}),
                    ))
                    .await
                    .unwrap_err();
                ensure!(
                    format!("{omitted_err:?}").contains("-32602")
                        || matches!(omitted_err, rmcp::ServiceError::McpError(_))
                );
                let reply = client
                    .call(
                        "change_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":false}),
                    )
                    .await?;
                failed(&reply, "unsupported")?;
                    ensure!(
                        reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false
                    );
                    for (path, inode) in entries.iter().zip(&inodes) {
                        ensure!(
                            fs::symlink_metadata(path)?.ino() == *inode,
                            "{} changed",
                            path.display()
                        );
                    }
                    ensure!(fs::read(directory.join("source"))? == b"KEEP_SOURCE");
                    ensure!(fs::read(&existing)? == b"KEEP_DESTINATION");
                    ensure!(fs::read(tree.join("child"))? == b"KEEP_CHILD");
                    ensure!(fs::read_link(&live)? == existing);
                    ensure!(fs::read_link(&dangling)? == missing_target);
                    ensure!(fs::symlink_metadata(&absent).is_err());
                    ensure!(fs::symlink_metadata(&missing_target).is_err());
                    ensure!(fs::read_dir(&directory)?.count() == 5);
            }
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "unsupported rename discarded a healthy master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("protected-private"),
            "rename audit disclosed private paths"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.contains("session opened") && log.contains("session closed"),
            "{log}"
        );
        for mutation in [
            "rename old ",
            "open \"",
            "mkdir ",
            "remove name ",
            "rmdir name ",
            "symlink old ",
            "hardlink old ",
            "setstat name ",
            "fsetstat ",
        ] {
            ensure!(
                !log.contains(mutation),
                "unsupported rename dispatched {mutation:?}: {log}"
            );
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_without_posix_extension_preserves_entries() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let server = Fixture::sftp_server()?;
    // OpenSSH suppresses the advertised extension for a denied request.
    let script = format!(
        "exec {} -P posix-rename -e -l VERBOSE 2>> {}",
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let directory = fixture.root.path().join("extension-private");
        fs::create_dir(&directory)?;
        let source = directory.join("source");
        let existing = directory.join("existing");
        let live = directory.join("live");
        let dangling = directory.join("dangling");
        let absent = directory.join("absent");
        let missing_target = directory.join("missing-target");
        fs::write(&source, b"KEEP_EXTENSION_SOURCE")?;
        fs::write(&existing, b"KEEP_EXTENSION_DESTINATION")?;
        symlink(&existing, &live)?;
        symlink(&missing_target, &dangling)?;
        let entries = [&source, &existing, &live, &dangling];
        let inodes = entries
            .iter()
            .map(|path| fs::symlink_metadata(path).map(|metadata| metadata.ino()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf EXTENSION_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            for destination in [&existing, &live, &dangling, &absent] {
                let reply = client
                    .call(
                        "change_rename",
                        json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                    )
                    .await?;
                failed(&reply, "unsupported")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
                for (path, inode) in entries.iter().zip(&inodes) {
                    ensure!(fs::symlink_metadata(path)?.ino() == *inode, "{} changed", path.display());
                }
                ensure!(fs::read(&source)? == b"KEEP_EXTENSION_SOURCE");
                ensure!(fs::read(&existing)? == b"KEEP_EXTENSION_DESTINATION");
                ensure!(fs::read_link(&live)? == existing);
                ensure!(fs::read_link(&dangling)? == missing_target);
                ensure!(fs::symlink_metadata(&absent).is_err());
                ensure!(fs::symlink_metadata(&missing_target).is_err());
                ensure!(fs::read_dir(&directory)?.count() == 4);
            }
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "missing extension discarded a healthy master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("extension-private"), "rename audit disclosed private paths");
        let log = fs::read_to_string(&requests)?;
        ensure!(log.contains("session opened") && log.contains("session closed"), "{log}");
        for mutation in [
            "rename old ", "open \"", "mkdir ", "remove name ", "rmdir name ",
            "symlink old ", "hardlink old ", "setstat name ", "fsetstat ",
        ] {
            ensure!(!log.contains(mutation), "missing extension dispatched {mutation:?}: {log}");
        }
        // OpenSSH logs one refusal while filtering each VERSION advertisement.
        // Any additional refusal would mean a rename reached request dispatch.
        ensure!(
            log.lines().filter(|line| line.contains("Refusing denylisted posix-rename request")).count() == 4,
            "expected only the four advertisement refusals: {log}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_rename_missing_source_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "echo launch >> {}; exec {} -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf MISSING_SOURCE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("dispatch-private");
            fs::create_dir(&directory)?;
            let source = directory.join("missing-source");
            let destination = directory.join("destination");
            fs::write(&destination, b"KEEP_DISPATCH_DESTINATION")?;
            let inode = fs::symlink_metadata(&destination)?.ino();
            let reply = client
                .call(
                    "change_rename",
                    json!({"host":"plain","source":source,"destination":destination,"overwrite":true}),
                )
                .await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::symlink_metadata(&source).is_err());
            ensure!(fs::symlink_metadata(&destination)?.ino() == inode);
            ensure!(fs::read(&destination)? == b"KEEP_DISPATCH_DESTINATION");
            ensure!(fs::read_dir(&directory)?.count() == 1);
            let audit = await_audit(&client.log, "finish", "not_found").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "dispatched rename failure discarded the healthy sibling master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("dispatch-private"), "rename audit disclosed private paths");
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "missing-source failure replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines().filter(|line| line.contains("posix-rename old ")).count() == 1,
            "expected exactly one real POSIX rename request: {log}"
        );
        ensure!(
            !log.lines().any(|line| line.contains("rename old ") && !line.contains("posix-rename old ")),
            "missing source caused standard rename fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_remove_file_entries_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.remove-locked]\nssh_host = 'plain'\nmax_tier = 'inspect'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("remove-private");
        fs::create_dir(&directory)?;
        let file = directory.join("ordinary");
        let retained = directory.join("retained-hardlink");
        fs::write(&file, b"REMOVE_KEEP_INODE_BYTES")?;
        fs::hard_link(&file, &retained)?;
        let inode = fs::symlink_metadata(&file)?.ino();
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"remove\0invalid"}),
                json!({"host":"plain","path":file,"timeout_secs":0}),
                json!({"host":"plain","path":file,"timeout_secs":16}),
            ] {
                let reply = client.call("change_file_remove", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call("change_file_remove", json!({"host":"remove-locked","path":file}))
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected unlink acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected unlink authenticated");
            ensure!(fs::symlink_metadata(&file)?.ino() == inode);
            ensure!(fs::read(&file)? == b"REMOVE_KEEP_INODE_BYTES");
            ensure!(fs::read_dir(&directory)?.count() == 2);

            succeeded(&exec(&client, "printf REMOVE_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let reply = client
                .call("change_file_remove", json!({"host":"plain","path":file}))
                .await?;
            ensure!(succeeded(&reply)? == &json!({"removed":true}));
            ensure!(
                matches!(fs::symlink_metadata(&file), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "successful unlink retained its entry"
            );
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::symlink_metadata(&retained)?.nlink() == 1);
            ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");

            let empty = directory.join("empty-directory");
            let tree = directory.join("tree");
            let child = tree.join("child");
            fs::create_dir(&empty)?;
            fs::create_dir(&tree)?;
            fs::write(&child, b"KEEP_TREE_CHILD")?;
            let empty_inode = fs::symlink_metadata(&empty)?.ino();
            let tree_inode = fs::symlink_metadata(&tree)?.ino();
            let child_inode = fs::symlink_metadata(&child)?.ino();
            let absent = directory.join("absent-target");
            for (index, target) in [&retained, &tree, &absent].into_iter().enumerate() {
                let link = directory.join(format!("final-link-{index}"));
                symlink(target, &link)?;
                let reply = client
                    .call("change_file_remove", json!({"host":"plain","path":link}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}));
                ensure!(
                    matches!(fs::symlink_metadata(&link), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "final symlink {index} survived unlink"
                );
                ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
                ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_TREE_CHILD");
                ensure!(fs::symlink_metadata(&absent).is_err());
            }

            let wildcard_sibling = directory.join("wildcard-KEEP");
            fs::write(&wildcard_sibling, b"KEEP_LITERAL_SIBLING")?;
            let sibling_inode = fs::symlink_metadata(&wildcard_sibling)?.ino();
            for name in [
                "  é雪 entry  ",
                "wildcard-*",
                "'\";~$*\n$(printf EVALUATED)",
                "${HOME} {{remove}}\n'\";*",
            ] {
                let literal = directory.join(name);
                fs::write(&literal, b"REMOVE_LITERAL_ONLY")?;
                let reply = client
                    .call("change_file_remove", json!({"host":"plain","path":literal}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}), "{name:?}: {reply}");
                ensure!(fs::symlink_metadata(&literal).is_err(), "{name:?}: entry survived");
                ensure!(fs::symlink_metadata(&wildcard_sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&wildcard_sibling)? == b"KEEP_LITERAL_SIBLING");
            }

            // A real REMOVE must reject both directories, not walk or use RMDIR.
            for path in [&empty, &tree] {
                let reply = client
                    .call("change_file_remove", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("permission_denied" | "io_error")),
                    "directory unlink did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
                ensure!(fs::read_dir(&empty)?.next().is_none());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_TREE_CHILD");
                ensure!(fs::read_dir(&tree)?.count() == 1);
            }
            // Missing is an acknowledged backend failure, never missing_ok.
            let reply = client
                .call("change_file_remove", json!({"host":"plain","path":file}))
                .await?;
            failed(&reply, "not_found")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "retained-hardlink", "empty-directory", "tree", "wildcard-KEEP",
            ].map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "unlink expanded literal paths or changed siblings");
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            let reply = client
                .call("inspect_file", json!({"host":"plain","path":retained}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "REMOVE_KEEP_INODE_BYTES");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "unlink discarded the shared healthy master"
            );

            let reply = client
                .call("change_file_remove", json!({"host":"nosftp","path":retained}))
                .await?;
            ensure!(
                matches!(reply["error"]["code"].as_str(), Some("unsupported" | "io_error" | "connection_lost")),
                "{reply}"
            );
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(fs::symlink_metadata(&retained)?.ino() == inode);
            ensure!(fs::read(&retained)? == b"REMOVE_KEEP_INODE_BYTES");
            let before = observed_masters(&client.log, 2).await?;
            let reply = client.call("exec_command", json!({
                "host":"nosftp","command":"printf REMOVE_NO_SUBSYSTEM_HEALTHY"
            })).await?;
            ensure!(succeeded(&reply)?["stdout"] == "REMOVE_NO_SUBSYSTEM_HEALTHY");
            ensure!(masters(&client.log)? == before, "unavailable SFTP replaced a healthy master");
            fixture.await_authentications(4).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("remove-private"), "unlink audit disclosed private paths");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_file_dispatch_refusal_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    // -P refuses the actual standard REMOVE, without hiding an extension.
    let script = format!(
        "echo launch >> {}; exec {} -P remove -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf REMOVE_REFUSAL_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("remove-refusal-private");
            fs::create_dir(&directory)?;
            let file = directory.join("denied");
            let sibling = directory.join("sibling");
            fs::write(&file, b"KEEP_REFUSED_ENTRY")?;
            fs::write(&sibling, b"KEEP_REFUSAL_SIBLING")?;
            let inode = fs::symlink_metadata(&file)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call("change_file_remove", json!({"host":"plain","path":file}))
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(
                fs::symlink_metadata(&file)?.ino() == inode,
                "refusal caused fallback unlink"
            );
            ensure!(fs::read(&file)? == b"KEEP_REFUSED_ENTRY");
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_REFUSAL_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "refused unlink discarded a healthy shared master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("remove-refusal-private"),
            "unlink audit disclosed private paths"
        );
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "refused unlink replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines()
                .filter(|line| line.contains("Refusing") && line.contains("remove request"))
                .count()
                == 1,
            "expected exactly one actual REMOVE refusal, without retry: {log}"
        );
        ensure!(
            !log.lines().any(|line| {
                [
                    "lstat name ",
                    "stat name ",
                    "readlink ",
                    "opendir ",
                    "rmdir name ",
                ]
                .iter()
                .any(|operation| line.contains(operation))
            }),
            "unlink performed a preflight or recursive fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_file_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {}",
        started.display(),
        done.display(),
        server.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf REMOVE_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("remove-delay-private");
            fs::create_dir(&directory)?;
            let file = directory.join("never-dispatched");
            let sibling = directory.join("sibling");
            fs::write(&file, b"KEEP_UNDISPATCHED_ENTRY")?;
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let inode = fs::symlink_metadata(&file)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call(
                    "change_file_remove",
                    json!({
                        "host":"plain","path":file,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake timeout discarded the healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "timeout replayed SFTP"
            );
            ensure!(fs::symlink_metadata(&file)?.ino() == inode);
            ensure!(fs::read(&file)? == b"KEEP_UNDISPATCHED_ENTRY");
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // The finite guard must finish even if an assertion above failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        completed?;
        gone?;
        ensure!(
            !log.text().contains("remove-delay-private"),
            "unlink audit disclosed private paths"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_remove_directory_entries_and_validation() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let mut config = fs::read_to_string(&fixture.config)?;
        config.push_str(
            "\n[targets.rmdir-locked]\nssh_host = 'plain'\nmax_tier = 'inspect'\n",
        );
        fs::write(&fixture.config, config)?;
        let directory = fixture.root.path().join("rmdir-private");
        fs::create_dir(&directory)?;
        let empty = directory.join("empty");
        let tree = directory.join("tree");
        let nested = tree.join("nested");
        let child = nested.join("child");
        let sibling = directory.join("wildcard-KEEP");
        fs::create_dir(&empty)?;
        fs::create_dir_all(&nested)?;
        fs::write(&child, b"KEEP_NESTED_CHILD\0BYTES")?;
        fs::write(&sibling, b"KEEP_LITERAL_SIBLING")?;
        let empty_inode = fs::symlink_metadata(&empty)?.ino();
        let tree_inode = fs::symlink_metadata(&tree)?.ino();
        let nested_inode = fs::symlink_metadata(&nested)?.ino();
        let child_inode = fs::symlink_metadata(&child)?.ino();
        let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
        let missing = directory.join("missing");
        let mut links = Vec::new();
        for (index, target) in [&empty, &tree, &sibling, &missing].into_iter().enumerate() {
            let link = directory.join(format!("final-link-{index}"));
            symlink(target, &link)?;
            let inode = fs::symlink_metadata(&link)?.ino();
            links.push((link, target, inode));
        }
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let initial_auth = fixture.authentications();
            for args in [
                json!({"host":"plain","path":""}),
                json!({"host":"plain","path":"rmdir\0invalid"}),
                json!({"host":"plain","path":empty,"timeout_secs":0}),
                json!({"host":"plain","path":empty,"timeout_secs":16}),
            ] {
                let reply = client.call("change_directory_remove", args).await?;
                failed(&reply, "invalid_argument")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            }
            let reply = client
                .call("change_directory_remove", json!({"host":"rmdir-locked","path":empty}))
                .await?;
            failed(&reply, "policy_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false);
            ensure!(masters(&client.log)?.is_empty(), "rejected rmdir acquired SSH");
            ensure!(fixture.authentications() == initial_auth, "rejected rmdir authenticated");
            ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
            ensure!(fs::read_dir(&empty)?.next().is_none());

            succeeded(&exec(&client, "printf RMDIR_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            // Plain final links must fail RMDIR, never fall back to REMOVE.
            // OpenSSH also maps ENOTDIR (file/final-link operands) to NO_SUCH_FILE.
            for (link, target, inode) in &links {
                let reply = client
                    .call("change_directory_remove", json!({"host":"plain","path":link}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("not_found" | "permission_denied" | "io_error")),
                    "final symlink rmdir did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                let metadata = fs::symlink_metadata(link)?;
                ensure!(metadata.file_type().is_symlink() && metadata.ino() == *inode);
                ensure!(fs::read_link(link)? == **target);
                ensure!(fs::symlink_metadata(&empty)?.ino() == empty_inode);
                ensure!(fs::read_dir(&empty)?.next().is_none());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&nested)?.ino() == nested_inode);
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_NESTED_CHILD\0BYTES");
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
                ensure!(fs::symlink_metadata(&missing).is_err());
            }
            for path in [&tree, &nested, &sibling] {
                let reply = client
                    .call("change_directory_remove", json!({"host":"plain","path":path}))
                    .await?;
                ensure!(
                    matches!(reply["error"]["code"].as_str(), Some("not_found" | "permission_denied" | "io_error")),
                    "nonempty directory/file rmdir did not fail: {reply}"
                );
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                ensure!(fs::symlink_metadata(&tree)?.is_dir());
                ensure!(fs::symlink_metadata(&tree)?.ino() == tree_inode);
                ensure!(fs::symlink_metadata(&nested)?.is_dir());
                ensure!(fs::symlink_metadata(&nested)?.ino() == nested_inode);
                ensure!(fs::symlink_metadata(&child)?.is_file());
                ensure!(fs::symlink_metadata(&child)?.ino() == child_inode);
                ensure!(fs::read(&child)? == b"KEEP_NESTED_CHILD\0BYTES");
                ensure!(fs::read_dir(&tree)?.count() == 1);
                ensure!(fs::read_dir(&nested)?.count() == 1);
                ensure!(fs::symlink_metadata(&sibling)?.is_file());
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
            }
            for name in [
                "  é雪 entry  ",
                "wildcard-*",
                "'\";~$*\n$(printf EVALUATED)",
                "${HOME} {{rmdir}}\n'\";*",
            ] {
                let literal = directory.join(name);
                fs::create_dir(&literal)?;
                let reply = client
                    .call("change_directory_remove", json!({"host":"plain","path":literal}))
                    .await?;
                ensure!(succeeded(&reply)? == &json!({"removed":true}), "{name:?}: {reply}");
                ensure!(
                    matches!(fs::symlink_metadata(&literal), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                    "{name:?}: empty directory survived"
                );
                ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
                ensure!(fs::read(&sibling)? == b"KEEP_LITERAL_SIBLING");
            }
            let reply = client
                .call("change_directory_remove", json!({"host":"plain","path":empty}))
                .await?;
            ensure!(succeeded(&reply)? == &json!({"removed":true}));
            ensure!(
                matches!(fs::symlink_metadata(&empty), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
                "successful rmdir retained its entry"
            );
            // Neither a missing entry nor a repeated deletion is missing_ok.
            for path in [&empty, &missing] {
                let reply = client
                    .call("change_directory_remove", json!({"host":"plain","path":path}))
                    .await?;
                failed(&reply, "not_found")?;
                ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            }
            let mut entries = fs::read_dir(&directory)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<Vec<_>>>()?;
            entries.sort();
            let mut expected = [
                "tree", "wildcard-KEEP", "final-link-0", "final-link-1",
                "final-link-2", "final-link-3",
            ].map(std::ffi::OsString::from);
            expected.sort();
            ensure!(entries == expected, "rmdir expanded literal paths or removed siblings");
            let reply = client
                .call("inspect_file", json!({"host":"plain","path":sibling}))
                .await?;
            ensure!(succeeded(&reply)?["content"] == "KEEP_LITERAL_SIBLING");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "rmdir discarded the shared healthy master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(!log.text().contains("rmdir-private"), "rmdir audit disclosed private paths");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_directory_dispatch_refusal_is_not_replayed() -> Result<()> {
    let work = tempfile::tempdir()?;
    let requests = work.path().join("sftp-requests");
    let launches = work.path().join("sftp-launches");
    let server = Fixture::sftp_server()?;
    let script = format!(
        "echo launch >> {}; exec {} -P rmdir -e -l VERBOSE 2>> {}",
        launches.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf RMDIR_REFUSAL_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("rmdir-refusal-private");
            fs::create_dir(&directory)?;
            let empty = directory.join("denied");
            let sibling = directory.join("sibling");
            fs::create_dir(&empty)?;
            fs::write(&sibling, b"KEEP_REFUSAL_SIBLING")?;
            let inode = fs::symlink_metadata(&empty)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call(
                    "change_directory_remove",
                    json!({"host":"plain","path":empty}),
                )
                .await?;
            failed(&reply, "permission_denied")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::symlink_metadata(&empty)?.is_dir());
            ensure!(
                fs::symlink_metadata(&empty)?.ino() == inode,
                "refusal caused fallback rmdir"
            );
            ensure!(fs::read_dir(&empty)?.next().is_none());
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_REFUSAL_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            let audit = await_audit(&client.log, "finish", "permission_denied").await?;
            ensure!(audit["remote_state_unknown"] == true && audit["identity_role"] == "ordinary");
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "refused rmdir discarded a healthy shared master"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        gone?;
        ensure!(
            !log.text().contains("rmdir-refusal-private"),
            "rmdir audit disclosed private paths"
        );
        ensure!(
            fs::read_to_string(&launches)?.lines().count() == 1,
            "refused rmdir replayed the SFTP session"
        );
        let log = fs::read_to_string(&requests)?;
        ensure!(
            log.lines()
                .filter(|line| line.contains("Refusing") && line.contains("rmdir request"))
                .count()
                == 1,
            "expected exactly one actual RMDIR refusal, without retry: {log}"
        );
        ensure!(
            !log.lines().any(|line| {
                [
                    "lstat name ",
                    "stat name ",
                    "readlink ",
                    "opendir ",
                    "readdir ",
                    "remove name ",
                    "Refusing remove request",
                    "mkdir name ",
                    "rename old ",
                    "open \"",
                    "setstat name ",
                ]
                .iter()
                .any(|operation| line.contains(operation))
            }),
            "rmdir performed a preflight or mutation fallback: {log}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let removed = work.close();
    scenario?;
    cleanup?;
    removed?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_remove_directory_prehandshake_timeout() -> Result<()> {
    let work = tempfile::tempdir()?;
    let started = work.path().join("sftp-started");
    let done = work.path().join("sftp-delay-done");
    let requests = work.path().join("sftp-requests");
    fs::write(&requests, b"")?;
    let server = Fixture::sftp_server()?;
    let script = format!(
        "trap \"\" HUP; echo launch >> {}; sleep 3; printf done > {}; exec {} -e -l VERBOSE 2>> {}",
        started.display(),
        done.display(),
        server.display(),
        requests.display(),
    );
    let subsystem = format!("/bin/sh -c {}", quote(&script));
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            succeeded(&exec(&client, "printf RMDIR_DELAY_MASTER").await?)?;
            let owned = observed_masters(&client.log, 1).await?;
            let transport = live_transport(&fixture, &client, &owned[0], 1, 3).await?;
            let directory = fixture.root.path().join("rmdir-delay-private");
            fs::create_dir(&directory)?;
            let empty = directory.join("never-dispatched");
            let sibling = directory.join("sibling");
            fs::create_dir(&empty)?;
            fs::write(&sibling, b"KEEP_DELAY_SIBLING")?;
            let inode = fs::symlink_metadata(&empty)?.ino();
            let sibling_inode = fs::symlink_metadata(&sibling)?.ino();
            let reply = client
                .call(
                    "change_directory_remove",
                    json!({
                        "host":"plain","path":empty,"timeout_secs":1
                    }),
                )
                .await?;
            Fixture::await_file(&started).await?;
            failed(&reply, "timeout")?;
            ensure!(
                reply["data"].is_null() && reply["error"]["remote_state_unknown"] == false,
                "handshake timeout acquired mutation uncertainty: {reply}"
            );
            ensure!(
                live_transport(&fixture, &client, &owned[0], 1, 3).await? == transport,
                "handshake timeout discarded the healthy sibling transport"
            );
            Fixture::await_file(&done).await?;
            ensure!(
                fs::read_to_string(&started)?.lines().count() == 1,
                "timeout replayed SFTP"
            );
            ensure!(fs::symlink_metadata(&empty)?.is_dir());
            ensure!(fs::symlink_metadata(&empty)?.ino() == inode);
            ensure!(fs::read_dir(&empty)?.next().is_none());
            ensure!(fs::symlink_metadata(&sibling)?.ino() == sibling_inode);
            ensure!(fs::read(&sibling)? == b"KEEP_DELAY_SIBLING");
            ensure!(fs::read_dir(&directory)?.count() == 2);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        // Await the finite remote guard even when an assertion failed.
        let completed = if started.exists() {
            Fixture::await_file(&done).await
        } else {
            Ok(())
        };
        let gone = match owned {
            Ok(owned) => assert_masters_gone(&owned).await,
            Err(error) => Err(error),
        };
        cases?;
        let log = stopped?;
        completed?;
        gone?;
        ensure!(
            !log.text().contains("rmdir-delay-private"),
            "rmdir audit disclosed private paths"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = fixture.stop().await;
    let log = fs::read_to_string(&requests);
    let removed = work.close();
    scenario?;
    cleanup?;
    let log = log?;
    ensure!(
        !log.contains("rmdir name ") && !log.contains("remove name "),
        "handshake timeout dispatched a mutation: {log}"
    );
    removed?;
    Ok(())
}

// All replacement observations below use the real server's shared filesystem,
// independently of the MCP response and of the SFTP client's buffers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_atomic_visibility_and_lost_ack() -> Result<()> {
    // Each relay owns exactly one real SFTP session, including for empty payloads.
    for (drop_ack, new_len) in [(false, 0), (false, 786_432), (true, 786_432)] {
        let work = tempfile::tempdir()?;
        let destination = work.path().join("destination");
        let hardlink = work.path().join("old-hardlink");
        let old = vec![b'O'; 262_144];
        let new = vec![b'N'; new_len];
        fs::write(&destination, &old)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))?;
        fs::hard_link(&destination, &hardlink)?;
        let before = fs::metadata(&destination)?;
        let fault = if drop_ack {
            replace_relay::Fault::RenameAck
        } else {
            replace_relay::Fault::None
        };
        let relay = replace_relay::Relay::start(
            &Fixture::sftp_server()?,
            fault,
            Some(replace_relay::Oracle {
                destination: destination.clone(),
                hardlink: hardlink.clone(),
                old: old.clone(),
                inode: before.ino(),
                new_len: new.len(),
            }),
        )
        .await?;
        let evidence = relay.evidence.clone();
        let setup = Fixture::start_with_sftp_subsystem("", &relay.subsystem).await;
        let fixture = match setup {
            Ok(fixture) => fixture,
            Err(error) => {
                let _ = relay.stop().await;
                return Err(error);
            }
        };
        let scenario = async {
            let configured = fs::read_to_string(&fixture.config)?
                .replace("[limits]", "[limits]\nmax_file_bytes = 1048576");
            fs::write(&fixture.config, configured)?;
            // Explicitly configured above the 64KiB write boundary.
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                let observed_path = destination.clone();
                let observed_old = old.clone();
                let observed_new = new.clone();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();
                let mut observer = tokio::spawn(async move {
                    let mut ready = Some(ready_tx);
                    let mut old_reads = 0usize;
                    let mut new_reads = 0usize;
                    timeout(Duration::from_secs(15), async {
                        loop {
                            let bytes = fs::read(&observed_path)?;
                            if bytes == observed_old { old_reads += 1; }
                            else if bytes == observed_new { new_reads += 1; }
                            else { anyhow::bail!("ordinary reader observed missing/partial/mixed replacement bytes"); }
                            if let Some(ready) = ready.take() { let _ = ready.send(()); }
                            if stop_rx.try_recv().is_ok() {
                                ensure!(fs::read(&observed_path)? == observed_new, "final independent publication observation");
                                new_reads += 1;
                                ensure!(old_reads > 0 && new_reads > 0, "observer missed old/new visibility");
                                return Ok::<_, anyhow::Error>(());
                            }
                            tokio::task::yield_now().await;
                        }
                    }).await.context("bounded visibility observer")?
                });
                let operation = async {
                    timeout(Duration::from_secs(5), ready_rx).await??;
                    let reply = client.call("change_file_replace", json!({
                        "host":"plain","path":destination,"content":String::from_utf8(new.clone())?,
                        "overwrite":true,"timeout_secs":3,
                    })).await?;
                    if drop_ack {
                        failed(&reply, "timeout")?;
                        ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
                        let blocked = client
                            .call(
                                "change_file_replace",
                                json!({
                                    "host":"plain",
                                    "path":destination,
                                    "content":"BLOCKED",
                                    "overwrite":true,
                                }),
                            )
                            .await?;
                        failed(&blocked, "target_quarantined")?;
                    } else {
                        ensure!(succeeded(&reply)? == &json!({"bytes_written":new.len()}));
                    }
                    ensure!(fs::read(&destination)? == new, "real server did not publish new bytes");
                    ensure!(fs::read(&hardlink)? == old);
                    let after = fs::metadata(&destination)?;
                    ensure!(after.ino() != before.ino());
                    ensure!(after.mode() & 0o7777 == 0o600);
                    ensure!(after.uid() == nix::unistd::Uid::current().as_raw());
                    ensure!(after.gid() == fs::metadata(work.path())?.gid());
                    ensure!(fs::metadata(&hardlink)?.ino() == before.ino());
                    ensure!(fs::metadata(&hardlink)?.mode() & 0o7777 == 0o644);
                    ensure!(fs::read_dir(work.path())?.count() == 2, "successful rename left a stage");
                    let seen = evidence.lock().map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                    seen.assert_private_stage_opens(1)?;
                    ensure!(!seen.requests.iter().any(|kind| matches!(*kind, 13 | 18)),
                        "replacement deleted an entry or used standard rename: {seen:?}");
                    ensure!(seen.renames == 1, "rename replayed: {seen:?}");
                    ensure!(seen.dropped_success == drop_ack, "lost ack was not a genuine successful STATUS");
                    if new.is_empty() {
                        ensure!(seen.writes == 0 && !seen.staged_partial, "empty replacement issued a write: {seen:?}");
                    } else {
                        ensure!(seen.writes > 1 && seen.staged_partial, "did not observe real multi-write staging");
                    }
                    let rename = seen.rename_index.context("POSIX rename request")?;
                    ensure!(seen.requests[rename + 1..].iter().all(|kind| !matches!(*kind, 3 | 6 | 13 | 18 | 200)),
                        "mutation/replay/cleanup after rename: {seen:?}");
                    Ok::<_, anyhow::Error>(())
                }.await;
                // Always stop and join the owned independent reader, including failed calls/assertions.
                let _ = stop_tx.send(());
                let observed = match timeout(Duration::from_secs(5), &mut observer).await {
                    Ok(result) => result.context("visibility observer panic").and_then(|result| result),
                    Err(error) => {
                        observer.abort();
                        let _ = observer.await;
                        Err(error.into())
                    }
                };
                operation?;
                observed
            }.await;
            let owned = masters(&client.log);
            let stopped = client.stop().await;
            let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
            cases?;
            stopped?;
            gone?;
            ensure!(fs::read_to_string(&relay.launches)?.lines().count() == 1, "replacement replayed the subsystem");
            Ok::<_, anyhow::Error>(())
        }.await;
        let observed_state = format!(
            "drop_ack={drop_ack}; new_len={new_len}; evidence={:?}; destination={:?}",
            evidence.lock(),
            fs::metadata(&destination).map(|metadata| (metadata.ino(), metadata.len()))
        );
        let relayed = relay.stop().await;
        let cleanup = fixture.stop().await;
        let removed = work.close();
        scenario.with_context(|| format!("{observed_state}; relay cleanup={relayed:?}"))?;
        relayed?;
        cleanup?;
        removed?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn ssh_replace_file_metadata_symlinks_and_literal_bytes() -> Result<()> {
    let fixture = Fixture::start().await?;
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let directory = fixture.root.path().join("replace-private-é雪 space-'\"\n${HOME}$(printf NEVER)");
            fs::create_dir(&directory)?;
            for (name, content, encoding, expected) in [
                ("é雪 space-'\"\n${HOME}$(printf NEVER)", "UTF8_é雪\0END", "utf8", "UTF8_é雪\0END".as_bytes()),
                ("binary", "AP+AQQ==", "base64", b"\0\xff\x80A".as_slice()),
                ("empty", "", "utf8", b"".as_slice()),
            ] {
                let path = directory.join(name);
                let reply = client.call("change_file_replace", json!({
                    "host":"plain","path":path,"content":content,"encoding":encoding,"overwrite":true,
                })).await?;
                ensure!(succeeded(&reply)? == &json!({"bytes_written":expected.len()}));
                ensure!(fs::read(&path)? == expected);
                ensure!(fs::metadata(&path)?.mode() & 0o7777 == 0o600);
            }
            let target = directory.join("target");
            let link = directory.join("final-link");
            fs::write(&target, b"SYMLINK_TARGET_UNCHANGED")?;
            let target_inode = fs::metadata(&target)?.ino();
            symlink(&target, &link)?;
            let reply = client.call("change_file_replace", json!({
                "host":"plain","path":link,"content":"LINK_ENTRY_REPLACED","overwrite":true,
            })).await?;
            succeeded(&reply)?;
            ensure!(fs::symlink_metadata(&link)?.file_type().is_file());
            ensure!(fs::read(&link)? == b"LINK_ENTRY_REPLACED");
            ensure!(fs::read(&target)? == b"SYMLINK_TARGET_UNCHANGED");
            ensure!(fs::metadata(&target)?.ino() == target_inode);
            let missing_target = directory.join("missing-target");
            let dangling = directory.join("dangling");
            symlink(&missing_target, &dangling)?;
            succeeded(&client.call("change_file_replace", json!({
                "host":"plain","path":dangling,"content":"NEW_ENTRY","overwrite":true,
            })).await?)?;
            ensure!(fs::read(&dangling)? == b"NEW_ENTRY" && !missing_target.exists());
            // Raw repeated slashes and intermediate symlinks keep server pathname semantics.
            let parent_link = fixture.root.path().join("replace-parent-link");
            symlink(&directory, &parent_link)?;
            let raw = format!("{}//through-parent", parent_link.display());
            succeeded(&client.call("change_file_replace", json!({
                "host":"plain","path":raw,"content":"RAW_PARENT","overwrite":true,
            })).await?)?;
            ensure!(fs::read(directory.join("through-parent"))? == b"RAW_PARENT");
            let tree = directory.join("tree");
            fs::create_dir(&tree)?;
            fs::write(tree.join("child"), b"TREE_UNCHANGED")?;
            let tree_inode = fs::metadata(&tree)?.ino();
            let reply = client.call("change_file_replace", json!({
                "host":"plain","path":tree,"content":"NO_DIRECTORY_REPLACE","overwrite":true,
            })).await?;
            ensure!(reply["error"].is_object() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::metadata(&tree)?.ino() == tree_inode);
            ensure!(fs::read(tree.join("child"))? == b"TREE_UNCHANGED");
            let stages = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
            let stages: Vec<_> = stages.iter().filter(|entry| entry.file_name().as_bytes().starts_with(b".estus-replace-")).collect();
            ensure!(stages.len() == 1, "rename-attempt failure must not clean its stage");
            ensure!(fs::read(stages[0].path())? == b"NO_DIRECTORY_REPLACE");
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        let log = stopped?;
        ensure!(!log.text().contains("replace-private") && !log.text().contains("LINK_ENTRY_REPLACED"));
        gone
    }.await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_capability_and_owned_stage_failures() -> Result<()> {
    let server = Fixture::sftp_server()?;
    for request in ["posix-rename", "open", "write", "fsetstat", "close"] {
        let work = tempfile::tempdir()?;
        let requests = work.path().join("requests.log");
        let relay = replace_relay::Relay::start_denied(&server, request, &requests).await?;
        let fixture = match Fixture::start_with_sftp_subsystem("", &relay.subsystem).await {
            Ok(fixture) => fixture,
            Err(error) => {
                let _ = relay.stop().await;
                return Err(error);
            }
        };
        let scenario = async {
            let client = Client::start(&fixture.config).await?;
            let cases = async {
                let directory = fixture.root.path().join("replace-fault");
                fs::create_dir(&directory)?;
                let path = directory.join("destination");
                fs::write(&path, b"PRESERVED_DESTINATION")?;
                let inode = fs::metadata(&path)?.ino();
                let reply = client.call("change_file_replace", json!({
                    "host":"plain","path":path,"content":"MUST_NOT_PUBLISH","overwrite":true,
                })).await?;
                failed(
                    &reply,
                    if request == "posix-rename" {
                        "unsupported"
                    } else {
                        "permission_denied"
                    },
                )?;
                ensure!(reply["data"].is_null());
                ensure!(reply["error"]["remote_state_unknown"] == (request != "posix-rename"));
                ensure!(fs::read(&path)? == b"PRESERVED_DESTINATION");
                ensure!(fs::metadata(&path)?.ino() == inode);
                ensure!(
                    fs::read_dir(&directory)?.count() == 1,
                    "failed OPEN created a stage or acknowledged pre-rename stage not removed"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let owned = masters(&client.log);
            let stopped = client.stop().await;
            let gone = match owned {
                Ok(owned) => assert_masters_gone(&owned).await,
                Err(error) => Err(error),
            };
            cases?;
            stopped?;
            gone?;
            let log = fs::read_to_string(&requests)?;
            let seen = relay
                .evidence
                .lock()
                .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
            if request == "open" {
                ensure!(seen.opens.len() == 1, "failed OPEN replayed: {seen:?}");
                let open = &seen.opens[0];
                ensure!(
                    open.pflags == (0x02 | 0x08 | 0x20)
                        && open.attr_flags == 0
                        && open.initial_mode.is_none()
                        && open.initial_len.is_none(),
                    "failed OPEN flags/attrs or fabricated HANDLE: {seen:?}"
                );
            } else {
                seen.assert_private_stage_opens(usize::from(request != "posix-rename"))?;
            }
            if request == "posix-rename" {
                for mutation in [
                    "open \"",
                    "remove name ",
                    "setstat name ",
                    "fsetstat ",
                    "rename old ",
                    "mkdir ",
                    "rmdir name ",
                ] {
                    ensure!(
                        !log.contains(mutation),
                        "unsupported extension mutated filesystem: {log}"
                    );
                }
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("Refusing denylisted posix-rename request"))
                        .count()
                        == 1
                );
            } else if request == "open" {
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("Refusing denylisted open request"))
                        .count()
                        == 1,
                    "expected one genuine rejected OPEN: {log}"
                );
                for mutation in ["remove name ", "write \"", "fsetstat ", "rename old "] {
                    ensure!(
                        !log.contains(mutation),
                        "failed OPEN claimed/mutated a stage: {log}"
                    );
                }
            } else {
                ensure!(
                    log.lines()
                        .filter(|line| line.contains("remove name "))
                        .count()
                        == 1,
                    "expected one owned-stage REMOVE: {log}"
                );
                ensure!(
                    !log.contains("rename old "),
                    "pre-rename failure attempted publication: {log}"
                );
                if request == "fsetstat" {
                    ensure!(
                        !log.contains("write \""),
                        "content was written before successful chmod: {log}"
                    );
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let cleanup = fixture.stop().await;
        let relayed = relay.stop().await;
        let removed = work.close();
        scenario?;
        cleanup?;
        relayed?;
        removed?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix sftp-server and a non-root local account"]
async fn ssh_replace_file_unacknowledged_open_does_not_claim_stage() -> Result<()> {
    let relay = replace_relay::Relay::start(
        &Fixture::sftp_server()?,
        replace_relay::Fault::OpenAck,
        None,
    )
    .await?;
    let setup = Fixture::start_with_sftp_subsystem("", &relay.subsystem).await;
    let fixture = match setup {
        Ok(fixture) => fixture,
        Err(error) => {
            let _ = relay.stop().await;
            return Err(error);
        }
    };
    let scenario = async {
        let client = Client::start(&fixture.config).await?;
        let cases = async {
            let directory = fixture.root.path().join("replace-unacknowledged");
            fs::create_dir(&directory)?;
            let path = directory.join("destination");
            fs::write(&path, b"UNACKNOWLEDGED_OLD")?;
            let inode = fs::metadata(&path)?.ino();
            let reply = client.call("change_file_replace", json!({
                "host":"plain","path":path,"content":"NEVER_WRITE_UNOWNED","overwrite":true,"timeout_secs":2,
            })).await?;
            failed(&reply, "timeout")?;
            ensure!(reply["data"].is_null() && reply["error"]["remote_state_unknown"] == true);
            ensure!(fs::metadata(&path)?.ino() == inode && fs::read(&path)? == b"UNACKNOWLEDGED_OLD");
            let entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
            let stages: Vec<_> = entries.iter().filter(|entry| entry.file_name().as_bytes().starts_with(b".estus-replace-")).collect();
            ensure!(stages.len() == 1 && fs::metadata(stages[0].path())?.len() == 0,
                "uncertain OPEN must leave the real empty stage, never claim/delete it");
            Ok::<_, anyhow::Error>(())
        }.await;
        let owned = masters(&client.log);
        let stopped = client.stop().await;
        let gone = match owned { Ok(owned) => assert_masters_gone(&owned).await, Err(error) => Err(error) };
        cases?;
        stopped?;
        gone?;
        let seen = relay.evidence.lock().map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
        ensure!(seen.dropped_open && !seen.dropped_success && seen.renames == 0 && seen.writes == 0);
        seen.assert_private_stage_opens(1)?;
        ensure!(seen.requests.iter().filter(|kind| **kind == 3).count() == 1, "uncertain OPEN replayed");
        let open = seen.requests.iter().position(|kind| *kind == 3).context("real OPEN request")?;
        ensure!(!seen.requests[open + 1..].iter().any(|kind| matches!(*kind, 6 | 13 | 18 | 9 | 10 | 200)),
            "uncertain OPEN triggered write/chmod/cleanup/rename: {seen:?}");
        ensure!(fs::read_to_string(&relay.launches)?.lines().count() == 1);
        Ok::<_, anyhow::Error>(())
    }.await;
    let relayed = relay.stop().await;
    let cleanup = fixture.stop().await;
    scenario?;
    relayed?;
    cleanup
}
