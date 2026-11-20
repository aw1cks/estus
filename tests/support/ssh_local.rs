//! Shared local-SSH acceptance helpers: audit and masters assertions, live
//! transports and the per-concern helpers shared by the split suites.
use crate::support::Client;
use crate::support::Fixture;
use crate::support::Log;
use crate::support::WireServer;
use crate::support::masters;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;
use tokio::time::timeout;

pub fn succeeded(reply: &Value) -> Result<&Value> {
    ensure!(reply["error"].is_null(), "unexpected tool failure: {reply}");
    ensure!(reply["data"].is_object(), "missing success data: {reply}");
    Ok(&reply["data"])
}

pub fn failed(reply: &Value, code: &str) -> Result<()> {
    ensure!(reply["error"]["code"] == code, "expected {code}: {reply}");
    Ok(())
}

pub async fn exec(client: &Client, command: &str) -> Result<Value> {
    client
        .call("exec_command", json!({"host":"plain","command":command}))
        .await
}

pub async fn await_audit(log: &Log, event: &str, code: &str) -> Result<Value> {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(record) = log
                .records()?
                .into_iter()
                .find(|record| record["event"] == event && record["error_code"] == code)
            {
                return Ok::<_, anyhow::Error>(record);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("expected audit event not emitted")?
}

pub async fn observed_masters(log: &Log, expected: usize) -> Result<Vec<(u32, PathBuf)>> {
    timeout(Duration::from_secs(5), async {
        loop {
            let owned = masters(log)?;
            if owned.len() >= expected {
                ensure!(owned.len() == expected, "unexpected additional SSH master");
                return Ok(owned);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("master lifecycle log did not catch up")?
}

pub async fn live_transport(
    fixture: &Fixture,
    client: &Client,
    master: &(u32, PathBuf),
    expected_masters: usize,
    expected_auth: usize,
) -> Result<String> {
    observed_masters(&client.log, expected_masters).await?;
    let before = fixture.listeners[0].log.text();
    let mut reply = exec(client, "printf %s \"$SSH_CONNECTION\"").await?;
    succeeded(&reply)?;
    let Value::String(connection) = reply["data"]["stdout"].take() else {
        anyhow::bail!("missing SSH_CONNECTION transport identity");
    };
    let mut fields = connection.split_ascii_whitespace();
    let port = fields.nth(1).context("missing SSH client port")?;
    ensure!(
        fields.count() == 2,
        "invalid SSH_CONNECTION transport identity"
    );
    let port = format!(" port {port} ");
    let closed = |text: &str| {
        text.lines()
            .filter(|line| line.contains("Close session:") && line.contains(&port))
            .count()
    };
    let before_closed = closed(&before);
    // This persistent-connection close is a positive log-drain barrier, unlike
    // merely sampling an append-only authentication counter after cancellation.
    timeout(Duration::from_secs(5), async {
        while closed(&fixture.listeners[0].log.text()) <= before_closed {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("transport probe close record did not arrive")?;
    let check = crate::support::run(
        Command::new(&fixture.ssh)
            .arg("-F")
            .arg(&fixture.ssh_config)
            .arg("-S")
            .arg(&master.1)
            .args(["-O", "check", "plain"]),
    )
    .await?;
    ensure!(
        check.status.success()
            && String::from_utf8_lossy(&check.stderr).contains(&format!("(pid={})", master.0)),
        "original master PID/control socket is no longer live"
    );
    observed_masters(&client.log, expected_masters).await?;
    fixture.await_authentications(expected_auth).await?;
    Ok(connection)
}

// The independent shared-filesystem oracle also rejects extra result fields,
// including paths, filenames, link targets, or authentication hints.
pub fn native_stat_data(path: &Path, follow: bool) -> Result<Value> {
    let metadata = if follow {
        fs::metadata(path)?
    } else {
        fs::symlink_metadata(path)?
    };
    let kind = if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };
    Ok(json!({
        "kind":kind,
        "size":metadata.len(),
        "permissions":metadata.mode() & 0o7777,
        "uid":metadata.uid(),
        "gid":metadata.gid(),
        "modified_unix_secs":u64::try_from(metadata.mtime())?,
    }))
}

// Keep the applet basename: find_program canonicalizes Nix multicall symlinks,
// whereas the remote exec must invoke printf/id/sleep, not bare coreutils.
pub fn binding_program(name: &str) -> Result<PathBuf> {
    let resolved = crate::support::find_program(name)?;
    ensure!(
        resolved.starts_with("/nix/store"),
        "{name} must be Nix-provided"
    );
    let program = resolved
        .parent()
        .context("coreutils executable directory")?
        .join(name);
    let metadata = fs::metadata(&program)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "missing executable coreutils applet {name}"
    );
    Ok(program)
}

pub async fn script_wire_call(
    server: &mut WireServer,
    id: u64,
    name: &str,
    args: Value,
) -> Result<Value> {
    let mut frame = server
        .request(id, "tools/call", json!({"name":name,"arguments":args}))
        .await?;
    let result = &frame["result"];
    let reply = &result["structuredContent"];
    ensure!(reply.is_object(), "missing script envelope: {frame}");
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("script text result")?,
    )?;
    ensure!(text == *reply, "script text and structured result disagree");
    ensure!(result["isError"].as_bool().unwrap_or(false) == !reply["error"].is_null());
    Ok(frame["result"]["structuredContent"].take())
}
