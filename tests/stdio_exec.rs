//! Command execution inputs, encoded-command and reply budgets. No SSH.
#[path = "support/stdio.rs"]
#[allow(dead_code)]
// Shared helpers used by other suites are inert here.
mod stdio;
use stdio::*;

use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use serde_json::Value;
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn command_input_and_policy_failures_never_launch_ssh() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
            [limits]
            max_file_bytes = 64
            [targets.allowed]
            ssh_host = 'ordinary.invalid'
            [targets.allowed.sudo]
            mode = 'separate-identity'
            ssh_host = 'privileged.invalid'
            programs = ['/usr/bin/id']
            [targets.disabled]
            ssh_host = 'disabled.invalid'
        "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})).await?;
        let listed = server.response(2).await?;
        let tools = listed["result"]["tools"].as_array().context("tools")?;
        ensure!(tools.iter().any(|tool| tool["name"] == "exec_sudo"));
        for name in ["exec_command", "exec_argv", "exec_sudo"] {
            let tool = tools.iter().find(|tool| tool["name"] == name).context("command tool")?;
            output_control_schema(&tool["inputSchema"])?;
        }
        for (index, (tool, args)) in [
            ("exec_command", json!({"host":"allowed","command":["DO_NOT_LOG_PAYLOAD"]})),
            ("exec_command", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","shell":"interactive"})),
            ("exec_command", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","sudo":true})),
            ("exec_argv", json!({"host":"allowed","argv":"DO_NOT_LOG_PAYLOAD"})),
            ("exec_argv", json!({"host":"allowed","argv":["true",17]})),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"env":{"SECRET":"DO_NOT_LOG_PAYLOAD"}})),
            ("exec_command", json!({"host":"allowed","command":"true","retain_output":"DO_NOT_LOG_PAYLOAD"})),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"retain_output":1})),
            ("exec_sudo", json!({"host":"allowed","argv":["/usr/bin/id"],"retain_output":null})),
        ].into_iter().enumerate() {
            let id = 10 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})).await?;
            ensure!(server.response(id).await?["error"]["code"] == -32602);
        }
        for (index, (tool, args, code)) in [
            ("exec_command", json!({"host":"ordinary.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("exec_command", json!({"host":"privileged.invalid","command":"DO_NOT_LOG_PAYLOAD"}), "policy_denied"),
            ("exec_command", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","timeout_secs":601}), "invalid_argument"),
            ("exec_command", json!({"host":"allowed","command":"DO_NOT_LOG_PAYLOAD","cwd":"relative"}), "invalid_argument"),
            ("exec_command", json!({"host":"allowed","command":"bad\u{0}DO_NOT_LOG_PAYLOAD"}), "invalid_argument"),
            ("exec_argv", json!({"host":"ordinary.invalid","argv":["DO_NOT_LOG_PAYLOAD"]}), "policy_denied"),
            ("exec_argv", json!({"host":"allowed","argv":[]}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":[""]}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["bad\u{0}DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["true","bad\u{0}DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"cwd":"relative"}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"timeout_secs":0}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"timeout_secs":601}), "invalid_argument"),
            ("exec_argv", json!({"host":"allowed","argv":["true"],"stdin":"λ".repeat(33)}), "invalid_argument"),
            ("exec_sudo", json!({"host":"disabled","argv":["/usr/bin/id"]}), "policy_denied"),
            ("exec_sudo", json!({"host":"allowed","user":"service","argv":["/usr/bin/id"]}), "policy_denied"),
            ("exec_sudo", json!({"host":"allowed","argv":["/bin/id"]}), "policy_denied"),
            ("exec_sudo", json!({"host":"allowed","argv":["relative"]}), "invalid_argument"),
            ("exec_sudo", json!({"host":"allowed","user":"bad DO_NOT_LOG_PAYLOAD","argv":["/usr/bin/id"]}), "invalid_argument"),
            ("exec_sudo", json!({"host":"allowed","user":"DO_NOT_LOG_PAYLOAD","argv":["/usr/bin/id"]}), "policy_denied"),
            ("exec_sudo", json!({"host":"allowed","argv":["DO_NOT_LOG_PAYLOAD"]}), "invalid_argument"),
            ("exec_sudo", json!({"host":"allowed","argv":["/DO_NOT_LOG_PAYLOAD"]}), "policy_denied"),
        ].into_iter().enumerate() {
            let id = 20 + index as u64;
            server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":args}})).await?;
            let response = server.response(id).await?;
            ensure!(!response.to_string().contains("DO_NOT_LOG_PAYLOAD"), "rejection reflected input");
            ensure!(response["result"]["isError"] == true, "{response}");
            ensure!(response["result"]["structuredContent"]["data"].is_null());
            ensure!(response["result"]["structuredContent"]["error"]["code"] == code, "{response}");
            ensure!(response["result"]["structuredContent"]["error"]["remote_state_unknown"] == false);
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    let stderr = String::from_utf8(stderr)?;
    ensure!(!stderr.contains("DO_NOT_LOG_PAYLOAD"));
    for line in stderr.lines() {
        let record: Value = serde_json::from_str(line)?;
        ensure!(
            record["event"] != "master_start",
            "rejected request launched SSH"
        );
        if record["tool"] == "exec_sudo" {
            ensure!(record["event"] == "reject");
            ensure!(
                record.get("user").is_none() && record.get("program").is_none(),
                "sudo rejection retained caller identity fields: {record}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn accepted_sudo_keeps_validated_identifiers_on_transport_failure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
            [targets.allowed]
            ssh_host = 'never-connected.invalid'
            [targets.allowed.sudo]
            mode = 'separate-identity'
            ssh_host = 'never-connected-elevated.invalid'
            users = ['root']
            programs = ['/usr/bin/id']
        "},
    )?;
    // A real, immediately failing local executable guarantees no network/SSH
    // configuration evaluation while exercising accepted-operation auditing.
    let false_binary = std::env::split_paths(&std::env::var_os("PATH").context("PATH")?)
        .map(|directory| directory.join("false"))
        .find(|path| path.is_file())
        .context("false executable prerequisite")?;
    let mut server = Server::start(&[
        "--config",
        path.to_str().context("config path")?,
        "--ssh",
        false_binary.to_str().context("false path")?,
    ])?;
    let scenario = async {
        server.initialize().await?;
        server
            .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"exec_sudo","arguments":{
                    "host":"allowed","user":"root","argv":["/usr/bin/id"]}}}))
            .await?;
        let response = server.response(2).await?;
        let code = response["result"]["structuredContent"]["error"]["code"]
            .as_str()
            .context("transport error")?;
        ensure!(
            code != "policy_denied" && code != "invalid_argument",
            "{response}"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success());
    let mut events = Vec::new();
    for line in stderr.split_inclusive(|byte| *byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        if record["tool"] == "exec_sudo" && record["request_id"] == 2 {
            ensure!(record["user"] == "root" && record["program"] == "/usr/bin/id");
            ensure!(record["identity_role"] == "elevated");
            events.push(record["event"].as_str().context("audit event")?.to_owned());
        }
    }
    ensure!(
        events == ["start", "finish"],
        "accepted sudo audit: {events:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_command_rejections_precede_ssh_and_keep_session_usable() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("operator.toml");
    std::fs::write(
        &path,
        indoc::indoc! {"
            capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }
            [targets.allowed]
            ssh_host = 'encoded-command.invalid'
            [targets.allowed.sudo]
            mode = 'same-account'
            users = ['root']
            programs = ['/usr/bin/true']
        "},
    )?;
    let mut server = Server::start(&["--config", path.to_str().context("config path")?])?;
    let scenario = timeout(Duration::from_secs(20), async {
        server.initialize().await?;
        let mut argv = vec![""; 100_001];
        argv[0] = "/usr/bin/true";
        let cases = [
            (
                "apostrophe expansion",
                "exec_command",
                json!({"host":"allowed","command":format!("#{}", "'".repeat(65_535))}),
            ),
            (
                "bang expansion",
                "exec_command",
                json!({"host":"allowed","command":"!".repeat(65_000)}),
            ),
            (
                "nested cwd escaping",
                "exec_command",
                // Both the raw cwd and inner script fit; outer shell escaping does not.
                json!({"host":"allowed","command":"true","cwd":format!("/{}", "'".repeat(8_000))}),
            ),
            (
                "ordinary argv quote expansion",
                "exec_argv",
                json!({"host":"allowed","argv":["true","'".repeat(20_000)]}),
            ),
            (
                "ordinary cwd quote expansion",
                "exec_argv",
                json!({"host":"allowed","argv":["true"],"cwd":format!("/{}", "'".repeat(20_000))}),
            ),
            (
                "empty ordinary arguments",
                "exec_argv",
                json!({"host":"allowed","argv":&argv}),
            ),
            (
                "empty sudo arguments",
                "exec_sudo",
                json!({"host":"allowed","user":"root","argv":argv}),
            ),
        ];
        for (index, (label, tool, arguments)) in cases.into_iter().enumerate() {
            let id = 10 + index as u64;
            server
                .send(json!({
                    "jsonrpc":"2.0", "id":id, "method":"tools/call",
                    "params":{"name":tool,"arguments":arguments}
                }))
                .await?;
            let response = server.response(id).await?;
            let result = &response["result"];
            ensure!(result["isError"] == true, "{label}: expected tool error");
            let content = &result["structuredContent"];
            ensure!(
                content.get("data") == Some(&Value::Null),
                "{label}: expected null data"
            );
            ensure!(
                content["error"]["code"] == "invalid_argument",
                "{label}: expected invalid_argument"
            );
            ensure!(
                content["error"]["remote_state_unknown"] == false,
                "{label}: remote state must remain known"
            );
        }
        server
            .send(json!({
                "jsonrpc":"2.0", "id":20, "method":"tools/call",
                "params":{"name":"observe_targets","arguments":{}}
            }))
            .await?;
        let discovery = server.response(20).await?;
        ensure!(discovery["result"]["isError"] != true);
        let data = discovery_data(&discovery["result"], "configured")?;
        let rows = data["targets"].as_array().context("recovery targets")?;
        ensure!(
            rows.len() == 1,
            "discovery failed after encoded-command rejections"
        );
        ensure!(rows[0]["name"] == "allowed");
        ensure!(rows[0]["sudo_mode"] == "same-account");
        ensure!(rows[0].get("description") == Some(&Value::Null));
        ensure!(rows[0]["labels"] == json!({}));
        ensure!(rows[0]["observed_capabilities"] == "unknown");
        ensure!(
            rows[0]["permitted_operations"]
                == json!([
                    "change_directory_remove",
                    "change_file_remove",
                    "change_file_replace",
                    "change_file_write",
                    "change_mkdir",
                    "change_rename",
                    "exec_argv",
                    "exec_command",
                    "exec_sudo",
                    "inspect_directory",
                    "inspect_file",
                    "observe_stat"
                ])
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("encoded-command scenario timed out")
    .and_then(|result| result);
    let finished = server.finish().await;
    let removed = dir.close();
    scenario?;
    let (status, stderr) = finished?;
    removed?;
    ensure!(status.success(), "server exit status: {status}");
    let mut rejected = [false; 4];
    for line in std::str::from_utf8(&stderr)?.lines() {
        let record: Value = serde_json::from_str(line).context("non-JSON audit record")?;
        ensure!(
            record["event"] != "master_start",
            "encoded-command rejection launched SSH"
        );
        for (index, seen) in rejected.iter_mut().enumerate() {
            if record["event"] == "reject" && record["request_id"] == 10 + index as u64 {
                ensure!(record["error_code"] == "invalid_argument");
                ensure!(record["remote_state_unknown"] == false);
                *seen = true;
            }
        }
    }
    ensure!(
        rejected.into_iter().all(|seen| seen),
        "missing encoded-command rejection audit records"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn insufficient_reply_budget_rejects_before_ssh_and_keeps_session_usable() -> Result<()> {
    const MESSAGE_LIMIT: usize = 16_777_216;
    let (mut server, _directory) = server_with_config(
        "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }\n[targets]\n",
    )?;
    let scenario = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})).await?;
        let listed = server.response(3).await?;
        let tools = listed["result"]["tools"].as_array().context("budget tool catalog")?;
        for (name, arguments) in [
            (
                "exec_command",
                json!({"host":"127.0.0.1","command":"printf budget"}),
            ),
            (
                "exec_command",
                json!({"host":"127.0.0.1","command":"printf budget","retain_output":true}),
            ),
            (
                "exec_argv",
                json!({"host":"127.0.0.1","argv":["/usr/bin/true"],"retain_output":true}),
            ),
            (
                "change_mkdir",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
            (
                "change_rename",
                json!({"host":"127.0.0.1","source":"budget-private-source","destination":"budget-private-destination","overwrite":true}),
            ),
            (
                "change_file_replace",
                json!({"host":"127.0.0.1","path":"budget-private-path","content":"x","overwrite":true}),
            ),
            (
                "change_file_remove",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
            (
                "change_directory_remove",
                json!({"host":"127.0.0.1","path":"budget-private-path"}),
            ),
        ] {
            ensure!(tools.iter().any(|tool| tool["name"] == name), "{name}: budget route absent");
            // Each full-size wire boundary has its own bounded deadline; adding
            // independent cases must not turn this into a suite-speed assertion.
            timeout(Duration::from_secs(20), async {
            let id = Value::String("i".repeat(MESSAGE_LIMIT - 256));
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {"name":name,"arguments":arguments}
            });
            let request_bytes = serde_json::to_vec(&request)?.len() + 1;
            ensure!(
                request_bytes < MESSAGE_LIMIT,
                "{name}: request must fit incoming limit: {request_bytes} bytes"
            );
            server.send(request).await?;
            let (response, response_bytes) = server.response_with_id(&id).await?;
            ensure!(response["id"] == id, "response did not preserve request ID");
            ensure!(
                response["error"]["code"] == -32602,
                "{name}: insufficient reply budget must be a protocol invalid-params error"
            );
            ensure!(
                response.get("result").is_none(),
                "{name}: rejected request returned a tool result"
            );
            ensure!(
                response_bytes <= MESSAGE_LIMIT,
                "response exceeds limit including newline: {response_bytes} bytes"
            );
            ensure!(
                !serde_json::to_string(&response)?.contains("budget-private-"),
                "{name}: reply-budget rejection disclosed private paths"
            );
                Ok::<_, anyhow::Error>(())
            }).await.with_context(|| format!("{name}: reply-budget case timed out"))??;
        }
        server
            .send(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "observe_targets", "arguments": {}}
            }))
            .await?;
        let targets = server.response(2).await?;
        ensure!(targets["result"]["isError"] != true);
        ensure!(
            discovery_data(&targets["result"], "configured")?["targets"] == json!([]),
            "normal discovery failed after budget rejection"
        );
        Ok::<_, anyhow::Error>(())
    }.await;
    let finished = server.finish().await;
    scenario?;
    let (status, stderr) = finished?;
    ensure!(status.success(), "server exit status: {status}");
    for line in std::str::from_utf8(&stderr)?.lines() {
        let record: Value = serde_json::from_str(line)?;
        ensure!(
            record["event"] != "master_start",
            "budget-rejected request launched SSH"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_requests_return_policy_denied_even_when_operations_saturated() -> Result<()> {
    let fixture = ControllerProtocolFixture::new()?;
    let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|path| path.join("sleep"))
        .chain([std::path::PathBuf::from("/bin/sleep")])
        .find(|path| path.is_file())
        .context("sleep executable is required")?;
    let sleep_q = format!("'{}'", sleep.to_string_lossy().replace('\'', "'\\''"));
    let marker_dir = fixture.directory.path().join("sat-markers");
    std::fs::create_dir(&marker_dir)?;
    let marker_dir_q = format!(
        "'{}'",
        marker_dir
            .to_str()
            .context("marker dir UTF-8")?
            .replace('\'', "'\\''")
    );
    let release = fixture.directory.path().join("sat-release");
    let release_q = format!(
        "'{}'",
        release
            .to_str()
            .context("release path UTF-8")?
            .replace('\'', "'\\''")
    );
    let script = format!(
        r#"IFS= read -r payload < "$1" || :
case "$payload" in
  *SLOT-1*) idx=1 ;;
  *SLOT-2*) idx=2 ;;
  *SLOT-3*) idx=3 ;;
  *SLOT-4*) idx=4 ;;
  *SLOT-5*) idx=5 ;;
  *SLOT-6*) idx=6 ;;
  *SLOT-7*) idx=7 ;;
  *SLOT-8*) idx=8 ;;
  *) idx=0 ;;
esac
: > {marker_dir_q}/started-"$idx"
i=0
while [ ! -f {release_q} ] && [ "$i" -lt 200 ]; do
  {sleep_q} 0.05
  i=$((i+1))
done
"#
    );
    std::fs::write(&fixture.source, script.as_bytes())?;
    use sha2::{Digest, Sha256};
    let hash = hex::encode(Sha256::digest(std::fs::read(&fixture.source)?));
    let config = fixture
        .config
        .replace(&fixture.hash, &hash)
        .replace(
            "capabilities = { named = true }",
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }",
        )
        .replace("timeout_secs = 2", "timeout_secs = 5");
    let mut server = fixture.start(&config)?;
    let scenario = async {
        server.initialize().await?;
        // Saturate all 8 global operation slots.
        for idx in 1..=8 {
            server
                .send(modern_request(
                    json!(idx),
                    "tools/call",
                    json!({
                        "name": "observe_controller",
                        "arguments": {"label": format!("SLOT-{idx}-CONTROLLER_INPUT_SECRET"), "count": 1, "verbose": false}
                    }),
                    MODERN_VERSION,
                ))
                .await?;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while std::fs::read_dir(&marker_dir)?.count() < 8 {
            ensure!(tokio::time::Instant::now() < deadline, "did not saturate 8 slots");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Unauthorized command and file calls must still return policy_denied, not resource_limit.
        server
            .send(modern_request(
                json!(101),
                "tools/call",
                json!({"name": "exec_command", "arguments": {"host": "unconfigured", "command": "true"}}),
                MODERN_VERSION,
            ))
            .await?;
        profile_policy_denied(&server.response(101).await?)?;
        server
            .send(modern_request(
                json!(102),
                "tools/call",
                json!({"name": "inspect_file", "arguments": {"host": "unconfigured", "path": "/etc/hosts"}}),
                MODERN_VERSION,
            ))
            .await?;
        profile_policy_denied(&server.response(102).await?)?;
        // An authorized call queues for a slot until its deadline instead of
        // being rejected at admission while all eight operation slots are busy.
        server
            .send(modern_request(
                json!(103),
                "tools/call",
                json!({
                    "name": "observe_controller",
                    "arguments": {"label": "CONTROLLER_INPUT_SECRET", "count": 1, "verbose": false}
                }),
                MODERN_VERSION,
            ))
            .await?;
        // Slots free only after the fixture observes this release, so an admitted
        // request must still be queued here; a rejection would have already
        // returned resource_limit instead of running to completion below.
        std::fs::write(&release, b"done")?;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 1..=9 {
            let (frame, _) = server
                .frame()
                .await?
                .context("server closed stdout before saturated calls finished")?;
            let id = frame["id"].as_u64().context("saturated response id")?;
            if id == 103 {
                ensure!(
                    frame["result"]["structuredContent"]["error"].is_null(),
                    "queued operation failed after a slot freed: {frame}"
                );
            }
            ensure!(seen.insert(id), "duplicate saturated response id {id}");
        }
        let mut expected: std::collections::BTreeSet<u64> = (1..=8).collect();
        expected.insert(103);
        ensure!(seen == expected, "unexpected saturated response ids: {seen:?}");
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let _ = std::fs::write(&release, b"done");
    let finished = server.finish().await;
    scenario?;
    let (status, _) = finished?;
    ensure!(status.success());
    Ok(())
}
