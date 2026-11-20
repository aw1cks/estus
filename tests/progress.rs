//! Consumer-visible progress acceptance against the installed server and real children.
#![cfg(unix)]

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod support;

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{Fixture, Log, WireServer, assert_masters_gone, masters, quote};
use tokio::time::{sleep, timeout};

const WAIT: Duration = Duration::from_secs(15);
const STRING_TOKEN: &str = "PROGRESS_PRIVATE_TOKEN_73b1";

struct Trace {
    token: Value,
    started: Instant,
    values: Vec<u64>,
    final_seen: bool,
}

impl Trace {
    fn new(token: Value) -> Self {
        Self {
            token,
            started: Instant::now(),
            values: Vec::new(),
            final_seen: false,
        }
    }

    fn observe(&mut self, frame: &Value, size: usize) -> Result<()> {
        ensure!(
            !self.final_seen,
            "progress arrived after its final response: {frame}"
        );
        ensure!(size <= 1024, "unbounded progress frame: {size}");
        let params = frame["params"].as_object().context("progress params")?;
        ensure!(
            params.get("progressToken") == Some(&self.token),
            "wrong correlation: {frame}"
        );
        ensure!(params.get("total").is_none(), "invented total: {frame}");
        ensure!(params.len() == 3, "unexpected progress metadata: {frame}");
        ensure!(
            params.get("message") == Some(&json!("Command output bytes received")),
            "progress disclosed output or invented a stage: {frame}"
        );
        let number = params
            .get("progress")
            .and_then(Value::as_f64)
            .context("numeric byte count")?;
        ensure!(
            number.is_finite()
                && number >= 0.0
                && number.fract() == 0.0
                && number <= 9_007_199_254_740_991.0,
            "invalid byte count: {frame}"
        );
        let value = number as u64;
        if let Some(previous) = self.values.last() {
            ensure!(value > *previous, "non-increasing byte count: {frame}");
        }
        self.values.push(value);
        // Allow a first immediate notification and scheduling/second-boundary slack.
        // This deliberately does not pin the implementation's default interval.
        ensure!(
            self.values.len() as f64 <= self.started.elapsed().as_secs_f64() * 4.0 + 3.0,
            "progress exceeds the fixed four-per-second bound"
        );
        Ok(())
    }
}

async fn call(
    server: &mut WireServer,
    id: u64,
    name: &str,
    arguments: Value,
    token: Option<Value>,
) -> Result<()> {
    let mut params = json!({"name":name,"arguments":arguments});
    if let Some(token) = token {
        params["_meta"] = json!({"progressToken":token});
    }
    server
        .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":params}))
        .await
}

fn notification(frame: &Value) -> Result<()> {
    ensure!(
        frame.get("id").is_none() && frame["method"] == "notifications/progress",
        "unexpected protocol frame: {frame}"
    );
    Ok(())
}

fn envelope(frame: &Value) -> Result<&Value> {
    ensure!(frame.get("error").is_none(), "JSON-RPC error: {frame}");
    let result = &frame["result"]["structuredContent"];
    ensure!(
        result.get("data").is_some() && result.get("error").is_some(),
        "missing result: {frame}"
    );
    let text: Value = serde_json::from_str(
        frame["result"]["content"][0]["text"]
            .as_str()
            .context("text envelope")?,
    )?;
    ensure!(text == *result, "text and structured result diverged");
    Ok(result)
}

async fn response(
    server: &mut WireServer,
    id: u64,
    mut trace: Option<&mut Trace>,
) -> Result<Value> {
    timeout(WAIT, async {
        loop {
            let (frame, size) = server.frame().await?;
            if frame.get("id") == Some(&json!(id)) {
                if let Some(trace) = &mut trace {
                    trace.final_seen = true;
                }
                return Ok(frame);
            }
            notification(&frame)?;
            trace
                .as_deref_mut()
                .context("unsolicited progress without an admitted token")?
                .observe(&frame, size)?;
        }
    })
    .await
    .context("progress response deadline")?
}

async fn barrier(server: &mut WireServer, id: u64) -> Result<()> {
    server
        .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}}))
        .await?;
    let frame = response(server, id, None).await?;
    ensure!(
        frame["result"]["tools"].is_array(),
        "tools/list barrier failed: {frame}"
    );
    Ok(())
}

async fn cancelled_barrier(server: &mut WireServer, id: u64, trace: &mut Trace) -> Result<()> {
    // An already-started complete frame can precede this response; no new
    // notification may follow the response barrier.
    server
        .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}}))
        .await?;
    let frame = response(server, id, Some(trace)).await?;
    ensure!(frame["result"]["tools"].is_array());
    barrier(server, id + 1000).await
}

async fn finish(log: &Log, id: u64, code: Option<&str>) -> Result<Value> {
    timeout(WAIT, async {
        loop {
            if let Some(record) = log
                .records()?
                .into_iter()
                .find(|record| record["event"] == "finish" && record["request_id"] == id)
            {
                if let Some(code) = code {
                    ensure!(
                        record["error_code"] == code,
                        "wrong terminal outcome: {record}"
                    );
                }
                return Ok(record);
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("independent finish audit deadline")?
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("UTF-8 acceptance path")
}

fn native_stream(release: &Path, ready: &Path, chunks: usize) -> Result<String> {
    // Burst enough data to exceed capture, then keep one observation window;
    // do not turn output progress into a repeated process-launch benchmark.
    Ok(format!(
        "i=0; while [ \"$i\" -lt {chunks} ]; do printf '%s' {}; printf '%s' {} >&2; i=$((i+1)); done; printf ready > {}; sleep 1; i=0; while [ ! -f {} ] && [ \"$i\" -lt 400 ]; do sleep 0.02; i=$((i+1)); done; exit 23",
        quote(&"o".repeat(1024)),
        quote(&"e".repeat(1024)),
        quote(text(ready)?),
        quote(text(release)?)
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn progress_native_correlation_clipping_suppression_and_terminal_outcomes() -> Result<()> {
    let mut fixture = Fixture::start().await?;
    let work = async {
        let mut server = WireServer::start(&fixture.config)?;
        let releases: Vec<_> = (0..5).map(|n| fixture.root.path().join(format!("release-{n}"))).collect();
        let done = fixture.root.path().join("interrupted-done");
        let interrupted_release = fixture.root.path().join("interrupted-release");
        let scenario = async {
            server.initialize().await?;
            // Absence is checked on every raw frame, not a receive helper that filters notifications.
            for (index, token) in [None, Some(json!("x".repeat(300))), Some(json!({"invalid":"TOKEN_OBJECT_PRIVATE"})), Some(json!(["TOKEN_ARRAY_PRIVATE"]))].into_iter().enumerate() {
                let id = 10 + index as u64;
                call(&mut server, id, "exec_command", json!({"host":"plain","command":"printf SUPPRESSION_OK; sleep 0.6"}), token).await?;
                let frame = response(&mut server, id, None).await?;
                let result = envelope(&frame)?;
                ensure!(result["error"].is_null() && result["data"]["stdout"] == "SUPPRESSION_OK" && result["data"]["exit_code"] == 0,
                    "optional-token suppression changed execution: {result}");
                barrier(&mut server, id + 100).await?;
            }

            let mut traces = [Trace::new(json!(73)), Trace::new(json!(STRING_TOKEN))];
            for index in 0..2 {
                let ready = fixture.root.path().join(format!("ready-{index}"));
                let command = native_stream(&releases[index], &ready, 32 * (index + 1))?;
                call(&mut server, 20 + index as u64, "exec_command", json!({"host":"plain","command":command}), Some(traces[index].token.clone())).await?;
                // Keep both request lifetimes overlapping, but do not require
                // two simultaneously contending advisory writes to be delivered.
                timeout(WAIT, async {
                    while traces[index].values.last().copied().unwrap_or(0) <= 2048 {
                        let (frame, size) = server.frame().await?;
                        notification(&frame)?;
                        let observed = traces.iter().position(|trace| trace.token == frame["params"]["progressToken"]).context("foreign token")?;
                        traces[observed].observe(&frame, size)?;
                    }
                    Ok::<_, anyhow::Error>(())
                }).await.context("no active output observation reached its token")??;
            }
            // Progress may coalesce/drop the last count; independent remote
            // markers, never advisory delivery, control command lifetime.
            for index in 0..2 {
                Fixture::await_file(&fixture.root.path().join(format!("ready-{index}"))).await?;
            }
            for release in &releases[..2] { fs::write(release, b"release")?; }
            let mut remaining = 2;
            while remaining > 0 {
                let (frame, size) = server.frame().await?;
                if let Some(id) = frame["id"].as_u64() {
                    ensure!((20..=21).contains(&id), "unexpected response: {frame}");
                    let trace = &mut traces[(id - 20) as usize];
                    ensure!(!trace.final_seen, "duplicate final");
                    trace.final_seen = true;
                    remaining -= 1;
                    let result = envelope(&frame)?;
                    ensure!(result["error"]["code"] == "command_failed", "lost nonzero outcome: {result}");
                    let data = &result["data"];
                    ensure!(data["exit_code"] == 23 && data["termination"] == "exited");
                    ensure!(data["stdout"] == "o".repeat(1024) && data["stderr"] == "e".repeat(1024));
                    ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
                    ensure!(data["remote_may_still_be_running"] == false);
                } else {
                    notification(&frame)?;
                    let index = traces.iter().position(|trace| trace.token == frame["params"]["progressToken"]).context("foreign token")?;
                    traces[index].observe(&frame, size)?;
                }
            }
            for (index, trace) in traces.iter().enumerate() {
                let maximum = trace.values.last().copied().unwrap_or(0);
                ensure!(maximum > 2048 && maximum <= [65536, 131072][index],
                    "progress did not observe drained bytes beyond both retained prefixes: {:?}", trace.values);
            }
            barrier(&mut server, 120).await?;

            for cancel in [false, true] {
                for path in [&done, &interrupted_release] { if path.exists() { fs::remove_file(path)?; } }
                let ready = fixture.root.path().join(if cancel { "cancel-ready" } else { "timeout-ready" });
                let command = format!("printf PARTIAL_OUT; printf PARTIAL_ERR >&2; printf ready > {}; i=0; while [ ! -f {} ] && [ \"$i\" -lt 500 ]; do sleep 0.02; i=$((i+1)); done; printf done > {}", quote(text(&ready)?), quote(text(&interrupted_release)?), quote(text(&done)?));
                let id = if cancel { 31 } else { 30 };
                let mut trace = Trace::new(json!(if cancel { "cancel-native" } else { "timeout-native" }));
                call(&mut server, id, "exec_command", json!({"host":"plain","command":command,"timeout_secs":if cancel { 10 } else { 2 }}), Some(trace.token.clone())).await?;
                if !fixture.eventual_markers.contains(&done) { fixture.eventual_markers.push(done.clone()); }
                Fixture::await_file(&ready).await?;
                while trace.values.last().copied().unwrap_or(0) == 0 {
                    let (frame, size) = server.frame().await?;
                    notification(&frame)?;
                    trace.observe(&frame, size)?;
                }
                if cancel {
                    server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id,"reason":"progress acceptance"}})).await?;
                    let audit = finish(&server.log, id, Some("cancelled")).await?;
                    ensure!(audit["exit_code"].is_null() && audit["remote_state_unknown"] == true);
                    cancelled_barrier(&mut server, 131, &mut trace).await?;
                } else {
                    let frame = response(&mut server, id, Some(&mut trace)).await?;
                    let result = envelope(&frame)?;
                    ensure!(result["error"]["code"] == "timeout" && result["error"]["remote_state_unknown"] == true);
                    ensure!(result["data"]["stdout"] == "PARTIAL_OUT" && result["data"]["stderr"] == "PARTIAL_ERR");
                    ensure!(result["data"]["termination"] == "timeout" && result["data"]["remote_may_still_be_running"] == true);
                    barrier(&mut server, 130).await?;
                }
                ensure!(!done.exists(), "interruption waited for remote completion");
                fs::write(&interrupted_release, b"release")?;
                Fixture::await_file(&done).await?;
                barrier(&mut server, 140 + id).await?;
            }
            Ok::<_, anyhow::Error>(())
        }.await;
        // Always release real remote work before stopping its server/SSH listeners.
        for release in &releases { fs::write(release, b"release")?; }
        fs::write(&interrupted_release, b"release")?;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = assert_masters_gone(&owned?).await;
        scenario?;
        let log = stopped?;
        gone?;
        for secret in [STRING_TOKEN, "TOKEN_OBJECT_PRIVATE", "TOKEN_ARRAY_PRIVATE"] {
            ensure!(!log.text().contains(secret), "token leaked into audit");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = fixture.stop().await;
    work?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn progress_controller_script_counts_interruption_and_blocked_consumer_cleanup() -> Result<()>
{
    // Concrete reviewed source + checksum + private workspace, matching controller.rs.
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let root = temp.path().join("controller-private");
    let observations = temp.path().join("observations");
    for path in [&root, &observations] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(root.join("operator-owned-sentinel"), b"retain me")?;
    let sh = support::find_program("sh")?;
    let sleeper = support::find_program("sleep")?;
    let source = temp.path().join("reviewed-progress.sh");
    let config = temp.path().join("controller.toml");
    let script = format!(
        r#"
set -eu
case "$MCP_MODE" in
  count) chunks=64 ;;
  slow) chunks=1024 ;;
  overload)
    printf ran > {observations}/overload-ran
    exit 0 ;;
  interrupt)
    printf PARTIAL_OUT
    printf PARTIAL_ERR >&2
    printf ready > {observations}/interrupt-ready
    i=0
    while [ ! -f {observations}/release ] && [ "$i" -lt 1000 ]; do
      {sleep} 0.02
      i=$((i+1))
    done
    printf forbidden > {observations}/interrupt-done
    exit 0 ;;
esac
i=0
while [ "$i" -lt "$chunks" ]; do
  printf '%s' {out}
  printf '%s' {err} >&2
  i=$((i+1))
done
printf drained > {observations}/"$MCP_MODE"-drained
{sleep} 0.8
exit 23
"#,
        observations = quote(text(&observations)?),
        sleep = quote(text(&sleeper)?),
        out = quote(&"o".repeat(1024)),
        err = quote(&"e".repeat(1024))
    );
    fs::write(&source, &script)?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
    let digest = hex::encode(Sha256::digest(script.as_bytes()));
    let string = |path: &Path| -> Result<String> {
        Ok(toml::Value::String(text(path)?.to_owned()).to_string())
    };
    let mut configuration = format!(
        r#"
capabilities = {{ named = true }}
enabled_tools = ["count_controller", "slow_controller", "timeout_controller", "cancel_controller", "overload_controller"]
[controller]
workspace_root = {}
[limits]
operation_timeout_secs = 15
max_timeout_secs = 15
max_output_bytes = 1048576
"#,
        string(&root)?
    );
    for (name, mode, seconds, limit) in [
        ("count_controller", "count", 10, 4096),
        ("slow_controller", "slow", 10, 524_288),
        ("timeout_controller", "interrupt", 2, 4096),
        ("cancel_controller", "interrupt", 10, 4096),
        ("overload_controller", "overload", 10, 4096),
    ] {
        configuration.push_str(&format!(r#"
[tools.{name}]
description = "Reviewed controller progress acceptance"
revision = "progress-1"
authority = "controller"
effects = ["read"]
execution = {{ kind = "controller_script", source = {{ path = {source}, content_sha256 = "{digest}", max_bytes = 65536 }}, interpreter = {{ program = {sh}, argv = [] }}, environment = {{ MCP_MODE = "{mode}" }} }}
input_schema = {{ type = "object", additionalProperties = false, required = [], properties = {{}} }}
result = {{ kind = "controller_command" }}
limits = {{ timeout_secs = {seconds}, max_output_bytes = {limit} }}
"#, source = string(&source)?, sh = string(&sh)?));
    }
    fs::write(&config, configuration)?;
    let mut server = WireServer::start(&config)?;
    let scenario = async {
        server.initialize().await?;
        call(&mut server, 2, "count_controller", json!({}), None).await?;
        let frame = response(&mut server, 2, None).await?;
        controller_failure(&frame, 4096)?;
        barrier(&mut server, 102).await?;

        let mut trace = Trace::new(json!(STRING_TOKEN));
        call(
            &mut server,
            3,
            "count_controller",
            json!({}),
            Some(trace.token.clone()),
        )
        .await?;
        let frame = response(&mut server, 3, Some(&mut trace)).await?;
        controller_failure(&frame, 4096)?;
        ensure!(
            trace
                .values
                .last()
                .is_some_and(|value| *value > 8192 && *value <= 131072),
            "controller progress did not count discarded output bytes: {:?}",
            trace.values
        );
        barrier(&mut server, 103).await?;
        controller_clean(&root).await?;

        for cancel in [false, true] {
            let ready = observations.join("interrupt-ready");
            if ready.exists() {
                fs::remove_file(&ready)?;
            }
            let id = if cancel { 5 } else { 4 };
            let mut trace = Trace::new(json!(if cancel {
                "cancel-controller"
            } else {
                "timeout-controller"
            }));
            call(
                &mut server,
                id,
                if cancel {
                    "cancel_controller"
                } else {
                    "timeout_controller"
                },
                json!({}),
                Some(trace.token.clone()),
            )
            .await?;
            Fixture::await_file(&ready).await?;
            while trace.values.last().copied().unwrap_or(0) == 0 {
                let (frame, size) = server.frame().await?;
                notification(&frame)?;
                trace.observe(&frame, size)?;
            }
            if cancel {
                server
                    .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                    "params":{"requestId":id,"reason":"controller progress acceptance"}}))
                    .await?;
                let audit = finish(&server.log, id, Some("cancelled")).await?;
                ensure!(
                    audit["owned_group_cleanup"] == "signalled_and_reaped",
                    "cancel failed owned cleanup: {audit}"
                );
                ensure!(audit.get("remote_state_unknown").is_none());
                cancelled_barrier(&mut server, 205, &mut trace).await?;
            } else {
                let frame = response(&mut server, id, Some(&mut trace)).await?;
                let result = envelope(&frame)?;
                ensure!(result["error"]["code"] == "timeout");
                ensure!(result["error"].get("remote_state_unknown").is_none());
                let data = &result["data"];
                ensure!(data["stdout"] == "PARTIAL_OUT" && data["stderr"] == "PARTIAL_ERR");
                ensure!(data["termination"] == "timeout" && data["exit_code"].is_null());
                ensure!(data["owned_group_cleanup"] == "signalled_and_reaped");
            }
            controller_clean(&root).await?;
            ensure!(
                !observations.join("interrupt-done").exists(),
                "interrupted local script kept running"
            );
            barrier(&mut server, 100 + id).await?;
        }

        // Leave stdout unread while filling 16 request credits, cancelling one
        // active request before overload, then submitting a 17th request.
        let ready = observations.join("interrupt-ready");
        if ready.exists() {
            fs::remove_file(&ready)?;
        }
        call(
            &mut server,
            300,
            "slow_controller",
            json!({}),
            Some(json!("slow-controller-private")),
        )
        .await?;
        Fixture::await_file(&observations.join("slow-drained")).await?;
        let audit = finish(&server.log, 300, Some("command_failed")).await?;
        ensure!(
            audit["exit_code"] == 23 && audit["owned_group_cleanup"] == "signalled_and_reaped",
            "blocked stdout delayed owned completion: {audit}"
        );
        controller_clean(&root).await?;
        // Let slow_controller's ~2 MiB frame enter BoundedTransport::send and block on the OS pipe.
        // Request 5 (cancelled earlier) reclaimed its credit after cleanup.
        // Fill 300 (1) + 14 tools/list = 15, cancel 301 in slot 16 and verify reclamation,
        // then refill slot 16 (tools/list 1099) and trip overload on 302 (17th).
        sleep(Duration::from_millis(50)).await;
        timeout(WAIT, async {
            for index in 0..14_u64 {
                server
                    .send(json!({"jsonrpc":"2.0","id":1000 + index,
                    "method":"tools/list","params":{}}))
                    .await?;
            }
            call(&mut server, 301, "cancel_controller", json!({}), None).await
        })
        .await
        .context("blocked consumer prevented request intake")??;
        Fixture::await_file(&ready).await?;
        server
            .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":301,"reason":"cancel before overload"}}))
            .await?;
        let audit = finish(&server.log, 301, Some("cancelled")).await?;
        ensure!(
            audit["owned_group_cleanup"] == "signalled_and_reaped",
            "cancel before overload failed owned cleanup: {audit}"
        );
        controller_clean(&root).await?;
        server
            .send(json!({"jsonrpc":"2.0","id":1099,"method":"tools/list","params":{}}))
            .await?;
        call(&mut server, 302, "overload_controller", json!({}), None).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    .with_context(|| format!("controller progress audit: {}", server.log.text()));
    let release = fs::write(observations.join("release"), b"release");
    let exited = server.wait_exit().await;
    scenario?;
    release?;
    let (status, frames, log) = exited?;
    ensure!(
        !status.success(),
        "overloaded session exited cleanly: {status}"
    );
    let records = log.final_records()?;
    ensure!(
        records
            .iter()
            .any(|record| record["event"] == "error" && record["code"] == "mcp_session_overloaded"),
        "missing mcp_session_overloaded audit record: {}",
        log.text()
    );
    ensure!(
        !observations.join("overload-ran").exists(),
        "17th overloaded request executed handler"
    );
    ensure!(
        !observations.join("interrupt-done").exists(),
        "cancelled script survived overload shutdown"
    );
    let response_count = frames
        .iter()
        .filter(|frame| frame.get("id").is_some())
        .count();
    ensure!(
        response_count <= 16,
        "retained response count exceeded 16: {response_count}"
    );
    let slow_progress_count = frames
        .iter()
        .filter(|frame| frame["params"]["progressToken"] == "slow-controller-private")
        .count();
    ensure!(
        slow_progress_count <= 2,
        "blocked consumer accumulated progress backlog: {slow_progress_count}"
    );
    for secret in [
        STRING_TOKEN,
        "slow-controller-private",
        "PARTIAL_OUT",
        "PARTIAL_ERR",
    ] {
        ensure!(
            !log.text().contains(secret),
            "progress/controller payload leaked into audit"
        );
    }
    controller_clean(&root).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn sequential_cancelled_requests_reclaim_credits_without_session_overload() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let root = temp.path().join("controller-private");
    let observations = temp.path().join("observations");
    for path in [&root, &observations] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    fs::write(root.join("operator-owned-sentinel"), b"retain me")?;
    let sh = support::find_program("sh")?;
    let sleeper = support::find_program("sleep")?;
    let source = temp.path().join("reviewed-cancel.sh");
    let config = temp.path().join("controller.toml");
    let script = format!(
        r#"
set -eu
case "$MCP_MODE" in
  verify)
    printf ran > {observations}/verify-ran
    exit 0 ;;
  interrupt)
    printf ready > {observations}/interrupt-ready
    i=0
    while [ ! -f {observations}/release ] && [ "$i" -lt 1000 ]; do
      {sleep} 0.02
      i=$((i+1))
    done
    exit 0 ;;
esac
"#,
        observations = quote(text(&observations)?),
        sleep = quote(text(&sleeper)?),
    );
    fs::write(&source, &script)?;
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600))?;
    let digest = hex::encode(Sha256::digest(script.as_bytes()));
    let string = |path: &Path| -> Result<String> {
        Ok(toml::Value::String(text(path)?.to_owned()).to_string())
    };
    let mut configuration = format!(
        "capabilities = {{ named = true }}\nenabled_tools = [\"cancel_controller\", \"verify_controller\"]\n[controller]\nworkspace_root = {}\n",
        string(&root)?
    );
    for (name, mode) in [
        ("cancel_controller", "interrupt"),
        ("verify_controller", "verify"),
    ] {
        configuration.push_str(&format!(
            "\n[tools.{name}]\ndescription = \"Cancel credit test\"\nrevision = \"cancel-1\"\nauthority = \"controller\"\neffects = [\"read\"]\nexecution = {{ kind = \"controller_script\", source = {{ path = {}, content_sha256 = \"{digest}\", max_bytes = 65536 }}, interpreter = {{ program = {}, argv = [] }}, environment = {{ MCP_MODE = \"{mode}\" }} }}\ninput_schema = {{ type = \"object\", additionalProperties = false, required = [], properties = {{}} }}\nresult = {{ kind = \"controller_command\" }}\n",
            string(&source)?,
            string(&sh)?
        ));
    }
    fs::write(&config, configuration)?;
    let mut server = WireServer::start(&config)?;
    let ready = observations.join("interrupt-ready");
    let scenario = async {
        server.initialize().await?;
        for id in 2..=21_u64 {
            if ready.exists() {
                fs::remove_file(&ready)?;
            }
            call(&mut server, id, "cancel_controller", json!({}), None).await?;
            Fixture::await_file(&ready).await?;
            server
                .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                "params":{"requestId":id,"reason":"sequential cancel"}}))
                .await?;
            let audit = finish(&server.log, id, Some("cancelled")).await?;
            ensure!(audit["owned_group_cleanup"] == "signalled_and_reaped");
            controller_clean(&root).await?;
        }
        call(&mut server, 22, "verify_controller", json!({}), None).await?;
        let frame = response(&mut server, 22, None).await?;
        let result = envelope(&frame)?;
        ensure!(result["error"].is_null() && result["data"]["exit_code"] == 0);
        ensure!(observations.join("verify-ran").exists());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let release = fs::write(observations.join("release"), b"release");
    let stopped = server.stop(None).await;
    scenario?;
    release?;
    stopped?;
    controller_clean(&root).await
}

fn controller_failure(frame: &Value, limit: usize) -> Result<()> {
    let result = envelope(frame)?;
    ensure!(
        result["error"]["code"] == "command_failed",
        "lost controller nonzero exit: {result}"
    );
    let data = &result["data"];
    ensure!(data["exit_code"] == 23 && data["termination"] == "exited");
    ensure!(data["stdout"] == "o".repeat(limit) && data["stderr"] == "e".repeat(limit));
    ensure!(data["stdout_truncated"] == true && data["stderr_truncated"] == true);
    ensure!(
        data["owned_group_cleanup"] == "signalled_and_reaped",
        "missing owned cleanup: {result}"
    );
    ensure!(data.get("remote_may_still_be_running").is_none());
    Ok(())
}

async fn controller_clean(root: &Path) -> Result<()> {
    timeout(WAIT, async {
        loop {
            let entries = fs::read_dir(root)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<PathBuf>>>()?;
            if entries == [root.join("operator-owned-sentinel")] {
                ensure!(
                    fs::read(&entries[0])? == b"retain me",
                    "operator sentinel changed"
                );
                return Ok(());
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("controller retained private operation files")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires loopback networking, Nix OpenSSH and a non-root local account"]
async fn progress_sftp_channel_stage_preserves_exact_read_and_terminal_order() -> Result<()> {
    let subsystem = format!(
        "/bin/sh -c {}",
        quote(&format!(
            "sleep 1; exec {}",
            Fixture::sftp_server()?.display()
        ))
    );
    let fixture = Fixture::start_with_sftp_subsystem("", &subsystem).await?;
    let scenario = async {
        let path = fixture.root.path().join("private-progress-read");
        fs::write(&path, b"EXACT_SFTP_BYTES")?;
        let mut server = WireServer::start(&fixture.config)?;
        let result = async {
            server.initialize().await?;
            call(
                &mut server,
                2,
                "inspect_file",
                json!({"host":"plain","path":path,"max_bytes":16}),
                Some(json!(-17)),
            )
            .await?;
            let mut previous = 0.0;
            let frame = timeout(WAIT, async {
                loop {
                    let (frame, size) = server.frame().await?;
                    if frame["id"] == 2 {
                        break Ok::<_, anyhow::Error>(frame);
                    }
                    notification(&frame)?;
                    let params = &frame["params"];
                    let value = params["progress"].as_f64().context("stage ordinal")?;
                    ensure!(value > previous && value <= 3.0 && value.fract() == 0.0);
                    previous = value;
                    ensure!(params["progressToken"] == -17 && params.get("total").is_none());
                    ensure!(
                        size <= 512
                            && matches!(
                                params["message"].as_str(),
                                Some(
                                    "SFTP channel opened"
                                        | "SFTP session ready"
                                        | "SFTP operation acknowledged"
                                )
                            )
                    );
                }
            })
            .await
            .context("SFTP progress deadline")??;
            let result = envelope(&frame)?;
            ensure!(
                previous > 0.0,
                "no actual channel stage observed during delayed handshake"
            );
            ensure!(result["error"].is_null() && result["data"]["content"] == "EXACT_SFTP_BYTES");
            ensure!(
                result["data"]["content_sha256"]
                    == hex::encode(Sha256::digest(b"EXACT_SFTP_BYTES"))
            );
            barrier(&mut server, 3).await
        }
        .await;
        let owned = masters(&server.log);
        let stopped = server.stop(None).await;
        let gone = assert_masters_gone(&owned?).await;
        result?;
        stopped?;
        gone
    }
    .await;
    let cleanup = fixture.stop().await;
    scenario?;
    cleanup
}
