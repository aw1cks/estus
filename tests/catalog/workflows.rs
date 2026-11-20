//! Opt-in, public-authoring acceptance on a fresh disposable NixOS guest per test.
//! Shell access below is trusted fixture setup/readback, never an MCP capability.
use crate::{catalog, support};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::{sleep, timeout};

const HEALTH: &str = include_str!("../../examples/workflows/health.toml");
const DIAGNOSIS: &str = include_str!("../../examples/workflows/service-diagnosis.toml");
const RESTART: &str = include_str!("../../examples/workflows/service-restart.toml");
const UNIT: &str = "estus-fixture.service";
const WAIT: Duration = Duration::from_secs(90);

async fn oracle(guest: &catalog::Guest, script: &str) -> Result<String> {
    let output = guest.shell(script).await?;
    ensure!(
        output.status.success(),
        "fixture/oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("oracle UTF8")
}

async fn host_state(guest: &catalog::Guest) -> Result<Value> {
    let text = oracle(guest, "/usr/bin/python3 -I -c 'import json,os; print(json.dumps(dict(boot_id=open(\"/proc/sys/kernel/random/boot_id\").read().strip(), kernel=os.uname().release, architecture=os.uname().machine, uptime_seconds=int(float(open(\"/proc/uptime\").read().split()[0])))))'").await?;
    serde_json::from_str(&text).context("host oracle JSON")
}

async fn unit_state(guest: &catalog::Guest, unit: &str) -> Result<Value> {
    let text = oracle(guest, &format!(
        "/usr/bin/python3 -I -c 'import json,subprocess; raw=subprocess.check_output([\"/usr/bin/systemctl\",\"show\",\"--property=Id,ActiveState,SubState,MainPID,InvocationID,Result\",\"--\",{unit:?}],text=True); print(json.dumps(dict(line.split(\"=\",1) for line in raw.splitlines())))'"
    )).await?;
    serde_json::from_str(&text).context("unit oracle JSON")
}

async fn controller_local_processes(
    workspace: &std::path::Path,
) -> Result<std::collections::BTreeSet<u32>> {
    let needle = workspace.to_str().context("workflow workspace UTF8")?;
    let mut command = tokio::process::Command::new(support::find_program("ps")?);
    command.args(["-axo", "pid=,args="]);
    let output = support::run(&mut command).await?;
    ensure!(
        output.status.success(),
        "cannot observe owned Runner processes"
    );
    let mut owned = std::collections::BTreeSet::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let Some((pid, arguments)) = line.trim_start().split_once(' ') else {
            continue;
        };
        if arguments.contains(needle) {
            owned.insert(pid.parse().context("observed Runner PID")?);
        }
    }
    Ok(owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM, ESTUS_TEST_ANSIBLE_BUNDLE; disposable Linux EFI guest"]
async fn reviewed_health_workflow() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = catalog::Binding::prepare_workflow(&guest.config, HEALTH).await?;
        binding.inspect_workflow_list().await?;
        binding.reject_workflow_runtime().await?;
        binding.reject(json!({"command":"uname -a"})).await?;
        let before = host_state(&guest).await?;
        let reply = binding.call(json!({})).await?;
        let after = host_state(&guest).await?;
        let value = catalog::projection(&reply)?;
        for key in ["boot_id", "kernel", "architecture"] {
            ensure!(value[key] == before[key] && value[key] == after[key], "health observation differs from independent {key}: {value}");
        }
        let uptime = value["uptime_seconds"].as_u64().context("observed uptime")?;
        ensure!(uptime >= before["uptime_seconds"].as_u64().context("before uptime")?
            && uptime <= after["uptime_seconds"].as_u64().context("after uptime")?, "uptime was not a real bounded observation");
        ensure!(value["system"] == "Linux" && value["scope"] == "ssh_process_view"
            && value.get("health").is_none(), "host observation was promoted to health/attestation");
        eprintln!("A14_WORKFLOW_SCOPE {}", json!({
            "workflow":"health", "platform":"disposable_nixos_efi_guest",
            "architecture":value["architecture"], "kernel":value["kernel"],
            "distribution":value["distribution"], "distribution_version":value["distribution_version"],
            "authority":"automation", "observation_scope":value["scope"]
        }));
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM, ESTUS_TEST_ANSIBLE_BUNDLE; disposable Linux EFI guest"]
async fn reviewed_service_diagnosis_workflow() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = catalog::Binding::prepare_workflow(&guest.config, DIAGNOSIS).await?;
        binding.inspect_workflow_list().await?;
        binding.reject(json!({"unit":"ssh.service"})).await?;
        oracle(&guest, "systemctl stop estus-fixture-idle.service; systemctl start estus-fixture-fail.service >/dev/null 2>&1; systemctl is-failed --quiet estus-fixture-fail.service").await?;
        for (unit, state) in [(UNIT, "active"), ("estus-fixture-idle.service", "inactive"), ("estus-fixture-fail.service", "failed")] {
            let before = unit_state(&guest, unit).await?;
            let reply = binding.call(json!({"unit":unit})).await?;
            let value = catalog::projection(&reply)?;
            let after = unit_state(&guest, unit).await?;
            ensure!(before == after, "diagnosis changed manager state: {unit}");
            ensure!(value["scope"] == "system" && value["properties"]["ActiveState"] == state, "{state} must be state data, not a workflow failure: {reply}");
            for key in ["Id", "ActiveState", "SubState", "MainPID", "InvocationID", "Result"] {
                if before[key] == "" {
                    ensure!(value["properties"].get(key).is_none()
                        && value["unavailable"].as_array().is_some_and(|fields| fields.iter().any(|field| field == key)),
                        "empty manager property was not truthfully unavailable: {unit}/{key}: {value}");
                } else {
                    ensure!(value["properties"][key] == before[key], "diagnosis {unit}/{key} differs from manager oracle: {value}");
                }
            }
            ensure!(value.get("health").is_none() && value["properties"].get("Environment").is_none(), "diagnosis claimed application health or exposed secrets");
        }
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM, ESTUS_TEST_ANSIBLE_BUNDLE; disposable Linux EFI guest"]
async fn reviewed_service_restart_workflow() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = catalog::Binding::prepare_workflow(&guest.config, RESTART).await?;
        binding.inspect_workflow_list().await?;
        let before = unit_state(&guest, UNIT).await?;
        binding.reject(json!({"unit":"ssh.service"})).await?;
        ensure!(
            before == unit_state(&guest, UNIT).await?,
            "denial altered selected unit"
        );
        let reply = binding.call(json!({"unit":UNIT})).await?;
        let value = catalog::projection(&reply)?;
        let after = unit_state(&guest, UNIT).await?;
        ensure!(
            value["operation"] == "restart"
                && value["operation_completed"] == true
                && value["health"] == "not_checked",
            "restart completion implied application health: {reply}"
        );
        ensure!(
            after["ActiveState"] == "active"
                && after["MainPID"] != "0"
                && before["MainPID"] != after["MainPID"]
                && before["InvocationID"] != after["InvocationID"],
            "manager did not actually restart selected service: {before} -> {after}"
        );
        ensure!(
            value["properties"]["MainPID"] == after["MainPID"],
            "restart readback differs from independent manager state"
        );
        interrupted_restart(&guest, &binding).await?;
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

/// Hold a real manager-owned stop job until cancellation is fully audited. The
/// manager can finish after the Runner is gone: cancellation is not rollback.
async fn interrupted_restart(guest: &catalog::Guest, binding: &catalog::Binding) -> Result<()> {
    oracle(
        guest,
        r#"set -eu
mkdir -p /run/systemd/system/estus-fixture.service.d
cat > /run/estus-a14-stop.py <<'PY'
import pathlib, time
with open('/run/estus-a14-attempts', 'a') as output:
    output.write('stop\n')
    output.flush()
deadline = time.monotonic() + 90
while not pathlib.Path('/run/estus-a14-release').exists():
    if time.monotonic() >= deadline:
        raise SystemExit('fixture stop gate deadline')
    time.sleep(0.05)
PY
cat > /run/systemd/system/estus-fixture.service.d/a14.conf <<'UNIT'
[Service]
ExecStop=
ExecStop=/usr/bin/python3 -I /run/estus-a14-stop.py
TimeoutStopSec=100
UNIT
systemctl daemon-reload
"#,
    )
    .await?;
    let before = unit_state(guest, UNIT).await?;
    let mut server = support::WireServer::start(&binding.config)?;
    let result: Result<()> = async {
        server.initialize().await?;
        server.send(json!({"jsonrpc":"2.0","id":40,"method":"tools/call","params":{
            "name":"change_systemd_restart","arguments":{"host":"plain","inputs":{"unit":UNIT},"timeout_secs":60}
        }})).await?;
        timeout(WAIT, async {
            loop {
                let seen = guest.shell("test -s /run/estus-a14-attempts").await?;
                if seen.status.success() {
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(50)).await;
            }
        }).await.context("restart never entered real manager-owned ExecStop")??;
        let pending = unit_state(guest, UNIT).await?;
        ensure!(pending["ActiveState"] == "deactivating", "fixture did not hold a real pending restart: {pending}");
        ensure!(
            controller_local_processes(&binding.workspace).await?.is_empty(),
            "SSH-native execution started an unexpected controller-local process"
        );
        server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{
            "requestId":40,"reason":"reviewed workflow cancellation during real systemd stop job"
        }})).await?;
        timeout(WAIT, async {
            loop {
                if let Some(finish) = server.log.records()?.into_iter().find(|row| row["event"] == "finish" && row["request_id"] == 40) {
                    ensure!(finish["error_code"] == "cancelled" && finish["remote_state_unknown"] == true
                        && finish["complete"] == false && finish["status"] == "cancelled",
                        "interrupted restart claimed completion/rollback: {finish}");
                    return Ok::<_, anyhow::Error>(());
                }
                sleep(Duration::from_millis(20)).await;
            }
        }).await.context("interrupted restart cleanup/audit deadline")??;
        Ok(())
    }.await;
    // Always release the fixture gate, even when an assertion failed. This is
    // trusted cleanup, NOT a second agent restart or an implicit retry.
    let release = oracle(guest, "touch /run/estus-a14-release").await;
    let stopped = server.stop(None).await;
    result?;
    release?;
    let log = stopped?;
    ensure!(
        log.records()?
            .iter()
            .filter(|row| row["event"] == "finish" && row["request_id"] == 40)
            .count()
            == 1,
        "cancelled restart was replayed"
    );
    timeout(WAIT, async {
        loop {
            let after = unit_state(guest, UNIT).await?;
            if after["ActiveState"] == "active"
                && after["InvocationID"] != before["InvocationID"]
                && after["MainPID"] != "0"
            {
                ensure!(
                    after["MainPID"] != before["MainPID"],
                    "interrupted manager job reused the old process"
                );
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("independent readback of manager job after cancellation")??;
    ensure!(
        oracle(guest, "cat /run/estus-a14-attempts").await? == "stop\n",
        "interrupted restart was automatically replayed"
    );
    ensure!(
        std::fs::read_dir(&binding.workspace)?.next().is_none(),
        "interrupted Runner left owned workspace"
    );
    ensure!(
        controller_local_processes(&binding.workspace)
            .await?
            .is_empty(),
        "interrupted restart retained a host process under its owned workspace"
    );
    Ok(())
}
