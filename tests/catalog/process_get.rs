use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn process_get() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let oracle = guest.shell("python3 -c 'import json,subprocess; p=int(subprocess.check_output([\"systemctl\",\"show\",\"estus-fixture.service\",\"-p\",\"MainPID\",\"--value\"])); s=open(\"/proc/%d/stat\"%p).read(); print(json.dumps({\"pid\":p,\"boot_id\":open(\"/proc/sys/kernel/random/boot_id\").read().strip(),\"start_ticks\":int(s[s.rfind(\") \")+2:].split()[19])}))'").await?;
        ensure!(oracle.status.success(), "independent process identity oracle");
        let identity: Value = serde_json::from_slice(&oracle.stdout)?;

        let binding = guest.binding("process_get", json!({})).await?;
        let mut invalid = identity.clone(); invalid["pid"] = json!(0);
        binding.reject(invalid).await?;
        let reply = binding.call(identity.clone()).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["status"] == "available", "fixture process available");
        let process = &value["process"];
        for key in ["pid", "boot_id", "start_ticks"] { ensure!(process[key] == identity[key], "independent identity {key}"); }
        ensure!(process["uid"] == 0, "fixture service owner");
        ensure!(process["limits"].as_array().context("limits")?.iter().any(|limit| limit["name"] == "Max open files"), "real proc limits");
        ensure!(process["cgroups"].as_array().context("cgroups")?.iter().any(|group| group.as_str().is_some_and(|s| s.contains("estus-fixture.service"))), "actual service cgroup membership");
        let mut reused = identity.clone(); reused["start_ticks"] = json!(identity["start_ticks"].as_u64().context("ticks")? + 1);
        let mismatch = binding.call(reused).await?;
        let mismatch = catalog::projection(&mismatch)?;
        ensure!(mismatch["status"] == "identity_mismatch" && mismatch.get("process").is_none(), "never return a different PID identity");
        let stopped = guest.shell("systemctl stop estus-fixture.service").await?;
        ensure!(stopped.status.success(), "stop independently");
        let gone = binding.call(identity).await?;
        let gone = catalog::projection(&gone)?;
        ensure!(gone["status"] == "gone" && gone.get("process").is_none(), "disappearance cannot return stale details");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
