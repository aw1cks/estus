use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn process_fds_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let oracle = guest.shell("python3 -c 'import json,subprocess; p=int(subprocess.check_output([\"systemctl\",\"show\",\"estus-fixture.service\",\"-p\",\"MainPID\",\"--value\"])); s=open(\"/proc/%d/stat\"%p).read(); print(json.dumps({\"pid\":p,\"boot_id\":open(\"/proc/sys/kernel/random/boot_id\").read().strip(),\"start_ticks\":int(s[s.rfind(\") \")+2:].split()[19])}))'").await?;
        ensure!(oracle.status.success(), "independent process identity oracle");
        let identity: Value = serde_json::from_slice(&oracle.stdout)?;

        let binding = guest.binding("process_fds_list", json!({})).await?;
        let mut inputs = identity.clone(); inputs["limit"] = json!(8);
        let mut invalid = inputs.clone(); invalid["limit"] = json!(9);
        binding.reject(invalid).await?;
        let oracle = guest.shell(&format!("readlink /proc/{}/fd/0", identity["pid"].as_u64().context("pid")?)).await?;
        ensure!(oracle.status.success(), "independent FD target oracle");
        let target = std::str::from_utf8(&oracle.stdout)?.trim();
        let reply = binding.call(inputs.clone()).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["status"] == "available", "fixture descriptors available");
        let descriptors = value["descriptors"].as_array().context("descriptor array")?;
        ensure!(descriptors.iter().any(|fd| fd["fd"] == 0 && fd["target"] == target), "actual separately sensitive FD path");
        inputs["start_ticks"] = json!(identity["start_ticks"].as_u64().context("start ticks")? + 1);
        let mismatch = binding.call(inputs).await?;
        let mismatch = catalog::projection(&mismatch)?;
        ensure!(mismatch["status"] == "identity_mismatch" && mismatch.get("descriptors").is_none(), "stale identities must disclose no targets");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
