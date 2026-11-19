use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn inspect_processes() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prep = guest.shell("python3 -c 'import os,subprocess; os.setgid(1000); os.setuid(1000); p=subprocess.Popen([\"sleep\",\"300\"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True); print(p.pid)'").await?;
        ensure!(prep.status.success(), "prepare ordinary owned process");
        let expected_pid: u64 = std::str::from_utf8(&prep.stdout)?.trim().parse()?;
        let oracle = guest.shell("python3 -c 'import os,json; print(json.dumps({\"boot\":open(\"/proc/sys/kernel/random/boot_id\").read().strip(),\"uid\":1000}))'").await?;
        ensure!(oracle.status.success(), "independent process oracle");
        let expected: Value = serde_json::from_slice(&oracle.stdout)?;
        let binding = guest.binding("inspect_processes", json!({})).await?;
        binding.reject(json!({"uid":1000,"name_contains":"sleep","limit":9})).await?;
        let reply = binding.call(json!({"uid":1000,"name_contains":"sleep","limit":8})).await?;
        let value = catalog::projection(&reply).context("filtered process inventory call")?;
        let rows = value["processes"].as_array().context("process inventory")?;
        ensure!(!rows.is_empty(), "must observe independently launched process");
        ensure!(rows.iter().any(|row| row["pid"] == expected_pid), "must include independently launched PID");
        for row in rows {
            ensure!(row["uid"] == 1000 && row["name"].as_str().context("name")?.contains("sleep"), "filters must hold");
            ensure!(row["boot_id"] == expected["boot"] && row["start_ticks"].as_u64().is_some(), "boot/start identity required");
            for forbidden in ["argv", "environment", "cmdline", "descriptors"] { ensure!(row.get(forbidden).is_none(), "no sensitive summary field"); }
        }
        let bounded_reply = binding.call(json!({"uid":1000,"name_contains":"","limit":1})).await?;
        ensure!(catalog::projection(&bounded_reply).context("empty-name process inventory call")?["processes"].as_array().context("bounded rows")?.len() == 1, "empty filter must select the live ordinary process within caller entry bound");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
