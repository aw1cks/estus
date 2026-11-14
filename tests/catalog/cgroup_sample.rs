use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn cgroup_sample_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("cgroup_sample", json!({})).await?;
        binding.reject(json!({"approved_root":"/"})).await?;
        let independent = guest.shell("cat /proc/sys/kernel/random/boot_id; stat -c '%d:%i' /sys/fs/cgroup/system.slice/estus-fixture.service").await?;
        ensure!(independent.status.success(), "cgroup identity oracle failed");
        let oracle = String::from_utf8(independent.stdout)?;
        let mut lines = oracle.lines();
        let boot = lines.next().context("boot")?;
        let identity = lines.next().context("inode")?;
        let reply = binding.call(json!({"duration_ms":200,"samples":3})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["boot_id"] == boot && value["identity"] == identity, "cgroup identity differs from independent source");
        ensure!(value["root"] == "/system.slice/estus-fixture.service", "subtree escaped");
        ensure!(value["ancestors"].as_array().context("ancestors")?.iter().any(|a| a["path"] == "/system.slice"), "slice ancestor omitted");

        let samples = value["observations"].as_array().context("samples")?;
        ensure!(samples.len() == 3, "finite sample count changed");
        ensure!(samples[0].get("cpu_usec_per_second").is_none(), "first cumulative value misreported as rate");
        for pair in samples.windows(2) {
            let elapsed = pair[1]["elapsed_usec"].as_u64().context("elapsed")? - pair[0]["elapsed_usec"].as_u64().context("elapsed")?;
            ensure!(elapsed > 0, "nonpositive interval");
            if pair[1]["reset"] == false {
                let before = pair[0]["cpu_usage_usec"].as_u64().context("CPU usage")?;
                let after = pair[1]["cpu_usage_usec"].as_u64().context("CPU usage")?;
                ensure!(after >= before, "reset not reported");
                let expected = (after-before) as f64 * 1_000_000.0 / elapsed as f64;
                ensure!((pair[1]["cpu_usec_per_second"].as_f64().context("rate")? - expected).abs() < 0.01, "rate interval/units incorrect");
            } else { ensure!(pair[1].get("cpu_usec_per_second").is_none(), "rate retained across reset"); }
        }
        let reference = guest.shell("cat /sys/fs/cgroup/system.slice/estus-fixture.service/cpu.stat").await?;
        ensure!(reference.status.success(), "CPU usage oracle failed");
        let text = String::from_utf8(reference.stdout)?;
        let usage: u64 = text.lines().find_map(|line| line.strip_prefix("usage_usec ")).context("oracle usage")?.parse()?;
        ensure!(usage >= samples.last().context("last sample")?["cpu_usage_usec"].as_u64().context("last counter")?, "sample counter exceeds subsequent independent cumulative counter");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
