use crate::payload;

use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

async fn capture_md(guest: &catalog::Guest, phase: &str) -> Result<()> {
    let capture = guest.shell("/usr/bin/python3 - <<'PY'\nimport json, pathlib\nbase = pathlib.Path('/sys/class/block/md0/md')\ndef read(path):\n    with path.open('rb') as source:\n        data = source.read(257)\n    if len(data) > 256:\n        raise ValueError('capture attribute too large')\n    return data.decode('ascii').strip()\nsnapshot = {key: read(base / key) for key in ('level', 'raid_disks', 'degraded', 'array_state', 'sync_action')}\nsnapshot['members'] = []\nfor device in ('vdb', 'vdc'):\n    member = base / ('dev-' + device)\n    if member.is_dir():\n        snapshot['members'].append(dict(device=device, **{key: read(member / key) for key in ('state', 'slot', 'errors')}))\nprint(json.dumps(snapshot, sort_keys=True))\nPY").await?;
    ensure!(
        capture.status.success() && capture.stdout.len() <= 4096,
        "bounded MD capture failed"
    );
    eprintln!(
        "MD_{phase}_CAPTURE={}",
        String::from_utf8(capture.stdout)?.trim()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn storage_raid_status() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(
            "/usr/bin/mdadm --create /dev/md0 --metadata=1.2 --level=1 --raid-devices=2 --run /dev/vdb /dev/vdc && /usr/bin/python3 - <<'PY'\nimport time\nfor _ in range(200):\n    if open('/sys/class/block/md0/md/sync_action').read().strip() == 'idle' and open('/sys/class/block/md0/md/degraded').read().strip() == '0':\n        break\n    time.sleep(0.1)\nelse:\n    raise RuntimeError('real RAID1 did not finish initial synchronization')\nPY",
        ).await?;
        ensure!(prepared.status.success(), "MD preparation: {}", String::from_utf8_lossy(&prepared.stderr));
        let ordinary = guest.ordinary("/usr/bin/id -u; cat /sys/class/block/md0/md/degraded").await?;
        ensure!(ordinary.status.success() && ordinary.stdout == b"1000\n0\n", "MD sysfs must be observable without raw-device/root authority");
        let binding = guest.binding("storage_raid_status", json!({})).await?;
        binding.reject(json!({"device":"/dev/vda"})).await?;
        binding.reject(json!({"device":"/dev/md0", "repair":true})).await?;
        let healthy = binding.call(json!({"device":"/dev/md0"})).await?;
        let p = catalog::projection(&healthy).context("healthy RAID projection")?;
        ensure!(p["degraded_members"] == 0 && p["raid_disks"] == 2 && p["sync_action"] == "idle", "healthy MD state: {p}");
        let members = p["members"].as_array().context("healthy members")?;
        ensure!(members.len() == 2, "missing real RAID members");
        for device in ["/dev/vdb", "/dev/vdc"] {
            let member = members.iter().find(|m| m["device"] == device).context("missing selected member")?;
            ensure!(member["states"].as_array().context("member states")?.iter().any(|s| s == "in_sync"), "member not in sync");
        }
        let oracle = guest.shell("/usr/bin/mdadm --detail --test /dev/md0 && cat /proc/mdstat").await?;
        ensure!(oracle.status.success() && String::from_utf8_lossy(&oracle.stdout).contains("[UU]"), "independent healthy RAID oracle failed");
        capture_md(&guest, "HEALTHY").await?;
        eprintln!("MD_HEALTHY_PROJECTION={p}");
        let failed = guest.shell("/usr/bin/mdadm /dev/md0 --fail /dev/vdc").await?;
        ensure!(failed.status.success(), "MD member failure preparation failed");
        let degraded = binding.call(json!({"device":"/dev/md0"})).await?;
        let p = catalog::projection(&degraded).context("degraded RAID projection")?;
        ensure!(p["degraded_members"] == 1, "degraded member count: {p}");
        capture_md(&guest, "DEGRADED").await?;
        eprintln!("MD_DEGRADED_PROJECTION={p}");
        let failed_member = p["members"].as_array().context("degraded members")?.iter().find(|m| m["device"] == "/dev/vdc").context("failed member missing")?;
        ensure!(failed_member["states"].as_array().context("failed states")?.iter().any(|s| s == "faulty"), "kernel failed member not reported");
        let oracle = guest.shell("/usr/bin/mdadm --detail --test /dev/md0; code=$?; test \"$code\" = 1 && cat /proc/mdstat").await?;
        let status = String::from_utf8_lossy(&oracle.stdout);
        ensure!(oracle.status.success() && (status.contains("[U_]") || status.contains("[_U]")), "independent degraded RAID oracle failed");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn captured_md_states_use_the_production_parser() -> Result<()> {
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/catalog/fixtures/storage_raid_status");
    for phase in ["healthy", "degraded"] {
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixtures.join(format!("{phase}.json")))?)?;
        let level = snapshot["level"].as_str().context("captured MD level")?;
        let attribute = payload::call(
            "storage_raid_status",
            "parse_attribute",
            json!([payload::bytes(level.as_bytes())]),
        )?;
        snapshot["level"] = attribute
            .get("ok")
            .context("captured MD attribute failed")?
            .clone();
        let result = payload::call(
            "storage_raid_status",
            "parse_md_snapshot",
            json!([snapshot]),
        )?;
        let actual = result.get("ok").context("captured MD parser failed")?;
        let expected: serde_json::Value = serde_json::from_slice(&std::fs::read(
            fixtures.join(format!("{phase}.expected.json")),
        )?)?;
        ensure!(
            actual == &expected,
            "{phase} captured MD state changed: {actual}"
        );
    }
    Ok(())
}
