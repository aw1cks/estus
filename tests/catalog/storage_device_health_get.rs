use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

fn counter(value: &Value) -> Result<u128> {
    if let Some(text) = value.as_str() {
        return Ok(text.parse()?);
    }
    Ok(u128::from(
        value.as_u64().context("invalid independent NVMe counter")?,
    ))
}

async fn capture_smart(guest: &catalog::Guest, phase: &str) -> Result<()> {
    let raw = guest.shell("/usr/bin/nvme smart-log /dev/nvme0 --raw-binary | /usr/bin/python3 -c 'import sys; data=sys.stdin.buffer.read(513); print(data.hex()) if len(data)==512 else sys.exit(1)'").await?;
    ensure!(
        raw.status.success() && raw.stdout.len() == 1025,
        "bounded SMART capture failed"
    );
    eprintln!(
        "NVME_{phase}_CAPTURE={}",
        String::from_utf8(raw.stdout)?.trim()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM and pinned Runner runtime"]
async fn storage_device_health_get() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let ordinary = guest.ordinary("/usr/bin/nvme smart-log /dev/nvme0 --raw-binary").await?;
        ensure!(!ordinary.status.success() && ordinary.stdout.is_empty(), "ordinary principal unexpectedly accessed privileged controller SMART ioctl");
        let binding = guest.binding("storage_device_health_get", json!({})).await?;
        binding.reject(json!({"device":"/dev/vda"})).await?;
        binding.reject(json!({"device":"/dev/nvme0n1"})).await?;
        binding.reject(json!({"device":"/dev/nvme0", "self_test":true})).await?;
        let before = binding.call(json!({"device":"/dev/nvme0"})).await?;
        let before = catalog::projection(&before).context("initial virtual controller projection")?;
        ensure!(before["scope"] == "virtual_reported_controller" && before["model"] == "QEMU NVMe Ctrl", "incorrect health scope");
        capture_smart(&guest, "BEFORE").await?;
        eprintln!("NVME_BEFORE_PROJECTION={before}");
        let io = guest.shell("dd if=/dev/zero of=/dev/nvme0n1 bs=4096 count=256 oflag=direct conv=fsync && dd if=/dev/nvme0n1 of=/dev/null bs=4096 count=256 iflag=direct").await?;
        ensure!(io.status.success(), "approved guest-only NVMe preparation IO failed: {}", String::from_utf8_lossy(&io.stderr));
        let after = binding.call(json!({"device":"/dev/nvme0"})).await?;
        let after = catalog::projection(&after).context("post-IO virtual controller projection")?;
        let oracle = guest.shell("/usr/bin/nvme smart-log /dev/nvme0 --output-format=json").await?;
        ensure!(oracle.status.success(), "independent nvme-cli SMART query failed");
        let oracle: Value = serde_json::from_slice(&oracle.stdout)?;
        capture_smart(&guest, "AFTER").await?;
        eprintln!("NVME_AFTER_PROJECTION={after}");
        eprintln!("NVME_JSON_ORACLE={oracle}");
        for name in ["host_read_commands", "host_write_commands", "data_units_read", "data_units_written"] {
            let old = counter(&before["counters"][name])?;
            let new = counter(&after["counters"][name])?;
            ensure!(new > old, "virtual controller did not report real {name} change: {old} -> {new}");
            ensure!(new == counter(&oracle[name])?, "independent reported {name} disagrees");
        }
        ensure!(after["critical_warning"] == oracle["critical_warning"], "reported warning mismatch");
        if let Some(temperature) = after.get("temperature_kelvin") {
            ensure!(temperature == &oracle["temperature"], "reported temperature mismatch");
        } else {
            ensure!(after["unavailable"] == json!(["temperature_kelvin"]), "unknown temperature was not preserved");
        }
        let state = guest.shell("cat /sys/class/nvme/nvme0/state").await?;
        ensure!(state.status.success(), "controller state oracle failed");
        ensure!(after["controller_state"].as_str() == Some(String::from_utf8_lossy(&state.stdout).trim()), "reported controller state mismatch");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[test]
fn captured_smart_logs_use_the_production_parser() -> Result<()> {
    let assets = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples"));
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/catalog/fixtures/storage_device_health_get");
    let parser = r#"import ast, json, pathlib, sys, textwrap
role = pathlib.Path(sys.argv[1]).read_text()
source = textwrap.dedent(role.split('      - |\n', 1)[1].split("      - '{{ device }}'", 1)[0])
tree = ast.parse(source)
functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'parse_smart_log']
exec(compile(ast.Module(body=functions, type_ignores=[]), '<production SMART parser>', 'exec'))
data = bytes.fromhex(pathlib.Path(sys.argv[2]).read_text())
if sys.argv[3] == 'truncated':
    data = data[:-1]
print(json.dumps(parse_smart_log(data), sort_keys=True))
"#;
    for phase in ["before", "after"] {
        for variant in ["captured", "truncated"] {
            let output = std::process::Command::new(crate::support::find_program("python3")?)
                .args(["-I", "-c", parser])
                .arg(assets.join("roles/storage_device_health_get/tasks/main.yml"))
                .arg(fixtures.join(format!("{phase}.hex")))
                .arg(variant)
                .output()?;
            if variant == "truncated" {
                ensure!(
                    !output.status.success()
                        && String::from_utf8_lossy(&output.stderr)
                            .contains("unexpected NVMe SMART log length"),
                    "truncated real SMART capture accepted"
                );
                continue;
            }
            ensure!(
                output.status.success(),
                "{phase} production parser: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ensure!(
                output.stdout.len() <= 4096,
                "SMART parser output exceeds bound"
            );
            let actual: Value = serde_json::from_slice(&output.stdout)?;
            let expected: Value = serde_json::from_slice(&std::fs::read(
                fixtures.join(format!("{phase}.expected.json")),
            )?)?;
            ensure!(
                actual == expected,
                "{phase} captured SMART state changed: {actual}"
            );
        }
    }
    Ok(())
}
