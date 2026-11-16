#[path = "support/payload.rs"]
mod payload;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

fn parsed(role: &str, function: &str, args: Value) -> Result<Value> {
    let result = payload::call(role, function, args)?;
    result
        .get("ok")
        .cloned()
        .with_context(|| format!("{role}.{function}: {result}"))
}

fn rejected(role: &str, function: &str, args: Value, error: &str) -> Result<()> {
    let result = payload::call(role, function, args)?;
    ensure!(
        result == json!({"error": error}),
        "{role}.{function} accepted malformed input: {result}"
    );
    Ok(())
}

#[test]
fn md_attributes_enforce_byte_encoding_and_both_bounds() -> Result<()> {
    for (input, expected) in [
        (b" clean\n".as_slice(), "clean".to_owned()),
        (&[b'a'; 128], "a".repeat(128)),
    ] {
        assert_eq!(
            parsed(
                "storage_raid_status",
                "parse_attribute",
                json!([payload::bytes(input)])
            )?,
            expected
        );
    }
    for input in [
        vec![],
        b" \n".to_vec(),
        vec![0xff],
        vec![b'a'; 129],
        vec![b' '; 257],
    ] {
        let error = if input == [0xff] {
            "UnicodeDecodeError"
        } else {
            "ValueError"
        };
        rejected(
            "storage_raid_status",
            "parse_attribute",
            json!([payload::bytes(&input)]),
            error,
        )?;
    }
    Ok(())
}

#[test]
fn md_members_counts_and_unknown_reported_states() -> Result<()> {
    let baseline: Value = serde_json::from_str(include_str!(
        "catalog/fixtures/storage_raid_status/healthy.json"
    ))?;
    let mut state = baseline.clone();
    state["members"][0]["state"] = json!("in_sync,new_kernel_state");
    state["members"][0]["errors"] = json!("9007199254740991");
    state["array_state"] = json!("future_state");
    state["members"]
        .as_array_mut()
        .context("members")?
        .reverse();
    let actual = parsed("storage_raid_status", "parse_md_snapshot", json!([state]))?;
    assert_eq!(actual["members"][0]["device"], "/dev/vdb");
    assert_eq!(
        actual["members"][0]["read_errors"],
        9_007_199_254_740_991u64
    );
    assert_eq!(
        actual["members"][0]["states"],
        json!(["in_sync", "new_kernel_state"])
    );
    assert_eq!(actual["array_state"], "future_state");
    for (pointer, value) in [
        ("/level", json!("raid5")),
        ("/raid_disks", json!("1")),
        ("/degraded", json!("3")),
        ("/degraded", json!("-1")),
        ("/degraded", json!("1.0")),
        ("/array_state", json!("x".repeat(129))),
        ("/members/0/device", json!("vda")),
        ("/members/0/slot", json!("2")),
        ("/members/0/state", json!("in_sync,,faulty")),
        ("/members/0/state", json!("x,".repeat(12) + "x")),
        ("/members/0/errors", json!("9007199254740992")),
        ("/members/0/errors", json!("-1")),
    ] {
        let mut input = baseline.clone();
        *input.pointer_mut(pointer).context("case pointer")? = value;
        rejected(
            "storage_raid_status",
            "parse_md_snapshot",
            json!([input]),
            "ValueError",
        )?;
    }
    let mut duplicate = baseline.clone();
    duplicate["members"][1] = duplicate["members"][0].clone();
    rejected(
        "storage_raid_status",
        "parse_md_snapshot",
        json!([duplicate]),
        "ValueError",
    )?;
    let mut excessive = baseline.clone();
    excessive["members"]
        .as_array_mut()
        .context("members")?
        .push(baseline["members"][0].clone());
    rejected(
        "storage_raid_status",
        "parse_md_snapshot",
        json!([excessive]),
        "ValueError",
    )?;
    let mut missing = baseline;
    missing
        .as_object_mut()
        .context("snapshot")?
        .remove("sync_action");
    rejected(
        "storage_raid_status",
        "parse_md_snapshot",
        json!([missing]),
        "KeyError",
    )?;
    Ok(())
}

#[test]
fn nvme_binary_layout_preserves_wide_counters_and_unknown_values() -> Result<()> {
    let mut data = vec![0; 512];
    data[0] = 0x80; // Unknown warning bits remain device-reported data, not a health verdict.
    data[1..3].copy_from_slice(&300u16.to_le_bytes());
    data[3..6].copy_from_slice(&[99, 10, 255]);
    data[32..48].copy_from_slice(&u128::MAX.to_le_bytes());
    data[48..64].copy_from_slice(&(1u128 << 80).to_le_bytes());
    data[176..192].copy_from_slice(&42u128.to_le_bytes());
    let actual = parsed(
        "storage_device_health_get",
        "parse_smart_log",
        json!([payload::bytes(&data)]),
    )?;
    assert_eq!(actual["critical_warning"], 128);
    assert_eq!(actual["temperature_kelvin"], 300);
    assert_eq!(actual["available_spare_percent"], 99);
    assert_eq!(actual["spare_threshold_percent"], 10);
    assert_eq!(actual["percentage_used"], 255);
    assert_eq!(
        actual["counters"]["data_units_read"],
        "340282366920938463463374607431768211455"
    );
    assert_eq!(
        actual["counters"]["data_units_written"],
        "1208925819614629174706176"
    );
    assert_eq!(actual["counters"]["error_log_entries"], "42");
    assert_eq!(actual["counters"]["host_read_commands"], "0");
    assert_eq!(actual["unavailable"], json!([]));
    data[1..3].fill(0);
    let absent = parsed(
        "storage_device_health_get",
        "parse_smart_log",
        json!([payload::bytes(&data)]),
    )?;
    assert!(absent.get("temperature_kelvin").is_none());
    assert_eq!(absent["unavailable"], json!(["temperature_kelvin"]));
    for size in [0, 511, 513] {
        rejected(
            "storage_device_health_get",
            "parse_smart_log",
            json!([payload::bytes(&vec![0; size])]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn cgroup_counter_parser_rejects_ambiguous_and_unbounded_sources() -> Result<()> {
    for (data, expected) in [
        ("usage_usec 0\n", 0u64),
        (
            "usage_usec 9007199254740991\nfuture_counter 12\n",
            9_007_199_254_740_991,
        ),
    ] {
        assert_eq!(
            parsed(
                "cgroup_sample",
                "parse_cpu_stat",
                json!([payload::bytes(data.as_bytes())])
            )?,
            expected
        );
    }
    for data in [
        "usage_usec 1\nusage_usec 2\n",
        "usage_usec -1\n",
        "usage_usec 1.0\n",
        "usage_usec 9007199254740992\n",
        "usage_usec 00000000000000000\n",
        "usage_usec 1 extra\n",
        "usage_usec\n",
    ] {
        rejected(
            "cgroup_sample",
            "parse_cpu_stat",
            json!([payload::bytes(data.as_bytes())]),
            "ValueError",
        )?;
    }
    rejected(
        "cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(b"user_usec 1\n")]),
        "KeyError",
    )?;
    rejected(
        "cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(&[0xff])]),
        "UnicodeDecodeError",
    )?;
    rejected(
        "cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(&vec![b' '; 4097])]),
        "ValueError",
    )?;
    // Exactly the accepted source bound, with a valid trailing blank-free line.
    let boundary = format!("usage_usec {}1\n", " ".repeat(4083));
    assert_eq!(boundary.len(), 4096);
    assert_eq!(
        parsed(
            "cgroup_sample",
            "parse_cpu_stat",
            json!([payload::bytes(boundary.as_bytes())])
        )?,
        1
    );
    Ok(())
}

#[test]
fn cgroup_rates_require_same_generation_monotonic_counter_and_positive_interval() -> Result<()> {
    let first = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([null, "1:2", 100, 1000]),
    )?;
    assert_eq!(
        first,
        json!({"identity":"1:2", "cpu_usage_usec":100, "elapsed_usec":1000, "reset":false})
    );
    let next = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([first, "1:2", 150, 3000]),
    )?;
    assert_eq!(next["cpu_usec_per_second"], 25000.0);
    for (identity, usage, elapsed, reset) in [
        ("1:3", 200, 4000, true),
        ("1:2", 10, 4000, true),
        ("1:2", 200, 3000, false),
        ("1:2", 200, 2000, false),
    ] {
        let item = parsed(
            "cgroup_sample",
            "cpu_observation",
            json!([next, identity, usage, elapsed]),
        )?;
        assert_eq!(item["reset"], reset, "{identity} {usage} {elapsed}");
        assert!(
            item.get("cpu_usec_per_second").is_none(),
            "invalid rate: {item}"
        );
    }
    let replaced = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([next, "1:3", 200, 4000]),
    )?;
    let baseline = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([replaced, "1:3", 250, 5000]),
    )?;
    assert_eq!(baseline["cpu_usec_per_second"], 50000.0);
    assert_eq!(baseline["reset"], false);
    Ok(())
}

#[test]
fn psi_parses_units_and_rejects_missing_duplicate_unknown_and_oversize_lines() -> Result<()> {
    let some = "some avg10=1.25 avg60=2.50 avg300=100.00 total=9007199254740991\n";
    let full = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n";
    let actual = parsed(
        "pressure_get",
        "parse_pressure",
        json!([payload::bytes(format!("{some}{full}").as_bytes())]),
    )?;
    assert_eq!(
        actual["some"],
        json!({"avg10_percent":1.25,"avg60_percent":2.5,"avg300_percent":100.0,"total_microseconds":9_007_199_254_740_991u64})
    );
    assert_eq!(actual["full"]["total_microseconds"], 0);
    assert!(
        parsed(
            "pressure_get",
            "parse_pressure",
            json!([payload::bytes(some.as_bytes())])
        )?
        .get("full")
        .is_none()
    );
    for data in [
        String::new(),
        full.to_owned(),
        format!("{some}{some}"),
        some.replace("some", "future"),
        some.replace("1.25", "101.00"),
        some.replace("1.25", "NaN"),
        some.replace("1.25", "-1.00"),
        some.replace("9007199254740991", "9007199254740992"),
        some.replace("avg60=2.50 ", ""),
        "x".repeat(2049),
    ] {
        rejected(
            "pressure_get",
            "parse_pressure",
            json!([payload::bytes(data.as_bytes())]),
            "ValueError",
        )?;
    }
    rejected(
        "pressure_get",
        "parse_pressure",
        json!([payload::bytes(&[0xff])]),
        "UnicodeDecodeError",
    )?;
    Ok(())
}

#[test]
fn memory_selected_fields_preserve_units_and_fail_closed_on_selected_corruption() -> Result<()> {
    let source = b"MemTotal: 4 kB\nMemFree: 1 kB\nFutureField: unknown\n";
    assert_eq!(
        parsed(
            "memory_stats",
            "parse_meminfo",
            json!([payload::bytes(source)])
        )?,
        json!({"mem_total_bytes":4096,"mem_free_bytes":1024})
    );
    assert_eq!(
        parsed("memory_stats", "parse_vmstat", json!([null]))?,
        json!({})
    );
    assert_eq!(
        parsed(
            "memory_stats",
            "parse_vmstat",
            json!([payload::bytes(
                b"pgfault 9007199254740991\nfuture_counter 1\n"
            )])
        )?,
        json!({"page_faults":9_007_199_254_740_991u64})
    );
    for data in [
        b"MemTotal: 1 kB\n".to_vec(),
        b"MemTotal: 1 kB\nMemFree: 0 kB\nMemFree: 2 kB\n".to_vec(),
        b"MemTotal: -1 kB\nMemFree: 0 kB\n".to_vec(),
        b"MemTotal: 1 MB\nMemFree: 0 kB\n".to_vec(),
        b"MemTotal: 8796093022208 kB\nMemFree: 0 kB\n".to_vec(),
        b"MemTotal: \xff kB\nMemFree: 0 kB\n".to_vec(),
        vec![b'x'; 131073],
    ] {
        rejected(
            "memory_stats",
            "parse_meminfo",
            json!([payload::bytes(&data)]),
            "ValueError",
        )?;
    }
    for data in [
        b"pgfault 1\npgfault 2\n".to_vec(),
        b"pgfault 9007199254740992\n".to_vec(),
        b"pgfault -1\n".to_vec(),
        vec![b'\n'; 4097],
        vec![b'x'; 262145],
    ] {
        rejected(
            "memory_stats",
            "parse_vmstat",
            json!([payload::bytes(&data)]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn pinned_cgroup_counter_cannot_mix_a_replacement_identity() -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{Duration, Instant};
    let root = tempfile::tempdir()?;
    let selected = root.path().join("selected");
    let retired = root.path().join("retired");
    std::fs::create_dir(&selected)?;
    nix::unistd::mkfifo(
        &selected.join("cpu.stat"),
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    let old = std::fs::metadata(&selected)?;
    let identity = format!("{}:{}", old.dev(), old.ino());
    let directory = selected.clone();
    let writer = std::thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
                .open(directory.join("cpu.stat"))
            {
                Ok(stream) => break stream,
                Err(error)
                    if error.raw_os_error() == Some(nix::errno::Errno::ENXIO as i32)
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.into()),
            }
        };
        std::fs::rename(&directory, retired)?;
        std::fs::create_dir(&directory)?;
        std::fs::write(directory.join("cpu.stat"), b"usage_usec 200\n")?;
        stream.write_all(b"usage_usec 100\n")?;
        Ok(())
    });
    let sampled = parsed("cgroup_sample", "sample_cpu", json!([selected]))?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("counter writer panicked"))??;
    assert_eq!(sampled, json!([identity, 100]));
    let replaced = parsed("cgroup_sample", "sample_cpu", json!([selected]))?;
    assert_ne!(replaced[0], identity);
    assert_eq!(replaced[1], 200);
    let first = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([null, sampled[0], sampled[1], 1000]),
    )?;
    let second = parsed(
        "cgroup_sample",
        "cpu_observation",
        json!([first, replaced[0], replaced[1], 2000]),
    )?;
    assert_eq!(second["reset"], true);
    assert!(second.get("cpu_usec_per_second").is_none());
    Ok(())
}

#[test]
fn cpu_integer_arguments_reject_signs_whitespace_and_overflow() -> Result<()> {
    assert_eq!(
        parsed("cpu_stats", "integer", json!([payload::bytes(b"16"), 16]))?,
        16
    );
    for data in [b"17".as_slice(), b"-1", b" 1", b"1.0", b"", &[0xff]] {
        rejected(
            "cpu_stats",
            "integer",
            json!([payload::bytes(data), 16]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn importing_bundled_payloads_cannot_observe_or_modify_the_target() -> Result<()> {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
    let manifest: Value = serde_json::from_slice(&std::fs::read(assets.join("catalog.json"))?)?;
    let bridge = r#"import importlib.util, json, os, resource, signal, sys
sys.dont_write_bytecode = True
resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
signal.alarm(5)
source = os.path.realpath(sys.argv[1])
stdlib = os.path.realpath(sys.base_prefix) + os.sep
owned = os.path.dirname(source) + os.sep
violations = []
def audit(event, args):
    forbidden = event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.fork'))
    forbidden = forbidden or event in ('os.system', 'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'os.chmod', 'os.chown', 'os.chdir')
    if event == 'open':
        path, mode, flags = args
        forbidden = forbidden or not isinstance(path, str)
        if isinstance(path, str):
            resolved = os.path.realpath(path)
            forbidden = forbidden or not (resolved.startswith(stdlib) or resolved.startswith(owned))
        forbidden = forbidden or isinstance(flags, int) and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
    if forbidden:
        violations.append(event)
        raise PermissionError('payload import side effect')
sys.addaudithook(audit)
error = None
try:
    spec = importlib.util.spec_from_file_location('payload_import', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
except Exception as exc:
    error = type(exc).__name__
print(json.dumps({'violations': violations, 'error': error}))
"#;
    for template in manifest["tools"]
        .as_object()
        .context("catalog templates")?
        .values()
    {
        let role = assets.join(template["role"].as_str().context("role path")?);
        let files = role.join("files");
        if !files.exists() {
            continue;
        }
        for entry in std::fs::read_dir(files)? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "py") {
                continue;
            }
            let output = std::process::Command::new(
                std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()),
            )
            .args(["-I", "-B", "-c", bridge])
            .arg(&path)
            .output()?;
            ensure!(
                output.status.success(),
                "payload import failed under a bounded interpreter: {}",
                path.display()
            );
            let evidence: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(
                evidence,
                json!({"violations":[],"error":null}),
                "import performed target IO or process/mutation work: {}",
                path.display()
            );
        }
    }
    Ok(())
}
