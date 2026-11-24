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
                "observe_storage_raid",
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
            "observe_storage_raid",
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
        "fixtures/catalog/captures/storage_raid_status/healthy.json"
    ))?;
    let mut state = baseline.clone();
    state["members"][0]["state"] = json!("in_sync,new_kernel_state");
    state["members"][0]["errors"] = json!("9007199254740991");
    state["array_state"] = json!("future_state");
    state["members"]
        .as_array_mut()
        .context("members")?
        .reverse();
    let actual = parsed("observe_storage_raid", "parse_md_snapshot", json!([state]))?;
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
            "observe_storage_raid",
            "parse_md_snapshot",
            json!([input]),
            "ValueError",
        )?;
    }
    let mut duplicate = baseline.clone();
    duplicate["members"][1] = duplicate["members"][0].clone();
    rejected(
        "observe_storage_raid",
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
        "observe_storage_raid",
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
        "observe_storage_raid",
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
        "observe_storage_device_health",
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
        "observe_storage_device_health",
        "parse_smart_log",
        json!([payload::bytes(&data)]),
    )?;
    assert!(absent.get("temperature_kelvin").is_none());
    assert_eq!(absent["unavailable"], json!(["temperature_kelvin"]));
    for size in [0, 511, 513] {
        rejected(
            "observe_storage_device_health",
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
                "observe_cgroup_sample",
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
            "observe_cgroup_sample",
            "parse_cpu_stat",
            json!([payload::bytes(data.as_bytes())]),
            "ValueError",
        )?;
    }
    rejected(
        "observe_cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(b"user_usec 1\n")]),
        "KeyError",
    )?;
    rejected(
        "observe_cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(&[0xff])]),
        "UnicodeDecodeError",
    )?;
    rejected(
        "observe_cgroup_sample",
        "parse_cpu_stat",
        json!([payload::bytes(&vec![b' '; 4097])]),
        "ValueError",
    )?;
    // Exactly the accepted source bound, with a valid trailing blank-free line.
    let boundary = format!("usage_usec {}1\n", " ".repeat(4083));
    assert_eq!(boundary.len(), 4096);
    assert_eq!(
        parsed(
            "observe_cgroup_sample",
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
        "observe_cgroup_sample",
        "cpu_observation",
        json!([null, "1:2", 100, 1000]),
    )?;
    assert_eq!(
        first,
        json!({"identity":"1:2", "cpu_usage_usec":100, "elapsed_usec":1000, "reset":false})
    );
    let next = parsed(
        "observe_cgroup_sample",
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
            "observe_cgroup_sample",
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
        "observe_cgroup_sample",
        "cpu_observation",
        json!([next, "1:3", 200, 4000]),
    )?;
    let baseline = parsed(
        "observe_cgroup_sample",
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
        "observe_pressure",
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
            "observe_pressure",
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
            "observe_pressure",
            "parse_pressure",
            json!([payload::bytes(data.as_bytes())]),
            "ValueError",
        )?;
    }
    rejected(
        "observe_pressure",
        "parse_pressure",
        json!([payload::bytes(&[0xff])]),
        "UnicodeDecodeError",
    )?;
    Ok(())
}

#[test]
fn psi_absence_distinguishes_disabled_from_unsupported() -> Result<()> {
    let built = "CONFIG_PSI=y\n";
    let default_off = "CONFIG_PSI=y\nCONFIG_PSI_DEFAULT_DISABLED=y\n";
    let absent = "# CONFIG_PSI is not set\n";
    for (cmdline, config, expected) in [
        // RHEL-family default: built in, off unless psi=1.
        (
            "ro quiet",
            json!(default_off),
            json!(["disabled", "kernel_default"]),
        ),
        (
            "ro psi=0",
            json!(built),
            json!(["disabled", "boot_parameter"]),
        ),
        (
            "psi=off",
            Value::Null,
            json!(["disabled", "boot_parameter"]),
        ),
        // The last psi= wins, as in the kernel.
        (
            "psi=1 psi=n",
            json!(default_off),
            json!(["disabled", "boot_parameter"]),
        ),
        (
            "psi=0 psi=1",
            json!(default_off),
            json!(["unsupported", null]),
        ),
        (
            "psi=bogus",
            json!(default_off),
            json!(["disabled", "kernel_default"]),
        ),
        ("psi=0", json!(absent), json!(["unsupported", null])),
        ("ro", json!(absent), json!(["unsupported", null])),
        ("ro", Value::Null, json!(["unsupported", null])),
        ("ro", json!(built), json!(["unsupported", null])),
    ] {
        assert_eq!(
            parsed(
                "observe_pressure",
                "classify_missing_psi",
                json!([cmdline, config])
            )?,
            expected,
            "{cmdline} {config}"
        );
    }
    Ok(())
}

#[test]
fn rss_large_tables_summarize_and_page_without_the_key() -> Result<()> {
    // Shape of `ethtool -x` on an Intel X550 (ixgbe): 512 slots over 12 rings.
    let mut text = String::from("\nRX flow hash indirection table for eth0 with 12 RX ring(s):\n");
    for row in 0..64 {
        let cells: Vec<String> = (0..8)
            .map(|c| format!("{:5}", (row * 8 + c) % 12))
            .collect();
        text.push_str(&format!("{:5}:  {}\n", row * 8, cells.join(" ")));
    }
    text.push_str("RSS hash key:\nc3:ff:8c:c4\nRSS hash function:\n    toeplitz: on\n    xor: off\n    crc32: off\nRSS input transformation:\n    symmetric-xor: off\n");
    let parsed_rss = parsed("observe_nic_rss", "parse_rss", json!([text]))?;
    let table: Vec<u64> = (0..512).map(|i| i % 12).collect();
    assert_eq!(parsed_rss[0], json!(table));
    assert_eq!(
        parsed_rss[1][0],
        json!({"name": "toeplitz", "enabled": true})
    );
    assert!(!serde_json::to_string(&parsed_rss)?.contains("c3:ff"));

    let base = json!({"source": "ethtool -x", "observed_at": "2026-11-24T00:00:00+00:00", "unavailable": [], "interface": "eth0", "supported": true, "hash_functions": parsed_rss[1]});
    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let page = parsed("observe_nic_rss", "page_rss", json!([base, table, offset]))?;
        assert!(serde_json::to_vec(&page)?.len() <= 4096);
        assert_eq!(page["indirection_size"], 512);
        // 512 slots over 12 queues: 8 queues get 43, 4 get 42.
        assert_eq!(
            page["queue_entries"],
            json!([43, 43, 43, 43, 43, 43, 43, 43, 42, 42, 42, 42])
        );
        let slice = page["indirection"].as_array().context("indirection")?;
        assert_eq!(page["omitted_records"], 512 - slice.len());
        seen.extend(slice.iter().map(|v| v.as_u64().unwrap()));
        match page.get("next_offset") {
            Some(next) => offset = next.as_u64().context("next_offset")?,
            None => break,
        }
    }
    assert_eq!(seen, table);
    for offset in [json!(-1), json!(65536), json!("0")] {
        rejected(
            "observe_nic_rss",
            "page_rss",
            json!([base, table, offset]),
            "ValueError",
        )?;
    }
    let gap = text.replace("    8:", "    9:");
    rejected("observe_nic_rss", "parse_rss", json!([gap]), "ValueError")?;
    Ok(())
}

#[test]
fn pci_devices_pages_reach_every_device() -> Result<()> {
    let devices: Vec<Value> = (0..45)
        .map(|i| json!({"address": format!("0000:{i:02x}:00.0"), "vendor": "0x8086", "device": "0x1563", "class": "0x020000", "subsystem_vendor": "0x1849", "subsystem_device": "0x1563", "revision": "0x01"}))
        .collect();
    let base = json!({"source": "Linux PCI sysfs numeric identities", "observed_at": "2026-11-24T00:00:00+00:00", "unavailable": []});
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = parsed(
            "observe_pci_devices",
            "page_devices",
            json!([base, devices, offset]),
        )?;
        pages += 1;
        assert!(serde_json::to_vec(&page)?.len() <= 4096);
        assert_eq!(page["device_count"], 45);
        let slice = page["devices"].as_array().context("devices")?;
        assert_eq!(page["omitted_records"], 45 - slice.len());
        seen.extend(slice.iter().cloned());
        match page.get("next_offset") {
            Some(next) => offset = next.as_u64().context("next_offset")?,
            None => break,
        }
    }
    assert!(pages > 1);
    assert_eq!(seen, devices);
    for offset in [json!(-1), json!(4096), json!(null)] {
        rejected(
            "observe_pci_devices",
            "page_devices",
            json!([base, devices, offset]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn pci_absent_device_is_not_found_and_malformed_is_policy() -> Result<()> {
    let root = tempfile::tempdir()?;
    std::fs::create_dir(root.path().join("0000:01:00.0"))?;
    let root = root.path().to_str().context("utf-8 tempdir")?;
    assert_eq!(
        parsed("observe_pci", "device_path", json!(["0000:01:00.0", root]))?,
        format!("{root}/0000:01:00.0")
    );
    rejected(
        "observe_pci",
        "device_path",
        json!(["0000:ff:1f.7", root]),
        "FileNotFoundError",
    )?;
    for address in [json!("bad;selector"), json!("0000:01:00.8"), json!(null)] {
        rejected(
            "observe_pci",
            "device_path",
            json!([address, root]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn kernel_module_pages_fill_the_budget_until_next_offset_is_absent() -> Result<()> {
    let modules: Vec<Value> = (0..82)
        .map(|i| json!({"name": format!("mod_{i:02}"), "size_bytes": 24576, "references": 1, "holders": ["sr_mod"], "state": "Live"}))
        .collect();
    let head = json!({"boot_id": "1ccac6df-3646-4eaf-a77d-bc9d57cc97b3", "source": "Linux procfs/sysfs", "unavailable": [], "scope": "name-sorted"});
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = parsed(
            "observe_kernel_modules",
            "page_modules",
            json!([head, modules, offset]),
        )?;
        pages += 1;
        assert!(serde_json::to_vec(&page)?.len() <= 3900);
        assert_eq!(page["total_count"], 82);
        seen.extend(
            page["modules"]
                .as_array()
                .context("modules")?
                .iter()
                .cloned(),
        );
        match page.get("next_offset") {
            Some(next) => offset = next.as_u64().context("next_offset")?,
            None => break,
        }
    }
    // More than the old fixed 8 per page, fewer calls than 82 / 8.
    assert!((2..=4).contains(&pages), "{pages} pages");
    assert_eq!(seen, modules);
    for offset in [json!(-1), json!(513), json!(1.5)] {
        rejected(
            "observe_kernel_modules",
            "page_modules",
            json!([head, modules, offset]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn systemd_units_pages_cover_every_row_once_and_fail_closed() -> Result<()> {
    let head = json!({"scope":"system","unit_pattern":"*","view":"loaded","unit_type":"service","state":"active"});
    let rows: Vec<Value> = (0..300)
        .map(|i| json!({"unit": format!("unit-{i:03}.service"), "load": "loaded", "active": "active", "sub": "running", "description": format!("Fixture {i}")}))
        .collect();
    let mut seen = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = parsed(
            "observe_systemd_units",
            "page_inventory",
            json!([head, rows, offset]),
        )?;
        pages += 1;
        assert!(serde_json::to_vec(&page)?.len() <= 3800);
        assert_eq!(page["source_count"], 256);
        assert_eq!(page["offset"], offset);
        // Rows past the 256 '*' cap are unreachable, so every page stays truncated.
        assert_eq!(page["truncated"], true);
        seen.extend(page["units"].as_array().context("units")?.iter().cloned());
        match page.get("next_offset") {
            Some(next) => offset = next.as_u64().context("next_offset")?,
            None => break,
        }
    }
    assert!(pages > 1);
    assert_eq!(seen, rows[..256]);

    let narrow = json!({"scope":"system","unit_pattern":"unit-*","view":"loaded","unit_type":"service","state":"active"});
    let last = parsed(
        "observe_systemd_units",
        "page_inventory",
        json!([narrow, rows[..3], 0]),
    )?;
    assert_eq!(last["truncated"], false);
    assert!(last.get("next_offset").is_none());
    for (head, rows, offset) in [
        (&narrow, json!(rows[..257]), json!(0)),
        (&narrow, json!(rows[..3]), json!(256)),
        (&narrow, json!(rows[..3]), json!(-1)),
        (&narrow, json!(rows[..3]), json!(true)),
        (&narrow, json!([{"unit": "x".repeat(4000)}]), json!(0)),
    ] {
        rejected(
            "observe_systemd_units",
            "page_inventory",
            json!([head, rows, offset]),
            "ValueError",
        )?;
    }
    Ok(())
}

#[test]
fn journal_collectors_accept_dashed_and_journald_boot_ids() -> Result<()> {
    let journald = "1ccac6df36464eafa77dbc9d57cc97b3";
    for role in [
        "inspect_journal",
        "inspect_journal_record",
        "inspect_kernel_log",
    ] {
        for input in [journald, "1ccac6df-3646-4eaf-a77d-bc9d57cc97b3"] {
            assert_eq!(
                parsed(role, "journal_boot_id", json!([input, null]))?,
                journald,
                "{role} {input}"
            );
        }
        for input in [
            json!(""),
            json!("1CCAC6DF36464EAFA77DBC9D57CC97B3"),
            json!("1ccac6df-36464eaf-a77d-bc9d57cc97b3"),
            json!("1ccac6df36464eafa77dbc9d57cc97b"),
            json!(null),
        ] {
            rejected(role, "journal_boot_id", json!([input, null]), "ValueError")?;
        }
    }
    Ok(())
}

#[test]
fn memory_selected_fields_preserve_units_and_fail_closed_on_selected_corruption() -> Result<()> {
    let source = b"MemTotal: 4 kB\nMemFree: 1 kB\nFutureField: unknown\n";
    assert_eq!(
        parsed(
            "observe_memory",
            "parse_meminfo",
            json!([payload::bytes(source)])
        )?,
        json!({"mem_total_bytes":4096,"mem_free_bytes":1024})
    );
    assert_eq!(
        parsed("observe_memory", "parse_vmstat", json!([null]))?,
        json!({})
    );
    assert_eq!(
        parsed(
            "observe_memory",
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
            "observe_memory",
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
            "observe_memory",
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
    let sampled = parsed("observe_cgroup_sample", "sample_cpu", json!([selected]))?;
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("counter writer panicked"))??;
    assert_eq!(sampled, json!([identity, 100]));
    let replaced = parsed("observe_cgroup_sample", "sample_cpu", json!([selected]))?;
    assert_ne!(replaced[0], identity);
    assert_eq!(replaced[1], 200);
    let first = parsed(
        "observe_cgroup_sample",
        "cpu_observation",
        json!([null, sampled[0], sampled[1], 1000]),
    )?;
    let second = parsed(
        "observe_cgroup_sample",
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
        parsed("observe_cpu", "integer", json!([payload::bytes(b"16"), 16]))?,
        16
    );
    for data in [b"17".as_slice(), b"-1", b" 1", b"1.0", b"", &[0xff]] {
        rejected(
            "observe_cpu",
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
import types
sys.modules['estus_runtime'] = types.ModuleType('estus_runtime')
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
        let executor = &template["executor"];
        let Some(path) = executor["path"].as_str() else {
            continue;
        };
        let bundle = assets.join(path);
        let files = bundle;
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

#[test]
fn collectors_have_no_hardcoded_single_location_binaries() -> Result<()> {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
    let scan = r#"import ast, os, re, sys
binpath = re.compile(r'^/(?:usr/)?s?bin/[^/]+$')
errors = []
count = 0
for payload in sorted(os.listdir(sys.argv[1])):
    path = os.path.join(sys.argv[1], payload, 'collector.py')
    if not os.path.isfile(path):
        continue
    count += 1
    tree = ast.parse(open(path, encoding='utf-8').read(), filename=path)
    parent_map = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            parent_map[c] = n
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if not binpath.match(node.value):
            continue
        parent = parent_map.get(node)
        if isinstance(parent, (ast.Tuple, ast.List)):
            siblings = [el.value for el in parent.elts if isinstance(el, ast.Constant) and isinstance(el.value, str)]
            if len(siblings) >= 2 and all(binpath.match(s) for s in siblings) and len(set(siblings)) == len(siblings):
                continue
        errors.append(path + ':' + str(node.lineno) + ':' + node.value)
print(str(count))
print('\n'.join(errors))
"#;
    let output = std::process::Command::new(
        std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()),
    )
    .args(["-I", "-B", "-c", scan])
    .arg(assets.join("payloads"))
    .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    ensure!(
        output.status.success(),
        "binary path scan failed: {}\n{}",
        String::from_utf8_lossy(&output.stderr),
        stdout
    );
    let mut lines = stdout.lines();
    let count: usize = lines.next().context("scan count")?.parse()?;
    ensure!(count >= 96, "expected 96+ collectors, scanned {count}");
    let offenders: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    ensure!(
        offenders.is_empty(),
        "hardcoded single-location binary paths (use ESTUS_EXEC_* or multi-location candidate tuples): {offenders:?}"
    );
    Ok(())
}

#[test]
fn inspect_journal_record_reconstructs_8kib_multiline_utf8_splits_and_rotated_cursors() -> Result<()>
{
    use base64::Engine;
    let boot = "0123456789abcdef0123456789abcdef";
    let cursor =
        "s=0123456789abcdef0123456789abcdef;i=1;b=0123456789abcdef0123456789abcdef;m=1;t=1;x=1";
    // 8 KiB multiline message containing multi-byte UTF-8 codepoints across chunk boundaries.
    let multiline = format!(
        "HEADER_LINE\n{}\nTAIL_LINE_é🙂_END",
        "é🙂line-content-\n".repeat(480)
    );
    assert!(multiline.len() > 8192);
    let record = json!({
        "__CURSOR": cursor,
        "_BOOT_ID": boot,
        "MESSAGE": multiline,
    });

    let mut offset = 0u64;
    let mut reconstructed = Vec::new();
    let mut chunks = 0usize;
    loop {
        let page = parsed(
            "inspect_journal_record",
            "read_journal_record_from_records",
            json!([[record], boot, cursor, offset, 1021]),
        )?;
        assert_eq!(page["status"], "available");
        assert_eq!(page["offset"], offset);
        assert_eq!(page["incomplete"], true);
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(page["data_base64"].as_str().context("data_base64")?)?;
        reconstructed.extend_from_slice(&bytes);
        chunks += 1;
        if page["eof"] == true {
            assert_eq!(page["total_bytes"], multiline.len() as u64);
            assert_eq!(page["next_offset"], multiline.len() as u64);
            break;
        }
        offset = page["next_offset"].as_u64().context("next_offset")?;
        assert!(chunks < 32);
    }
    assert!(chunks >= 8);
    assert_eq!(String::from_utf8(reconstructed)?, multiline);

    // Rotated / missing cursor or boot mismatch returns cursor_unavailable.
    let empty = parsed(
        "inspect_journal_record",
        "read_journal_record_from_records",
        json!([[], boot, cursor, 0, 128]),
    )?;
    assert_eq!(empty["status"], "cursor_unavailable");
    assert_eq!(empty["eof"], true);
    assert_eq!(empty["data_base64"], "");

    let wrong_boot = parsed(
        "inspect_journal_record",
        "read_journal_record_from_records",
        json!([[record], "fedcba9876543210fedcba9876543210", cursor, 0, 128]),
    )?;
    assert_eq!(wrong_boot["status"], "cursor_unavailable");
    Ok(())
}

#[test]
fn inspect_journal_filters_literally_binds_direction_and_packs_within_32768_bytes() -> Result<()> {
    let boot = "0123456789abcdef0123456789abcdef";
    let mut records = Vec::new();
    for i in 0..50usize {
        let cursor = format!(
            "s=0123456789abcdef0123456789abcdef;i={i:x};b={boot};m={};t={};x=1",
            1000 + i,
            2000 + i
        );
        let msg = if i % 2 == 0 {
            format!("[err.*] match #{i} {}", "a".repeat(900))
        } else {
            format!("noise #{i} {}", "b".repeat(900))
        };
        records.push(json!({
            "__CURSOR": cursor,
            "_BOOT_ID": boot,
            "__REALTIME_TIMESTAMP": (1_700_000_000_000_000u64 + i as u64).to_string(),
            "__MONOTONIC_TIMESTAMP": (100_000u64 + i as u64).to_string(),
            "MESSAGE": msg,
            "PRIORITY": "3",
            "_SYSTEMD_UNIT": "estus-fixture.service",
            "_TRANSPORT": "journal"
        }));
    }

    let filtered = parsed(
        "inspect_journal",
        "select_journal_records",
        json!([
            records,
            boot,
            50,
            0,
            4102444800_u64,
            7,
            "system_journal",
            "available",
            "[err.*]",
            "backward",
            "",
            "",
            32768
        ]),
    )?;
    assert_eq!(filtered["scope"], "system_journal");
    assert_eq!(filtered["status"], "available");
    let items = filtered["records"].as_array().context("records")?;
    assert_eq!(items.len(), 25);
    assert!(items.iter().all(|r| {
        r["message"].as_str().unwrap().starts_with("[err.*]") && r["message_truncated"] == true
    }));
    let cont = filtered["continuation_cursor"].as_str().context("cont")?;
    assert!(cont.starts_with("backward:"));

    // Direction mismatch on continuation cursor is rejected.
    rejected(
        "inspect_journal",
        "parse_cursor_arg",
        json!([cont, "forward"]),
        "ValueError",
    )?;
    let parsed_raw = parsed(
        "inspect_journal",
        "parse_cursor_arg",
        json!([cont, "backward"]),
    )?;
    assert_eq!(parsed_raw, items.last().unwrap()["cursor"]);

    // Verify 32768-byte packing sets truncated=true when byte budget clips before limit.
    let packed = parsed(
        "inspect_journal",
        "select_journal_records",
        json!([
            records,
            boot,
            50,
            0,
            4102444800_u64,
            7,
            "system_journal",
            "available",
            "",
            "forward",
            "",
            "",
            2048
        ]),
    )?;
    assert_eq!(packed["truncated"], true);
    let packed_items = packed["records"].as_array().context("packed records")?;
    assert!(!packed_items.is_empty() && packed_items.len() < 50);
    assert!(serde_json::to_vec(&packed)?.len() <= 2048);
    Ok(())
}

#[test]
fn cgroup_collectors_check_unified_hierarchy_file() -> Result<()> {
    let python = std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/payloads");
    for name in [
        "inspect_cgroup_processes",
        "observe_cgroup_sample",
        "observe_cgroup_stats",
        "observe_cgroup_tree",
    ] {
        // Collectors read their request through estus_runtime.request(); the test supplies
        // that seam directly rather than injecting process argv.
        let request = if name == "observe_cgroup_sample" {
            "['/system.slice', 2, 50]"
        } else {
            "['/system.slice', 1]"
        };
        let script = format!(
            r#"import importlib.util, os, sys, types
from unittest import mock
runtime = types.ModuleType('estus_runtime')
runtime.request = lambda: {request}
sys.modules['estus_runtime'] = runtime
spec = importlib.util.spec_from_file_location('cg', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
orig = os.path.isfile
def fake_isfile(p):
    if p == '/sys/fs/cgroup/cgroup.controllers':
        return False
    return orig(p)
with mock.patch('os.path.isfile', side_effect=fake_isfile):
    try:
        mod.main()
    except ValueError as e:
        assert 'cgroup v2 unified hierarchy required' in str(e), str(e)
        sys.exit(0)
    raise AssertionError('expected cgroup v2 check failure')
"#
        );
        let out = std::process::Command::new(&python)
            .args(["-I", "-B", "-c", &script])
            .arg(assets.join(name).join("collector.py"))
            .output()?;
        ensure!(
            out.status.success(),
            "{name} cgroup v2 predicate failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Runs a shipped collector's `main()` on this host with a stub runtime, then
/// validates its output against the definition's result schema.
fn run_host_collector(
    tool: &str,
    request_json: &str,
    env_vars: &[(&str, &std::path::Path)],
) -> Result<Value> {
    let python = std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let collector = root
        .join("catalog/payloads")
        .join(tool)
        .join("collector.py");
    let toml_text = std::fs::read_to_string(root.join("catalog").join(format!("{tool}.toml")))?;
    let toml_doc: toml::Value = toml::from_str(&toml_text)?;
    let schema = serde_json::to_value(&toml_doc["tools"][tool]["result"]["schema"])?;
    let validator = jsonschema::draft202012::new(&schema)
        .map_err(|e| anyhow::anyhow!("{tool}: invalid result schema: {e}"))?;
    let runner = r#"import importlib.util, json, subprocess, sys, types
rt = types.ModuleType('estus_runtime')
payload = json.loads(sys.argv[2])
rt.request = lambda: payload
rt.allowed = lambda value, allow: isinstance(allow, list) and bool(allow) and ('*' in allow or value in allow)
def check_text(value, maximum=4096):
    if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
        raise ValueError('invalid text')
    return value
def run_bounded(argv, timeout=20, max_bytes=262144, accepted=(0,), env=None):
    p = subprocess.run(argv, capture_output=True, timeout=timeout, check=False, env=env)
    if accepted is not None and p.returncode not in accepted:
        raise RuntimeError('subprocess failed with exit ' + str(p.returncode))
    return {'returncode': p.returncode, 'timed_out': False, 'stdout': p.stdout[:max_bytes].decode('utf-8', 'strict'), 'stderr': p.stderr[:max_bytes].decode('utf-8', 'replace')}
rt.check_text = check_text
rt.run_bounded = run_bounded
sys.modules['estus_runtime'] = rt
spec = importlib.util.spec_from_file_location('collector', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
"#;
    let mut cmd = std::process::Command::new(&python);
    cmd.args(["-I", "-B", "-c", runner])
        .arg(&collector)
        .arg(request_json);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
    ensure!(
        out.status.success(),
        "{tool} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = estus::internal::strict_json::parse(&out.stdout)?;
    ensure!(
        validator.is_valid(&parsed),
        "{tool} output failed result.schema validation: {parsed}"
    );
    Ok(parsed)
}

#[test]
fn systemd_sockets_keep_every_listen_endpoint_and_page() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let multi = "Listen=/run/systemd/journal/socket (Datagram)\nListen=/run/systemd/journal/stdout (Stream)\nId=systemd-journald.socket\n";
    assert_eq!(
        parsed("observe_systemd_sockets", "parse_show", json!([multi]))?,
        json!({"Id": "systemd-journald.socket", "Listen": ["/run/systemd/journal/socket (Datagram)", "/run/systemd/journal/stdout (Stream)"]})
    );
    for raw in ["Id=a\nId=b\n", "Unknown=x\n", "no separator\n"] {
        rejected(
            "observe_systemd_sockets",
            "parse_show",
            json!([raw]),
            "ValueError",
        )?;
    }

    let stubs = tempfile::tempdir()?;
    let stub = stubs.path().join("systemctl");
    std::fs::write(
        &stub,
        r#"#!/bin/sh
for a in "$@"; do last="$a"; done
case " $* " in
  *" list-units "*) i=0; while [ $i -lt 30 ]; do printf 'sock-%02d.socket loaded active listening Fixture socket %d\n' $i $i; i=$((i+1)); done ;;
  *" show "*) printf 'Id=%s\nActiveState=active\nTriggers=%s\nListen=/run/%s/a (Stream)\nListen=/run/%s/b (Datagram)\nAccept=no\nNConnections=0\nNAccepted=0\n' "$last" "${last%.socket}.service" "$last" "$last" ;;
  *) exit 1 ;;
esac
"#,
    )?;
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))?;
    let mut ids = Vec::new();
    let mut offset = 0;
    let mut pages = 0;
    loop {
        let page = run_host_collector(
            "observe_systemd_sockets",
            &json!([{"target_python": "/usr/bin/python3", "manager_scope": "system", "offset": offset}]).to_string(),
            &[("ESTUS_EXEC_SYSTEMCTL", &stub)],
        )?;
        pages += 1;
        assert_eq!(page["source_count"], 30);
        for socket in page["sockets"].as_array().context("sockets")? {
            assert_eq!(socket["Listen"].as_array().context("listen")?.len(), 2);
            ids.push(socket["Id"].as_str().context("id")?.to_owned());
        }
        match page.get("next_offset") {
            Some(next) => {
                assert_eq!(page["truncated"], true);
                offset = next.as_u64().context("next_offset")?;
            }
            None => {
                assert_eq!(page["truncated"], false);
                break;
            }
        }
    }
    let expected: Vec<String> = (0..30).map(|i| format!("sock-{i:02}.socket")).collect();
    assert!(pages > 1);
    assert_eq!(ids, expected);
    Ok(())
}

#[test]
fn host_runnable_native_preview_collector_contracts() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let stubs = tempfile::tempdir()?;
    let stub_systemctl = stubs.path().join("systemctl");
    std::fs::write(
        &stub_systemctl,
        "#!/bin/sh\nprintf 'Id=estus-fixture.service\\nLoadState=loaded\\nActiveState=inactive\\nSubState=dead\\nUnitFileState=disabled\\nMainPID=0\\nResult=success\\n'\n",
    )?;
    std::fs::set_permissions(&stub_systemctl, std::fs::Permissions::from_mode(0o755))?;

    let start_prev = run_host_collector(
        "preview_systemd_service",
        r#"[{"target_python":"/usr/bin/python3","manager_scope":"system","allowed_units":["estus-fixture.service"],"unit":"estus-fixture.service","operation":"start"}]"#,
        &[("ESTUS_EXEC_SYSTEMCTL", &stub_systemctl)],
    )?;
    ensure!(start_prev["changed"] == true && start_prev["operation"] == "start");
    let stop_prev = run_host_collector(
        "preview_systemd_service",
        r#"[{"target_python":"/usr/bin/python3","manager_scope":"system","allowed_units":["estus-fixture.service"],"unit":"estus-fixture.service","operation":"stop"}]"#,
        &[("ESTUS_EXEC_SYSTEMCTL", &stub_systemctl)],
    )?;
    ensure!(stop_prev["changed"] == false);

    if std::path::Path::new("/proc/sys/kernel/printk_ratelimit").is_file()
        && std::path::Path::new("/etc/sysctl.d").is_dir()
    {
        let cfg_prev = run_host_collector(
            "preview_sysctl",
            r#"["kernel.printk_ratelimit", 10, "config", ["kernel.printk_ratelimit"]]"#,
            &[],
        )?;
        ensure!(
            cfg_prev["config_path"]
                == "/etc/sysctl.d/90-estus-catalog-kernel_printk__ratelimit.conf"
                && cfg_prev["persistent"] == true
                && cfg_prev["after_config"] == "kernel.printk_ratelimit = 10\n"
        );
        let rt_prev = run_host_collector(
            "preview_sysctl",
            r#"["kernel.printk_ratelimit", 10, "runtime", ["kernel.printk_ratelimit"]]"#,
            &[],
        )?;
        ensure!(rt_prev["config_path"] == "" && rt_prev["persistent"] == false);
    }
    Ok(())
}
