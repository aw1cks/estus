use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

async fn native(guest: &catalog::Guest, enabled: bool, timer: u64) -> Result<()> {
    let output = guest
        .shell("/usr/bin/ethtool --json --show-eee model0")
        .await?;
    ensure!(
        output.status.success(),
        "native EEE read failed: {output:?}"
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        value[0]["ifname"] == "model0"
            && value[0]["status"] == if enabled { "inactive" } else { "disabled" }
            && value[0]["tx-lpi"] == timer,
        "native EEE readback mismatch: {value}"
    );
    Ok(())
}

async fn writes(guest: &catalog::Guest) -> Result<u64> {
    let output = guest
        .shell("cat /sys/module/estus_nic_model/parameters/eee_writes")
        .await?;
    ensure!(
        output.status.success(),
        "native write counter unavailable: {output:?}"
    );
    String::from_utf8(output.stdout)?
        .trim()
        .parse()
        .context("EEE callback counter")
}

async fn fault(guest: &catalog::Guest, value: u8) -> Result<()> {
    let output = guest
        .shell(&format!(
            "printf {value} > /sys/module/estus_nic_model/parameters/eee_write_fault"
        ))
        .await?;
    ensure!(
        output.status.success(),
        "root-only EEE fault setup failed: {output:?}"
    );
    Ok(())
}

fn completed_failure(envelope: &Value) -> Result<()> {
    ensure!(
        envelope["error"]["code"] == "payload_failed"
            && envelope["error"]["remote_state_unknown"] == false
            && envelope["data"]["status"] == "failed"
            && envelope["data"]["complete"] == true
            && envelope["data"]["runner_rc"]
                .as_i64()
                .is_some_and(|code| code != 0)
            && envelope["data"]["changed"].is_null()
            && envelope["data"]["projection"]["status"] == "unavailable",
        "failed NIC operation lost evidence or claimed unchanged/success: {envelope}"
    );
    Ok(())
}

fn state(enabled: bool, timer: Option<u64>) -> Value {
    let mut value = json!({"enabled":enabled,"active":false,"tx_lpi_enabled":timer.is_some(),"supported_modes":["100baseT/Full","1000baseT/Full"],"advertised_modes":["100baseT/Full","1000baseT/Full"],"peer_modes":[]});
    if let Some(timer) = timer {
        value["tx_lpi_timer_us"] = json!(timer);
    }
    value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn change_nic_eee() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let prepared = guest.shell("/usr/bin/ethtool --set-eee model0 eee off tx-lpi off tx-timer 913").await?;
        ensure!(prepared.status.success(), "native LPI-off setup failed: {prepared:?}");
        let binding = guest.binding("change_nic_eee", json!({})).await?;
        for input in [
            json!({"interface":"management0","enabled":true,"tx_lpi_timer_us":237}),
            json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":-1}),
            json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":1000001}),
            json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":true}),
            json!({"interface":"model0","enabled":"on","tx_lpi_timer_us":237}),
            json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":237,"operator_policy":{"allow_runtime_tuning":true}}),
            json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":237,"tx_lpi_enabled":false}),
        ] {
            binding.reject(input).await?;
        }
        let denied = guest.ordinary("/usr/bin/ethtool --set-eee model0 eee on tx-lpi on tx-timer 237").await?;
        ensure!(!denied.status.success(), "ordinary kernel setter unexpectedly allowed");
        let denied = guest.ordinary("printf 1 > /sys/module/estus_nic_model/parameters/eee_write_fault").await?;
        ensure!(!denied.status.success(), "ordinary account changed root-only fault control");
        let count = writes(&guest).await?;
        let request = json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":237});
        let reply = binding.call(request.clone()).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value == &json!({"interface":"model0","driver":"estus_nic_model","scope":"software_model","before":state(false,None),"after":state(true,Some(237)),"changed":true,"verified":true,"persistence":"runtime_only"}), "complete EEE mutation/readback: {value}");
        ensure!(reply["data"]["changed"] == true, "EEE change evidence lost");
        native(&guest, true, 237).await?;
        ensure!(writes(&guest).await? == count + 1, "enable must invoke one kernel setter");
        let reply = binding.call(request).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == false && value["before"] == state(true,Some(237)) && value["after"] == state(true,Some(237)) && value["verified"] == true, "no-op must report actual unchanged state: {value}");
        ensure!(reply["data"]["changed"] == false, "EEE no-op reported a change");
        ensure!(writes(&guest).await? == count + 1, "no-op invoked kernel setter");
        let reply = binding.call(json!({"interface":"model0","enabled":false,"tx_lpi_timer_us":0})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["before"] == state(true,Some(237)) && value["after"] == state(false,Some(0)), "explicit disable keeps fixed LPI on and explicit zero timer: {value}");
        native(&guest, false, 0).await?;
        let reply = binding.call(json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":1000000})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["changed"] == true && value["after"] == state(true,Some(1000000)), "explicit reverse: {value}");
        native(&guest, true, 1000000).await?;
        let alive = guest.ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate").await?;
        ensure!(alive.status.success() && alive.stdout == b"1000\nup\n", "ordinary management path lost: {alive:?}");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn nic_eee_set_failures_preserve_partial_effects_without_replay() -> Result<()> {
    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_nic_eee", json!({})).await?;
        for injected in [1, 2] {
            let before = writes(&guest).await?;
            let control = guest
                .shell(&format!(
                    "printf {injected} > /sys/module/estus_nic_model/parameters/eee_read_fault"
                ))
                .await?;
            ensure!(control.status.success(), "root read-fault setup failed");
            let failed = binding
                .call(json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":237}))
                .await?;
            completed_failure(&failed)?;
            ensure!(
                writes(&guest).await? == before,
                "unsupported/read-error observation reached a setter"
            );
            let reset = guest
                .shell("printf 0 > /sys/module/estus_nic_model/parameters/eee_read_fault")
                .await?;
            ensure!(reset.status.success(), "root read-fault reset failed");
        }
        for injected in [1, 2, 3] {
            fault(&guest, 0).await?;
            let baseline = guest
                .shell("/usr/bin/ethtool --set-eee model0 eee off tx-lpi on tx-timer 100")
                .await?;
            ensure!(
                baseline.status.success(),
                "native fault baseline failed: {baseline:?}"
            );
            let before = writes(&guest).await?;
            fault(&guest, injected).await?;
            let failed = binding
                .call(json!({"interface":"model0","enabled":true,"tx_lpi_timer_us":237}))
                .await?;
            completed_failure(&failed)?;
            ensure!(
                writes(&guest).await? == before + 1,
                "fault {injected} was skipped, replayed or rolled back"
            );
            // Fault 3 applies state then returns EIO; do not pretend that failure means unchanged.
            if injected == 3 {
                native(&guest, true, 237).await?;
            } else {
                native(&guest, false, 100).await?;
            }
            fault(&guest, 0).await?;
        }
        let alive = guest
            .ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate")
            .await?;
        ensure!(
            alive.status.success() && alive.stdout == b"1000\nup\n",
            "management path lost after partial effects: {alive:?}"
        );
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_LAB_VM"]
async fn nic_eee_set_requires_stable_ethtool() -> Result<()> {
    use crate::support::Client;

    async fn set(client: &Client, enabled: bool, timer: u64) -> Result<Value> {
        client
            .call(
                "change_nic_eee",
                json!({
                    "host":"plain", "inputs":{
                        "interface":"model0", "enabled":enabled, "tx_lpi_timer_us":timer
                    }, "timeout_secs":20
                }),
            )
            .await
    }

    let guest = catalog::Guest::start_lab().await?;
    let result: Result<()> = async {
        let binding = guest.binding("change_nic_eee", json!({})).await?;
        let prepared = guest
            .shell(
                r#"set -eu
/usr/bin/ethtool --set-eee model0 eee off tx-lpi on tx-timer 100
mkdir -m700 /run/estus-native-ethtool
real=$(readlink -f /usr/bin/ethtool)
printf '#!/bin/sh\nexec "%s" "$@"\n' "$real" > /run/estus-native-ethtool/replacement
chmod 755 /run/estus-native-ethtool/replacement
mv /usr/bin/ethtool /run/estus-native-ethtool/original
test ! -e /usr/bin/ethtool
"#,
            )
            .await?;
        ensure!(
            prepared.status.success(),
            "native executable fixture setup failed"
        );
        let before = writes(&guest).await?;
        let client = Client::start(&binding.config).await?;
        let calls: Result<()> = async {
            let missing = set(&client, true, 237).await?;
            ensure!(
                missing["error"]["code"] == "resource_unavailable"
                    && missing["error"]["remote_state_unknown"] == false
                    && missing["data"]["status"] == "not_started"
                    && missing["data"]["complete"] == false,
                "missing ethtool reached NIC payload execution: {missing}"
            );
            ensure!(
                writes(&guest).await? == before,
                "missing utility invoked a setter"
            );
            let restored = guest
                .shell("cp -P /run/estus-native-ethtool/original /usr/bin/ethtool")
                .await?;
            ensure!(restored.status.success(), "native utility restore failed");
            native(&guest, false, 100).await?;

            let applied = set(&client, true, 237).await?;
            ensure!(
                catalog::projection(&applied)?["verified"] == true
                    && applied["data"]["changed"] == true,
                "negative discovery persisted after utility restoration: {applied}"
            );
            native(&guest, true, 237).await?;
            ensure!(
                writes(&guest).await? == before + 1,
                "enable must write exactly once"
            );
            let changed = guest
                .shell(
                    r#"set -eu
rm /usr/bin/ethtool
ln -s /run/estus-native-ethtool/replacement /usr/bin/ethtool
"#,
                )
                .await?;
            ensure!(changed.status.success(), "executable replacement failed");

            let stale = set(&client, false, 0).await?;
            ensure!(
                stale["error"]["code"] == "payload_rejected"
                    && stale["error"]["remote_state_unknown"] == false
                    && stale["data"]["status"] == "not_started",
                "stale ethtool identity silently acquired new execution: {stale}"
            );
            native(&guest, true, 237).await?;
            ensure!(
                writes(&guest).await? == before + 1,
                "stale prerequisite executed or replayed a setter"
            );

            let explicit = set(&client, false, 0).await?;
            ensure!(
                catalog::projection(&explicit)?["verified"] == true
                    && explicit["data"]["changed"] == true,
                "later explicit request could not rediscover: {explicit}"
            );
            native(&guest, false, 0).await?;
            ensure!(
                writes(&guest).await? == before + 2,
                "explicit retry did not write exactly once"
            );
            let noop = set(&client, false, 0).await?;
            ensure!(
                catalog::projection(&noop)?["changed"] == false
                    && noop["data"]["changed"] == false
                    && writes(&guest).await? == before + 2,
                "unchanged EEE request invoked a setter"
            );
            let alive = guest
                .ordinary("/usr/bin/id -u; cat /sys/class/net/management0/operstate")
                .await?;
            ensure!(
                alive.status.success() && alive.stdout == b"1000\nup\n",
                "ordinary management path lost"
            );
            Ok(())
        }
        .await;
        let stopped = client.stop().await;
        let recovery = guest
            .shell(
                r#"set -eu
rm -f /usr/bin/ethtool
mv /run/estus-native-ethtool/original /usr/bin/ethtool
/usr/bin/ethtool --set-eee model0 eee off tx-lpi on tx-timer 100
rm -rf /run/estus-native-ethtool
"#,
            )
            .await?;
        ensure!(
            recovery.status.success(),
            "independent utility/state recovery failed"
        );
        stopped?;
        calls
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
