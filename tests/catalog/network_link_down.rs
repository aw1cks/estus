use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM"]
async fn network_link_down() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up"#).await?;
        ensure!(
            prepared.status.success(),
            "independent fixture preparation failed: {:?}",
            prepared
        );
        let binding = guest.binding("network_link_down", json!({})).await?;
        binding.reject(json!({"interface": "lo"})).await?;
        binding
            .reject(json!({"operator_policy":{"interfaces":["eth0"]}}))
            .await?;
        let mutation: Result<()> = async {
            let oracle = guest
                .shell(r#"/usr/bin/ip -j link show dev catalog0"#)
                .await?;
            ensure!(oracle.status.success(), "independent network oracle failed");
            let reply = binding.call(json!({"interface": "catalog0"})).await?;
            let value = catalog::projection(&reply)?;
            ensure!(
                value["verified"] == true && value["persistence"] == "runtime_only",
                "mutation receipt missing"
            );
            let after = guest
                .shell(r#"/usr/bin/ip -j link show dev catalog0"#)
                .await?;
            ensure!(
                after.status.success(),
                "independent postcondition oracle failed"
            );
            let rows: serde_json::Value = serde_json::from_slice(&after.stdout)?;
            let up = rows[0]["flags"]
                .as_array()
                .context("flags")?
                .iter()
                .any(|f| f == "UP");
            ensure!(!up, "link state did not change");
            Ok(())
        }
        .await;
        let recovery = guest.shell(r#"/usr/bin/ip link set catalog0 up"#).await?;
        ensure!(
            recovery.status.success(),
            "independent root-control recovery failed: {:?}",
            recovery
        );
        mutation?;
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM"]
async fn network_link_down_requires_stable_executable() -> Result<()> {
    use crate::support::Client;

    async fn down(client: &Client) -> Result<serde_json::Value> {
        client
            .call(
                "network_link_down",
                json!({
                    "host":"plain", "inputs":{"interface":"catalog0"}, "timeout_secs":20
                }),
            )
            .await
    }

    async fn observed_up(guest: &catalog::Guest) -> Result<bool> {
        let output = guest
            .shell(r#""$(cat /run/estus-native-ip/real)" -j link show dev catalog0"#)
            .await?;
        ensure!(output.status.success(), "independent link oracle failed");
        let rows: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        Ok(rows[0]["flags"]
            .as_array()
            .context("link flags")?
            .iter()
            .any(|flag| flag == "UP"))
    }

    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("network_link_down", json!({})).await?;
        let setup = guest.shell(r#"set -eu
mkdir -m700 /run/estus-native-ip
real=$(readlink -f /usr/bin/ip)
printf '%s\n' "$real" > /run/estus-native-ip/real
"$real" link set catalog0 up
mv /usr/bin/ip /run/estus-native-ip/original
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> /run/estus-native-ip/calls\nexec "%s" "$@"\n' "$real" > /run/estus-native-ip/replacement
chmod 755 /run/estus-native-ip/replacement
test ! -e /usr/bin/ip
"#).await?;
        ensure!(setup.status.success(), "executable prerequisite fixture failed");
        let client = Client::start(&binding.config).await?;
        let calls: Result<()> = async {
            let missing = down(&client).await?;
            ensure!(missing["error"]["code"] == "discovery_failed"
                && missing["error"]["remote_state_unknown"] == false
                && missing["data"]["status"] == "not_started"
                && missing["data"]["complete"] == false,
                "missing utility reached payload execution: {missing}");
            ensure!(observed_up(&guest).await?, "missing prerequisite changed the link");

            let restore = guest.shell(
                "ln -s /run/estus-native-ip/replacement /usr/bin/ip",
            ).await?;
            ensure!(restore.status.success(), "executable restore failed");
            let first = down(&client).await?;
            ensure!(catalog::projection(&first)?["verified"] == true
                && !observed_up(&guest).await?,
                "a negative discovery result prevented a new explicit request");

            let changed = guest.shell(r#"set -eu
"$(cat /run/estus-native-ip/real)" link set catalog0 up
cp /run/estus-native-ip/replacement /run/estus-native-ip/replacement-next
mv /run/estus-native-ip/replacement-next /run/estus-native-ip/replacement
rm /run/estus-native-ip/calls
"#).await?;
            ensure!(changed.status.success(), "positive-cache invalidation fixture failed");
            let stale = down(&client).await?;
            ensure!(stale["error"]["code"] == "payload_rejected"
                && stale["error"]["remote_state_unknown"] == false
                && stale["data"]["status"] == "not_started",
                "changed executable silently refreshed approval: {stale}");
            ensure!(observed_up(&guest).await?, "stale discovery reached mutation");
            ensure!(guest.shell("test ! -e /run/estus-native-ip/calls").await?.status.success(),
                "stale request invoked a utility or replayed itself");

            let explicit = down(&client).await?;
            ensure!(catalog::projection(&explicit)?["verified"] == true
                && !observed_up(&guest).await?,
                "a later explicit request could not rediscover");
            let invoked = guest.shell("cat /run/estus-native-ip/calls").await?;
            ensure!(invoked.status.success());
            ensure!(String::from_utf8(invoked.stdout)?.lines()
                .eq(["link set dev catalog0 down", "-j link show dev catalog0"]),
                "mutation/readback ran more than once");
            Ok(())
        }.await;
        let stopped = client.stop().await;
        let recovery = guest.shell(r#"set -eu
rm -f /usr/bin/ip
mv /run/estus-native-ip/original /usr/bin/ip
/usr/bin/ip link set catalog0 up
rm -rf /run/estus-native-ip
"#).await?;
        ensure!(recovery.status.success(), "independent prerequisite recovery failed");
        stopped?;
        calls
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
