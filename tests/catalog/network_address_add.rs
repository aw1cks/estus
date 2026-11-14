use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_address_add() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("network_address_add", json!({})).await?;
        binding.reject(json!({"interface": "catalog0", "address": "10.0.2.1/24"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let mutation: Result<()> = async {
            let oracle = guest.shell(r#"/usr/bin/ip -j address show dev catalog0"#).await?;
            ensure!(oracle.status.success(), "independent network oracle failed");
            let reply = binding.call(json!({"interface": "catalog0", "address": "192.0.2.9/24"})).await?;
            let value = catalog::projection(&reply)?;
            ensure!(value["verified"] == true && value["persistence"] == "runtime_only", "mutation receipt missing");
            let after = guest.shell(r#"/usr/bin/ip -j address show dev catalog0"#).await?;
            ensure!(after.status.success(), "independent postcondition oracle failed");
            let rows: serde_json::Value = serde_json::from_slice(&after.stdout)?;
            let present = rows[0]["addr_info"].as_array().context("addr_info")?.iter().any(|r| r["local"] == "192.0.2.9");
            ensure!(present, "address postcondition missing");
            Ok(())
        }.await;
        let recovery = guest.shell(r#"/usr/bin/python3 -c 'import json,subprocess; rows=json.loads(subprocess.check_output(["/usr/bin/ip","-j","address","show","dev","catalog0"])); found=any(x.get("local")=="192.0.2.9" for r in rows for x in r.get("addr_info",[])); subprocess.check_call(["/usr/bin/ip","address","del","192.0.2.9/24","dev","catalog0"]) if found else None'"#).await?;
        ensure!(recovery.status.success(), "independent root-control recovery failed: {:?}", recovery);
        mutation?;
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
