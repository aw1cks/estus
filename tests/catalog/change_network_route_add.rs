use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM"]
async fn change_network_route_add() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"/usr/bin/ip link set catalog0 up"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("change_network_route_add", json!({})).await?;
        binding.reject(json!({"interface": "catalog0", "destination": "0.0.0.0/0"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let mutation: Result<()> = async {
            let oracle = guest.shell(r#"/usr/bin/ip -j route show exact 198.51.100.0/24"#).await?;
            ensure!(oracle.status.success(), "independent network oracle failed");
            let reply = binding.call(json!({"interface": "catalog0", "destination": "198.51.100.0/24"})).await?;
            let value = catalog::projection(&reply)?;
            ensure!(value["verified"] == true && value["persistence"] == "runtime_only", "mutation receipt missing");
            let after = guest.shell(r#"/usr/bin/ip -j route show exact 198.51.100.0/24"#).await?;
            ensure!(after.status.success(), "independent postcondition oracle failed");
            let rows: serde_json::Value = serde_json::from_slice(&after.stdout)?;
            ensure!(rows.as_array().context("routes")?.iter().any(|r| r["dst"] == "198.51.100.0/24"), "route postcondition missing");
            let repeated = binding.call(json!({"interface":"catalog0","destination":"198.51.100.0/24"})).await?;
            ensure!(repeated["error"]["code"] == "payload_failed"
                && repeated["error"]["remote_state_unknown"] == false
                && repeated["data"]["complete"] == true
                && repeated["data"]["changed"].is_null(),
                "strict route add was silently converted into replace/ensure-present: {repeated}");
            let repeated_state = guest.shell(r#"/usr/bin/ip -j route show exact 198.51.100.0/24"#).await?;
            ensure!(repeated_state.status.success());
            let rows: serde_json::Value = serde_json::from_slice(&repeated_state.stdout)?;
            ensure!(rows.as_array().context("routes")?.iter()
                .filter(|row| row["dst"] == "198.51.100.0/24" && row["dev"] == "catalog0").count() == 1,
                "failed repeated add changed the approved route");
            Ok(())
        }.await;
        let recovery = guest.shell(r#"/usr/bin/python3 -c 'import json,subprocess; rows=json.loads(subprocess.check_output(["/usr/bin/ip","-j","route","show","exact","198.51.100.0/24"])); subprocess.check_call(["/usr/bin/ip","route","del","198.51.100.0/24","dev","catalog0"]) if rows else None'"#).await?;
        ensure!(recovery.status.success(), "independent root-control recovery failed: {:?}", recovery);
        mutation?;
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
