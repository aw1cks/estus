use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn network_sockets_list() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"systemd-run --unit=catalog-listener /usr/bin/python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",18080)); s.listen(8); time.sleep(120)'
for n in 1 2 3 4 5; do /usr/bin/ss -H -lnt | grep -q :18080 && exit 0; sleep 1; done; exit 1"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("network_sockets_list", json!({})).await?;
        binding.reject(json!({"flags": "--kill"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let oracle = guest.shell(r#"/usr/bin/ss -H -lnt"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"protocol": "tcp", "state": "listening", "address": "127.0.0.1", "local_port": 18080})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["scope"] == "current_network_namespace" && value["truncated"] == false, "list scope or completeness metadata missing");
        let limited = binding.call(json!({"limit":1})).await?;
        let limited = catalog::projection(&limited)?;
        ensure!(limited["entries"].as_array().context("bounded entries")?.len() == 1 && limited["truncated"] == true, "omitted records must report truncation");
        ensure!(value["entries"].as_array().context("sockets")?.iter().any(|r| r["local_port"] == 18080 && r["state"] == "LISTEN"), "real listener missing");
        ensure!(value["process_attribution"] == "not_collected", "sensitive process attribution leaked");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
