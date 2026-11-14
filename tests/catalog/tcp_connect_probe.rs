use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn tcp_connect_probe() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"systemd-run --unit=catalog-listener /usr/bin/python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",18080)); s.listen(8); time.sleep(120)'
for n in 1 2 3 4 5; do /usr/bin/ss -H -lnt | grep -q :18080 && exit 0; sleep 1; done; exit 1"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("tcp_connect_probe", json!({})).await?;
        binding.reject(json!({"destination": "8.8.8.8", "destination_port": 18080, "timeout": 1})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let oracle = guest.shell(r#"/usr/bin/ss -H -lnt"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"destination": "127.0.0.1", "destination_port": 18080, "timeout": 2})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["connected"] == true && value["bytes_sent"] == 0, "real TCP connect failed");
        let restricted = guest.binding("tcp_connect_probe", json!({"operator_policy":{"interface":"catalog0","interfaces":["lo","catalog0"],"destinations":["127.0.0.1"],"ports":[18081]}})).await?;
        let denied = restricted.call(json!({"destination":"127.0.0.1","destination_port":18080,"timeout":1})).await?;
        ensure!(catalog::projection(&denied).is_err(), "operator fixed port policy bypassed");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
