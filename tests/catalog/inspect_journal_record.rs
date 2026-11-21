use crate::catalog;
use anyhow::{Context, Result, ensure};
use base64::Engine;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn journal_record_real_guest_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("inspect_journal_record", json!({})).await?;
        let multiline = format!(
            "ESTUS_RECORD_LINE1\n{}\nESTUS_RECORD_END",
            "x".repeat(8192)
        );
        // The native journal protocol keeps one multi-line MESSAGE (a stream
        // writer such as systemd-cat would split it), and needs no extra tool.
        let logged = guest
            .shell(
                "/usr/bin/python3 -c 'import socket, struct; msg=(\"ESTUS_RECORD_LINE1\\n\"+\"x\"*8192+\"\\nESTUS_RECORD_END\").encode(); s=socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); s.sendto(b\"SYSLOG_IDENTIFIER=estus-record-test\\nMESSAGE\\n\"+struct.pack(\"<Q\", len(msg))+msg+b\"\\n\", \"/run/systemd/journal/socket\")'",
            )
            .await?;
        ensure!(
            logged.status.success(),
            "native journal write failed: {}",
            String::from_utf8_lossy(&logged.stderr)
        );
        ensure!(guest.shell("/usr/bin/journalctl --sync").await?.status.success());
        let oracle = guest
            .shell("/usr/bin/journalctl -b --no-pager --all -o json SYSLOG_IDENTIFIER=estus-record-test")
            .await?;
        ensure!(oracle.status.success(), "oracle journalctl failed");
        let marker: Value = String::from_utf8(oracle.stdout)?
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|r| {
                r["MESSAGE"]
                    .as_str()
                    .is_some_and(|v| v.contains("ESTUS_RECORD_END"))
            })
            .context("multiline test marker missing from journal")?;
        let cursor = marker["__CURSOR"].as_str().context("cursor")?;
        let boot_id = marker["_BOOT_ID"].as_str().context("boot_id")?;

        let mut offset = 0u64;
        let mut reconstructed = Vec::new();
        loop {
            let envelope = binding
                .call(json!({
                    "boot_id": boot_id,
                    "cursor": cursor,
                    "offset": offset,
                    "max_bytes": 3000
                }))
                .await?;
            let page = catalog::projection(&envelope)?;
            ensure!(page["status"] == "available");
            let chunk = base64::engine::general_purpose::STANDARD
                .decode(page["data_base64"].as_str().context("data_base64")?)?;
            reconstructed.extend_from_slice(&chunk);
            if page["eof"] == true {
                ensure!(page["total_bytes"] == reconstructed.len() as u64);
                break;
            }
            offset = page["next_offset"].as_u64().context("next_offset")?;
        }
        ensure!(String::from_utf8(reconstructed)? == multiline);

        let missing_cursor =
            "s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;m=1;t=1;x=1";
        let missing = binding
            .call(json!({
                "boot_id": boot_id,
                "cursor": missing_cursor,
                "offset": 0,
                "max_bytes": 128
            }))
            .await?;
        let missing_page = catalog::projection(&missing)?;
        ensure!(missing_page["status"] == "cursor_unavailable");
        ensure!(missing_page["eof"] == true);
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
