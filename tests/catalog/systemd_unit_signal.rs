use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_unit_signal_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("systemd_unit_signal", json!({})).await?;
        binding.reject(json!({"unit": "estus-fixture.service", "signal": "USR1", "flags": ["--now"]})).await?;
        binding.reject(json!({"unit": "ssh.service", "signal": "USR1"})).await?;
        binding.reject(json!({"unit":"estus-fixture.service","signal":"KILL"})).await?;
        let prep = guest.shell(r#"set -eu
cat > /etc/estus-catalog/signal_receiver.py <<'SCRIPT'
import pathlib, signal, time
signal.signal(signal.SIGUSR1, lambda *_: pathlib.Path('/var/lib/estus-catalog/signal-marker').write_text('USR1'))
pathlib.Path('/var/lib/estus-catalog/signal-ready').write_text('ready')
while True:
    time.sleep(10)
SCRIPT
printf '[Service]\nExecStart=/usr/bin/python3 -I /etc/estus-catalog/signal_receiver.py\n' > /run/systemd/system/estus-fixture-signal.service
systemctl daemon-reload
systemctl start estus-fixture-signal.service
for i in $(seq 1 100); do test ! -f /var/lib/estus-catalog/signal-ready || exit 0; sleep 0.1; done
systemctl show estus-fixture-signal.service -p ActiveState -p Result -p ExecMainStatus >&2
journalctl -u estus-fixture-signal.service -n 10 --no-pager >&2
exit 1"#).await?;
        ensure!(prep.status.success(), "signal receiver preparation failed: stdout={} stderr={}", String::from_utf8_lossy(&prep.stdout), String::from_utf8_lossy(&prep.stderr));
        let reply = binding.call(json!({"unit":"estus-fixture-signal.service","signal":"USR1"})).await?;
        ensure!(catalog::projection(&reply)?["signal"] == "USR1", "signal receipt lost");
        let oracle = guest.shell("for i in $(seq 1 30); do test ! -f /var/lib/estus-catalog/signal-marker || { test \"$(cat /var/lib/estus-catalog/signal-marker)\" = USR1 && systemctl is-active --quiet estus-fixture-signal.service; exit $?; }; sleep 0.1; done; exit 1").await?;
        ensure!(oracle.status.success(), "real main process did not receive approved signal");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
