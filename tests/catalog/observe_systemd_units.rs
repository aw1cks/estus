use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn systemd_units_list_real_acceptance() -> Result<()> {
    let guest = catalog::Guest::start()
        .await
        .context("BOOT real inventory qualification guest")?;
    let result: Result<()> = async {
        let binding = guest.binding("observe_systemd_units", json!({})).await.context("IMPORT system-scope inventory binding")?;
        binding.reject(json!({"view": "loaded", "unit_type": "service", "state": "active", "flags": ["--now"]})).await?;
        let prep = guest.shell(r#"set -eu
printf '[Service]\nExecStart=/usr/bin/sleep infinity\n' > /run/systemd/system/estus-fixture@.service
systemctl daemon-reload"#).await.context("PREPARE installed template: root unit write and manager reload")?;
        ensure!(prep.status.success(), "template preparation failed: {}", String::from_utf8_lossy(&prep.stderr));
        let loaded = binding.call(json!({"view":"loaded","unit_type":"service","state":"active","unit_pattern":"estus-fixture*"})).await.context("FIRST loaded inventory execution")?;
        let loaded = catalog::projection(&loaded).context("FIRST loaded inventory call")?;
        ensure!(loaded["units"].as_array().context("loaded inventory")?.iter().any(|u| u["unit"] == "estus-fixture.service" && u["active"] == "active"), "loaded service missing");
        let installed = binding.call(json!({"view":"installed","unit_type":"service","state":"all","unit_pattern":"estus-fixture*"})).await.context("SECOND installed template inventory execution")?;
        let installed = catalog::projection(&installed).context("SECOND installed template inventory call")?;
        ensure!(installed["units"].as_array().context("installed inventory")?.iter().any(|u| u["unit_file"] == "estus-fixture@.service"), "installed but unloaded template missing");
        let oracle = guest.shell("systemctl list-unit-files estus-fixture@.service --no-legend --no-pager").await.context("ORACLE installed template inventory")?;
        ensure!(oracle.status.success() && String::from_utf8(oracle.stdout)?.contains("estus-fixture@.service"), "template oracle failed");
        let prep = guest.shell(r#"set -eu
for i in $(seq 1 80); do
  printf '[Service]\nExecStart=/usr/bin/sleep infinity\n' > "/run/systemd/system/estus-fixture-overflow$i.service"
done
systemctl daemon-reload"#).await.context("PREPARE installed inventory overflow")?;
        ensure!(prep.status.success(), "overflow preparation failed: {}", String::from_utf8_lossy(&prep.stderr));
        let oracle = guest.shell("systemctl list-unit-files 'estus-fixture*' --type=service --no-legend --no-pager --plain").await.context("ORACLE paged installed inventory")?;
        ensure!(oracle.status.success(), "paged inventory oracle failed");
        let expected = String::from_utf8(oracle.stdout)?.lines().filter(|line| !line.trim().is_empty()).count();
        let mut paged = Vec::new();
        let mut offset = 0;
        let mut pages = 0;
        loop {
            let page = binding.call(json!({"view":"installed","unit_type":"service","state":"all","unit_pattern":"estus-fixture*","offset":offset})).await.context("THIRD paged installed inventory execution")?;
            let page = catalog::projection(&page).context("THIRD paged installed inventory projection")?;
            pages += 1;
            ensure!(page["source_count"].as_u64().context("source count")? as usize == expected, "page source_count disagrees with oracle");
            paged.extend(page["units"].as_array().context("paged units")?.iter().filter_map(|u| u["unit_file"].as_str().map(str::to_owned)));
            match page.get("next_offset") {
                Some(next) => {
                    ensure!(page["truncated"] == true, "page with next_offset must be truncated");
                    offset = next.as_u64().context("next_offset")?;
                }
                None => {
                    ensure!(page["truncated"] == false, "final page below the cap must not be truncated");
                    break;
                }
            }
        }
        let unique: std::collections::BTreeSet<_> = paged.iter().collect();
        ensure!(pages > 1 && paged.len() == expected && unique.len() == expected, "paged inventory lost or repeated entries");
        let prep = guest.shell(r#"set -eu
mkdir -p /home/mcp/.config/systemd/user
printf '[Service]\nExecStart=/usr/bin/sleep infinity\n' > /home/mcp/.config/systemd/user/estus-fixture.service
chown -R mcp /home/mcp/.config"#).await.context("PREPARE user-manager unit file and ownership")?;
        ensure!(prep.status.success(), "user unit-file preparation failed: {}", String::from_utf8_lossy(&prep.stderr));
        let prep = guest.shell("systemctl start user@1000.service").await.context("PREPARE start real user@1000 manager")?;
        ensure!(prep.status.success(), "user manager start failed: {}", String::from_utf8_lossy(&prep.stderr));
        let prep = guest.shell("sudo -H -n -u mcp -- /usr/bin/env XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/systemctl --user daemon-reload").await.context("PREPARE reload real mcp user manager")?;
        ensure!(prep.status.success(), "user manager reload failed: {}", String::from_utf8_lossy(&prep.stderr));
        let prep = guest.shell("sudo -H -n -u mcp -- /usr/bin/env XDG_RUNTIME_DIR=/run/user/1000 /usr/bin/systemctl --user start estus-fixture.service").await.context("PREPARE start real mcp user unit")?;
        ensure!(prep.status.success(), "real user-manager unit start failed: {}", String::from_utf8_lossy(&prep.stderr));
        let user_binding = guest.binding("observe_systemd_units", json!({"manager_scope":"user"})).await.context("IMPORT user-scope inventory binding")?;
        let user = user_binding.call(json!({"view":"loaded","unit_type":"service","state":"active","unit_pattern":"estus-fixture*"})).await.context("FOURTH user-manager inventory execution")?;
        let user = catalog::projection(&user).context("FOURTH user-manager inventory projection")?;
        ensure!(user["scope"] == "user" && user["units"].as_array().context("user units")?.iter().any(|u| u["unit"] == "estus-fixture.service" && u["active"] == "active"), "user manager was replaced by system manager inventory");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
