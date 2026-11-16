use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM"]
async fn kernel_module_parameter_set() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let binding = guest.binding("kernel_module_parameter_set", json!({})).await?;
        for invalid in [json!({"name":"dummy","parameter":"numdummies","value":1}),json!({"name":"estus_catalog","parameter":"value","value":1025}),json!({"name":"estus_catalog","parameter":"../value","value":9})] {
            binding.reject(invalid).await?;
        }
        let before = guest.shell("cat /sys/module/estus_catalog/parameters/value").await?;
        ensure!(before.status.success() && String::from_utf8(before.stdout)?.trim() == "7", "positive compatible parameter fixture absent");
        let envelope = binding.call(json!({"name":"estus_catalog","parameter":"value","value":9})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["outcome"] == "verified" && p["previous_value"] == "7" && p["observed_value"] == "9" && p["postcondition_verified"] == true, "parameter write/readback not verified");
        ensure!(envelope["data"]["changed"] == true, "actual parameter mutation not reported");
        let after = guest.shell("cat /sys/module/estus_catalog/parameters/value").await?;
        ensure!(after.status.success() && String::from_utf8(after.stdout)?.trim() == "9", "positive real sysfs effect absent");
        let repeated = binding.call(json!({"name":"estus_catalog","parameter":"value","value":9})).await?;
        let p = catalog::projection(&repeated)?;
        ensure!(p["outcome"] == "verified" && p["previous_value"] == "9"
            && p["observed_value"] == "9" && p["postcondition_verified"] == true
            && repeated["data"]["changed"] == true,
            "same-value parameter write was silently converted into a no-op: {repeated}");
        let repeated_state = guest.shell("cat /sys/module/estus_catalog/parameters/value").await?;
        ensure!(repeated_state.status.success() && String::from_utf8(repeated_state.stdout)?.trim() == "9",
            "independent same-value write readback disagrees");
        let remove = guest.shell("set -eu; /usr/bin/modprobe --remove estus_catalog; test ! -d /sys/module/estus_catalog; test ! -e /sys/module/estus_catalog/parameters/value").await?;
        ensure!(remove.status.success(), "parameter capability was not independently proven absent before no-write call");
        let envelope = binding.call(json!({"name":"estus_catalog","parameter":"value","value":10})).await?;
        let p = catalog::projection(&envelope)?;
        ensure!(p["outcome"] == "unsupported" && p["postcondition_verified"] == false, "absent parameter not explicitly unsupported");
        ensure!(envelope["data"]["changed"] == false, "unsupported no-write branch falsely reported a change");
        let absent = guest.shell("test ! -d /sys/module/estus_catalog && test ! -e /sys/module/estus_catalog/parameters/value").await?;
        ensure!(absent.status.success(), "unsupported parameter setter mutated module state");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
