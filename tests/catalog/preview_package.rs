use crate::catalog;
use anyhow::{Context, Result, ensure};
use serde_json::json;

/// The single package the signed local apt fixture installs at version 1.0.
const PACKAGE: &str = "estus-catalog-base";

/// Enable one package preview through the site's own reviewed-enable flow. The
/// recipe names the canonical tool and authority; the guest site then states the
/// package allowlist as `constraints.allowed_packages`, exactly as an operator
/// restates a unit or interface allowlist. A policy-required template is only
/// materialised once the site states that policy.
fn enable(base: &std::path::Path, tool: &str) -> Result<catalog::Binding> {
    let recipe = format!("tool = \"{tool}\"\nauthority = \"automation:catalog\"\n");
    let binding = catalog::Binding::enable_workflow(base, &recipe)?;
    let mut site: toml::Value = toml::from_str(&std::fs::read_to_string(&binding.config)?)?;
    let mut policy = toml::Table::new();
    policy.insert(
        "constraints".into(),
        toml::Value::try_from(json!({"allowed_packages": [PACKAGE]}))?,
    );
    let catalog_root = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    site.as_table_mut().context("guest site table")?.insert(
        "catalog".into(),
        toml::Value::try_from(json!({"root": catalog_root}))?,
    );
    site.as_table_mut()
        .context("guest site table")?
        .entry("tools")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .context("guest tools table")?
        .insert(tool.to_owned(), toml::Value::Table(policy));
    std::fs::write(&binding.config, toml::to_string(&site)?)?;
    Ok(binding)
}

/// Real installed state plus the guest's apt sources, read directly over the
/// fixture's control identity. Every source must be the local signed repository.
async fn package_state(guest: &catalog::Guest, tool: &str) -> Result<String> {
    let state = guest
        .shell(&format!(
            "set -eu; test ! -e /var/lib/apt/periodic/update-success-stamp; \
             cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list; \
             /usr/bin/dpkg-query -W -f='${{Status}} ${{Version}}\\n' {PACKAGE}"
        ))
        .await?;
    ensure!(
        state.status.success(),
        "{tool} state/source oracle failed: {}",
        String::from_utf8_lossy(&state.stderr)
    );
    let text = String::from_utf8(state.stdout)?;
    ensure!(
        text.lines()
            .filter(|line| line.starts_with("deb "))
            .all(|line| line.starts_with(
                "deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-"
            )),
        "{tool} reached a nonlocal or unreviewed apt source: {text}"
    );
    ensure!(
        text.lines().any(|line| line == "install ok installed 1.0"),
        "{tool} fixture package lost its genuine installed version/state: {text}"
    );
    Ok(text)
}

/// A real check-mode package module over the normal Estus path must not be
/// refused for an internal argument the caller never supplied. Both the generic
/// router (`ansible.builtin.package`) and the explicit apt module
/// (`ansible.builtin.apt`) preview the same real, already-satisfied package and
/// must leave the guest's installed state untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM, ESTUS_TEST_ANSIBLE_BUNDLE; disposable Linux EFI guest with signed apt fixture"]
async fn preview_package() -> Result<()> {
    let guest = catalog::Guest::start_packages().await?;
    let result: Result<()> = async {
        for tool in ["preview_package", "preview_apt"] {
            let binding = enable(&guest.config, tool)?;
            binding.inspect_workflow_list().await?;
            // The site allowlist and the reviewed schema both refuse before
            // opening SSH: no other package, and no unreviewed module option.
            binding
                .reject(json!({"name":["other-package"],"state":"present"}))
                .await?;
            binding
                .reject(json!({"name":[PACKAGE],"state":"present","force":true}))
                .await?;
            let before = package_state(&guest, tool).await?;
            let reply = binding
                .call(json!({"name":[PACKAGE],"state":"present"}))
                .await?;
            let value = catalog::projection(&reply)?;
            ensure!(
                value["changed"] == false,
                "{tool} reported a change for an already-installed package: {reply}"
            );
            let after = package_state(&guest, tool).await?;
            ensure!(
                before == after,
                "{tool} changed real installed package state:\nbefore: {before}\nafter: {after}"
            );
        }
        Ok(())
    }
    .await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
