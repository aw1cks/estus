//! Concrete EFI guest and installed-role acceptance; never a fallback SSH backend.
use crate::support::{self, Client, WireServer};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

pub struct Guest {
    child: Child,
    root: TempDir,
    pub config: PathBuf,
    control: PathBuf,
    ssh: PathBuf,
}

impl Guest {
    pub async fn start() -> Result<Self> {
        Self::launch("ESTUS_TEST_CATALOG_VM").await
    }

    pub async fn start_lab() -> Result<Self> {
        Self::launch("ESTUS_TEST_CATALOG_LAB_VM").await
    }

    async fn launch(variable: &str) -> Result<Self> {
        let runner = std::env::var_os(variable)
            .with_context(|| format!("set {variable} to the Nix-built catalog guest executable"))?;
        let runner = support::executable(Path::new(&runner))?;
        let root = tempfile::Builder::new()
            .prefix("estus-catalog-")
            .tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let keys = root.path().join("keys");
        let temporary = root.path().join("tmp");
        fs::create_dir(&keys)?;
        fs::create_dir(&temporary)?;
        let keygen = support::find_program("ssh-keygen")?;
        for name in ["mcp", "mcp-admin", "root", "host"] {
            let path = root.path().join(name);
            let output = support::run(
                Command::new(&keygen)
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(&path),
            )
            .await?;
            ensure!(
                output.status.success(),
                "private guest key generation failed"
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            fs::copy(path.with_extension("pub"), keys.join(format!("{name}.pub")))?;
            if name == "host" {
                fs::copy(&path, keys.join("host"))?;
            }
        }
        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let known = root.path().join("known_hosts");
        fs::write(
            &known,
            format!(
                "[127.0.0.1]:{port} {}",
                fs::read_to_string(root.path().join("host.pub"))?
            ),
        )?;
        let settings = format!(
            "  HostName 127.0.0.1\n  Port {port}\n  BatchMode yes\n  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile {}\n  GlobalKnownHostsFile /dev/null\n  ConnectTimeout 2\n  ConnectionAttempts 1\n  LogLevel ERROR\n",
            ssh_path(&known)?
        );
        for (file, alias, user) in [
            ("ssh_config", "plain", "mcp"),
            ("authority_ssh_config", "catalog-admin", "mcp-admin"),
            ("control_ssh_config", "control", "root"),
        ] {
            fs::write(
                root.path().join(file),
                format!(
                    "Host {alias}\n{settings}  User {user}\n  IdentityFile {}\n",
                    ssh_path(&root.path().join(user))?
                ),
            )?;
        }
        let ssh = support::find_program("ssh")?;
        let config = root.path().join("server.toml");
        let value = json!({"mode":"headless","capabilities":{"named":true},"ssh":{"config_file":root.path().join("ssh_config"),"executable":ssh},"targets":{"plain":{"ssh_host":"plain"}},"automation":{"authorities":{"catalog":{"ssh_config_file":root.path().join("authority_ssh_config"),"become":{"method":"sudo","user":"root"},"targets":{"plain":{"destination":"catalog-admin","python":"/usr/bin/python3"}}}}}});
        fs::write(&config, toml::to_string(&toml::Value::try_from(value)?)?)?;
        let log = fs::File::create(root.path().join("console.log"))?;
        let child = Command::new(runner)
            .current_dir(root.path())
            .env_clear()
            .env("HOME", root.path())
            .env("TMPDIR", &temporary)
            .env("USE_TMPDIR", "1")
            .env("NIX_DISK_IMAGE", root.path().join("disk.qcow2"))
            .env("NIX_EFI_VARS", root.path().join("efi.fd"))
            .env("ESTUS_CATALOG_KEYS", &keys)
            .env("ESTUS_CATALOG_PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .kill_on_drop(true)
            .spawn()?;
        let mut guest = Self {
            child,
            config,
            control: root.path().join("control_ssh_config"),
            ssh,
            root,
        };
        let ready = guest.ready().await;
        if let Err(error) = ready {
            let log = fs::read_to_string(guest.root.path().join("console.log")).unwrap_or_default();
            let cleanup = guest.stop().await;
            cleanup?;
            return Err(error.context(format!("guest console: {log}")));
        }
        Ok(guest)
    }

    pub async fn start_packages() -> Result<Self> {
        let guest = Self::start().await?;
        let result: Result<()> = async {
            let initial = guest.shell("test -s /usr/share/keyrings/estus-catalog.gpg && test -s /opt/estus-catalog/repo-a/InRelease && /usr/bin/dpkg-query -W -f='${Status} ${Version}\\n' estus-catalog-base").await?;
            ensure!(initial.status.success() && initial.stdout == b"install ok installed 1.0\n", "signed apt fixture lacks its genuine initialized package state");
            Ok(())
        }.await;
        if let Err(error) = result {
            guest.stop().await?;
            return Err(error);
        }
        Ok(guest)
    }

    async fn ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            ensure!(
                self.child.try_wait()?.is_none(),
                "catalog guest exited before readiness"
            );
            if let Ok(output) = self.shell("test -e /sys/module/estus_catalog/parameters/value && systemctl is-active --quiet estus-fixture.service").await
                && output.status.success() { return Ok(()); }
            ensure!(
                Instant::now() < deadline,
                "catalog guest did not become SSH/systemd ready within 180 seconds"
            );
            sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn shell(&self, script: &str) -> Result<Output> {
        support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(&self.control)
                .args(["--", "control", script]),
        )
        .await
    }

    pub async fn ordinary(&self, script: &str) -> Result<Output> {
        support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(self.root.path().join("ssh_config"))
                .args(["--", "plain", script]),
        )
        .await
    }

    pub async fn administrative(&self, script: &str) -> Result<Output> {
        support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(self.root.path().join("authority_ssh_config"))
                .args(["--", "catalog-admin", script]),
        )
        .await
    }

    pub async fn wait_for_reboot(&self, previous_boot_id: &str) -> Result<String> {
        ensure!(
            canonical_uuid(previous_boot_id),
            "invalid previous boot identity"
        );
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(output) = self.shell("cat /proc/sys/kernel/random/boot_id").await
                && output.status.success()
            {
                let id = String::from_utf8(output.stdout)?.trim().to_owned();
                ensure!(canonical_uuid(&id), "noncanonical reboot identity");
                if id != previous_boot_id {
                    return Ok(id);
                }
            }
            ensure!(
                Instant::now() < deadline,
                "no independently confirmed new boot within 120 seconds"
            );
            sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn binding(&self, name: &str, overrides: Value) -> Result<Binding> {
        Binding::install(&self.config, name, overrides).await
    }

    pub async fn stop(mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            timeout(Duration::from_secs(10), self.child.kill())
                .await
                .context("QEMU kill/reap deadline")??;
        } else {
            self.child.wait().await?;
        }
        self.root.close()?;
        Ok(())
    }
}

fn canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn ssh_path(path: &Path) -> Result<String> {
    let path = path.to_str().context("non-UTF8 guest path")?;
    ensure!(
        !path.contains(['\n', '\r', '\0', '"', '\\']),
        "unsupported SSH config path"
    );
    Ok(format!("\"{path}\""))
}

pub struct Binding {
    root: TempDir,
    pub config: PathBuf,
    pub workspace: PathBuf,
    name: String,
    timeout_secs: u64,
}

impl Binding {
    /// A broken explicitly selected runtime must fail authoring, not fall back.
    pub async fn reject_workflow_runtime(&self) -> Result<()> {
        let mut site: toml::Value =
            toml::from_str(&fs::read_to_string(self.root.path().join("site.toml"))?)?;
        site["automation"]["runtime"] = self
            .root
            .path()
            .join("missing-runtime")
            .to_str()
            .context("runtime path")?
            .into();
        let site_path = self.root.path().join("invalid-site.toml");
        fs::write(&site_path, toml::to_string(&site)?)?;
        let output_path = self.root.path().join("invalid-prepared");
        let mut command = workflow_command()?;
        command
            .arg("prepare")
            .arg("--site")
            .arg(site_path)
            .arg("--definitions")
            .arg(self.root.path().join("export/tools.toml"))
            .args(["--target", "plain"])
            .arg("--output")
            .arg(&output_path);
        let output = support::run(&mut command).await?;
        ensure!(
            output.status.code() == Some(2) && output.stdout.is_empty() && !output_path.exists(),
            "invalid selected site runtime fell back or retained partial preparation"
        );
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "runtime_unavailable" && diagnostic["phase"] == "runtime_import",
            "setup failure must identify runtime provisioning/import repair: {diagnostic}"
        );
        Ok(())
    }

    /// Exercise offline export, explicit site-policy review, prepare, and inspect.
    /// Recipes select canonical definitions; they never carry approval snapshots.
    pub async fn prepare_workflow(base: &Path, recipe: &str) -> Result<Self> {
        let recipe: toml::Value = toml::from_str(recipe)?;
        let name = recipe["tool"].as_str().context("workflow tool")?;
        let root = tempfile::Builder::new()
            .prefix("estus-workflow-")
            .tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let export = root.path().join("export");
        let mut command = workflow_command()?;
        command
            .args(["export", "--tool", name, "--output"])
            .arg(&export);
        workflow_output(&mut command).await?;
        let definitions = export.join("tools.toml");
        let mut document: toml::Value = toml::from_str(&fs::read_to_string(&definitions)?)?;
        let tool = &mut document["tools"][name];
        if let Some(units) = recipe.get("allowed_units") {
            ensure!(
                !units.as_array().context("reviewed units")?.is_empty(),
                "empty unit policy"
            );
            let constraints = tool
                .as_table_mut()
                .context("tool table")?
                .entry("constraints")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .context("constraints table")?;
            constraints.insert("allowed_units".into(), units.clone());
        }
        let timeout_secs = tool["limits"]["timeout_secs"]
            .as_integer()
            .context("workflow timeout")? as u64;
        let authority = recipe["authority"]
            .as_str()
            .context("reviewed workflow authority")?
            .to_owned();
        ensure!(
            tool["authority"].as_str() == Some(authority.as_str()),
            "canonical authority changed; workflow requires explicit review"
        );
        fs::write(&definitions, toml::to_string(&document)?)?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let mut site: toml::Value = toml::from_str(&fs::read_to_string(base)?)?;
        site["mode"] = "headless".into();
        site["capabilities"] = toml::Value::try_from(json!({"named":true}))?;
        site.as_table_mut().context("site")?.insert(
            "enabled_tools".into(),
            toml::Value::try_from(json!([name]))?,
        );
        site["automation"]
            .as_table_mut()
            .context("automation")?
            .insert(
                "runtime".into(),
                std::env::var("ESTUS_TEST_ANSIBLE_RUNTIME")
                    .context("set ESTUS_TEST_ANSIBLE_RUNTIME to pinned installed runtime")?
                    .into(),
            );
        site["automation"]
            .as_table_mut()
            .context("automation")?
            .insert(
                "workspace_root".into(),
                workspace.to_str().context("workspace UTF8")?.into(),
            );
        site["automation"]
            .as_table_mut()
            .context("automation")?
            .insert(
                "targets".into(),
                toml::Value::try_from(
                    json!({"plain":{"destination":"plain","python":"/usr/bin/python3"}}),
                )?,
            );
        let site_path = root.path().join("site.toml");
        fs::write(&site_path, toml::to_string(&site)?)?;
        let prepared = root.path().join("prepared");
        let mut command = workflow_command()?;
        command
            .arg("prepare")
            .arg("--site")
            .arg(&site_path)
            .arg("--definitions")
            .arg(&definitions)
            .args(["--target", "plain"])
            .arg("--output")
            .arg(&prepared);
        let report = workflow_output(&mut command).await?;
        ensure!(
            report["prepared"] == 1 && report["activated"] == false,
            "prepare did not explicitly approve one tool: {report}"
        );
        let config = prepared.join("estus.toml");
        let mut command = workflow_command()?;
        command.arg("inspect").arg("--site").arg(&config);
        let inspected = workflow_output(&mut command).await?;
        ensure!(
            inspected["global_native_execution"] == false
                && inspected["global_native_file_read"] == false
                && inspected["global_native_file_write"] == false,
            "workflow exposed native escape: {inspected}"
        );
        let tools = inspected["tools"].as_array().context("inspected tools")?;
        ensure!(
            tools.len() == 1
                && tools[0]["name"] == name
                && tools[0]["enabled"] == true
                && tools[0]["authority"] == authority
                && tools[0]["execution_location"] == "controller_and_remote"
                && tools[0]["targets"] == json!([{"name":"plain","permitted":true}]),
            "unexpected workflow authority/exposure: {inspected}"
        );
        let snapshot: Value = serde_json::from_slice(&fs::read(
            prepared.join("snapshots").join(format!("{name}.json")),
        )?)?;
        ensure!(
            snapshot["schema"] == 2,
            "prepare omitted real reviewed approval"
        );
        Ok(Self {
            root,
            config,
            workspace,
            name: name.into(),
            timeout_secs,
        })
    }

    pub async fn inspect_workflow_list(&self) -> Result<()> {
        let mut server = WireServer::start(&self.config)?;
        let result: Result<()> = async {
            server.initialize().await?;
            let reply = server.request(2, "tools/list", json!({})).await?;
            let tools = reply["result"]["tools"]
                .as_array()
                .context("workflow tools/list")?;
            // These two non-executing protocol tools are always present in
            // actions-only; neither grants generic shell or file access.
            ensure!(
                tools.len() == 4
                    && tools.iter().all(|tool| tool["name"] == self.name
                        || tool["name"] == "clear_target_quarantine"
                        || tool["name"] == "ssh_targets"
                        || tool["name"] == "ssh_read_output"),
                "workflow tools/list escape: {reply}"
            );
            let published = tools
                .iter()
                .find(|tool| tool["name"] == self.name)
                .context("selected workflow publication")?;
            let config: toml::Value = toml::from_str(&fs::read_to_string(&self.config)?)?;
            ensure!(
                published["_meta"]["authority"].as_str()
                    == config["tools"][self.name.as_str()]["authority"].as_str()
                    && published["_meta"]["execution_location"] == "controller_and_remote",
                "workflow discovery authority/location differs from review: {published}"
            );
            Ok(())
        }
        .await;
        server.stop(None).await?;
        result
    }

    pub async fn install(base: &Path, name: &str, overrides: Value) -> Result<Self> {
        ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
            "invalid catalog name"
        );
        let root = tempfile::Builder::new()
            .prefix("estus-catalog-binding-")
            .tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        let export = root.path().join("export");
        let mut command = workflow_command()?;
        command
            .args(["export", "--tool", name, "--output"])
            .arg(&export);
        workflow_output(&mut command).await?;
        let definitions = export.join("tools.toml");
        let mut document: toml::Value = toml::from_str(&fs::read_to_string(&definitions)?)?;
        let tool = document["tools"][name]
            .as_table_mut()
            .context("shipped catalog binding")?;
        let fixed = tool
            .get_mut("fixed_args")
            .and_then(toml::Value::as_table_mut)
            .context("catalog fixed args")?;
        for (key, value) in overrides
            .as_object()
            .context("operator fixed-argument overrides must be object")?
        {
            ensure!(
                fixed.contains_key(key),
                "override must name an existing reviewed fixed argument"
            );
            fixed.insert(key.clone(), toml::Value::try_from(value)?);
        }
        let native = tool["execution"]["kind"].as_str() == Some("native_payload");
        let timeout_secs = tool
            .get("limits")
            .and_then(|value| value.get("timeout_secs"))
            .and_then(toml::Value::as_integer)
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(20);
        fs::write(&definitions, toml::to_string(&document)?)?;
        let mut site: toml::Table = toml::from_str(&fs::read_to_string(base)?)?;
        site.insert("mode".into(), "headless".into());
        site.insert(
            "capabilities".into(),
            toml::Value::try_from(json!({"named":true}))?,
        );
        site.insert(
            "enabled_tools".into(),
            toml::Value::try_from(json!([name]))?,
        );
        let automation = site
            .entry("automation")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .context("automation base")?;
        if !native {
            automation.insert(
                "runtime".into(),
                std::env::var("ESTUS_TEST_ANSIBLE_RUNTIME")
                    .context("set ESTUS_TEST_ANSIBLE_RUNTIME to pinned installed runtime")?
                    .into(),
            );
            automation.insert(
                "workspace_root".into(),
                workspace.to_str().context("workspace UTF8")?.into(),
            );
        }
        automation.insert(
            "targets".into(),
            toml::Value::try_from(
                json!({"plain":{"destination":"plain","python":"/usr/bin/python3"}}),
            )?,
        );
        let site_path = root.path().join("site.toml");
        fs::write(&site_path, toml::to_string(&site)?)?;
        let prepared = root.path().join("prepared");
        let mut command = workflow_command()?;
        command
            .arg("prepare")
            .arg("--site")
            .arg(site_path)
            .arg("--definitions")
            .arg(definitions)
            .args(["--target", "plain"])
            .arg("--output")
            .arg(&prepared);
        workflow_output(&mut command).await?;
        Ok(Self {
            root,
            config: prepared.join("estus.toml"),
            workspace,
            name: name.into(),
            timeout_secs,
        })
    }

    pub async fn call(&self, inputs: Value) -> Result<Value> {
        let client = Client::start(&self.config).await?;
        let result = client
            .call(
                &self.name,
                json!({"host":"plain","inputs":inputs,"timeout_secs":self.timeout_secs}),
            )
            .await;
        let cleanup = client.stop().await;
        cleanup?;
        ensure!(
            fs::read_dir(&self.workspace)?.next().is_none(),
            "catalog workspace survived completed call"
        );
        result
    }

    pub async fn reject(&self, inputs: Value) -> Result<()> {
        let mut server = WireServer::start(&self.config)?;
        let result: Result<()> = async {
            server.initialize().await?;
            let response = server
                .request(
                    2,
                    "tools/call",
                    json!({"name":self.name,"arguments":{"host":"plain","inputs":inputs}}),
                )
                .await?;
            let error = &response["result"]["structuredContent"]["error"];
            ensure!(
                response["error"]["code"] == -32602
                    || (matches!(
                        error["code"].as_str(),
                        Some("invalid_argument" | "policy_denied")
                    ) && error["remote_state_unknown"] == false),
                "invalid catalog input reached execution: {response}"
            );
            Ok(())
        }
        .await;
        let log = server.stop(None).await?;
        ensure!(
            !log.text().contains("\"master_start\""),
            "rejected catalog input started SSH"
        );
        ensure!(
            fs::read_dir(&self.workspace)?.next().is_none(),
            "rejected catalog input created scratch"
        );
        result
    }
}

/// Deliberately no global --config: catalog export is an offline operation.
fn workflow_command() -> Result<Command> {
    let binary = std::env::var_os("ESTUS_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(option_env!("ESTUS_TEST_BINARY").unwrap_or(env!("CARGO_BIN_EXE_estus")))
        });
    let mut command = Command::new(support::executable(&binary)?);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ESTUS_") {
            command.env_remove(name);
        }
    }
    let assets = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    command
        .arg("catalog")
        .arg("--root")
        .arg(assets)
        .kill_on_drop(true);
    Ok(command)
}

async fn workflow_output(command: &mut Command) -> Result<Value> {
    let output = support::run_authoring(command).await?;
    ensure!(
        output.status.success(),
        "workflow public CLI failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).context("workflow CLI JSON")
}

pub fn projection(envelope: &Value) -> Result<&Value> {
    ensure!(
        envelope["error"].is_null()
            && envelope["data"]["status"] == "successful"
            && envelope["data"]["complete"] == true
            && matches!(
                envelope["data"]["owned_group_cleanup"].as_str(),
                Some("signalled_and_reaped" | "not_applicable")
            ),
        "catalog execution is not confirmed complete: {envelope}"
    );
    ensure!(
        envelope["data"]["projection"]["status"] == "complete",
        "catalog projection unavailable: {envelope}"
    );
    Ok(&envelope["data"]["projection"]["value"])
}
