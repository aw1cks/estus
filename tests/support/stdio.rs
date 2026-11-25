//! Shared stdio-assertion protocol client: the spawned `estus` server, framed
//! JSON-RPC over stdin/stdout, and the helpers shared by the split suites.
use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use nix::sys::signal::Signal;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use serde_json::Value;
use serde_json::json;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::process::Child;
use tokio::process::ChildStdin;
use tokio::process::ChildStdout;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The executable under test: the installed server in acceptance runs, the
/// freshly built one otherwise.
pub fn binary() -> std::ffi::OsString {
    std::env::var_os("ESTUS_TEST_BINARY").unwrap_or_else(|| {
        option_env!("ESTUS_TEST_BINARY")
            .unwrap_or(env!("CARGO_BIN_EXE_estus"))
            .into()
    })
}

/// The catalog the tested server actually ships. A harness that installed the
/// server elsewhere (the wheel keeps it at `site-packages/estus/_catalog`) names
/// it with `ESTUS_TEST_CATALOG`; an installed package otherwise keeps it at
/// `../share/estus/catalog` beside the executable (the server's own default
/// discovery); a source build falls back to the checkout.
pub fn bundled_catalog_json() -> std::path::PathBuf {
    if let Some(directory) = std::env::var_os("ESTUS_TEST_CATALOG") {
        return std::path::PathBuf::from(directory).join("catalog.json");
    }
    std::path::Path::new(&binary())
        .parent()
        .map(|bin| bin.join("../share/estus/catalog/catalog.json"))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog/catalog.json")
        })
}

pub fn command(args: &[&str]) -> Command {
    let mut command = Command::new(binary());
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("ESTUS_") {
            command.env_remove(name);
        }
    }
    command.args(args).kill_on_drop(true);
    command
}

pub struct Server {
    pub child: Child,
    pub input: Option<ChildStdin>,
    pub output: BufReader<ChildStdout>,
    pub stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl Server {
    pub fn start(args: &[&str]) -> Result<Self> {
        Self::from_command(command(args))
    }

    pub fn from_command(mut command: Command) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().context("child stdin")?;
        let output = child.stdout.take().context("child stdout")?;
        let mut error = child.stderr.take().context("child stderr")?;
        let stderr = tokio::spawn(async move {
            let mut bytes = Vec::new();
            error.read_to_end(&mut bytes).await?;
            Ok(bytes)
        });
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            stderr: Some(stderr),
        })
    }

    pub async fn send(&mut self, value: Value) -> Result<()> {
        let input = self.input.as_mut().context("stdin already closed")?;
        input.write_all(&serde_json::to_vec(&value)?).await?;
        input.write_all(b"\n").await?;
        input.flush().await?;
        Ok(())
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let input = self.input.as_mut().context("stdin already closed")?;
        input.write_all(bytes).await?;
        input.flush().await?;
        Ok(())
    }

    pub async fn frame(&mut self) -> Result<Option<(Value, usize)>> {
        let mut line = Vec::new();
        let size = timeout(Duration::from_secs(5), async {
            (&mut self.output)
                .take(16_777_217)
                .read_until(b'\n', &mut line)
                .await
        })
        .await??;
        if size == 0 {
            return Ok(None);
        }
        ensure!(size <= 16_777_216, "response exceeds 16 MiB: {size} bytes");
        ensure!(line.last() == Some(&b'\n'), "unterminated response");
        let value: Value = serde_json::from_slice(&line).context("non-JSON stdout")?;
        ensure!(value["jsonrpc"] == "2.0", "non-JSON-RPC stdout");
        Ok(Some((value, size)))
    }

    pub async fn response(&mut self, id: u64) -> Result<Value> {
        Ok(self.response_with_id(&json!(id)).await?.0)
    }

    pub async fn response_with_id(&mut self, id: &Value) -> Result<(Value, usize)> {
        loop {
            let (value, size) = self
                .frame()
                .await?
                .context("server closed stdout before response")?;
            if value.get("id") == Some(id) {
                ensure!(
                    value.get("result").is_some() ^ value.get("error").is_some(),
                    "correlated frame is not a JSON-RPC response"
                );
                return Ok((value, size));
            }
            ensure!(
                value.get("id").is_none() && value["method"].is_string(),
                "unexpected response ID or non-notification frame"
            );
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        self.send(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "stdio-acceptance", "version": "1"}
            }
        }))
        .await?;
        let initialized = self.response(1).await?;
        ensure!(initialized["result"]["protocolVersion"] == "2025-11-25");
        ensure!(
            initialized["result"]["serverInfo"]["name"] == "estus",
            "server identifies itself as {}, not estus",
            initialized["result"]["serverInfo"]["name"]
        );
        ensure!(initialized["result"]["capabilities"]["tools"].is_object());
        ensure!(initialized["result"]["capabilities"]["prompts"].is_object());
        ensure!(initialized["result"]["capabilities"]["resources"].is_object());
        ensure!(initialized["result"]["instructions"].is_string());
        for unsupported in ["tasks", "logging"] {
            ensure!(
                initialized["result"]["capabilities"]
                    .get(unsupported)
                    .is_none()
            );
        }
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await
    }

    pub async fn close_stderr(&mut self) -> Result<()> {
        if let Some(stderr) = self.stderr.take() {
            stderr.abort();
            match stderr.await {
                Err(error) if error.is_cancelled() => {}
                Ok(result) => {
                    result?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    pub async fn sigterm(&mut self) -> Result<()> {
        kill(
            Pid::from_raw(i32::try_from(self.child.id().context("live server PID")?)?),
            Signal::SIGTERM,
        )?;
        // Keep stdin open: EOF must not mask the signal lifecycle.
        let status = timeout(Duration::from_secs(5), self.child.wait())
            .await
            .context("SIGTERM did not stop the server")??;
        ensure!(status.success(), "SIGTERM exit status: {status}");
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(std::process::ExitStatus, Vec<u8>)> {
        drop(self.input.take());
        let status = match timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                self.child.kill().await?;
                bail!("server failed to exit after EOF");
            }
        };
        while let Some((frame, _)) = self.frame().await? {
            ensure!(
                frame.get("id").is_none() && frame["method"].is_string(),
                "uncorrelated response remained at EOF"
            );
        }
        let stderr = match self.stderr {
            Some(mut stderr) => match timeout(Duration::from_secs(5), &mut stderr).await {
                Ok(result) => result??,
                Err(_) => {
                    stderr.abort();
                    let _ = stderr.await;
                    bail!("stderr did not reach EOF after server exit");
                }
            },
            None => Vec::new(),
        };
        Ok((status, stderr))
    }
}

// Assert the public discovery envelope, not incidental default policy values.
pub fn discovery_data<'a>(result: &'a Value, mode: &str) -> Result<&'a Value> {
    ensure!(result["isError"] != true, "discovery returned a tool error");
    let structured = &result["structuredContent"];
    ensure!(structured.get("error") == Some(&Value::Null));
    let data = &structured["data"];
    ensure!(data["mode"] == mode);
    ensure!(data["targets"].is_array());
    let limits = &data["limits"];
    for field in [
        "connect_timeout_secs",
        "operation_timeout_secs",
        "max_timeout_secs",
        "max_output_bytes",
        "max_file_bytes",
        "max_stdin_bytes",
        "max_command_bytes",
        "max_encoded_command_bytes",
        "max_response_bytes",
        "max_directory_page_bytes",
    ] {
        ensure!(
            limits[field].as_u64().is_some(),
            "missing numeric limit {field}"
        );
    }
    ensure!(limits["max_stdin_bytes"] == limits["max_file_bytes"]);
    ensure!(limits["max_command_bytes"] == 65_536);
    ensure!(limits["max_encoded_command_bytes"] == 65_536);
    ensure!(limits["max_response_bytes"] == 16_777_216);
    ensure!(limits["max_directory_page_bytes"] == 1_048_576);
    let content = result["content"]
        .as_array()
        .context("discovery text content")?;
    ensure!(content.len() == 1);
    ensure!(content[0]["type"] == "text");
    let text: Value = serde_json::from_str(content[0]["text"].as_str().context("discovery text")?)?;
    ensure!(text == *structured, "discovery text/structured mismatch");
    Ok(data)
}

pub const MODERN_VERSION: &str = "2026-07-28";

pub fn modern_request(id: Value, method: &str, mut params: Value, version: &str) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name":"stdio-acceptance","version":"1"},
    });
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

pub fn server_with_config(text: &str) -> Result<(Server, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("operator.toml");
    // A regression must fail without ever consulting the developer's SSH authority.
    std::fs::write(&path, text)?;
    let server = Server::start(&["--config", path.to_str().context("config path")?])?;
    Ok((server, directory))
}

pub fn no_remote_dispatch(stderr: &[u8]) -> Result<()> {
    ensure!(
        stderr.is_empty() || stderr.last() == Some(&b'\n'),
        "incomplete final audit"
    );
    for line in stderr.split_inclusive(|&byte| byte == b'\n') {
        let record: Value = serde_json::from_slice(line)?;
        ensure!(
            record["event"] != "master_start",
            "protocol rejection launched SSH"
        );
        ensure!(
            record["tool"] != "exec_command",
            "protocol rejection reached remote handler"
        );
    }
    Ok(())
}

// Every payload is valid for its route: a JSON-RPC rejection therefore proves
// omission, rather than accidentally testing argument deserialization.
pub fn profile_call_arguments(tool: &str, host: &str) -> Value {
    match tool {
        "exec_command" => json!({"host":host,"command":"true"}),
        "exec_argv" => json!({"host":host,"argv":["/usr/bin/true"]}),
        "exec_sudo" => json!({"host":host,"argv":["/usr/bin/true"]}),
        "change_rename" => {
            json!({"host":host,"source":"/private/profile-payload-source","destination":"/private/profile-payload-destination","overwrite":true})
        }
        "change_file_replace" => {
            json!({"host":host,"path":"/private/profile-payload","content":"x","overwrite":true})
        }
        "change_file_write" => {
            json!({"host":host,"path":"/private/profile-payload","content":"PROFILE_PAYLOAD"})
        }
        "inspect_file"
        | "observe_stat"
        | "inspect_directory"
        | "change_mkdir"
        | "change_directory_remove"
        | "change_file_remove" => {
            json!({"host":host,"path":"/private/profile-payload"})
        }
        _ => panic!("unexpected profile test tool"),
    }
}

pub fn profile_policy_denied(response: &Value) -> Result<()> {
    ensure!(
        response.get("error").is_none(),
        "route was not registered: {response}"
    );
    let result = &response["result"];
    ensure!(result["isError"] == true, "{response}");
    let structured = &result["structuredContent"];
    ensure!(structured["data"].is_null());
    ensure!(structured["error"]["code"] == "policy_denied", "{response}");
    ensure!(structured["error"]["remote_state_unknown"] == false);
    let text: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .context("policy error text")?,
    )?;
    ensure!(text == *structured);
    let encoded = serde_json::to_string(response)?;
    for secret in [
        "profile-payload",
        "PROFILE_PAYLOAD",
        "private-backend",
        "private-identity",
        "read-only-files",
        "files-only",
        "actions-only",
    ] {
        ensure!(
            !encoded.contains(secret),
            "policy error leaked private input"
        );
    }
    Ok(())
}

pub const NAMED_TOOL_CONFIG: &str = indoc::indoc! {r#"
    capabilities = { named = true }
    [selection]
    allow = ["inspect_account", "change_account"]
    [ssh]
    config_file = "replacement.conf"
    [limits]
    connect_timeout_secs = 1
    operation_timeout_secs = 3
    max_timeout_secs = 5
    max_output_bytes = 4096
    [targets.base]
    ssh_host = "private-binding-backend.invalid"
    [targets.base.sudo]
    mode = "separate-identity"
    ssh_host = "private-binding-elevated.invalid"
    [targets.read]
    ssh_host = "private-binding-read.invalid"
    selection = { deny = ["inspect_account", "change_account"] }
    max_tier = "inspect"
    [targets.files]
    ssh_host = "private-binding-files.invalid"
    selection = { deny = ["inspect_account", "change_account"] }
    max_tier = "change"
    [targets.other]
    ssh_host = "private-binding-other.invalid"
    [tools.inspect_account]
    description = "Observe an approved account."
    revision = "review-1"
    targets = ["base", "read", "files"]
    authority = "ordinary"
    effects = ["read", "sensitive_read"]
    execution = { kind = "native_argv", program = "/private/binding-program", cwd = "/private/binding-cwd", argv = ["private-binding-fixed", "--", { input = "account" }, { input = "count" }, { input = "verbose" }] }
    input_schema = { type = "object", additionalProperties = false, required = ["account", "count", "verbose"], properties = { account = { type = "string", minLength = 1, maxLength = 16, enum = ["root", "operator"] }, count = { type = "integer", minimum = -2, maximum = 4 }, verbose = { type = "boolean" } } }
    result = { kind = "command" }
    limits = { timeout_secs = 2, max_output_bytes = 1024 }
    [tools.change_account]
    description = "Change an approved account."
    revision = "change-2"
    targets = ["base"]
    authority = "ordinary"
    effects = ["persistent_write"]
    execution = { kind = "native_argv", program = "/private/binding-program", argv = ["private-binding-fixed"] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
    [tools.disabled_account]
    description = "Not enabled."
    revision = "disabled-3"
    targets = ["base"]
    authority = "ordinary"
    effects = ["unknown"]
    execution = { kind = "native_argv", program = "/private/binding-disabled", argv = [] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
"#};

pub fn named_tools_server(config: &str) -> Result<(Server, tempfile::TempDir)> {
    let directory = tempfile::tempdir()?;
    let probe = directory.path().join("binding-must-not-probe");
    std::fs::write(
        directory.path().join("replacement.conf"),
        format!(
            "Host *\n  ProxyCommand false\nMatch exec \"touch '{}'\"\n  User nobody\n",
            probe.display()
        ),
    )?;
    let path = directory.path().join("operator.toml");
    std::fs::write(&path, config)?;
    let server = Server::start(&["--config", path.to_str().context("config path")?])?;
    Ok((server, directory))
}

pub fn binding_public_only(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    for private in [
        "private-binding",
        "/private/binding",
        "BINDING_INPUT_SECRET",
        "replacement.conf",
    ] {
        ensure!(!text.contains(private), "binding private content disclosed");
    }
    Ok(())
}

pub const FIXED_SUDO_TOOL_CONFIG: &str = indoc::indoc! {r#"
    capabilities = { named = true }
    [selection]
    allow = ["fixed_id", "fixed_printf"]
    [ssh]
    config_file = "replacement.conf"
    [limits]
    connect_timeout_secs = 1
    operation_timeout_secs = 3
    max_timeout_secs = 5
    max_output_bytes = 4096
    [targets.base]
    ssh_host = "private-binding-backend.invalid"
    [targets.base.sudo]
    mode = "separate-identity"
    ssh_host = "private-binding-elevated.invalid"
    users = ["root"]
    programs = ["/usr/bin/id", "/usr/bin/printf"]
    [targets.same]
    ssh_host = "private-binding-same.invalid"
    [targets.same.sudo]
    mode = "same-account"
    users = ["root"]
    programs = ["/usr/bin/id", "/usr/bin/printf"]
    [targets.read]
    ssh_host = "private-binding-read.invalid"
    selection = { deny = ["fixed_id", "fixed_printf"] }
    max_tier = "inspect"
    [targets.read.sudo]
    mode = "same-account"
    [targets.files]
    ssh_host = "private-binding-files.invalid"
    selection = { deny = ["fixed_id", "fixed_printf"] }
    max_tier = "change"
    [targets.files.sudo]
    mode = "same-account"
    [targets.other]
    ssh_host = "private-binding-other.invalid"
    [tools.fixed_id]
    description = "Observe the fixed privileged account."
    revision = "id-1"
    targets = ["base", "same", "read", "files"]
    authority = { sudo = "root" }
    effects = ["read"]
    execution = { kind = "native_argv", program = "/usr/bin/id", argv = ["-u"] }
    input_schema = { type = "object", additionalProperties = false, required = [], properties = {} }
    result = { kind = "command" }
    [tools.fixed_printf]
    description = "Perform the reviewed privileged operation."
    revision = "printf-1"
    targets = ["base", "same", "read", "files"]
    authority = { sudo = "root" }
    effects = ["persistent_write"]
    execution = { kind = "native_argv", program = "/usr/bin/printf", argv = ["--", "%s", { input = "value" }] }
    input_schema = { type = "object", additionalProperties = false, required = ["value"], properties = { value = { type = "string", maxLength = 64 } } }
    result = { kind = "command" }
"#};

// Every local capability prerequisite is real and owned by this fixture. In
// particular, a missing SSH config must never mask a controller compiler error.
pub struct ControllerProtocolFixture {
    pub directory: tempfile::TempDir,
    pub source: std::path::PathBuf,
    pub interpreter: std::path::PathBuf,
    pub root: std::path::PathBuf,
    pub config_path: std::path::PathBuf,
    pub config: String,
    pub hash: String,
}

impl ControllerProtocolFixture {
    pub fn new() -> Result<Self> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let source = directory.path().join("private-controller-source");
        let interpreter = directory.path().join("private-controller-interpreter");
        let root = directory.path().join("private-controller-workspace");
        let config_path = directory.path().join("private-controller-config.toml");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let shell = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join("sh"))
            .chain([std::path::PathBuf::from("/bin/sh")])
            .find(|path| path.is_file())
            .context("a POSIX sh interpreter is required")?;
        let shell = std::fs::canonicalize(shell)?;
        let quoted_shell = format!("'{}'", shell.to_string_lossy().replace('\'', "'\\''"));
        std::fs::write(
            &interpreter,
            format!("#!{}\nexec {quoted_shell} \"$@\"\n", shell.display()),
        )?;
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o700))?;
        // Shell builtins only: no runtime PATH dependencies and no evaluation of
        // the private input, including hostile shell metacharacters.
        let bytes = b"IFS= read -r payload < \"$1\" || :\nprintf '%s' \"$payload\"\n";
        std::fs::write(&source, bytes)?;
        let hash = hex::encode(Sha256::digest(std::fs::read(&source)?));
        std::fs::write(
            directory.path().join("replacement.conf"),
            "Host *\n  ProxyCommand false\n  BatchMode yes\n",
        )?;
        let string = |path: &std::path::Path| -> Result<String> {
            Ok(serde_json::to_string(
                path.to_str().context("fixture UTF-8 path")?,
            )?)
        };
        let config = format!(
            r#"capabilities = {{ named = true }}
[selection]
allow = ["observe_controller"]
[ssh]
config_file = "replacement.conf"
[limits]
connect_timeout_secs = 1
operation_timeout_secs = 3
max_timeout_secs = 5
max_output_bytes = 4096
max_file_bytes = 8192
[controller]
workspace_root = {}
[targets.base]
ssh_host = "controller-protocol-never-connect.invalid"
max_tier = "inspect"
[tools.observe_controller]
description = "Observe explicit controller authority."
revision = "review-controller-1"
authority = "controller"
effects = ["read"]
execution = {{ kind = "controller_script", source = {{ path = {}, content_sha256 = "{hash}", max_bytes = 4096 }}, interpreter = {{ program = {}, argv = [] }}, environment = {{ MCP_APPLICATION = "CONTROLLER_CONFIG_SECRET" }} }}
input_schema = {{ type = "object", additionalProperties = false, required = ["label", "count", "verbose"], properties = {{ label = {{ type = "string", maxLength = 256 }}, count = {{ type = "integer", minimum = -2, maximum = 4 }}, verbose = {{ type = "boolean" }} }} }}
result = {{ kind = "controller_command" }}
limits = {{ timeout_secs = 2, max_output_bytes = 1024 }}
"#,
            string(&root)?,
            string(&source)?,
            string(&interpreter)?,
        );
        Ok(Self {
            directory,
            source,
            interpreter,
            root,
            config_path,
            config,
            hash,
        })
    }

    pub fn start(&self, config: &str) -> Result<Server> {
        std::fs::write(&self.config_path, config)?;
        Server::start(&[
            "--config",
            self.config_path.to_str().context("config path")?,
        ])
    }

    pub fn public_only(&self, bytes: &[u8]) -> Result<()> {
        let text = std::str::from_utf8(bytes)?;
        for secret in [
            self.directory.path().to_str().context("fixture path")?,
            self.hash.as_str(),
            "CONTROLLER_CONFIG_SECRET",
            "CONTROLLER_INPUT_SECRET",
            "controller-protocol-never-connect.invalid",
        ] {
            ensure!(
                !text.contains(secret),
                "controller private content disclosed"
            );
        }
        Ok(())
    }

    pub async fn rejects_startup(&self, label: &str, config: &str) -> Result<()> {
        std::fs::write(&self.config_path, config)?;
        let output = timeout(
            Duration::from_secs(5),
            command(&[
                "--config",
                self.config_path.to_str().context("config path")?,
            ])
            .output(),
        )
        .await??;
        ensure!(!output.status.success(), "accepted {label}");
        ensure!(output.stdout.is_empty(), "started MCP for {label}");
        self.public_only(&output.stderr)?;
        let diagnostic: Value = serde_json::from_slice(&output.stderr)?;
        ensure!(
            diagnostic["code"] == "invalid_config",
            "{label}: {diagnostic}"
        );
        Ok(())
    }
}

pub fn output_control_schema(schema: &Value) -> Result<()> {
    ensure!(schema["properties"]["retain_output"]["type"] == "boolean");
    ensure!(schema["properties"]["retain_output"]["default"] == false);
    ensure!(
        !schema["required"]
            .as_array()
            .is_some_and(|fields| fields.contains(&json!("retain_output"))),
        "output retention became required"
    );
    Ok(())
}

pub fn schema_has_property(value: &Value, property: &str) -> bool {
    match value {
        Value::Object(object) => {
            object
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key(property))
                || object
                    .values()
                    .any(|child| schema_has_property(child, property))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| schema_has_property(child, property)),
        _ => false,
    }
}
