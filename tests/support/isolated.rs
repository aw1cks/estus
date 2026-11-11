//! Concrete Nix-image fixture with artifact and running-image digest checks.
//! Local runs retain the documented SDK create-404 pull race. Required CI must
//! additionally retain the image and deny registry egress (V03).
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Output, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use indoc::{formatdoc, indoc};
use tempfile::TempDir;
use testcontainers::{
    ContainerAsync, CopyTargetOptions, GenericImage, ImageExt,
    core::{ExecCommand, IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::{process::Command, time::timeout};

use crate::support::{find_program, quote, run};

const STARTUP: Duration = Duration::from_secs(60);
const CLEANUP: Duration = Duration::from_secs(10);
const ACCOUNTS: [&str; 5] = ["mcp", "mcp-sudo", "mcp-admin", "mcp-password", "mcp-tty"];

struct Artifact {
    archive: PathBuf,
    reference: String,
    digest: String,
}

impl Artifact {
    fn read(directory: &Path) -> Result<Self> {
        let mut names = fs::read_dir(directory)
            .context("SSH_MCP_TEST_FIXTURE must name the built artifact directory")?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        ensure!(
            names == ["image-id", "image-ref", "image.tar.gz"].map(std::ffi::OsString::from),
            "fixture artifact must contain exactly image.tar.gz, image-ref, image-id"
        );
        let archive = directory.join("image.tar.gz");
        ensure!(
            fs::metadata(&archive)?.is_file() && fs::metadata(&archive)?.len() > 0,
            "fixture archive must be a nonempty regular file"
        );
        let reference = metadata_line(&directory.join("image-ref"))?;
        let digest = metadata_line(&directory.join("image-id"))?;
        let tag = reference
            .strip_prefix("ssh-mcp-fixture:")
            .context("image-ref must use ssh-mcp-fixture:<derivation-derived-tag>")?;
        ensure!(
            !tag.is_empty()
                && tag.len() <= 128
                && tag != "latest"
                && tag
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
            "image-ref must have a concrete derivation-derived tag"
        );
        ensure!(
            digest
                .strip_prefix("sha256:")
                .is_some_and(|hash| hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
            "image-id must be sha256:<64 lowercase hex digits>"
        );
        Ok(Self {
            archive,
            reference,
            digest,
        })
    }
}

fn metadata_line(path: &Path) -> Result<String> {
    ensure!(
        fs::metadata(path)?.is_file(),
        "artifact metadata is not a regular file: {}",
        path.display()
    );
    let text = fs::read_to_string(path)?;
    let line = text.strip_suffix('\n').unwrap_or(&text);
    ensure!(
        !line.is_empty() && !line.chars().any(char::is_whitespace),
        "artifact metadata must contain one nonempty token: {}",
        path.display()
    );
    Ok(line.to_owned())
}

struct Docker {
    program: PathBuf,
    endpoint: String,
}

impl Docker {
    fn explicit() -> Result<Self> {
        let endpoint = std::env::var("DOCKER_HOST")
            .context("set explicit DOCKER_HOST to the dedicated Docker-compatible Unix socket")?;
        let socket = endpoint
            .strip_prefix("unix://")
            .context("fixture supports only explicit local unix:///absolute/path DOCKER_HOST")?;
        ensure!(
            Path::new(socket).is_absolute() && !socket.contains(['?', '#', '\n', '\r']),
            "invalid DOCKER_HOST Unix socket"
        );
        for name in [
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_API_VERSION",
            "DOCKER_DEFAULT_PLATFORM",
            "TESTCONTAINERS_HOST_OVERRIDE",
            "TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE",
            "TESTCONTAINERS_COMMAND",
        ] {
            ensure!(
                std::env::var_os(name).is_none(),
                "remove conflicting runtime override {name}; fixture uses explicit DOCKER_HOST and default SDK removal"
            );
        }
        let program = find_program("docker")
            .context("Nix-provided Docker CLI prerequisite (enter nix develop)")?;
        ensure!(
            program.starts_with("/nix/store"),
            "Docker CLI must come from the Nix development environment"
        );
        Ok(Self { program, endpoint })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command
            .arg("--host")
            .arg(&self.endpoint)
            .env("DOCKER_HOST", &self.endpoint)
            .env_remove("DOCKER_CONTEXT");
        command
    }

    async fn checked(&self, args: &[&str], deadline: Duration) -> Result<Output> {
        let output = bounded(self.command().args(args), deadline).await?;
        ensure!(
            output.status.success(),
            "Docker {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }

    async fn inspect_image(&self, artifact: &Artifact) -> Result<()> {
        let output = self
            .checked(
                &[
                    "image",
                    "inspect",
                    "--format",
                    "{{.Id}}",
                    &artifact.reference,
                ],
                STARTUP,
            )
            .await?;
        ensure!(
            String::from_utf8(output.stdout)?.trim() == artifact.digest,
            "loaded image-ref does not match artifact image-id"
        );
        Ok(())
    }

    async fn named_ids(&self, name: &str) -> Result<Vec<String>> {
        let filter = format!("name={name}");
        let output = self
            .checked(
                &[
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    &filter,
                    "--format",
                    "{{.ID}} {{.Names}}",
                ],
                CLEANUP,
            )
            .await?;
        let text = String::from_utf8(output.stdout)?;
        let mut ids = Vec::new();
        for line in text.lines() {
            let (id, names) = line
                .split_once(' ')
                .context("Docker container listing identity")?;
            if names
                .split(',')
                .any(|candidate| candidate.trim_start_matches('/') == name)
            {
                ids.push(id.to_owned());
            }
        }
        Ok(ids)
    }
}

// Unlike support::run, image loading and inspection have sixty-second deadlines.
async fn bounded(command: &mut Command, deadline: Duration) -> Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().context("starting Docker CLI")?;
    use tokio::io::AsyncReadExt;
    let mut stdout = child.stdout.take().context("Docker stdout")?;
    let mut stderr = child.stderr.take().context("Docker stderr")?;
    let out = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let err = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match timeout(deadline, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            let killed = timeout(CLEANUP, child.kill()).await;
            out.abort();
            err.abort();
            killed.context("Docker CLI kill/reap deadline")??;
            bail!("Docker CLI exceeded {deadline:?} and was killed/reaped");
        }
    };
    Ok(Output {
        status,
        stdout: timeout(CLEANUP, out).await???,
        stderr: timeout(CLEANUP, err).await???,
    })
}

pub struct Fixture {
    root: TempDir,
    docker: Docker,
    artifact: Artifact,
    containers: Vec<ContainerAsync<GenericImage>>,
    names: Vec<String>,
    pub ssh: PathBuf,
    pub ssh_config: PathBuf,
    pub config: PathBuf,
}

impl Fixture {
    pub async fn start() -> Result<Self> {
        // All malformed/missing artifact boundaries precede CLI/SDK side effects.
        let directory = std::env::var_os("SSH_MCP_TEST_FIXTURE")
            .context("set SSH_MCP_TEST_FIXTURE to the Nix-built three-file artifact directory")?;
        let artifact = Artifact::read(Path::new(&directory))?;
        let docker = Docker::explicit()?;
        let root = tempfile::tempdir()?;
        let mut fixture = Self {
            ssh: find_program("ssh")?,
            ssh_config: root.path().join("ssh_config"),
            config: root.path().join("server.toml"),
            root,
            docker,
            artifact,
            containers: Vec::new(),
            names: Vec::new(),
        };
        let result = fixture.initialize().await;
        if let Err(error) = result {
            let cleanup = fixture.stop().await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => {
                    Err(error.context(format!("fixture cleanup also failed: {cleanup:#}")))
                }
            };
        }
        Ok(fixture)
    }

    async fn initialize(&mut self) -> Result<()> {
        let mut command = self.docker.command();
        command
            .args(["image", "load", "--input"])
            .arg(&self.artifact.archive);
        let loaded = bounded(&mut command, STARTUP).await?;
        ensure!(
            loaded.status.success(),
            "fixture image load failed: {}",
            String::from_utf8_lossy(&loaded.stderr)
        );
        self.docker.inspect_image(&self.artifact).await?;
        let keygen = find_program("ssh-keygen")?;
        for name in ACCOUNTS
            .into_iter()
            .chain(["host-primary", "host-nosftp", "unknown"])
        {
            let path = self.root.path().join(name);
            let output = run(Command::new(&keygen)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path))
            .await?;
            ensure!(
                output.status.success(),
                "ssh-keygen failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        for (index, host_key) in ["host-primary", "host-nosftp"].into_iter().enumerate() {
            let name = format!(
                "ssh-mcp-{}-{index}",
                self.root
                    .path()
                    .file_name()
                    .context("fixture temporary directory")?
                    .to_string_lossy()
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            );
            ensure!(
                self.docker.named_ids(&name).await?.is_empty(),
                "fixture container name already exists"
            );
            self.names.push(name.clone());
            self.docker.inspect_image(&self.artifact).await?;
            let (image, tag) = self
                .artifact
                .reference
                .split_once(':')
                .context("validated image reference")?;
            let mut config = indoc! {"
                Port 2222
                ListenAddress 0.0.0.0
                HostKey /fixture/host_key
                PidFile /run/sshd/sshd.pid
                AuthorizedKeysFile /fixture/authorized_keys/%u
                AuthenticationMethods publickey
                PasswordAuthentication no
                KbdInteractiveAuthentication no
                PermitEmptyPasswords no
                PermitRootLogin no
                StrictModes yes
                PermitUserRC no
                LogLevel VERBOSE
                UsePAM no
                AllowTcpForwarding yes
            "}
            .to_owned();
            if index == 0 {
                config.push_str("Subsystem sftp internal-sftp\n");
            }
            let mut request = GenericImage::new(image, tag)
                .with_exposed_port(2222.tcp())
                .with_wait_for(WaitFor::message_on_stderr("Server listening on"))
                .with_container_name(name)
                .with_startup_timeout(STARTUP)
                .with_copy_to(
                    CopyTargetOptions::new("/fixture/host_key").with_mode(0o600),
                    self.root.path().join(host_key),
                )
                .with_copy_to(
                    CopyTargetOptions::new("/fixture/sshd_config").with_mode(0o644),
                    config.into_bytes(),
                );
            for account in ACCOUNTS {
                request = request.with_copy_to(
                    CopyTargetOptions::new(format!("/fixture/authorized_keys/{account}"))
                        .with_mode(0o644),
                    self.root.path().join(format!("{account}.pub")),
                );
            }
            let container = timeout(STARTUP, request.start())
                .await
                .context("fixture container startup exceeded sixty seconds")??;
            self.containers.push(container);
        }
        self.verify_identities().await?;
        self.write_configuration().await?;
        for alias in ["plain", "nosftp", "viajump"] {
            let output = self.direct(alias, "/usr/bin/id -u").await?;
            ensure!(
                output.status.success() && output.stdout == b"1000\n",
                "real fixture SSH readiness failed for {alias}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // A real transition distinguishes a usable fixture from a runtime whose
        // nosuid/no-new-privileges policy makes all later sudo acceptance fake.
        let sudo = self
            .direct("same", "/usr/bin/sudo -n -k -u root -- /usr/bin/id -u")
            .await?;
        ensure!(
            sudo.status.success() && sudo.stdout == b"0\n",
            "fixture prerequisite: real setuid sudo failed; check runtime nosuid/no-new-privileges and fixture policy: {}",
            String::from_utf8_lossy(&sudo.stderr)
        );
        Ok(())
    }

    pub async fn verify_identities(&self) -> Result<()> {
        ensure!(
            self.containers.len() == 2,
            "both fixture containers must exist"
        );
        ensure!(
            self.containers[0].id() != self.containers[1].id(),
            "fixture container identities must differ"
        );
        for container in &self.containers {
            let output = self
                .docker
                .checked(
                    &[
                        "container",
                        "inspect",
                        "--format",
                        "{{.Image}} {{.State.Running}}",
                        container.id(),
                    ],
                    STARTUP,
                )
                .await?;
            ensure!(
                String::from_utf8(output.stdout)?.trim()
                    == format!("{} true", self.artifact.digest),
                "running container does not match artifact config digest/running state"
            );
        }
        Ok(())
    }

    async fn write_configuration(&self) -> Result<()> {
        let mut endpoints = Vec::new();
        let mut known = String::new();
        for (index, container) in self.containers.iter().enumerate() {
            let host = container.get_host().await?.to_string();
            let port = container.get_host_port_ipv4(2222.tcp()).await?;
            let key = fs::read_to_string(self.root.path().join(if index == 0 {
                "host-primary.pub"
            } else {
                "host-nosftp.pub"
            }))?;
            known.push_str(&format!("[{host}]:{port} {key}"));
            if index == 0 {
                known.push_str(&format!("[127.0.0.1]:2222 {key}"));
            }
            endpoints.push((host, port));
        }
        fs::write(self.root.path().join("known_hosts"), known)?;
        let mut hosts = String::new();
        for (alias, account, endpoint) in [
            ("plain", "mcp", 0),
            ("same", "mcp-sudo", 0),
            ("split", "mcp", 0),
            ("split-admin", "mcp-admin", 0),
            ("password", "mcp-password", 0),
            ("requiretty", "mcp-tty", 0),
            ("nosftp", "mcp", 1),
            ("jump", "mcp", 0),
        ] {
            let (host, port) = &endpoints[endpoint];
            hosts.push_str(&formatdoc! {"
                Host {alias}
                    HostName {host}
                    Port {port}
                    User {account}
                    IdentityFile {identity}
            ", identity = ssh_path(&self.root.path().join(account))?});
        }
        // ProxyJump's child must use our replacement config, not ~/.ssh/config.
        hosts.push_str(&formatdoc! {"
            Host viajump
                HostName 127.0.0.1
                Port 2222
                User mcp
                IdentityFile {identity}
                ProxyCommand {ssh} -F {config} -W %h:%p jump
        ",
            identity = ssh_path(&self.root.path().join("mcp"))?,
            ssh = quote(self.ssh.to_str().context("SSH executable UTF-8")?),
            config = quote(self.ssh_config.to_str().context("SSH config UTF-8")?),
        });
        fs::write(self.root.path().join("included.conf"), hosts)?;
        fs::write(
            &self.ssh_config,
            formatdoc! {"
            Include {included}
            Host *
                IdentityAgent none
                IdentitiesOnly yes
                BatchMode yes
                StrictHostKeyChecking yes
                UserKnownHostsFile {known}
                GlobalKnownHostsFile /dev/null
                PasswordAuthentication no
                KbdInteractiveAuthentication no
                ControlMaster no
                ControlPath none
                ConnectTimeout 5
                ConnectionAttempts 1
        ",
                included = ssh_path(&self.root.path().join("included.conf"))?,
                known = ssh_path(&self.root.path().join("known_hosts"))?,
            },
        )?;
        let mut config = format!(
            "[ssh]\nconfig_file = {}\n",
            serde_json::to_string(&self.ssh_config.to_string_lossy())?
        );
        for alias in [
            "plain",
            "same",
            "split",
            "password",
            "requiretty",
            "nosftp",
            "viajump",
        ] {
            config.push_str(&format!("[targets.{alias}]\nssh_host = '{alias}'\n"));
            if ["same", "split", "password", "requiretty"].contains(&alias) {
                config.push_str(&formatdoc! {"
                    [targets.{alias}.sudo]
                    mode = '{mode}'
                    users = ['root']
                    programs = ['/usr/bin/id', '/usr/bin/printf']
                ", mode = if alias == "split" { "separate-identity" } else { "same-account" }});
                if alias == "split" {
                    config.push_str("ssh_host = 'split-admin'\n");
                }
            }
        }
        fs::write(&self.config, config)?;
        Ok(())
    }

    pub async fn direct(&self, alias: &str, command: &str) -> Result<Output> {
        run(Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.ssh_config)
            .args(["-T", alias, command]))
        .await
    }

    pub async fn direct_tty(&self, alias: &str, command: &str) -> Result<Output> {
        run(Command::new(&self.ssh)
            .arg("-F")
            .arg(&self.ssh_config)
            .args(["-tt", alias, command]))
        .await
    }

    pub async fn reject_unknown_key(&self) -> Result<()> {
        let (host, port) = (
            self.containers[0].get_host().await?.to_string(),
            self.containers[0].get_host_port_ipv4(2222.tcp()).await?,
        );
        // -F /dev/null and a single -i prevent configured identities or an existing
        // master from authenticating; the independently valid known_hosts remains.
        let output = run(Command::new(&self.ssh)
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "IdentityAgent=none",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "ControlPath=none",
                "-o",
                "ConnectTimeout=5",
                "-o",
            ])
            .arg(format!(
                "UserKnownHostsFile={}",
                ssh_path(&self.root.path().join("known_hosts"))?
            ))
            .arg("-i")
            .arg(self.root.path().join("unknown"))
            .arg("-p")
            .arg(port.to_string())
            .arg(format!("mcp@{host}"))
            .arg("/usr/bin/id -u"))
        .await?;
        ensure!(
            output.status.code() == Some(255)
                && String::from_utf8_lossy(&output.stderr)
                    .contains("Permission denied (publickey)"),
            "unknown key was not refused specifically by public-key authentication: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    pub async fn primary_endpoint(&self) -> Result<(String, u16)> {
        Ok((
            self.containers[0].get_host().await?.to_string(),
            self.containers[0].get_host_port_ipv4(2222.tcp()).await?,
        ))
    }

    /// Add only the test-owned relay endpoint; the real primary host key is pinned.
    pub fn configure_write_relay(&self, port: u16) -> Result<()> {
        use std::io::Write;

        let key = fs::read_to_string(self.root.path().join("host-primary.pub"))?;
        writeln!(
            fs::OpenOptions::new()
                .append(true)
                .open(self.root.path().join("known_hosts"))?,
            "[127.0.0.1]:{port} {key}"
        )?;
        write!(
            fs::OpenOptions::new()
                .append(true)
                .open(self.root.path().join("included.conf"))?,
            "{}",
            formatdoc! {"
                Host slowwrite
                    HostName 127.0.0.1
                    Port {port}
                    User mcp
                    IdentityFile {identity}
                    Compression no
            ", identity = ssh_path(&self.root.path().join("mcp"))?}
        )?;
        write!(
            fs::OpenOptions::new().append(true).open(&self.config)?,
            "{}",
            indoc! {"
                [targets.slowwrite]
                ssh_host = 'slowwrite'
            "}
        )?;
        Ok(())
    }

    /// Root container exec is fixture setup/observation, never the production writer.
    pub async fn primary_exec(&self, script: &str) -> Result<Vec<u8>> {
        timeout(CLEANUP, async {
            let mut exec = self.containers[0]
                .exec(ExecCommand::new(["/bin/sh", "-eu", "-c", script]))
                .await?;
            let stdout = exec.stdout_to_vec().await?;
            let stderr = exec.stderr_to_vec().await?;
            ensure!(
                exec.exit_code().await? == Some(0),
                "fixture exec failed: {}",
                String::from_utf8_lossy(&stderr)
            );
            Ok::<_, anyhow::Error>(stdout)
        })
        .await
        .context("fixture exec deadline")?
    }

    pub async fn kill_primary(&self) -> Result<()> {
        timeout(CLEANUP, self.containers[0].stop_with_timeout(Some(0)))
            .await
            .context("primary container kill deadline")??;
        ensure!(
            !timeout(CLEANUP, self.containers[0].is_running()).await??,
            "primary container survived kill"
        );
        Ok(())
    }

    pub async fn authentication_count(&self) -> Result<usize> {
        let logs = timeout(CLEANUP, self.containers[0].stderr_to_vec()).await??;
        Ok(String::from_utf8_lossy(&logs)
            .lines()
            .filter(|line| line.contains("Accepted publickey for mcp "))
            .count())
    }

    pub async fn authentication_keys(&self) -> Result<Vec<(String, String)>> {
        let logs = timeout(CLEANUP, self.containers[0].stderr_to_vec()).await??;
        String::from_utf8(logs)?
            .lines()
            .filter_map(|line| {
                line.split_once("Accepted publickey for ")
                    .map(|(_, accepted)| {
                        let account = accepted
                            .split_ascii_whitespace()
                            .next()
                            .context("accepted SSH account")?;
                        let fingerprint = accepted
                            .split_ascii_whitespace()
                            .find(|field| field.starts_with("SHA256:"))
                            .context("accepted SSH key fingerprint")?;
                        Ok((account.to_owned(), fingerprint.to_owned()))
                    })
            })
            .collect()
    }

    pub async fn key_fingerprint(&self, account: &str) -> Result<String> {
        let output = run(Command::new(find_program("ssh-keygen")?)
            .args(["-l", "-E", "sha256", "-f"])
            .arg(self.root.path().join(format!("{account}.pub"))))
        .await?;
        ensure!(
            output.status.success(),
            "fixture public-key fingerprint failed"
        );
        Ok(std::str::from_utf8(&output.stdout)?
            .split_ascii_whitespace()
            .nth(1)
            .context("fixture public-key fingerprint")?
            .to_owned())
    }

    pub fn credential_markers(&self) -> Result<Vec<String>> {
        let mut markers = vec![
            "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned(),
            self.root
                .path()
                .to_str()
                .context("fixture credential directory UTF-8")?
                .to_owned(),
        ];
        for key in ACCOUNTS
            .into_iter()
            .chain(["host-primary", "host-nosftp", "unknown"])
        {
            let private = fs::read_to_string(self.root.path().join(key))?;
            markers.extend(
                private
                    .lines()
                    .filter(|line| line.len() >= 32 && !line.starts_with("-----"))
                    .map(str::to_owned),
            );
        }
        Ok(markers)
    }

    pub async fn stop(mut self) -> Result<()> {
        let mut errors = Vec::new();
        for container in self.containers.drain(..) {
            if let Err(error) = async {
                timeout(CLEANUP, container.rm())
                    .await
                    .context("container rm deadline")??;
                Ok::<_, anyhow::Error>(())
            }
            .await
            {
                errors.push(format!("SDK removal: {error:#}"));
            }
        }
        // Also covers create/copy/start failures before AsyncRunner returned its
        // handle. Names were registered before create and checked absent first.
        for name in &self.names {
            let result = async {
                for id in self.docker.named_ids(name).await? {
                    self.docker
                        .checked(&["container", "rm", "--force", &id], CLEANUP)
                        .await?;
                }
                ensure!(
                    self.docker.named_ids(name).await?.is_empty(),
                    "owned container survived explicit removal: {name}"
                );
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = result {
                errors.push(format!("{name}: {error:#}"));
            }
        }
        ensure!(
            errors.is_empty(),
            "fixture cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}

fn ssh_path(path: &Path) -> Result<String> {
    let text = path.to_str().context("fixture path must be UTF-8")?;
    ensure!(
        !text.contains(['\n', '\r']),
        "fixture path contains SSH config newline"
    );
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_missing_and_malformed_artifacts() -> Result<()> {
        let root = tempfile::tempdir()?;
        ensure!(Artifact::read(root.path()).is_err());
        fs::write(root.path().join("image.tar.gz"), b"archive")?;
        fs::write(root.path().join("image-ref"), "ssh-mcp-fixture:abc123\n")?;
        fs::write(
            root.path().join("image-id"),
            format!("sha256:{}\n", "a".repeat(64)),
        )?;
        Artifact::read(root.path())?;
        for reference in [
            "ssh-mcp-fixture:latest",
            "other:abc123",
            "ssh-mcp-fixture:abc\nsecond",
        ] {
            fs::write(root.path().join("image-ref"), reference)?;
            ensure!(
                Artifact::read(root.path()).is_err(),
                "accepted invalid image reference"
            );
        }
        fs::write(root.path().join("image-ref"), "ssh-mcp-fixture:abc123")?;
        for digest in [
            "a".repeat(64),
            format!("sha256:{}", "A".repeat(64)),
            "sha256:abc".to_owned(),
        ] {
            fs::write(root.path().join("image-id"), digest)?;
            ensure!(
                Artifact::read(root.path()).is_err(),
                "accepted invalid config digest"
            );
        }
        Ok(())
    }
}
