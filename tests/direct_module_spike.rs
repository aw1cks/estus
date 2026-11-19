//! Spike-only qualification of direct AnsiballZ module execution against
//! Runner across stock Debian 12, Ubuntu 24.04, and Rocky Linux 9 guests (C19).
#![cfg(unix)]
#![allow(dead_code)]

mod support;

use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::process::Command;

const TIMING_SAMPLES: usize = 30;
const NO_LOG_SECRET: &str = "ESTUS_SPIKE_SECRET_DO_NOT_LEAK_9f3a";

// Tiny stdin-only launcher that executes the verbatim pinned AnsiballZ wrapper
// without placing any module arguments or secrets in remote command-line argv.
const DIRECT_STDIN_SHIM: &str = r#"import datetime, json, os, shutil, sys, tempfile
payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
sys.stdin = open(os.devnull, "r")
tmpdir = os.path.realpath(tempfile.mkdtemp(prefix="estus_direct_tmp_"))
try:
    params = payload["params"]
    params["ANSIBLE_MODULE_ARGS"]["_ansible_tmpdir"] = tmpdir
    ns = {}
    exec(compile(payload["wrapper"], "ansiballz_wrapper.py", "exec"), ns)
    ns["_ansiballz_main"](
        zip_data=payload["zip_data"],
        ansible_module=payload["ansible_module"],
        module_fqn=payload["module_fqn"],
        params=json.dumps(params),
        profile=payload["profile"],
        date_time=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
        extensions=payload["extensions"],
        rlimit_nofile=payload["rlimit_nofile"],
    )
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
"#;

#[derive(Clone, Copy)]
enum Distro {
    Debian12,
    Ubuntu2404,
    Rocky9,
}

impl Distro {
    fn id(self) -> &'static str {
        match self {
            Self::Debian12 => "debian12",
            Self::Ubuntu2404 => "ubuntu2404",
            Self::Rocky9 => "rocky9",
        }
    }

    fn pkg_mgr_fact(self) -> &'static str {
        match self {
            Self::Debian12 | Self::Ubuntu2404 => "apt",
            Self::Rocky9 => "rpm",
        }
    }

    fn image_tag(self) -> &'static str {
        match self {
            Self::Debian12 => "estus-spike-debian12:c19",
            Self::Ubuntu2404 => "estus-spike-ubuntu2404:c19",
            Self::Rocky9 => "estus-spike-rocky9:c19",
        }
    }

    fn ssh_service_name(self) -> &'static str {
        match self {
            Self::Debian12 | Self::Ubuntu2404 => "ssh",
            Self::Rocky9 => "sshd",
        }
    }
}

struct DistroGuest {
    distro: Distro,
    docker: PathBuf,
    ssh: PathBuf,
    container_id: String,
    port: u16,
    ssh_config: PathBuf,
    control_path: PathBuf,
    cm_child: tokio::process::Child,
    target_python: String,
    os_release: BTreeMap<String, String>,
}

impl DistroGuest {
    async fn start(
        distro: Distro,
        docker: PathBuf,
        ssh: PathBuf,
        dockerfiles_dir: &Path,
        work_root: &Path,
    ) -> Result<Self> {
        let context_dir = dockerfiles_dir.join(distro.id());
        ensure!(
            context_dir.join("Dockerfile").is_file(),
            "missing spike Dockerfile at {}",
            context_dir.display()
        );
        let build_out = support::run_authoring(
            Command::new(&docker)
                .args(["build", "-q", "-t", distro.image_tag()])
                .arg(&context_dir),
        )
        .await?;
        ensure!(
            build_out.status.success(),
            "docker build failed for {}: {}",
            distro.id(),
            String::from_utf8_lossy(&build_out.stderr)
        );

        let port = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
        let run_out = support::run(Command::new(&docker).args([
            "run",
            "-d",
            "--rm",
            "--privileged",
            "--cgroupns=private",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "-p",
            &format!("127.0.0.1:{port}:22"),
            distro.image_tag(),
        ]))
        .await?;
        ensure!(
            run_out.status.success(),
            "docker run failed for {}: {}",
            distro.id(),
            String::from_utf8_lossy(&run_out.stderr)
        );
        let container_id = String::from_utf8(run_out.stdout)?.trim().to_owned();
        ensure!(!container_id.is_empty(), "empty container id");

        let guest_dir = work_root.join(distro.id());
        fs::create_dir_all(&guest_dir)?;
        fs::set_permissions(&guest_dir, fs::Permissions::from_mode(0o700))?;

        let keygen = support::find_program("ssh-keygen")?;
        let key_path = guest_dir.join("id_ed25519");
        let kg_out = support::run(
            Command::new(&keygen)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key_path),
        )
        .await?;
        ensure!(kg_out.status.success(), "ssh-keygen failed");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        let pub_key = fs::read_to_string(key_path.with_extension("pub"))?;

        // Wait until systemd + sshd are active inside the container.
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let ready = support::run(Command::new(&docker).args([
                "exec",
                &container_id,
                "sh",
                "-c",
                &format!(
                    "systemctl is-active --quiet estus-spike.service && systemctl is-active --quiet {}",
                    distro.ssh_service_name()
                ),
            ]))
            .await;
            if let Ok(out) = ready
                && out.status.success()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = support::run(Command::new(&docker).args(["rm", "-f", &container_id])).await;
                bail!(
                    "container {} ({}) failed to reach systemd+ssh readiness",
                    distro.id(),
                    container_id
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Inject ephemeral SSH authorized_keys and capture container host key.
        let setup_cmd = format!(
            "mkdir -p /home/mcp-admin/.ssh /home/mcp/.ssh && printf %s '{}' > /home/mcp-admin/.ssh/authorized_keys && cp /home/mcp-admin/.ssh/authorized_keys /home/mcp/.ssh/authorized_keys && chown -R mcp-admin:mcp-admin /home/mcp-admin/.ssh && chown -R mcp:mcp /home/mcp/.ssh && chmod 700 /home/mcp-admin/.ssh /home/mcp/.ssh && chmod 600 /home/mcp-admin/.ssh/authorized_keys /home/mcp/.ssh/authorized_keys && cat /etc/ssh/ssh_host_ed25519_key.pub",
            pub_key.trim().replace('\'', "'\\''")
        );
        let setup_out = support::run(Command::new(&docker).args([
            "exec",
            &container_id,
            "sh",
            "-c",
            &setup_cmd,
        ]))
        .await?;
        ensure!(
            setup_out.status.success(),
            "failed to inject authorized_keys in {}: {}",
            distro.id(),
            String::from_utf8_lossy(&setup_out.stderr)
        );
        let host_pub = String::from_utf8(setup_out.stdout)?.trim().to_owned();

        let known_hosts = guest_dir.join("known_hosts");
        fs::write(&known_hosts, format!("[127.0.0.1]:{port} {host_pub}\n"))?;
        let ssh_config = guest_dir.join("ssh_config");
        fs::write(
            &ssh_config,
            format!(
                "Host target\n  HostName 127.0.0.1\n  Port {port}\n  User mcp-admin\n  IdentityFile \"{}\"\n  IdentitiesOnly yes\n  BatchMode yes\n  StrictHostKeyChecking yes\n  UserKnownHostsFile \"{}\"\n  GlobalKnownHostsFile /dev/null\n  ConnectTimeout 5\n  ConnectionAttempts 1\n  LogLevel ERROR\n",
                key_path.display(),
                known_hosts.display()
            ),
        )?;

        let control_path = guest_dir.join("cm.sock");
        let mut cm_child = Command::new(&ssh)
            .arg("-F")
            .arg(&ssh_config)
            .args([
                "-o",
                "ControlMaster=yes",
                "-o",
                &format!("ControlPath={}", control_path.display()),
                "-o",
                "ControlPersist=no",
                "-N",
                "target",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let cm_deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = cm_child.try_wait()? {
                let _ = support::run(Command::new(&docker).args(["rm", "-f", &container_id])).await;
                bail!(
                    "ControlMaster exited prematurely for {} ({status})",
                    distro.id()
                );
            }
            let chk = support::run(Command::new(&ssh).arg("-F").arg(&ssh_config).args([
                "-o",
                &format!("ControlPath={}", control_path.display()),
                "-O",
                "check",
                "target",
            ]))
            .await?;
            if chk.status.success() {
                break;
            }
            if Instant::now() >= cm_deadline {
                let _ = cm_child.kill().await;
                let _ = support::run(Command::new(&docker).args(["rm", "-f", &container_id])).await;
                bail!("ControlMaster timeout for {}", distro.id());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let probe_out = support::run(Command::new(&ssh).arg("-F").arg(&ssh_config).args([
            "-o",
            &format!("ControlPath={}", control_path.display()),
            "-o",
            "ControlMaster=auto",
            "target",
            "/usr/bin/python3 -c 'import platform; print(platform.python_version())' && cat /etc/os-release",
        ]))
        .await?;
        ensure!(
            probe_out.status.success(),
            "failed SSH probe to {}: {}",
            distro.id(),
            String::from_utf8_lossy(&probe_out.stderr)
        );
        let probe_text = String::from_utf8(probe_out.stdout)?;
        let mut lines = probe_text.lines();
        let target_python = lines
            .next()
            .context("target python version")?
            .trim()
            .to_owned();
        let mut os_release = BTreeMap::new();
        for line in lines {
            if let Some((k, v)) = line.trim().split_once('=') {
                os_release.insert(k.to_owned(), v.trim_matches('"').to_owned());
            }
        }

        Ok(Self {
            distro,
            docker,
            ssh,
            container_id,
            port,
            ssh_config,
            control_path,
            cm_child,
            target_python,
            os_release,
        })
    }

    async fn exec_root(&self, cmd: &str) -> Result<std::process::Output> {
        support::run(Command::new(&self.docker).args(["exec", &self.container_id, "sh", "-c", cmd]))
            .await
    }

    async fn stop(mut self) -> Result<()> {
        let _ = support::run(
            Command::new(&self.ssh)
                .arg("-F")
                .arg(&self.ssh_config)
                .args([
                    "-o",
                    &format!("ControlPath={}", self.control_path.display()),
                    "-O",
                    "exit",
                    "target",
                ]),
        )
        .await;
        if self.cm_child.try_wait()?.is_none() {
            let _ = tokio::time::timeout(Duration::from_secs(3), self.cm_child.wait()).await;
            if self.cm_child.try_wait()?.is_none() {
                let _ = self.cm_child.kill().await;
                let _ = self.cm_child.wait().await;
            }
        }
        let rm_out =
            support::run(Command::new(&self.docker).args(["rm", "-f", &self.container_id])).await?;
        ensure!(
            rm_out.status.success(),
            "failed to remove container {}",
            self.container_id
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
struct DirectOutcome {
    failed: bool,
    changed: Option<bool>,
    censored: bool,
    diff_present: bool,
    output: Value,
    raw_json_valid: bool,
    elapsed_ms: f64,
}

fn build_ansible_params(
    module_fqcn: &str,
    module_args: &Value,
    check_mode: bool,
    diff: bool,
    no_log: bool,
    ansible_version: &str,
) -> Result<Value> {
    let mut args = module_args
        .as_object()
        .context("module_args must be JSON object")?
        .clone();
    args.insert("_ansible_check_mode".into(), json!(check_mode));
    args.insert("_ansible_no_log".into(), json!(no_log));
    args.insert("_ansible_debug".into(), json!(false));
    args.insert("_ansible_diff".into(), json!(diff));
    args.insert("_ansible_verbosity".into(), json!(0));
    args.insert("_ansible_version".into(), json!(ansible_version));
    args.insert("_ansible_module_name".into(), json!(module_fqcn));
    args.insert("_ansible_syslog_facility".into(), json!("LOG_USER"));
    args.insert(
        "_ansible_selinux_special_fs".into(),
        json!(["fuse", "nfs", "vboxsf", "ramfs", "9p", "vfat"]),
    );
    args.insert("_ansible_socket".into(), Value::Null);
    args.insert("_ansible_shell_executable".into(), json!("/bin/sh"));
    args.insert("_ansible_keep_remote_files".into(), json!(false));
    args.insert("_ansible_tmpdir".into(), Value::Null);
    args.insert("_ansible_remote_tmp".into(), json!("~/.ansible/tmp"));
    args.insert("_ansible_ignore_unknown_opts".into(), json!(false));
    args.insert("_ansible_target_log_info".into(), Value::Null);
    args.insert("_ansible_tracebacks_for".into(), json!([]));
    args.insert("_ansible_inject_invocation".into(), json!(true));
    Ok(json!({ "ANSIBLE_MODULE_ARGS": Value::Object(args) }))
}

fn parse_module_stdout(stdout: &[u8], no_log: bool) -> DirectOutcome {
    let Ok(text) = std::str::from_utf8(stdout) else {
        return DirectOutcome {
            failed: true,
            changed: None,
            censored: no_log,
            diff_present: false,
            output: json!({ "error": "invalid_utf8_output" }),
            raw_json_valid: false,
            elapsed_ms: 0.0,
        };
    };
    let trimmed = text.trim();
    let Ok(parsed) = serde_json::from_str::<Value>(trimmed) else {
        return DirectOutcome {
            failed: true,
            changed: None,
            censored: no_log,
            diff_present: false,
            output: json!({ "error": "non_json_output" }),
            raw_json_valid: false,
            elapsed_ms: 0.0,
        };
    };
    let Some(obj) = parsed.as_object() else {
        return DirectOutcome {
            failed: true,
            changed: None,
            censored: no_log,
            diff_present: false,
            output: json!({ "error": "non_object_json_output" }),
            raw_json_valid: false,
            elapsed_ms: 0.0,
        };
    };
    let failed = obj.get("failed").and_then(Value::as_bool).unwrap_or(false)
        || obj
            .get("rc")
            .and_then(Value::as_i64)
            .is_some_and(|rc| rc != 0);
    let raw_changed = obj.get("changed").and_then(Value::as_bool);
    let changed = if no_log || (failed && raw_changed == Some(false)) {
        None
    } else if !failed {
        raw_changed.or(Some(false))
    } else {
        raw_changed
    };
    let diff_present = !no_log && obj.get("diff").is_some_and(|v| !v.is_null());
    let output = if no_log {
        json!({ "status": "censored" })
    } else {
        let mut sanitized = obj.clone();
        sanitized.remove("invocation");
        Value::Object(sanitized)
    };
    DirectOutcome {
        failed,
        changed,
        censored: no_log,
        diff_present,
        output,
        raw_json_valid: true,
        elapsed_ms: 0.0,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_direct_module(
    guest: &DistroGuest,
    bundle_dir: &Path,
    wrapper_src: &str,
    ansible_version: &str,
    module_fqcn: &str,
    module_args: &Value,
    check_mode: bool,
    diff: bool,
    no_log: bool,
    warm_ssh: bool,
) -> Result<DirectOutcome> {
    let bundle_path = bundle_dir
        .join("bundles")
        .join(format!("{module_fqcn}.json"));
    let bundle: Value = serde_json::from_slice(&fs::read(&bundle_path)?)?;
    let params = build_ansible_params(
        module_fqcn,
        module_args,
        check_mode,
        diff,
        no_log,
        ansible_version,
    )?;
    let payload = json!({
        "wrapper": wrapper_src,
        "zip_data": bundle["zip_data"],
        "ansible_module": bundle["ansible_module"],
        "module_fqn": bundle["module_fqn"],
        "profile": bundle["serialization_profile"],
        "extensions": bundle["extensions"],
        "rlimit_nofile": bundle["rlimit_nofile"],
        "params": params,
    });
    let payload_bytes = serde_json::to_vec(&payload)?;

    let remote_cmd = format!(
        "sudo -H -n -k {} -I -c {}",
        guest.target_python_bin(),
        shell_quote(DIRECT_STDIN_SHIM)
    );

    let started = Instant::now();
    let mut cmd = Command::new(&guest.ssh);
    cmd.arg("-F").arg(&guest.ssh_config);
    if warm_ssh {
        cmd.args([
            "-o",
            "ControlMaster=auto",
            "-o",
            &format!("ControlPath={}", guest.control_path.display()),
            "-o",
            "ControlPersist=no",
        ]);
    } else {
        cmd.args(["-o", "ControlMaster=no", "-o", "ControlPath=none"]);
    }
    cmd.arg("target")
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(&payload_bytes).await?;
        stdin.shutdown().await?;
    }
    let out = tokio::time::timeout(Duration::from_secs(60), child.wait_with_output())
        .await
        .context("direct module execution timed out")??;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut outcome = parse_module_stdout(&out.stdout, no_log);
    outcome.elapsed_ms = elapsed_ms;
    if !out.status.success() && !outcome.raw_json_valid {
        outcome.failed = true;
    }
    Ok(outcome)
}

impl DistroGuest {
    fn target_python_bin(&self) -> &'static str {
        "/usr/bin/python3"
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

struct RunnerContext {
    runtime_root: PathBuf,
    work_dir: TempDir,
    playbook_launcher: PathBuf,
    ansible_cfg: PathBuf,
    path_env: std::ffi::OsString,
    collections_path: PathBuf,
}

impl RunnerContext {
    fn new(runtime_root: PathBuf, ssh_bin: &Path) -> Result<Self> {
        let work_dir = tempfile::Builder::new()
            .prefix("estus-spike-runner-")
            .tempdir()?;
        fs::create_dir_all(work_dir.path().join("tmp"))?;
        fs::create_dir_all(work_dir.path().join("home"))?;
        fs::set_permissions(work_dir.path(), fs::Permissions::from_mode(0o700))?;

        let runtime_manifest: Value =
            serde_json::from_slice(&fs::read(runtime_root.join("runtime.json"))?)?;
        let site_packages = runtime_root.join(
            runtime_manifest["site_packages"]
                .as_str()
                .context("site_packages")?,
        );
        let playbook_launcher = work_dir.path().join("playbook_main.py");
        fs::write(
            &playbook_launcher,
            format!(
                "import runpy, sys\nsys.path.insert(0, {:?})\nrunpy.run_module('ansible.cli.playbook', run_name='__main__')\n",
                site_packages.display().to_string()
            ),
        )?;
        let ansible_cfg = work_dir.path().join("ansible.cfg");
        fs::write(
            &ansible_cfg,
            "[defaults]\ncollections_scan_sys_path = False\nretry_files_enabled = False\nfact_caching = memory\nhost_key_checking = True\ndisplay_args_to_stdout = False\nstdout_callback = ansible.builtin.json\n[ssh_connection]\nssh_transfer_method = piped\n",
        )?;
        let ssh_parent = ssh_bin.parent().context("ssh parent")?.to_owned();
        let path_env = std::env::join_paths([
            runtime_root.join("bin"),
            ssh_parent,
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ])?;
        let collections_path = runtime_root.join("collections");
        Ok(Self {
            runtime_root,
            work_dir,
            playbook_launcher,
            ansible_cfg,
            path_env,
            collections_path,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_module(
        &self,
        guest: &DistroGuest,
        module_fqcn: &str,
        module_args: &Value,
        check_mode: bool,
        diff: bool,
        no_log: bool,
        warm_ssh: bool,
        keep_remote_dir: Option<&str>,
    ) -> Result<DirectOutcome> {
        let case_dir = tempfile::Builder::new()
            .prefix("case-")
            .tempdir_in(self.work_dir.path())?;
        let ssh_args = if warm_ssh {
            format!(
                "-o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes -o ControlMaster=auto -o ControlPath={} -o ControlPersist=no -F {}",
                guest.control_path.display(),
                guest.ssh_config.display()
            )
        } else {
            format!(
                "-o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes -o ControlMaster=no -o ControlPath=none -F {}",
                guest.ssh_config.display()
            )
        };
        let inventory_doc = json!({
            "all": {
                "hosts": {
                    "estus_target": {
                        "ansible_host": "target",
                        "ansible_connection": "ssh",
                        "ansible_python_interpreter": "/usr/bin/python3",
                        "ansible_ssh_executable": guest.ssh.display().to_string(),
                        "ansible_ssh_args": ssh_args,
                        "ansible_ssh_transfer_method": "piped",
                        "ansible_ssh_use_tty": false,
                        "ansible_ssh_password_mechanism": "disable",
                        "ansible_become": true,
                        "ansible_become_method": "ansible.builtin.sudo",
                        "ansible_become_user": "root",
                        "ansible_become_exe": "/usr/bin/sudo",
                        "ansible_become_flags": "-H -n -k",
                        "ansible_become_password": "",
                        "ansible_become_pass": "",
                        "ansible_sudo_pass": ""
                    }
                }
            }
        });
        let inventory_yml = case_dir.path().join("hosts.yml");
        fs::write(&inventory_yml, serde_json::to_string(&inventory_doc)?)?;
        let playbook_yml = case_dir.path().join("playbook.yml");
        let play_doc = json!([{
            "name": "estus_runner_spike",
            "hosts": "estus_target",
            "gather_facts": false,
            "become": true,
            "tasks": [{
                "name": "estus_module",
                "no_log": no_log,
                "check_mode": check_mode,
                "diff": diff,
                module_fqcn: module_args
            }]
        }]);
        fs::write(&playbook_yml, serde_json::to_string(&play_doc)?)?;

        let runtime_py = self.runtime_root.join("bin/python3");
        let mut cmd = Command::new(&runtime_py);
        cmd.arg("-I")
            .arg("-B")
            .arg(&self.playbook_launcher)
            .arg("-i")
            .arg(&inventory_yml)
            .arg(&playbook_yml)
            .env_clear()
            .env("PATH", &self.path_env)
            .env("HOME", self.work_dir.path().join("home"))
            .env("TMPDIR", self.work_dir.path().join("tmp"))
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("ANSIBLE_CONFIG", &self.ansible_cfg)
            .env("ANSIBLE_HOME", self.work_dir.path().join("home/ansible"))
            .env(
                "ANSIBLE_LOCAL_TEMP",
                self.work_dir.path().join("tmp/ansible-local"),
            )
            .env("ANSIBLE_COLLECTIONS_PATH", &self.collections_path)
            .env("ANSIBLE_COLLECTIONS_SCAN_SYS_PATH", "False")
            .env("ANSIBLE_NOCOWS", "True")
            .env("ANSIBLE_RETRY_FILES_ENABLED", "False");
        if let Some(remote_tmp) = keep_remote_dir {
            cmd.env("ANSIBLE_KEEP_REMOTE_FILES", "1")
                .env("ANSIBLE_PIPELINING", "False")
                .env("ANSIBLE_REMOTE_TEMP", remote_tmp);
        } else {
            cmd.env("ANSIBLE_PIPELINING", "True");
        }

        let started = Instant::now();
        let out = support::run_authoring(&mut cmd).await?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;

        let parsed: Value = serde_json::from_slice(&out.stdout).with_context(|| {
            format!(
                "Runner JSON callback parse failed ({}): stdout={} stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })?;
        let task = &parsed["plays"][0]["tasks"][0]["hosts"]["estus_target"];
        let failed = !out.status.success() || task["failed"].as_bool().unwrap_or(false);
        let raw_changed = task.get("changed").and_then(Value::as_bool);
        let changed = if no_log || (failed && raw_changed == Some(false)) {
            None
        } else {
            raw_changed
        };
        let censored = no_log
            || task
                .get("_ansible_no_log")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let diff_present = !no_log && task.get("diff").is_some_and(|v| !v.is_null());
        let output = if no_log {
            json!({ "status": "censored" })
        } else {
            let mut obj = task.as_object().cloned().unwrap_or_default();
            obj.remove("invocation");
            obj.remove("_ansible_no_log");
            Value::Object(obj)
        };
        Ok(DirectOutcome {
            failed,
            changed,
            censored,
            diff_present,
            output,
            raw_json_valid: true,
            elapsed_ms,
        })
    }
}

async fn assert_no_leftover_temp_dirs(guest: &DistroGuest) -> Result<()> {
    let out = guest
        .exec_root(
            "find /tmp /root /home -maxdepth 3 \\( -name 'ansible_*_payload_*' -o -name 'estus_direct_tmp_*' -o -name 'ansible-tmp-*' \\) 2>/dev/null",
        )
        .await?;
    ensure!(out.status.success(), "temp-dir audit command failed");
    let found = String::from_utf8(out.stdout)?;
    ensure!(
        found.trim().is_empty(),
        "leftover temporary directories on {}: {}",
        guest.distro.id(),
        found
    );
    Ok(())
}

fn percentile_ms(sorted: &[f64], num: usize, den: usize) -> Result<f64> {
    ensure!(!sorted.is_empty(), "empty samples");
    let rank = (sorted.len() * num).div_ceil(den);
    Ok(sorted[rank.saturating_sub(1).min(sorted.len() - 1)])
}

fn summarize(samples: &[f64]) -> Result<Value> {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    Ok(json!({
        "sample_count": samples.len(),
        "cold_first_ms": samples[0],
        "p50_ms": percentile_ms(&sorted, 50, 100)?,
        "p95_ms": percentile_ms(&sorted, 95, 100)?,
        "min_ms": sorted[0],
        "max_ms": sorted[sorted.len() - 1],
    }))
}

#[derive(Debug, Serialize)]
struct PairQualification {
    module: String,
    target: String,
    target_python: String,
    status: String,
    action_plugin: bool,
    checks: BTreeMap<String, bool>,
}

#[test]
fn stdin_adaptation_shim_preserves_wrapper_hides_args_and_cleans_tmpdir() -> Result<()> {
    let py = support::find_program("python3")?;
    let td = tempfile::tempdir()?;

    // Stub AnsiballZ wrapper matching exact _ansiballz_main signature to independently
    // verify the stdin-adaptation shim without modifying the shipped wrapper contract.
    let stub_wrapper = r#"import datetime, json, os, sys
def _ansiballz_main(zip_data, ansible_module, module_fqn, params, profile, date_time, extensions, rlimit_nofile):
    cmdline = open('/proc/self/cmdline', 'rb').read().decode('utf-8', 'replace')
    parsed = json.loads(params)
    args = parsed['ANSIBLE_MODULE_ARGS']
    assert args['_ansible_tmpdir'] and os.path.isdir(args['_ansible_tmpdir']), 'missing live tmpdir'
    assert 'SHIM_SECRET_XYZ' not in cmdline, 'secret leaked to argv/cmdline'
    assert 'SHIM_SECRET_XYZ' not in ' '.join(sys.argv), 'secret leaked to sys.argv'
    assert sys.stdin.read() == '', 'stdin was not closed/isolated from module'
    marker_file = os.path.join(args['_ansible_tmpdir'], 'marker')
    open(marker_file, 'w').write('ok')
    if args.get('force_fail'):
        print(json.dumps({'failed': True, 'msg': 'boom', 'tmpdir': args['_ansible_tmpdir']}))
        sys.exit(1)
    print(json.dumps({'changed': False, 'tmpdir': args['_ansible_tmpdir'], 'unicode': args.get('u')}))
"#;

    // 1. Success path + argv privacy + stdin closure + tmpdir cleanup
    let payload_ok = json!({
        "wrapper": stub_wrapper,
        "zip_data": "",
        "ansible_module": "stat",
        "module_fqn": "ansible.modules.stat",
        "profile": "legacy",
        "extensions": {},
        "rlimit_nofile": 0,
        "params": {
            "ANSIBLE_MODULE_ARGS": {
                "secret": "SHIM_SECRET_XYZ",
                "u": "☃ café",
                "force_fail": false
            }
        }
    });
    let mut cmd = std::process::Command::new(&py);
    cmd.args(["-I", "-c", DIRECT_STDIN_SHIM])
        .env("TMPDIR", td.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .context("stdin")?
            .write_all(&serde_json::to_vec(&payload_ok)?)?;
    }
    let out = child.wait_with_output()?;
    ensure!(
        out.status.success(),
        "shim success case failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout)?;
    let tmpdir = PathBuf::from(parsed["tmpdir"].as_str().context("tmpdir")?);
    ensure!(!tmpdir.exists(), "tmpdir survived successful exit");
    ensure!(parsed["unicode"] == "☃ café");

    // 2. Failure path (sys.exit(1)): tmpdir still cleaned up
    let mut payload_fail = payload_ok;
    payload_fail["params"]["ANSIBLE_MODULE_ARGS"]["force_fail"] = json!(true);
    let mut cmd = std::process::Command::new(&py);
    cmd.args(["-I", "-c", DIRECT_STDIN_SHIM])
        .env("TMPDIR", td.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .context("stdin")?
            .write_all(&serde_json::to_vec(&payload_fail)?)?;
    }
    let out_fail = child.wait_with_output()?;
    ensure!(!out_fail.status.success());
    let parsed_fail: Value = serde_json::from_slice(&out_fail.stdout)?;
    let tmpdir_fail = PathBuf::from(parsed_fail["tmpdir"].as_str().context("tmpdir_fail")?);
    ensure!(!tmpdir_fail.exists(), "tmpdir survived failure exit");

    // 3. Non-JSON and invalid UTF-8 output fail closed
    let non_json = parse_module_stdout(b"WARNING: stray stdout\n{\"changed\":false}", false);
    ensure!(non_json.failed && !non_json.raw_json_valid);
    let bad_utf8 = parse_module_stdout(b"\xff\xfe", false);
    ensure!(bad_utf8.failed && !bad_utf8.raw_json_valid);
    let nolog = parse_module_stdout(
        format!("{{\"changed\":true,\"secret\":\"{NO_LOG_SECRET}\"}}").as_bytes(),
        true,
    );
    ensure!(
        nolog.censored
            && !nolog.output.to_string().contains(NO_LOG_SECRET)
            && nolog.changed.is_none()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Docker, ESTUS_TEST_ANSIBLE_RUNTIME, ESTUS_TEST_DIRECT_BUNDLE, and ESTUS_TEST_SPIKE_DOCKERFILES"]
async fn qualify_direct_ansible_module_execution() -> Result<()> {
    let runtime_root = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_ANSIBLE_RUNTIME")
            .context("ESTUS_TEST_ANSIBLE_RUNTIME is required")?,
    )?;
    let bundle_dir = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_DIRECT_BUNDLE")
            .context("ESTUS_TEST_DIRECT_BUNDLE is required")?,
    )?;
    let dockerfiles_dir = fs::canonicalize(
        std::env::var_os("ESTUS_TEST_SPIKE_DOCKERFILES")
            .context("ESTUS_TEST_SPIKE_DOCKERFILES is required")?,
    )?;
    let docker = support::find_program("docker")?;
    let ssh = support::find_program("ssh")?;

    let docker_chk =
        support::run(Command::new(&docker).args(["info", "--format", "{{.ServerVersion}}"]))
            .await?;
    ensure!(
        docker_chk.status.success(),
        "Docker daemon unavailable; missing environment fails qualification: {}",
        String::from_utf8_lossy(&docker_chk.stderr)
    );

    let bundle_manifest: Value =
        serde_json::from_slice(&fs::read(bundle_dir.join("bundle.json"))?)?;
    let wrapper_src = fs::read_to_string(bundle_dir.join("wrapper.py"))?;
    let ansible_version = bundle_manifest["ansible_core_version"]
        .as_str()
        .context("ansible_core_version")?
        .to_owned();

    let work_root = tempfile::Builder::new()
        .prefix("estus-c19-guests-")
        .tempdir()?;
    fs::set_permissions(work_root.path(), fs::Permissions::from_mode(0o700))?;

    let runner = RunnerContext::new(runtime_root.clone(), &ssh)?;

    let mut guests = Vec::new();
    for distro in [Distro::Debian12, Distro::Ubuntu2404, Distro::Rocky9] {
        match DistroGuest::start(
            distro,
            docker.clone(),
            ssh.clone(),
            &dockerfiles_dir,
            work_root.path(),
        )
        .await
        {
            Ok(guest) => guests.push(guest),
            Err(err) => {
                for g in guests {
                    let _ = g.stop().await;
                }
                return Err(err);
            }
        }
    }

    let qual_result: Result<Value> = async {
        // 1. Capture actual wrapper and _ansible_* args used by Runner with ANSIBLE_KEEP_REMOTE_FILES=1.
        let keep_dir = "/tmp/estus-keep-remote-spike";
        let _ = guests[0]
            .exec_root(&format!("rm -rf {keep_dir} && mkdir -p {keep_dir} && chmod 777 {keep_dir}"))
            .await?;
        let keep_out = runner
            .run_module(
                &guests[0],
                "ansible.builtin.stat",
                &json!({"path": "/opt/spike-fixture/sample.txt"}),
                false,
                false,
                false,
                true,
                Some(keep_dir),
            )
            .await?;
        ensure!(!keep_out.failed, "ANSIBLE_KEEP_REMOTE_FILES capture failed");
        let kept_file_out = guests[0]
            .exec_root(&format!(
                "find {keep_dir} -name 'AnsiballZ_stat.py' -exec cat {{}} +"
            ))
            .await?;
        ensure!(
            kept_file_out.status.success() && !kept_file_out.stdout.is_empty(),
            "failed to read kept AnsiballZ_stat.py"
        );
        let kept_src = String::from_utf8(kept_file_out.stdout)?;
        ensure!(
            kept_src.contains("def _ansiballz_main(") && kept_src.contains("_ansible_check_mode"),
            "captured AnsiballZ_stat.py missing expected wrapper or _ansible_* params"
        );
        // Strip comments/blank lines just like Runner's _strip_comments when comparing wrapper body.
        let strip_comments = |s: &str| -> String {
            s.lines()
                .map(|l| {
                    let t = l.trim();
                    if t.is_empty() || t.starts_with('#') {
                        ""
                    } else {
                        l
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        let norm_kept = strip_comments(&kept_src);
        let norm_pinned = strip_comments(&wrapper_src);
        let pinned_fn_idx = norm_pinned
            .find("def _ansiballz_main(")
            .context("pinned _ansiballz_main")?;
        let pinned_body = &norm_pinned[pinned_fn_idx..];
        ensure!(
            norm_kept.contains(pinned_body),
            "pinned wrapper.py diverged from live Runner ANSIBLE_KEEP_REMOTE_FILES output"
        );
        let _ = guests[0].exec_root(&format!("rm -rf {keep_dir}")).await?;
        assert_no_leftover_temp_dirs(&guests[0]).await?;

        // 2. Qualify all 6 modules across all 3 distros (status, mutation, check_mode, diff, failure, no_log, temp cleanup).
        let mut matrix: Vec<PairQualification> = Vec::new();
        for guest in &guests {
            // (a) ansible.builtin.systemd_service (status + restart)
            {
                let mut checks = BTreeMap::new();
                let args_status = json!({"name": "estus-spike.service"});
                let r_stat = runner
                    .run_module(guest, "ansible.builtin.systemd_service", &args_status, false, false, false, true, None)
                    .await?;
                let d_stat = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.systemd_service", &args_status, false, false, false, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(
                    !r_stat.failed && !d_stat.failed
                        && r_stat.changed == Some(false) && d_stat.changed == Some(false)
                        && r_stat.output["status"]["ActiveState"] == "active"
                        && d_stat.output["status"]["ActiveState"] == "active",
                    "systemd_service status parity failed on {}: r={:?} d={:?}",
                    guest.distro.id(), r_stat, d_stat
                );
                checks.insert("status_parity".into(), true);

                // Check mode + diff on restart
                let pid_before = String::from_utf8(
                    guest.exec_root("systemctl show estus-spike.service -p MainPID --value").await?.stdout
                )?.trim().to_owned();
                let args_restart = json!({"name": "estus-spike.service", "state": "restarted"});
                let r_chk = runner
                    .run_module(guest, "ansible.builtin.systemd_service", &args_restart, true, true, false, true, None)
                    .await?;
                let d_chk = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.systemd_service", &args_restart, true, true, false, true)
                    .await?;
                let pid_after_chk = String::from_utf8(
                    guest.exec_root("systemctl show estus-spike.service -p MainPID --value").await?.stdout
                )?.trim().to_owned();
                ensure!(
                    pid_before == pid_after_chk
                        && r_chk.changed == d_chk.changed
                        && r_chk.diff_present == d_chk.diff_present,
                    "systemd_service check_mode/diff parity failed on {}",
                    guest.distro.id()
                );
                checks.insert("check_mode_and_diff_parity".into(), true);

                // Real disposable restart mutation (Runner then Direct)
                let r_mut = runner
                    .run_module(guest, "ansible.builtin.systemd_service", &args_restart, false, false, false, true, None)
                    .await?;
                let pid_after_runner = String::from_utf8(
                    guest.exec_root("systemctl show estus-spike.service -p MainPID --value").await?.stdout
                )?.trim().to_owned();
                ensure!(!r_mut.failed && r_mut.changed == Some(true) && pid_after_runner != pid_before);
                let d_mut = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.systemd_service", &args_restart, false, false, false, true)
                    .await?;
                let pid_after_direct = String::from_utf8(
                    guest.exec_root("systemctl show estus-spike.service -p MainPID --value").await?.stdout
                )?.trim().to_owned();
                ensure!(!d_mut.failed && d_mut.changed == Some(true) && pid_after_direct != pid_after_runner);
                checks.insert("mutation_post_state_parity".into(), true);

                // Failure parity
                let args_fail = json!({"name": "estus-nonexistent-spike.service", "state": "restarted"});
                let r_fail = runner
                    .run_module(guest, "ansible.builtin.systemd_service", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.systemd_service", &args_fail, false, false, false, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                // no_log parity
                let r_nl = runner
                    .run_module(guest, "ansible.builtin.systemd_service", &args_status, false, false, true, true, None)
                    .await?;
                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.systemd_service", &args_status, false, false, true, true)
                    .await?;
                ensure!(r_nl.censored && d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.builtin.systemd_service".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: false,
                    checks,
                });
            }

            // (b) ansible.posix.sysctl
            {
                let mut checks = BTreeMap::new();
                let sysctl_file = "/etc/sysctl.d/99-estus-spike.conf";
                let _ = guest
                    .exec_root(&format!("rm -f {sysctl_file} && sysctl -w net.ipv4.ip_forward=0 >/dev/null"))
                    .await?;
                let args_set = json!({
                    "name": "net.ipv4.ip_forward",
                    "value": "1",
                    "sysctl_file": sysctl_file,
                    "sysctl_set": true,
                    "reload": false,
                    "state": "present"
                });
                let r_chk = runner
                    .run_module(guest, "ansible.posix.sysctl", &args_set, true, true, false, true, None)
                    .await?;
                let d_chk = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.posix.sysctl", &args_set, true, true, false, true)
                    .await?;
                let exists_chk = guest.exec_root(&format!("test ! -e {sysctl_file} && test \"$(sysctl -n net.ipv4.ip_forward)\" = 0")).await?;
                ensure!(
                    exists_chk.status.success()
                        && r_chk.changed == Some(true)
                        && d_chk.changed == Some(true)
                        && r_chk.diff_present == d_chk.diff_present,
                    "sysctl check_mode/diff failed on {}",
                    guest.distro.id()
                );
                checks.insert("check_mode_and_diff_parity".into(), true);

                // Runner mutation then reset, then Direct mutation then reset
                let r_mut = runner
                    .run_module(guest, "ansible.posix.sysctl", &args_set, false, false, false, true, None)
                    .await?;
                let r_val = guest.exec_root(&format!("grep -Eq '^net\\.ipv4\\.ip_forward\\s*=\\s*1$' {sysctl_file} && test \"$(sysctl -n net.ipv4.ip_forward)\" = 1")).await?;
                ensure!(!r_mut.failed && r_mut.changed == Some(true) && r_val.status.success(), "runner sysctl mutation failed: {r_mut:?}");
                let _ = guest.exec_root(&format!("rm -f {sysctl_file} && sysctl -w net.ipv4.ip_forward=0 >/dev/null")).await?;

                let d_mut = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.posix.sysctl", &args_set, false, false, false, true)
                    .await?;
                let d_val = guest.exec_root(&format!("grep -Eq '^net\\.ipv4\\.ip_forward\\s*=\\s*1$' {sysctl_file} && test \"$(sysctl -n net.ipv4.ip_forward)\" = 1")).await?;
                ensure!(!d_mut.failed && d_mut.changed == Some(true) && d_val.status.success(), "direct sysctl mutation failed: {d_mut:?}");
                let _ = guest.exec_root(&format!("rm -f {sysctl_file} && sysctl -w net.ipv4.ip_forward=0 >/dev/null")).await?;
                checks.insert("mutation_post_state_parity".into(), true);

                // Failure case
                let args_fail = json!({
                    "name": "estus.invalid.nonexistent.key",
                    "value": "1",
                    "sysctl_file": sysctl_file,
                    "sysctl_set": true,
                    "reload": false,
                    "state": "present"
                });
                let r_fail = runner
                    .run_module(guest, "ansible.posix.sysctl", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.posix.sysctl", &args_fail, false, false, false, true)
                    .await?;
                let _ = guest.exec_root(&format!("rm -f {sysctl_file}")).await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                // no_log parity
                let args_nl = json!({
                    "name": "net.ipv4.ip_forward",
                    "value": "0",
                    "sysctl_file": "/etc/sysctl.d/99-estus-nolog.conf",
                    "sysctl_set": false,
                    "reload": false,
                    "state": "present"
                });
                let r_nl = runner
                    .run_module(guest, "ansible.posix.sysctl", &args_nl, false, false, true, true, None)
                    .await?;
                let _ = guest.exec_root("rm -f /etc/sysctl.d/99-estus-nolog.conf").await?;
                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.posix.sysctl", &args_nl, false, false, true, true)
                    .await?;
                let _ = guest.exec_root("rm -f /etc/sysctl.d/99-estus-nolog.conf").await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(r_nl.censored && d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.posix.sysctl".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: false,
                    checks,
                });
            }

            // (c) ansible.builtin.package_facts
            {
                let mut checks = BTreeMap::new();
                let args = json!({"manager": [guest.distro.pkg_mgr_fact()]});
                let r_ok = runner
                    .run_module(guest, "ansible.builtin.package_facts", &args, true, true, false, true, None)
                    .await?;
                let d_ok = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.package_facts", &args, true, true, false, true)
                    .await?;
                ensure!(
                    !r_ok.failed && !d_ok.failed
                        && r_ok.changed == Some(false) && d_ok.changed == Some(false)
                        && r_ok.output["ansible_facts"]["packages"]["openssh-server"].is_array()
                        && d_ok.output["ansible_facts"]["packages"]["openssh-server"].is_array(),
                    "package_facts parity failed on {}",
                    guest.distro.id()
                );
                checks.insert("output_and_check_mode_parity".into(), true);

                let args_fail = json!({"manager": ["invalid_manager_choice"]});
                let r_fail = runner
                    .run_module(guest, "ansible.builtin.package_facts", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.package_facts", &args_fail, false, false, false, true)
                    .await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                let r_nl = runner
                    .run_module(guest, "ansible.builtin.package_facts", &args, false, false, true, true, None)
                    .await?;
                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.package_facts", &args, false, false, true, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(r_nl.censored && d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.builtin.package_facts".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: false,
                    checks,
                });
            }

            // (d) ansible.builtin.apt (applicable on Debian 12 & Ubuntu 24.04; not_applicable on Rocky 9)
            if matches!(guest.distro, Distro::Debian12 | Distro::Ubuntu2404) {
                let mut checks = BTreeMap::new();
                let args_present = json!({"name": "estus-spike-pkg", "state": "present"});
                let args_absent = json!({"name": "estus-spike-pkg", "state": "absent"});
                let r_chk = runner
                    .run_module(guest, "ansible.builtin.apt", &args_present, true, true, false, true, None)
                    .await?;
                let d_chk = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_present, true, true, false, true)
                    .await?;
                let absent_chk = guest.exec_root("test ! -e /usr/share/estus-spike/marker").await?;
                ensure!(
                    absent_chk.status.success()
                        && r_chk.changed == Some(true)
                        && d_chk.changed == Some(true)
                        && r_chk.diff_present == d_chk.diff_present
                );
                checks.insert("check_mode_and_diff_parity".into(), true);

                let r_ins = runner
                    .run_module(guest, "ansible.builtin.apt", &args_present, false, false, false, true, None)
                    .await?;
                ensure!(!r_ins.failed && r_ins.changed == Some(true));
                ensure!(guest.exec_root("test -s /usr/share/estus-spike/marker").await?.status.success());
                let r_rem = runner
                    .run_module(guest, "ansible.builtin.apt", &args_absent, false, false, false, true, None)
                    .await?;
                ensure!(!r_rem.failed && r_rem.changed == Some(true));

                let d_ins = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_present, false, false, false, true)
                    .await?;
                ensure!(!d_ins.failed && d_ins.changed == Some(true));
                ensure!(guest.exec_root("test -s /usr/share/estus-spike/marker").await?.status.success());
                let d_rem = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_absent, false, false, false, true)
                    .await?;
                ensure!(!d_rem.failed && d_rem.changed == Some(true));
                ensure!(guest.exec_root("test ! -e /usr/share/estus-spike/marker").await?.status.success());
                checks.insert("mutation_post_state_parity".into(), true);

                let args_fail = json!({"name": "estus-nonexistent-spike-pkg", "state": "present"});
                let r_fail = runner
                    .run_module(guest, "ansible.builtin.apt", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_fail, false, false, false, true)
                    .await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_present, false, false, true, true)
                    .await?;
                let _ = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.apt", &args_absent, false, false, true, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.builtin.apt".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: false,
                    checks,
                });
            } else {
                matrix.push(PairQualification {
                    module: "ansible.builtin.apt".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "not_applicable".into(),
                    action_plugin: false,
                    checks: BTreeMap::new(),
                });
            }

            // (e) ansible.builtin.dnf (applicable on Rocky 9; not_applicable on Debian 12 & Ubuntu 24.04)
            if matches!(guest.distro, Distro::Rocky9) {
                let mut checks = BTreeMap::new();
                let args_present = json!({"name": "estus-spike-pkg", "state": "present"});
                let args_absent = json!({"name": "estus-spike-pkg", "state": "absent"});
                let r_chk = runner
                    .run_module(guest, "ansible.builtin.dnf", &args_present, true, true, false, true, None)
                    .await?;
                let d_chk = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_present, true, true, false, true)
                    .await?;
                let absent_chk = guest.exec_root("test ! -e /usr/share/estus-spike/marker").await?;
                ensure!(
                    absent_chk.status.success()
                        && r_chk.changed == Some(true)
                        && d_chk.changed == Some(true)
                        && r_chk.diff_present == d_chk.diff_present
                );
                checks.insert("check_mode_and_diff_parity".into(), true);

                let r_ins = runner
                    .run_module(guest, "ansible.builtin.dnf", &args_present, false, false, false, true, None)
                    .await?;
                ensure!(!r_ins.failed && r_ins.changed == Some(true));
                ensure!(guest.exec_root("test -s /usr/share/estus-spike/marker").await?.status.success());
                let r_rem = runner
                    .run_module(guest, "ansible.builtin.dnf", &args_absent, false, false, false, true, None)
                    .await?;
                ensure!(!r_rem.failed && r_rem.changed == Some(true));

                let d_ins = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_present, false, false, false, true)
                    .await?;
                ensure!(!d_ins.failed && d_ins.changed == Some(true));
                ensure!(guest.exec_root("test -s /usr/share/estus-spike/marker").await?.status.success());
                let d_rem = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_absent, false, false, false, true)
                    .await?;
                ensure!(!d_rem.failed && d_rem.changed == Some(true));
                ensure!(guest.exec_root("test ! -e /usr/share/estus-spike/marker").await?.status.success());
                checks.insert("mutation_post_state_parity".into(), true);

                let args_fail = json!({"name": "estus-nonexistent-spike-pkg", "state": "present"});
                let r_fail = runner
                    .run_module(guest, "ansible.builtin.dnf", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_fail, false, false, false, true)
                    .await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_present, false, false, true, true)
                    .await?;
                let _ = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.dnf", &args_absent, false, false, true, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.builtin.dnf".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: true,
                    checks,
                });
            } else {
                matrix.push(PairQualification {
                    module: "ansible.builtin.dnf".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "not_applicable".into(),
                    action_plugin: true,
                    checks: BTreeMap::new(),
                });
            }

            // (f) ansible.builtin.stat
            {
                let mut checks = BTreeMap::new();
                let args = json!({
                    "path": "/opt/spike-fixture/sample.txt",
                    "follow": false,
                    "get_checksum": true,
                    "checksum_algorithm": "sha256"
                });
                let r_ok = runner
                    .run_module(guest, "ansible.builtin.stat", &args, true, true, false, true, None)
                    .await?;
                let d_ok = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.stat", &args, true, true, false, true)
                    .await?;
                ensure!(
                    !r_ok.failed && !d_ok.failed
                        && r_ok.changed == Some(false) && d_ok.changed == Some(false)
                        && r_ok.output["stat"]["exists"] == true
                        && d_ok.output["stat"]["exists"] == true
                        && r_ok.output["stat"]["checksum"] == d_ok.output["stat"]["checksum"],
                    "stat parity failed on {}",
                    guest.distro.id()
                );
                checks.insert("output_and_check_mode_parity".into(), true);

                let args_fail = json!({
                    "path": "/opt/spike-fixture/sample.txt",
                    "checksum_algorithm": "bogus_algo"
                });
                let r_fail = runner
                    .run_module(guest, "ansible.builtin.stat", &args_fail, false, false, false, true, None)
                    .await?;
                let d_fail = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.stat", &args_fail, false, false, false, true)
                    .await?;
                ensure!(r_fail.failed && d_fail.failed);
                checks.insert("failure_parity".into(), true);

                let r_nl = runner
                    .run_module(guest, "ansible.builtin.stat", &args, false, false, true, true, None)
                    .await?;
                let d_nl = run_direct_module(guest, &bundle_dir, &wrapper_src, &ansible_version, "ansible.builtin.stat", &args, false, false, true, true)
                    .await?;
                assert_no_leftover_temp_dirs(guest).await?;
                ensure!(r_nl.censored && d_nl.censored && !d_nl.failed);
                checks.insert("no_log_parity".into(), true);
                checks.insert("temp_cleanup".into(), true);

                matrix.push(PairQualification {
                    module: "ansible.builtin.stat".into(),
                    target: guest.distro.id().into(),
                    target_python: guest.target_python.clone(),
                    status: "qualified".into(),
                    action_plugin: false,
                    checks,
                });
            }
        }

        // 3. Direct vs Runner cold/warm SSH timings on Debian 12 (30 samples each).
        let bench_guest = &guests[0];
        let timing_cases = [
            (
                "ansible.builtin.systemd_service",
                json!({"name": "estus-spike.service"}),
            ),
            (
                "ansible.builtin.package_facts",
                json!({"manager": ["apt"]}),
            ),
            (
                "ansible.posix.sysctl",
                json!({
                    "name": "net.ipv4.ip_forward",
                    "value": "0",
                    "sysctl_file": "/etc/sysctl.d/99-estus-timing.conf",
                    "sysctl_set": true,
                    "reload": false,
                    "state": "present"
                }),
            ),
        ];
        // Pre-seed timing sysctl file so every sample is a pure read/check.
        let _ = bench_guest
            .exec_root("printf 'net.ipv4.ip_forward = 0\\n' > /etc/sysctl.d/99-estus-timing.conf")
            .await?;

        let mut timings = Vec::new();
        for (module, args) in &timing_cases {
            for (kind, warm) in [("direct_cold_ssh", false), ("direct_warm_ssh", true), ("runner_cold_ssh", false)] {
                let mut samples = Vec::with_capacity(TIMING_SAMPLES);
                for _ in 0..TIMING_SAMPLES {
                    let res = if kind.starts_with("direct_") {
                        run_direct_module(
                            bench_guest,
                            &bundle_dir,
                            &wrapper_src,
                            &ansible_version,
                            module,
                            args,
                            false,
                            false,
                            false,
                            warm,
                        )
                        .await?
                    } else {
                        runner
                            .run_module(bench_guest, module, args, false, false, false, warm, None)
                            .await?
                    };
                    ensure!(!res.failed, "timing sample failed for {module} ({kind})");
                    samples.push(res.elapsed_ms);
                }
                timings.push(json!({
                    "module": module,
                    "path_kind": kind,
                    "ssh_connection_cold": !warm,
                    "stats": summarize(&samples)?,
                }));
            }
        }
        let _ = bench_guest.exec_root("rm -f /etc/sysctl.d/99-estus-timing.conf").await?;
        assert_no_leftover_temp_dirs(bench_guest).await?;

        Ok(json!({
            "bundle_metadata": {
                "ansible_core_version": bundle_manifest["ansible_core_version"],
                "target_python_floor": bundle_manifest["target_python_floor"],
                "controller_python_requires": bundle_manifest["controller_python_requires"],
                "wrapper_sha256": bundle_manifest["wrapper_sha256"],
                "modules": bundle_manifest["modules"],
            },
            "guests": guests.iter().map(|g| json!({
                "distro": g.distro.id(),
                "target_python": g.target_python,
                "os_release_pretty": g.os_release.get("PRETTY_NAME"),
            })).collect::<Vec<_>>(),
            "qualification_matrix": matrix,
            "timings": timings,
        }))
    }
    .await;

    for guest in guests {
        let _ = guest.stop().await;
    }

    let report = qual_result?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
