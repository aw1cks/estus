//! Regressions for lossless Unix filename decoding in the upstream SFTP protocol.
use std::os::unix::ffi::OsStrExt;

use openssh_sftp_protocol::{
    response::{NameEntry, Response, ResponseInner},
    ssh_format,
};

fn entry_bytes(name: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
    bytes.extend_from_slice(name);
    // The human-oriented longname is not a filename and need not be UTF-8.
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(b"\xff -");
    bytes.extend_from_slice(&0u32.to_be_bytes()); // No metadata attributes supplied.
    bytes
}

#[test]
fn sftp_name_packets_preserve_non_utf8_filename_bytes() {
    let names: [&[u8]; 3] = [b"raw-\xff\xfe", b"quote'\"\\\n\x01", "é-雪".as_bytes()];
    let mut packet = vec![104]; // SSH_FXP_NAME, without the outer packet length.
    packet.extend_from_slice(&17u32.to_be_bytes());
    packet.extend_from_slice(&3u32.to_be_bytes());
    for name in names {
        packet.extend_from_slice(&entry_bytes(name));
    }
    let (response, rest) = ssh_format::from_bytes::<Response>(&packet)
        .expect("SFTP filenames are raw Unix bytes, not UTF-8 strings");
    assert!(rest.is_empty());
    assert_eq!(response.response_id, 17);
    let ResponseInner::Name(entries) = response.response_inner else {
        panic!("name packet decoded as another response type");
    };
    let actual: Vec<_> = entries
        .iter()
        .map(|entry| entry.filename.as_os_str().as_bytes())
        .collect();
    assert_eq!(actual, names);
    for entry in entries.iter() {
        assert_eq!(&*entry.longname, b"\xff -");
        assert_eq!(entry.attrs.get_size(), None);
    }
}

#[test]
fn standalone_name_entries_use_the_same_lossless_decoder() {
    let bytes = entry_bytes(b"raw-\xff\xfe");
    let (entry, rest) = ssh_format::from_bytes::<NameEntry>(&bytes)
        .expect("standalone directory entries must also preserve raw names");
    assert!(rest.is_empty());
    assert_eq!(entry.filename.as_os_str().as_bytes(), b"raw-\xff\xfe");
}

// Include the existing isolated-image fixture without changing its API.
#[allow(dead_code)]
#[path = "support/isolated.rs"]
mod isolated;
#[allow(dead_code, unused_imports)]
mod support;

use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, ensure};
use openssh_sftp_client::{Sftp, SftpOptions, metadata::Permissions};
use tokio::{process::Command, time::timeout};

/// This direct-client slice mirrors the replace staging sequence: exclusive
/// OPEN, handle chmod, payload write. The observer must be denied while the
/// stage is still empty, before any content is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires native ESTUS_TEST_FIXTURE, explicit DOCKER_HOST and Docker CLI"]
async fn sftp_private_stage_denies_observer_before_payload() -> Result<()> {
    let fixture = isolated::Fixture::start(isolated::ImageKind::Native).await?;
    let result = private_stage_acceptance(&fixture).await;
    // Do not let an assertion, protocol error or timeout bypass fixture cleanup.
    let stopped = fixture.stop().await;
    result.and(stopped)
}

async fn private_stage_acceptance(fixture: &isolated::Fixture) -> Result<()> {
    let setup = fixture
        .primary_exec(
            "directory=$(mktemp -d /tmp/estus-private-stage.XXXXXXXX)\n\
             chown mcp:mcp \"$directory\"\n\
             chmod 0755 \"$directory\"\n\
             sshd=$(readlink /proc/1/exe)\n\
             server=${sshd%/bin/sshd}/libexec/sftp-server\n\
             test -x \"$server\"\n\
             printf '%s\\n%s\\n' \"$directory\" \"$server\"",
        )
        .await?;
    let setup = String::from_utf8(setup)?;
    let mut lines = setup.lines();
    let directory = lines.next().context("disposable stage parent")?;
    let server = lines.next().context("image's real sftp-server")?;
    ensure!(lines.next().is_none(), "unexpected fixture setup output");
    let private = format!("{directory}/private-stage");
    let control = format!("{directory}/default-mode-control");
    let private_arg = support::quote(&private);
    let control_arg = support::quote(&control);

    // Both aliases target the primary container, but plain is mcp (1000)
    // and same is mcp-sudo (1001). No sudo is invoked by either client.
    for (alias, uid) in [
        ("plain", b"1000\n".as_slice()),
        ("same", b"1001\n".as_slice()),
    ] {
        let identity = fixture.direct(alias, "/usr/bin/id -u").await?;
        ensure!(
            identity.status.success() && identity.stdout == uid,
            "{alias} must be its distinct unprivileged account"
        );
    }

    let mut child = Command::new(&fixture.ssh)
        .arg("-F")
        .arg(&fixture.ssh_config)
        .args(["-T", "plain"])
        .arg(format!("exec {} -u 0000", support::quote(server)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Avoid an undrained diagnostics pipe; SSH banners never enter stdout.
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("start genuine sftp-server as mcp with umask 0000")?;
    let mut client = None;
    let result = timeout(Duration::from_secs(90), async {
        let stdin = child.stdin.take().context("SFTP stdin")?;
        let stdout = child.stdout.take().context("SFTP stdout")?;
        client = Some(Sftp::new(stdin, stdout, SftpOptions::default()).await?);
        let sftp = client.as_ref().context("connected SFTP client")?;
        let mut stage = sftp
            .options()
            .write(true)
            .create_new(true)
            .open(&private)
            .await?;
        stage.set_permissions(Permissions::from(0o600_u16)).await?;
        // Fresh options without any chmod. Under the very same server and
        // parent this must create a world-readable 0666.
        let mut readable = sftp
            .options()
            .write(true)
            .create_new(true)
            .open(&control)
            .await?;

        let metadata = fixture
            .primary_exec(&format!(
                "stat -c '%a %u' -- {parent}; stat -c '%a %u %s' -- {private_arg} {control_arg}",
                parent = support::quote(directory),
            ))
            .await?;
        ensure!(
            metadata == b"755 1000\n600 1000 0\n666 1000 0\n",
            "OPEN must create an empty 0600 stage and 0666 control: {}",
            String::from_utf8_lossy(&metadata)
        );
        let visible = fixture
            .direct("same", &format!("/bin/cat -- {control_arg}"))
            .await?;
        ensure!(
            visible.status.success() && visible.stdout.is_empty(),
            "observer cannot open empty default-mode control: {}",
            String::from_utf8_lossy(&visible.stderr)
        );
        let denied = fixture
            .direct("same", &format!("/bin/cat -- {private_arg}"))
            .await?;
        ensure!(
            denied.status.code() == Some(1)
                && denied.stdout.is_empty()
                && String::from_utf8_lossy(&denied.stderr).contains("Permission denied"),
            "observer must be denied opening the stage before any WRITE: {denied:?}"
        );

        stage
            .write_all(b"private payload after observer denial\n")
            .await?;
        readable.write_all(b"readable negative control\n").await?;
        stage.close().await?;
        readable.close().await?;
        let owner = fixture
            .direct("plain", &format!("/bin/cat -- {private_arg}"))
            .await?;
        ensure!(
            owner.status.success() && owner.stdout == b"private payload after observer denial\n",
            "owner must retain a working writable SFTP handle and readable payload"
        );
        let visible = fixture
            .direct("same", &format!("/bin/cat -- {control_arg}"))
            .await?;
        ensure!(
            visible.status.success() && visible.stdout == b"readable negative control\n",
            "observer must read the control payload through the same parent"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("private-stage acceptance exceeded ninety seconds")
    .and_then(|result| result);

    // The body has dropped every file handle even on error/cancellation.
    let closed = async {
        if let Some(client) = client {
            timeout(Duration::from_secs(10), client.close())
                .await
                .context("SFTP close deadline")??;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    // Reap on every outcome, killing a stuck/failed client before waiting.
    let reaped = async {
        if result.is_err() || closed.is_err() {
            child.start_kill()?;
        }
        match timeout(Duration::from_secs(10), child.wait()).await {
            Ok(status) => {
                let status = status?;
                if result.is_ok() && closed.is_ok() {
                    ensure!(status.success(), "SFTP SSH client failed: {status}");
                }
            }
            Err(_) => {
                child.start_kill()?;
                timeout(Duration::from_secs(10), child.wait())
                    .await
                    .context("killed SFTP SSH client reap deadline")??;
                anyhow::bail!("SFTP SSH client exit deadline");
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    result.and(closed).and(reaped)
}
