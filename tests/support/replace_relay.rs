//! Test-private transparent relay: never generates an SFTP response.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, Command},
    task::JoinHandle,
    time::timeout,
};

#[derive(Clone, Copy)]
pub enum Fault {
    None,
    OpenAck,
    RenameAck,
}

#[derive(Default, Debug)]
pub struct Evidence {
    pub requests: Vec<u8>,
    pub renames: usize,
    pub dropped_success: bool,
    pub dropped_open: bool,
    pub staged_partial: bool,
    pub writes: usize,
    pub rename_index: Option<usize>,
    rename_id: Option<u32>,
    open_id: Option<u32>,
}

pub struct Oracle {
    pub destination: PathBuf,
    pub hardlink: PathBuf,
    pub old: Vec<u8>,
    pub inode: u64,
    pub new_len: usize,
}

pub struct Relay {
    pub launches: PathBuf,
    work: tempfile::TempDir,
    children: Vec<Child>,
    task: JoinHandle<Result<()>>,
    pub evidence: Arc<Mutex<Evidence>>,
    pub subsystem: String,
}

async fn frame(reader: &mut (impl AsyncRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut header = [0; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        (1..=2_097_152).contains(&length),
        "unbounded SFTP frame: {length}"
    );
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

async fn forward(writer: &mut (impl AsyncWrite + Unpin), body: &[u8]) -> Result<()> {
    writer.write_u32(body.len() as u32).await?;
    writer.write_all(body).await?;
    writer.flush().await?;
    Ok(())
}

async fn reap(children: &mut Vec<Child>) -> Result<()> {
    let mut failures = Vec::new();
    for child in children {
        let result = async {
            if child.try_wait()?.is_none() {
                child.start_kill()?;
            }
            timeout(Duration::from_secs(5), child.wait()).await??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            failures.push(error.to_string());
        }
    }
    ensure!(failures.is_empty(), "relay cleanup: {failures:?}");
    Ok(())
}

impl Relay {
    pub async fn start(server: &Path, fault: Fault, oracle: Option<Oracle>) -> Result<Self> {
        let work = tempfile::tempdir()?;
        fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700))?;
        let requests = work.path().join("requests");
        let responses = work.path().join("responses");
        let launches = work.path().join("launches");
        ensure!(
            work.path()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'.' | b'-' | b'_')),
            "native relay requires a shell-safe private temporary path"
        );
        fs::write(&launches, b"")?;
        for path in [&requests, &responses] {
            nix::unistd::mkfifo(
                path.as_path(),
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )?;
        }
        let script = format!(
            "echo launch >> {}; exec 3<&0; cat <&3 > {} & cat < {}; wait",
            launches.display(),
            requests.display(),
            responses.display(),
        );
        let subsystem = format!("/bin/sh -c {}", super::support::quote(&script));
        let mut children = Vec::new();
        let setup = async {
            children.push(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        &format!(
                            "exec cat < {}",
                            super::support::quote(&requests.to_string_lossy())
                        ),
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?,
            );
            let input = children
                .last_mut()
                .context("request cat")?
                .stdout
                .take()
                .context("request pipe")?;
            children.push(
                Command::new("/bin/sh")
                    .args([
                        "-c",
                        &format!(
                            "exec cat > {}",
                            super::support::quote(&responses.to_string_lossy())
                        ),
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?,
            );
            let output = children
                .last_mut()
                .context("response cat")?
                .stdin
                .take()
                .context("response pipe")?;
            children.push(
                Command::new(server)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .spawn()?,
            );
            let child = children.last_mut().context("real sftp-server")?;
            let remote_in = child.stdin.take().context("server stdin")?;
            let remote_out = child.stdout.take().context("server stdout")?;
            Ok::<_, anyhow::Error>((input, output, remote_in, remote_out))
        }
        .await;
        let (mut input, mut output, mut remote_in, mut remote_out) = match setup {
            Ok(pipes) => pipes,
            Err(error) => {
                let _ = reap(&mut children).await;
                return Err(error);
            }
        };
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        let requests_seen = evidence.clone();
        let replies_seen = evidence.clone();
        let (status_tx, mut status_rx) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(async move {
            let requests = async move {
                while let Some(body) = frame(&mut input).await? {
                    {
                        let mut seen = requests_seen
                            .lock()
                            .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                        ensure!(seen.requests.len() < 4096, "too many SFTP requests");
                        seen.requests.push(body[0]);
                        if body[0] == 3 && body.len() >= 5 {
                            seen.open_id = Some(u32::from_be_bytes(body[1..5].try_into()?));
                        }
                        if body[0] == 6 {
                            seen.writes += 1;
                            if let Some(oracle) = &oracle {
                                ensure!(
                                    fs::read(&oracle.destination)? == oracle.old,
                                    "destination changed during staging"
                                );
                                ensure!(
                                    fs::metadata(&oracle.destination)?.ino() == oracle.inode,
                                    "destination inode changed before rename"
                                );
                                ensure!(
                                    fs::read(&oracle.hardlink)? == oracle.old,
                                    "old hardlink changed during staging"
                                );
                                let stages = fs::read_dir(
                                    oracle.destination.parent().context("destination parent")?,
                                )?
                                .collect::<std::io::Result<Vec<_>>>()?;
                                let stages: Vec<_> = stages
                                    .iter()
                                    .filter(|entry| {
                                        entry
                                            .file_name()
                                            .to_string_lossy()
                                            .starts_with(".estus-replace-")
                                    })
                                    .collect();
                                ensure!(stages.len() == 1, "expected one owned sibling stage");
                                let name = stages[0].file_name();
                                let name = name.to_string_lossy();
                                let suffix = name
                                    .strip_prefix(".estus-replace-")
                                    .context("stage prefix")?;
                                ensure!(
                                    suffix.len() == 32
                                        && suffix
                                            .bytes()
                                            .all(|b| b.is_ascii_digit()
                                                || (b'a'..=b'f').contains(&b)),
                                    "stage name: {name}"
                                );
                                let metadata = stages[0].metadata()?;
                                ensure!(
                                    metadata.mode() & 0o7777 == 0o600,
                                    "content write before mode0600"
                                );
                                seen.staged_partial |=
                                    metadata.len() > 0 && metadata.len() < oracle.new_len as u64;
                            }
                        }
                        if body[0] == 200 && body.len() >= 9 {
                            let length = u32::from_be_bytes(body[5..9].try_into()?) as usize;
                            if body.get(9..9 + length)
                                == Some(b"posix-rename@openssh.com".as_slice())
                            {
                                seen.renames += 1;
                                seen.rename_index = Some(seen.requests.len() - 1);
                                seen.rename_id = Some(u32::from_be_bytes(body[1..5].try_into()?));
                            }
                        }
                    }
                    forward(&mut remote_in, &body).await?;
                    // Serialize only genuine writes against their genuine STATUS:
                    // the next stage observation cannot race server write dispatch.
                    if body[0] == 6 {
                        let id = u32::from_be_bytes(body[1..5].try_into()?);
                        status_rx.wait_for(|status| *status == Some(id)).await?;
                    }
                }
                // Half-close only the request direction. Drain the real server's
                // remaining responses and EOF before closing the response FIFO.
                drop(remote_in);
                Ok::<_, anyhow::Error>(())
            };
            let replies = async move {
                while let Some(body) = frame(&mut remote_out).await? {
                    if body[0] == 101 && body.len() >= 9 {
                        status_tx.send_replace(Some(u32::from_be_bytes(body[1..5].try_into()?)));
                    }
                    let discard = {
                        let mut seen = replies_seen
                            .lock()
                            .map_err(|_| anyhow::anyhow!("relay evidence poisoned"))?;
                        if matches!(fault, Fault::OpenAck)
                            && body[0] == 102
                            && body.len() >= 5
                            && Some(u32::from_be_bytes(body[1..5].try_into()?)) == seen.open_id
                        {
                            ensure!(!seen.dropped_open, "replayed OPEN HANDLE");
                            seen.dropped_open = true;
                            true
                        } else if matches!(fault, Fault::RenameAck)
                            && body[0] == 101
                            && body.len() >= 9
                            && Some(u32::from_be_bytes(body[1..5].try_into()?)) == seen.rename_id
                        {
                            ensure!(
                                u32::from_be_bytes(body[5..9].try_into()?) == 0,
                                "real rename failed instead of applying"
                            );
                            ensure!(!seen.dropped_success, "replayed rename STATUS");
                            seen.dropped_success = true;
                            true
                        } else {
                            false
                        }
                    };
                    if !discard {
                        forward(&mut output, &body).await?;
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(requests, replies).map(|_| ())
        });
        Ok(Self {
            work,
            children,
            task,
            evidence,
            subsystem,
            launches,
        })
    }

    pub async fn stop(mut self) -> Result<()> {
        // A still-live task is normal while the deliberately discarded STATUS is pending.
        let task_result = if self.task.is_finished() {
            Some(
                (&mut self.task)
                    .await
                    .context("relay task panicked")
                    .and_then(|result| result),
            )
        } else {
            self.task.abort();
            match (&mut self.task).await {
                Ok(result) => Some(result),
                Err(error) if error.is_cancelled() => None,
                Err(error) => Some(Err(error.into())),
            }
        };
        let reaped = reap(&mut self.children).await;
        let removed = self.work.close();
        reaped?;
        removed?;
        // Clean EOF is handled at frame boundaries; truncated frames are errors.
        // Only a closed client pipe during teardown may be ignored.
        if let Some(Err(error)) = task_result
            && !error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe)
        {
            return Err(error);
        }
        Ok(())
    }
}
