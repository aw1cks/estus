use std::io;
use std::time::Instant;

use openssh::{Session, Stdio};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::command::{Invocation, shell_script, sudo_arguments};
use crate::reply::{CommandData, Termination, ToolError, ToolReply};

pub(crate) struct RunContext<'a> {
    pub max_output_bytes: u64,
    pub deadline: tokio::time::Instant,
    pub ct: &'a CancellationToken,
    pub shutdown: &'a CancellationToken,
    pub started: Instant,
}

struct Capture {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl Capture {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            truncated: false,
        }
    }

    fn retain(&mut self, bytes: &[u8]) {
        let retained = bytes.len().min(self.limit - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
        self.truncated |= retained < bytes.len();
    }

    fn decode(self) -> (String, bool, bool) {
        match String::from_utf8(self.bytes) {
            Ok(text) => (text, self.truncated, false),
            Err(error) => (
                String::from_utf8_lossy(error.as_bytes()).into_owned(),
                self.truncated,
                true,
            ),
        }
    }
}

async fn drain<R: AsyncRead + Unpin>(mut stream: R, capture: &mut Capture) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        capture.retain(&buffer[..count]);
    }
}

async fn send_stdin(stream: Option<openssh::ChildStdin>, input: Option<&str>) -> io::Result<()> {
    if let Some(mut stream) = stream {
        if let Some(input) = input {
            // Early exit/closed stdin is ordinary command behavior, not transport loss.
            if let Err(error) = stream.write_all(input.as_bytes()).await {
                return if error.kind() == io::ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(error)
                };
            }
        }
        if let Err(error) = stream.shutdown().await
            && error.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(error);
        }
    }
    Ok(())
}

struct Completion {
    exit_code: i32,
    io_failed: bool,
}

enum Outcome {
    Completed(Completion),
    Backend(openssh::Error),
    Timeout,
    Cancelled,
}

fn argv_command<'s, 'a>(
    session: &'s Session,
    program: &str,
    arguments: impl IntoIterator<Item = &'a str>,
    cwd: Option<&str>,
) -> openssh::Command<'s> {
    let mut command = if let Some(cwd) = cwd {
        let mut command = session.command("cd");
        // Only fixed syntax is raw; cwd, program and arguments remain escaped data.
        command.arg("--").arg(cwd).raw_arg("&& exec");
        command
    } else {
        session.command("exec")
    };
    command.arg("--").arg(program).args(arguments);
    command
}

/// Run only a native mux channel. Dropping the operation closes that channel, never the master.
pub(crate) async fn run(
    session: &Session,
    invocation: Invocation<'_>,
    stdin: Option<&str>,
    context: RunContext<'_>,
) -> ToolReply<CommandData> {
    let mut stdout = Capture::new(context.max_output_bytes);
    let mut stderr = Capture::new(context.max_output_bytes);
    let outcome = {
        let operation = async {
            let mut command = match invocation {
                Invocation::Shell {
                    command: script,
                    shell,
                    cwd,
                } => {
                    let mut command = session.command(shell.program());
                    command.arg("-c").arg(shell_script(script, cwd));
                    command
                }
                Invocation::Argv { argv, cwd } => {
                    argv_command(session, &argv[0], argv[1..].iter().map(String::as_str), cwd)
                }
                Invocation::BoundArgv {
                    program,
                    arguments,
                    cwd,
                } => argv_command(
                    session,
                    program,
                    arguments.iter().map(|value| value.as_ref()),
                    cwd,
                ),
                Invocation::Sudo { argv, user } => {
                    let mut command = session.command("sudo");
                    command.args(sudo_arguments(user)).args(argv);
                    command
                }
                Invocation::BoundSudo {
                    program,
                    arguments,
                    user,
                } => {
                    let mut command = session.command("sudo");
                    command
                        .args(sudo_arguments(user))
                        .arg(program)
                        .args(arguments.iter().map(|value| value.as_ref()));
                    command
                }
            };
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            command.stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            });
            let mut child = command.spawn().await?;
            let input = child.stdin().take();
            let output = child
                .stdout()
                .take()
                .ok_or_else(|| openssh::Error::ChildIo(io::Error::other("missing stdout pipe")))?;
            let errors = child
                .stderr()
                .take()
                .ok_or_else(|| openssh::Error::ChildIo(io::Error::other("missing stderr pipe")))?;

            // Child::wait consumes the native channel and closes its pipes on completion.
            // Drain before polling wait so buffered tail bytes cannot be lost. The outer
            // select bounds this entire join, including descendants retaining pipe FDs.
            let (out, err, input) = tokio::join!(
                drain(output, &mut stdout),
                drain(errors, &mut stderr),
                send_stdin(input, stdin),
            );
            let io_failed = out.is_err() || err.is_err() || input.is_err();
            let exit_code = match child.wait().await {
                // Native mux cannot distinguish a remote signal from a channel
                // closed while remote work continues. Only an exit code proves completion.
                Ok(status) => status
                    .code()
                    .ok_or(openssh::Error::RemoteProcessTerminated)?,
                Err(openssh::Error::Remote(error)) if error.kind() == io::ErrorKind::NotFound => {
                    127
                }
                Err(error) => return Err(error),
            };
            Ok::<_, openssh::Error>(Completion {
                exit_code,
                io_failed,
            })
        };
        tokio::select! {
            biased;
            () = context.ct.cancelled() => Outcome::Cancelled,
            () = context.shutdown.cancelled() => Outcome::Cancelled,
            () = tokio::time::sleep_until(context.deadline) => Outcome::Timeout,
            result = operation => match result {
                Ok(completion) => Outcome::Completed(completion),
                Err(error) => Outcome::Backend(error),
            },
        }
        // All operation-owned pipes and the wait/spawn future are dropped here before
        // captures are decoded; no task owns output that cancellation could discard.
    };

    let (exit_code, termination, error, unknown) = match outcome {
        Outcome::Completed(completion) => {
            let error = if completion.io_failed {
                Some(ToolError::new(
                    "io_error",
                    "Command stream I/O failed",
                    false,
                ))
            } else if completion.exit_code != 0 {
                Some(ToolError::new(
                    "command_failed",
                    "Remote command failed",
                    false,
                ))
            } else {
                None
            };
            (
                Some(completion.exit_code),
                Termination::Exited,
                error,
                false,
            )
        }
        Outcome::Timeout => (
            None,
            Termination::Timeout,
            Some(ToolError::new(
                "timeout",
                "Command deadline exceeded; remote execution may continue",
                true,
            )),
            true,
        ),
        Outcome::Cancelled => (
            None,
            Termination::Cancelled,
            Some(ToolError::new(
                "cancelled",
                "Command cancelled; remote execution may continue",
                true,
            )),
            true,
        ),
        Outcome::Backend(error) => {
            let lost = connection_lost(&error);
            let error = if lost {
                ToolError::new(
                    "connection_lost",
                    "SSH command channel was lost; remote execution state is unknown",
                    true,
                )
            } else {
                ToolError::new(
                    "io_error",
                    "SSH command channel failed; remote execution state is unknown",
                    true,
                )
            };
            (None, Termination::ConnectionLost, Some(error), true)
        }
    };
    let (stdout, stdout_truncated, stdout_lossy) = stdout.decode();
    let (stderr, stderr_truncated, stderr_lossy) = stderr.decode();
    let data = CommandData {
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        stdout_lossy,
        stderr_lossy,
        exit_code,
        termination,
        duration_ms: u64::try_from(context.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        remote_may_still_be_running: unknown,
    };
    ToolReply {
        data: Some(data),
        error,
    }
}

fn connection_lost(error: &openssh::Error) -> bool {
    use std::error::Error;
    if matches!(
        error,
        openssh::Error::Disconnected
            | openssh::Error::Master(_)
            | openssh::Error::Connect(_)
            | openssh::Error::RemoteProcessTerminated
    ) {
        return true;
    }
    // Inspect typed I/O sources, never localized stderr or backend diagnostic strings.
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<io::Error>()
            && matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::NotConnected
            )
        {
            return true;
        }
        source = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_capture_marks_split_utf8_and_discards_later_bytes() {
        let mut capture = Capture::new(4);
        capture.retain(b"ab");
        capture.retain("€".as_bytes());
        capture.retain(b"later");
        assert_eq!(capture.bytes, [b'a', b'b', 0xe2, 0x82]);
        assert_eq!(capture.decode(), ("ab�".into(), true, true));
        let mut capture = Capture::new(3);
        capture.retain("€".as_bytes());
        assert_eq!(capture.decode(), ("€".into(), false, false));
        let mut capture = Capture::new(0);
        capture.retain(b"discard");
        assert_eq!(capture.decode(), (String::new(), true, false));
    }

    #[test]
    fn typed_transport_errors_do_not_classify_remote_exit_errors() {
        assert!(connection_lost(&openssh::Error::Disconnected));
        assert!(connection_lost(&openssh::Error::ChildIo(io::Error::from(
            io::ErrorKind::UnexpectedEof
        ))));
        assert!(!connection_lost(&openssh::Error::Remote(io::Error::from(
            io::ErrorKind::NotFound
        ))));
        assert!(!connection_lost(&openssh::Error::ChildIo(
            io::Error::other("Connection reset by peer")
        )));
    }
}
