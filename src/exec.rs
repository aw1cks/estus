use std::borrow::Cow;
use std::io;
use std::time::Instant;

use openssh::{Session, Stdio};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::server::{ToolError, ToolReply};

const MAX_COMMAND_BYTES: usize = 65_536;

#[derive(Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Shell {
    #[default]
    Sh,
    Bash,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecRequest {
    pub host: String,
    pub command: String,
    #[serde(default)]
    pub shell: Shell,
    pub cwd: Option<String>,
    pub stdin: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SudoRequest {
    pub host: String,
    pub argv: Vec<String>,
    #[serde(default = "root_user")]
    pub user: String,
    pub stdin: Option<String>,
    pub timeout_secs: Option<u64>,
}

fn root_user() -> String {
    "root".to_owned()
}

fn invalid(message: &'static str) -> ToolError {
    ToolError::new("invalid_argument", message, false)
}

impl ExecRequest {
    pub(crate) fn validate(&self, max_stdin_bytes: u64) -> Result<(), ToolError> {
        if self.command.is_empty()
            || self.command.contains('\0')
            || self.command.len() > MAX_COMMAND_BYTES
        {
            return Err(invalid(
                "command must be nonempty, NUL-free, and at most 65536 UTF-8 bytes",
            ));
        }
        if self
            .cwd
            .as_ref()
            .is_some_and(|cwd| !cwd.starts_with('/') || cwd.contains('\0'))
        {
            return Err(invalid("cwd must be an absolute path without NUL"));
        }
        validate_common(self.stdin.as_deref(), self.timeout_secs, max_stdin_bytes)
    }
}

impl SudoRequest {
    pub(crate) fn validate(&self, max_stdin_bytes: u64) -> Result<(), ToolError> {
        let Some(program) = self.argv.first() else {
            return Err(invalid("argv must contain an absolute executable path"));
        };
        if !program.starts_with('/') || program.ends_with('/') {
            return Err(invalid(
                "argv[0] must be an absolute executable path without a trailing slash",
            ));
        }
        let mut bytes = 0usize;
        for argument in &self.argv {
            if argument.contains('\0') || argument.len() > MAX_COMMAND_BYTES - bytes {
                return Err(invalid(
                    "argv must be NUL-free and at most 65536 combined UTF-8 bytes",
                ));
            }
            bytes += argument.len();
        }
        // Match the configured policy's named-account syntax, excluding sudo options and IDs.
        if self.user.is_empty()
            || !self.user.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic()
                    || byte == b'_'
                    || (index > 0 && (byte.is_ascii_digit() || byte == b'-' || byte == b'.'))
            })
        {
            return Err(invalid("user must be a named account"));
        }
        validate_common(self.stdin.as_deref(), self.timeout_secs, max_stdin_bytes)
    }
}

fn validate_common(
    stdin: Option<&str>,
    timeout_secs: Option<u64>,
    max_stdin_bytes: u64,
) -> Result<(), ToolError> {
    if stdin.is_some_and(|input| input.len() as u64 > max_stdin_bytes) {
        return Err(invalid("stdin exceeds the configured byte limit"));
    }
    if timeout_secs == Some(0) {
        return Err(invalid("timeout_secs must be positive"));
    }
    Ok(())
}

pub(crate) enum Invocation<'a> {
    Shell {
        command: &'a str,
        shell: Shell,
        cwd: Option<&'a str>,
    },
    Sudo {
        argv: &'a [String],
        user: &'a str,
    },
}

pub(crate) struct RunContext<'a> {
    pub max_output_bytes: u64,
    pub deadline: tokio::time::Instant,
    pub ct: &'a CancellationToken,
    pub shutdown: &'a CancellationToken,
    pub started: Instant,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Termination {
    Exited,
    Timeout,
    Cancelled,
    ConnectionLost,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct CommandData {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_lossy: bool,
    pub stderr_lossy: bool,
    pub exit_code: Option<i32>,
    pub termination: Termination,
    pub duration_ms: u64,
    pub remote_may_still_be_running: bool,
}

fn shell_script<'a>(command: &'a str, cwd: Option<&str>) -> Cow<'a, str> {
    let Some(cwd) = cwd else {
        return Cow::Borrowed(command);
    };
    let quote_expansion = cwd.bytes().filter(|&byte| byte == b'\'').count() * 3;
    let mut script = String::with_capacity(command.len() + cwd.len() + quote_expansion + 14);
    script.push_str("cd '");
    for character in cwd.chars() {
        if character == '\'' {
            script.push_str("'\\''");
        } else {
            script.push(character);
        }
    }
    script.push_str("' || exit\n");
    script.push_str(command);
    Cow::Owned(script)
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
                    let mut command = session.command(match shell {
                        Shell::Sh => "/bin/sh",
                        Shell::Bash => "bash",
                    });
                    command.arg("-c").arg(shell_script(script, cwd));
                    command
                }
                Invocation::Sudo { argv, user } => {
                    let mut command = session.command("sudo");
                    command.args(["-n", "-k", "-u", user, "--"]).args(argv);
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

    fn exec(command: String) -> ExecRequest {
        ExecRequest {
            host: "target".into(),
            command,
            shell: Shell::Sh,
            cwd: None,
            stdin: None,
            timeout_secs: None,
        }
    }

    fn sudo(argv: Vec<String>) -> SudoRequest {
        SudoRequest {
            host: "target".into(),
            argv,
            user: "root".into(),
            stdin: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn validates_command_utf8_byte_limit_and_nul() {
        assert!(exec("é".repeat(32_768)).validate(0).is_ok());
        for command in [String::new(), "echo\0bad".into(), "é".repeat(32_769)] {
            assert_eq!(
                exec(command).validate(0).unwrap_err().code,
                "invalid_argument"
            );
        }
        let mut request = exec("pwd".into());
        for cwd in ["", "relative", "/bad\0path"] {
            request.cwd = Some(cwd.into());
            assert!(request.validate(0).is_err());
        }
        request.cwd = Some("/with ' quote\nand newline".into());
        assert!(request.validate(0).is_ok());
    }

    #[test]
    fn validates_sudo_program_and_combined_argument_bytes() {
        for argv in [
            vec![],
            vec!["relative".into()],
            vec!["/".into()],
            vec!["/bin/".into()],
            vec!["/bin/id".into(), "bad\0argument".into()],
        ] {
            assert!(sudo(argv).validate(0).is_err());
        }
        let mut request = sudo(vec!["/bin/x".into(), "é".repeat(32_765)]);
        assert!(request.validate(0).is_ok());
        request.argv.push("a".into());
        assert!(request.validate(0).is_err());
        request.argv = vec!["/bin/printf".into(), "".into(), "' ; $(id)\n".into()];
        assert!(request.validate(0).is_ok());
        for user in ["", "-root", "#0", "user\0bad", "user name"] {
            request.user = user.into();
            assert!(request.validate(0).is_err());
        }
    }

    #[test]
    fn stdin_limit_counts_bytes_and_allows_nul() {
        let mut request = exec("cat".into());
        request.stdin = Some("é\0".into());
        assert!(request.validate(3).is_ok());
        assert!(request.validate(2).is_err());
        request.timeout_secs = Some(0);
        assert!(request.validate(3).is_err());
    }

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
