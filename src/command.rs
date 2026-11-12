use std::borrow::Cow;

use schemars::JsonSchema;
use serde::Deserialize;

use crate::reply::ToolError;

pub(crate) const MAX_COMMAND_BYTES: usize = 65_536;
const CWD_PREFIX: &str = "cd '";
const CWD_SUFFIX: &str = "' || exit\n";
const CWD_QUOTE: &str = "'\\''";

#[derive(Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Shell {
    #[default]
    Sh,
    Bash,
}

impl Shell {
    pub(crate) fn program(self) -> &'static str {
        match self {
            Self::Sh => "/bin/sh",
            Self::Bash => "bash",
        }
    }
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
pub(crate) struct RunRequest {
    pub host: String,
    pub argv: Vec<String>,
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
        validate_cwd(self.cwd.as_deref())?;
        validate_common(self.stdin.as_deref(), self.timeout_secs, max_stdin_bytes)?;
        Invocation::Shell {
            command: &self.command,
            shell: self.shell,
            cwd: self.cwd.as_deref(),
        }
        .encoded_len()
        .map(|_| ())
    }
}

impl RunRequest {
    pub(crate) fn validate(&self, max_stdin_bytes: u64) -> Result<(), ToolError> {
        if self.argv.first().is_none_or(String::is_empty) {
            return Err(invalid("argv must contain a nonempty executable"));
        }
        validate_argv(&self.argv)?;
        validate_cwd(self.cwd.as_deref())?;
        validate_common(self.stdin.as_deref(), self.timeout_secs, max_stdin_bytes)?;
        Invocation::Argv {
            argv: &self.argv,
            cwd: self.cwd.as_deref(),
        }
        .encoded_len()
        .map(|_| ())
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
        validate_argv(&self.argv)?;
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
        validate_common(self.stdin.as_deref(), self.timeout_secs, max_stdin_bytes)?;
        Invocation::Sudo {
            argv: &self.argv,
            user: &self.user,
        }
        .encoded_len()
        .map(|_| ())
    }
}

fn validate_argv(argv: &[String]) -> Result<(), ToolError> {
    let mut bytes = 0usize;
    for argument in argv {
        if argument.contains('\0') || argument.len() > MAX_COMMAND_BYTES - bytes {
            return Err(invalid(
                "argv must be NUL-free and at most 65536 combined UTF-8 bytes",
            ));
        }
        bytes += argument.len();
    }
    Ok(())
}

fn validate_cwd(cwd: Option<&str>) -> Result<(), ToolError> {
    if cwd.is_some_and(|cwd| !cwd.starts_with('/') || cwd.contains('\0')) {
        return Err(invalid("cwd must be an absolute path without NUL"));
    }
    Ok(())
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
    Argv {
        argv: &'a [String],
        cwd: Option<&'a str>,
    },
    BoundArgv {
        program: &'a str,
        arguments: Vec<Cow<'a, str>>,
        cwd: Option<&'a str>,
    },
    Sudo {
        argv: &'a [String],
        user: &'a str,
    },
    BoundSudo {
        program: &'a str,
        arguments: Vec<Cow<'a, str>>,
        user: &'a str,
    },
}

fn checked_size(bytes: usize, extra: usize) -> Result<usize, ToolError> {
    bytes
        .checked_add(extra)
        .filter(|&size| size <= MAX_COMMAND_BYTES)
        .ok_or_else(|| invalid("Escaped remote command exceeds 65536 bytes"))
}

/// Size of shell_escape::unix::escape as used by the pinned openssh encoder.
/// Fragments let cwd quoting be counted without constructing the expanded script.
#[derive(Default)]
struct EscapedSize {
    bytes: usize,
    quoted: bool,
}

impl EscapedSize {
    fn add(&mut self, fragment: &str) -> Result<(), ToolError> {
        self.bytes = checked_size(self.bytes, fragment.len())?;
        for byte in fragment.bytes() {
            match byte {
                b'\'' | b'!' => {
                    self.quoted = true;
                    self.bytes = checked_size(self.bytes, 3)?;
                }
                b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'-'
                | b'_'
                | b'='
                | b'/'
                | b','
                | b'.'
                | b'+' => {}
                _ => self.quoted = true,
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<usize, ToolError> {
        checked_size(
            self.bytes,
            if self.quoted || self.bytes == 0 { 2 } else { 0 },
        )
    }
}

fn escaped_len(argument: &str) -> Result<usize, ToolError> {
    let mut size = EscapedSize::default();
    size.add(argument)?;
    size.finish()
}

fn append_argument(bytes: &mut usize, argument_bytes: usize) -> Result<(), ToolError> {
    *bytes = checked_size(checked_size(*bytes, 1)?, argument_bytes)?;
    Ok(())
}

pub(crate) fn sudo_arguments(user: &str) -> [&str; 5] {
    ["-n", "-k", "-u", user, "--"]
}

fn argv_encoded_len<'a>(
    program: &str,
    arguments: impl IntoIterator<Item = &'a str>,
    cwd: Option<&str>,
) -> Result<usize, ToolError> {
    let mut bytes = if let Some(cwd) = cwd {
        let mut bytes = escaped_len("cd")?;
        append_argument(&mut bytes, escaped_len("--")?)?;
        append_argument(&mut bytes, escaped_len(cwd)?)?;
        // The sole raw argument in the builder, including its internal space.
        append_argument(&mut bytes, "&& command".len())?;
        bytes
    } else {
        escaped_len("command")?
    };
    append_argument(&mut bytes, escaped_len("--")?)?;
    append_argument(&mut bytes, escaped_len(program)?)?;
    for argument in arguments {
        append_argument(&mut bytes, escaped_len(argument)?)?;
    }
    Ok(bytes)
}
fn sudo_encoded_len<'a>(
    user: &'a str,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<usize, ToolError> {
    let mut bytes = escaped_len("sudo")?;
    for argument in sudo_arguments(user).into_iter().chain(arguments) {
        append_argument(&mut bytes, escaped_len(argument)?)?;
    }
    Ok(bytes)
}

impl Invocation<'_> {
    pub(crate) fn encoded_len(&self) -> Result<usize, ToolError> {
        match self {
            Self::Shell {
                command,
                shell,
                cwd,
            } => {
                let mut bytes = escaped_len(shell.program())?;
                append_argument(&mut bytes, escaped_len("-c")?)?;
                let mut script = EscapedSize::default();
                if let Some(cwd) = cwd {
                    script.add(CWD_PREFIX)?;
                    let mut parts = cwd.split('\'');
                    script.add(parts.next().unwrap_or_default())?;
                    for part in parts {
                        script.add(CWD_QUOTE)?;
                        script.add(part)?;
                    }
                    script.add(CWD_SUFFIX)?;
                }
                script.add(command)?;
                append_argument(&mut bytes, script.finish()?)?;
                Ok(bytes)
            }
            Self::Argv { argv, cwd } => {
                let (program, arguments) = argv
                    .split_first()
                    .ok_or_else(|| invalid("argv must contain a nonempty executable"))?;
                argv_encoded_len(program, arguments.iter().map(String::as_str), *cwd)
            }
            Self::BoundArgv {
                program,
                arguments,
                cwd,
            } => argv_encoded_len(program, arguments.iter().map(Cow::as_ref), *cwd),
            Self::Sudo { argv, user } => sudo_encoded_len(user, argv.iter().map(String::as_str)),
            Self::BoundSudo {
                program,
                arguments,
                user,
            } => sudo_encoded_len(
                user,
                std::iter::once(*program).chain(arguments.iter().map(Cow::as_ref)),
            ),
        }
    }
}

pub(crate) fn shell_script<'a>(command: &'a str, cwd: Option<&str>) -> Cow<'a, str> {
    let Some(cwd) = cwd else {
        return Cow::Borrowed(command);
    };
    let quote_expansion = cwd.bytes().filter(|&byte| byte == b'\'').count() * (CWD_QUOTE.len() - 1);
    let mut script = String::with_capacity(
        command.len() + cwd.len() + quote_expansion + CWD_PREFIX.len() + CWD_SUFFIX.len(),
    );
    script.push_str(CWD_PREFIX);
    for character in cwd.chars() {
        if character == '\'' {
            script.push_str(CWD_QUOTE);
        } else {
            script.push(character);
        }
    }
    script.push_str(CWD_SUFFIX);
    script.push_str(command);
    Cow::Owned(script)
}

#[cfg(test)]
mod bound_argv_tests {
    use super::*;

    fn actual_encoding(program: &str, arguments: &[Cow<'_, str>], cwd: Option<&str>) -> String {
        let escape = |value: &str| shell_escape::unix::escape(Cow::Borrowed(value)).into_owned();
        let mut encoded = match cwd {
            Some(cwd) => format!("cd -- {} && command --", escape(cwd)),
            None => "command --".into(),
        };
        for argument in std::iter::once(program).chain(arguments.iter().map(Cow::as_ref)) {
            encoded.push(' ');
            encoded.push_str(&escape(argument));
        }
        encoded
    }

    #[test]
    fn mixed_bound_values_match_ordinary_argv_and_pinned_encoder() {
        let fixed = String::from("--");
        let input = String::from("'! $(touch nope); *\n\"\\ é🙂");
        for cwd in [None, Some("/fixed ' !\n$(pwd)")] {
            for number in [i64::MIN, 0, i64::MAX] {
                let arguments = vec![
                    Cow::Borrowed(fixed.as_str()),
                    Cow::Borrowed(""),
                    Cow::Borrowed(input.as_str()),
                    Cow::Owned(number.to_string()),
                    Cow::Borrowed("true"),
                ];
                let expected = actual_encoding("/bin/printf", &arguments, cwd);
                let ordinary: Vec<String> = std::iter::once("/bin/printf")
                    .chain(arguments.iter().map(Cow::as_ref))
                    .map(str::to_owned)
                    .collect();
                let bound = Invocation::BoundArgv {
                    program: "/bin/printf",
                    arguments,
                    cwd,
                };
                assert_eq!(bound.encoded_len().unwrap(), expected.len());
                assert_eq!(
                    bound.encoded_len().unwrap(),
                    Invocation::Argv {
                        argv: &ordinary,
                        cwd
                    }
                    .encoded_len()
                    .unwrap(),
                );
                // The integer occupies one literal argument even at both i64 extrema.
                assert!(expected.ends_with(&format!(" {number} true")));
            }
        }
    }

    #[test]
    fn complete_bound_command_cap_counts_fixed_prefix_and_expanded_quotes() {
        let quoted = "'".repeat(1023);
        for cwd in [None, Some("/fixed ' !\n")] {
            let mut arguments = vec![Cow::Borrowed(quoted.as_str()); 15];
            let overhead = actual_encoding("/bin/x", &arguments, cwd).len();
            let padding = "x".repeat(MAX_COMMAND_BYTES - overhead - 1);
            arguments.push(Cow::Borrowed(padding.as_str()));
            let expected = actual_encoding("/bin/x", &arguments, cwd);
            assert_eq!(expected.len(), MAX_COMMAND_BYTES);
            let mut bound = Invocation::BoundArgv {
                program: "/bin/x",
                arguments,
                cwd,
            };
            assert_eq!(bound.encoded_len().unwrap(), MAX_COMMAND_BYTES);
            if let Invocation::BoundArgv {
                program, arguments, ..
            } = &mut bound
            {
                *program = "/bin/xx";
                assert_eq!(
                    actual_encoding(program, arguments, cwd).len(),
                    MAX_COMMAND_BYTES + 1,
                );
            }
            let error = bound.encoded_len().unwrap_err();
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }
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

    fn actual_encoded_len<'a>(arguments: impl IntoIterator<Item = &'a str>) -> usize {
        arguments
            .into_iter()
            .map(|argument| shell_escape::unix::escape(Cow::Borrowed(argument)))
            .collect::<Vec<_>>()
            .join(" ")
            .len()
    }

    #[test]
    fn escaped_size_matches_the_pinned_encoder_across_fragment_boundaries() {
        let characters: String = (1..=u8::MAX).map(char::from).collect();
        for argument in [
            "",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
            characters.as_str(),
            "space ' ! \" é🙂\n\t$()\\",
        ] {
            let expected = shell_escape::unix::escape(Cow::Borrowed(argument)).len();
            assert_eq!(escaped_len(argument).unwrap(), expected);
            for (boundary, _) in argument.char_indices() {
                let mut size = EscapedSize::default();
                size.add(&argument[..boundary]).unwrap();
                size.add(&argument[boundary..]).unwrap();
                assert_eq!(size.finish().unwrap(), expected, "boundary {boundary}");
            }
        }
    }

    #[test]
    fn complete_size_includes_nested_cwd_interpreter_and_sudo_arguments() {
        for shell in [Shell::Sh, Shell::Bash] {
            for (command, cwd) in [
                ("true", None),
                ("printf '%s\\n' \"é!\"", Some("/space ' !\nend")),
                ("#'''!!!", Some("/'")),
            ] {
                let script = shell_script(command, cwd);
                let expected = actual_encoded_len([shell.program(), "-c", script.as_ref()]);
                let observed = Invocation::Shell {
                    command,
                    shell,
                    cwd,
                }
                .encoded_len()
                .unwrap();
                assert_eq!(observed, expected);
            }
        }
        let argv: Vec<String> = ["/bin/printf", "", "space ' !\n", "é🙂"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let expected = actual_encoded_len(
            ["sudo", "-n", "-k", "-u", "some-user", "--"]
                .into_iter()
                .chain(argv.iter().map(String::as_str)),
        );
        assert_eq!(
            Invocation::Sudo {
                argv: &argv,
                user: "some-user"
            }
            .encoded_len()
            .unwrap(),
            expected
        );
        assert_eq!(
            Invocation::BoundSudo {
                program: &argv[0],
                arguments: argv[1..]
                    .iter()
                    .map(|v| Cow::Borrowed(v.as_str()))
                    .collect(),
                user: "some-user",
            }
            .encoded_len()
            .unwrap(),
            expected,
        );
    }

    #[test]
    fn full_command_boundaries_include_separators_and_empty_arguments() {
        for (shell, overhead) in [(Shell::Sh, 11), (Shell::Bash, 8)] {
            let mut request = exec("x".repeat(MAX_COMMAND_BYTES - overhead));
            request.shell = shell;
            assert_eq!(
                actual_encoded_len([shell.program(), "-c", request.command.as_str()]),
                MAX_COMMAND_BYTES
            );
            request.validate(0).unwrap();
            request.command.push('x');
            assert_eq!(request.validate(0).unwrap_err().code, "invalid_argument");
        }
        let mut request = sudo(vec![String::new(); 21_837]);
        request.argv[0] = "/bin/x".into();
        assert_eq!(
            actual_encoded_len(
                ["sudo", "-n", "-k", "-u", "root", "--"]
                    .into_iter()
                    .chain(request.argv.iter().map(String::as_str)),
            ),
            MAX_COMMAND_BYTES
        );
        request.validate(0).unwrap();
        let bound_size = |argv: &[String]| {
            Invocation::BoundSudo {
                program: &argv[0],
                arguments: argv[1..]
                    .iter()
                    .map(|v| Cow::Borrowed(v.as_str()))
                    .collect(),
                user: "root",
            }
            .encoded_len()
        };
        assert_eq!(bound_size(&request.argv).unwrap(), MAX_COMMAND_BYTES);
        request.argv.push(String::new());
        assert_eq!(request.validate(0).unwrap_err().code, "invalid_argument");
        let error = bound_size(&request.argv).unwrap_err();
        assert_eq!(error.code, "invalid_argument");
        assert!(!error.remote_state_unknown);
    }

    #[test]
    fn encoded_size_rejects_overflow_as_known_unmodified_input() {
        assert_eq!(
            checked_size(MAX_COMMAND_BYTES, 0).unwrap(),
            MAX_COMMAND_BYTES
        );
        for (bytes, extra) in [(MAX_COMMAND_BYTES, 1), (usize::MAX, 1)] {
            let error = checked_size(bytes, extra).unwrap_err();
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }

    #[test]
    fn validates_command_utf8_byte_limit_and_nul() {
        assert!(exec("é".repeat(32_761)).validate(0).is_ok());
        for command in [String::new(), "echo\0bad".into(), "é".repeat(32_762)] {
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
        let mut request = sudo(vec!["/bin/x".into(), "é".repeat(32_752)]);
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

    fn run(argv: Vec<String>) -> RunRequest {
        RunRequest {
            host: "target".into(),
            argv,
            cwd: None,
            stdin: None,
            timeout_secs: None,
        }
    }

    fn actual_run_encoding(argv: &[String], cwd: Option<&str>) -> String {
        let escape =
            |argument: &str| shell_escape::unix::escape(Cow::Borrowed(argument)).into_owned();
        let prefix = match cwd {
            Some(cwd) => format!("cd -- {} && command --", escape(cwd)),
            None => "command --".into(),
        };
        argv.iter().fold(prefix, |mut encoded, argument| {
            encoded.push(' ');
            encoded.push_str(&escape(argument));
            encoded
        })
    }

    #[test]
    fn run_encoding_counts_literal_argv_and_only_the_fixed_raw_join() {
        for (program, cwd) in [
            ("printf", None),
            ("./relative", Some("/plain")),
            ("/bin/printf", Some("/space ' !\n")),
            ("NAME=value", None),
            ("if", Some("/")),
            ("-option", None),
        ] {
            let argv = [program, "", "'!", "$(touch nope); *\n", "é🙂"].map(str::to_owned);
            let expected = actual_run_encoding(&argv, cwd);
            assert_eq!(
                Invocation::Argv { argv: &argv, cwd }.encoded_len().unwrap(),
                expected.len(),
                "program {program:?}, cwd {cwd:?}"
            );
            let mut request = run(Vec::from(argv));
            request.cwd = cwd.map(str::to_owned);
            request.validate(0).unwrap();
        }
    }

    #[test]
    fn run_encoded_cap_includes_prefix_cwd_quotes_and_empty_arguments() {
        for (cwd, argument) in [(None, ""), (Some("/' !"), "'!")] {
            let mut request = run(vec!["x".into(), argument.into(), String::new()]);
            request.cwd = cwd.map(str::to_owned);
            let overhead = actual_run_encoding(&request.argv, cwd).len();
            // Keep the empty argument and grow a separate safe argument to the cap.
            request
                .argv
                .push("x".repeat(MAX_COMMAND_BYTES - overhead - 1));
            assert_eq!(
                actual_run_encoding(&request.argv, cwd).len(),
                MAX_COMMAND_BYTES
            );
            assert_eq!(
                Invocation::Argv {
                    argv: &request.argv,
                    cwd
                }
                .encoded_len()
                .unwrap(),
                MAX_COMMAND_BYTES
            );
            request.validate(0).unwrap();
            request.argv.last_mut().unwrap().push('x');
            assert_eq!(request.validate(0).unwrap_err().code, "invalid_argument");
        }
        // Empty arguments have no raw payload, but their quotes and separators count.
        let mut request = run(vec!["xx".into()]);
        request.argv.resize_with(21_842, String::new);
        assert_eq!(
            actual_run_encoding(&request.argv, None).len(),
            MAX_COMMAND_BYTES
        );
        request.validate(0).unwrap();
        request.argv.push(String::new());
        assert!(request.validate(0).is_err());
    }

    #[test]
    fn run_rejects_invalid_program_arguments_cwd_stdin_and_timeout() {
        for argv in [
            vec![],
            vec![String::new()],
            vec!["bad\0program".into()],
            vec!["printf".into(), "bad\0argument".into()],
        ] {
            assert_eq!(run(argv).validate(0).unwrap_err().code, "invalid_argument");
        }
        let mut request = run(vec!["cat".into()]);
        for cwd in ["", "relative", "/bad\0path"] {
            request.cwd = Some(cwd.into());
            assert_eq!(request.validate(0).unwrap_err().code, "invalid_argument");
        }
        request.cwd = Some("/with ' quote\nand newline".into());
        request.stdin = Some("é\0".into());
        request.validate(3).unwrap();
        assert!(request.validate(2).is_err());
        request.timeout_secs = Some(0);
        assert!(request.validate(3).is_err());
    }
}
