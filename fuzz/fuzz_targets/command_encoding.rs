#![no_main]
#![allow(dead_code)]

use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

#[path = "../../src/command.rs"]
mod command;
#[path = "../../src/reply.rs"]
mod reply;

use command::{ExecRequest, Invocation, MAX_COMMAND_BYTES, RunRequest, Shell, SudoRequest};

// Bound raw JSON before deserialization and every expansion before allocation.
const MAX_INPUT_BYTES: usize = 16_384;
const MAX_FIELD_BYTES: usize = 131_072;
const MAX_EXPANDED_BYTES: usize = 262_144;
const MAX_ARGUMENTS: usize = 21_844;
const MAX_EXPLICIT_ARGUMENTS: usize = 64;

fn one() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Text {
    Literal(String),
    Repeated {
        text: String,
        #[serde(default = "one")]
        repeat: usize,
    },
}

impl Text {
    fn expand(self, remaining: &mut usize) -> Option<String> {
        let (text, repeat) = match self {
            Self::Literal(text) => (text, 1),
            Self::Repeated { text, repeat } => (text, repeat),
        };
        if repeat > MAX_FIELD_BYTES {
            return None;
        }
        let bytes = text.len().checked_mul(repeat)?;
        if bytes > MAX_FIELD_BYTES || bytes > *remaining {
            return None;
        }
        *remaining -= bytes;
        Some(if repeat == 1 {
            text
        } else {
            text.repeat(repeat)
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Fixture {
    Exec {
        command: Text,
        #[serde(default)]
        shell: Shell,
        cwd: Option<Text>,
        stdin: Option<Text>,
        timeout_secs: Option<u64>,
        #[serde(default)]
        max_stdin_bytes: u64,
    },
    Run {
        argv: Vec<Text>,
        #[serde(default)]
        empty_args: usize,
        cwd: Option<Text>,
        stdin: Option<Text>,
        timeout_secs: Option<u64>,
        #[serde(default)]
        max_stdin_bytes: u64,
    },
    Sudo {
        argv: Vec<Text>,
        #[serde(default)]
        empty_args: usize,
        #[serde(default = "root")]
        user: String,
        stdin: Option<Text>,
        timeout_secs: Option<u64>,
        #[serde(default)]
        max_stdin_bytes: u64,
    },
}

fn root() -> String {
    "root".into()
}

fn expand_optional(text: Option<Text>, remaining: &mut usize) -> Option<Option<String>> {
    match text {
        Some(text) => Some(Some(text.expand(remaining)?)),
        None => Some(None),
    }
}

fn expand_argv(argv: Vec<Text>, empty_args: usize, remaining: &mut usize) -> Option<Vec<String>> {
    if argv.len() > MAX_EXPLICIT_ARGUMENTS
        || empty_args > MAX_ARGUMENTS
        || argv.len().checked_add(empty_args)? > MAX_ARGUMENTS
    {
        return None;
    }
    let mut arguments = Vec::with_capacity(argv.len() + empty_args);
    for argument in argv {
        arguments.push(argument.expand(remaining)?);
    }
    arguments.resize_with(arguments.len() + empty_args, String::new);
    Some(arguments)
}

fn encoded<'a>(arguments: impl IntoIterator<Item = &'a str>) -> String {
    arguments
        .into_iter()
        .map(|argument| shell_escape::unix::escape(Cow::Borrowed(argument)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn check_accounting(invocation: Invocation<'_>, expected: usize) {
    match invocation.encoded_len() {
        Ok(observed) => {
            assert!(expected <= MAX_COMMAND_BYTES);
            assert_eq!(observed, expected);
        }
        Err(error) => {
            assert!(expected > MAX_COMMAND_BYTES);
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }
}

fn check_validation(result: Result<(), reply::ToolError>, valid: bool, encoded_bytes: usize) {
    assert_eq!(result.is_ok(), valid);
    match result {
        Ok(()) => assert!(encoded_bytes <= MAX_COMMAND_BYTES),
        Err(error) => {
            assert_eq!(error.code, "invalid_argument");
            assert!(!error.remote_state_unknown);
        }
    }
}

fn common_valid(stdin: Option<&str>, timeout: Option<u64>, limit: u64) -> bool {
    stdin.is_none_or(|text| text.len() as u64 <= limit) && timeout != Some(0)
}

fn exercise(fixture: Fixture) -> Option<()> {
    let mut remaining = MAX_EXPANDED_BYTES;
    match fixture {
        Fixture::Exec {
            command,
            shell,
            cwd,
            stdin,
            timeout_secs,
            max_stdin_bytes,
        } => {
            let request = ExecRequest {
                host: "unused".into(),
                command: command.expand(&mut remaining)?,
                shell,
                cwd: expand_optional(cwd, &mut remaining)?,
                stdin: expand_optional(stdin, &mut remaining)?,
                timeout_secs,
                retain_output: false,
            };
            // Independently render the cwd wrapper, then use the actual pinned
            // encoder rather than reproducing production escaped-size arithmetic.
            let expected_script = match request.cwd.as_deref() {
                Some(cwd) => format!(
                    "cd '{}' || exit\n{}",
                    cwd.replace('\'', "'\\''"),
                    request.command
                ),
                None => request.command.clone(),
            };
            let script = command::shell_script(&request.command, request.cwd.as_deref());
            assert_eq!(script.as_ref(), expected_script);
            let program = match shell {
                Shell::Sh => "/bin/sh",
                Shell::Bash => "bash",
            };
            let expected_bytes = encoded([program, "-c", expected_script.as_str()]).len();
            check_accounting(
                Invocation::Shell {
                    command: &request.command,
                    shell,
                    cwd: request.cwd.as_deref(),
                },
                expected_bytes,
            );
            let valid = !request.command.is_empty()
                && !request.command.as_bytes().contains(&0)
                && request.command.len() <= MAX_COMMAND_BYTES
                && request.cwd.as_deref().is_none_or(|cwd| {
                    cwd.as_bytes().first() == Some(&b'/') && !cwd.as_bytes().contains(&0)
                })
                && common_valid(request.stdin.as_deref(), timeout_secs, max_stdin_bytes)
                && expected_bytes <= MAX_COMMAND_BYTES;
            check_validation(request.validate(max_stdin_bytes), valid, expected_bytes);
        }
        Fixture::Run {
            argv,
            empty_args,
            cwd,
            stdin,
            timeout_secs,
            max_stdin_bytes,
        } => {
            let request = RunRequest {
                host: "unused".into(),
                argv: expand_argv(argv, empty_args, &mut remaining)?,
                cwd: expand_optional(cwd, &mut remaining)?,
                stdin: expand_optional(stdin, &mut remaining)?,
                timeout_secs,
                retain_output: false,
            };
            // The raw join is fixed syntax, not an escaped argument. All caller
            // values use the real encoder, independently of production counting.
            let mut expected = match request.cwd.as_deref() {
                Some(cwd) => format!("{} && command --", encoded(["cd", "--", cwd])),
                None => encoded(["command", "--"]),
            };
            if !request.argv.is_empty() {
                expected.push(' ');
                expected.push_str(&encoded(request.argv.iter().map(String::as_str)));
            }
            let expected_bytes = expected.len();
            // No executable means there is no command to account; validation
            // must reject it. The counter is exercised on actual argv layouts.
            if !request.argv.is_empty() {
                check_accounting(
                    Invocation::Argv {
                        argv: &request.argv,
                        cwd: request.cwd.as_deref(),
                    },
                    expected_bytes,
                );
                let (program, arguments) = request.argv.split_first().unwrap();
                check_accounting(
                    Invocation::BoundArgv {
                        program,
                        arguments: arguments
                            .iter()
                            .map(|argument| std::borrow::Cow::Borrowed(argument.as_str()))
                            .collect(),
                        cwd: request.cwd.as_deref(),
                    },
                    expected_bytes,
                );
            }
            let valid = request
                .argv
                .first()
                .is_some_and(|program| !program.is_empty())
                && request
                    .argv
                    .iter()
                    .all(|argument| !argument.as_bytes().contains(&0))
                && request.cwd.as_deref().is_none_or(|cwd| {
                    cwd.as_bytes().first() == Some(&b'/') && !cwd.as_bytes().contains(&0)
                })
                && common_valid(request.stdin.as_deref(), timeout_secs, max_stdin_bytes)
                && expected_bytes <= MAX_COMMAND_BYTES;
            check_validation(request.validate(max_stdin_bytes), valid, expected_bytes);
        }
        Fixture::Sudo {
            argv,
            empty_args,
            user,
            stdin,
            timeout_secs,
            max_stdin_bytes,
        } => {
            let arguments = expand_argv(argv, empty_args, &mut remaining)?;
            let request = SudoRequest {
                host: "unused".into(),
                argv: arguments,
                user,
                stdin: expand_optional(stdin, &mut remaining)?,
                timeout_secs,
                retain_output: false,
            };
            let expected_bytes = encoded(
                ["sudo", "-n", "-k", "-u", request.user.as_str(), "--"]
                    .into_iter()
                    .chain(request.argv.iter().map(String::as_str)),
            )
            .len();
            check_accounting(
                Invocation::Sudo {
                    argv: &request.argv,
                    user: &request.user,
                },
                expected_bytes,
            );
            if let Some((program, arguments)) = request.argv.split_first() {
                check_accounting(
                    Invocation::BoundSudo {
                        program,
                        arguments: arguments
                            .iter()
                            .map(|argument| Cow::Borrowed(argument.as_str()))
                            .collect(),
                        user: &request.user,
                    },
                    expected_bytes,
                );
            }
            // This explicit alphabet also rejects non-ASCII names and sudo IDs/options.
            let mut name = request.user.chars();
            let first_valid = name.next().is_some_and(|c| {
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_".contains(c)
            });
            let name_valid = first_valid
                && name.all(|c| {
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789-.".contains(c)
                });
            let valid = request.argv.first().is_some_and(|program| {
                program.as_bytes().first() == Some(&b'/')
                    && program.as_bytes().last() != Some(&b'/')
            }) && request
                .argv
                .iter()
                .all(|argument| !argument.as_bytes().contains(&0))
                && request.argv.iter().map(String::len).sum::<usize>() <= MAX_COMMAND_BYTES
                && name_valid
                && common_valid(request.stdin.as_deref(), timeout_secs, max_stdin_bytes)
                && expected_bytes <= MAX_COMMAND_BYTES;
            check_validation(request.validate(max_stdin_bytes), valid, expected_bytes);
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    // Malformed JSON/UTF-8 and unknown shell variants are ordinary rejected inputs.
    let Ok(fixture) = serde_json::from_slice::<Fixture>(data) else {
        return;
    };
    let _ = exercise(fixture);
});
