#![no_main]
#![allow(dead_code)]

#[path = "../../src/automation/protocol.rs"]
mod protocol;
#[path = "../../src/contracts"]
mod contracts {
    pub(crate) mod module_schema;
    pub(crate) mod projection;
}
#[path = "../../src/reply.rs"]
mod reply;
#[path = "../../src/strict_json.rs"]
mod strict_json;

use contracts::projection;
use protocol::{Completion, Evidence, ExecutionMode, Observations};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use serde_json::{Value, json};

const RAW_CAP: usize = 16 * 1024;
const EXPANDED_CAP: usize = 65_536 + 8192;
const READY: &str = "{\"schema\":2,\"id\":\"test\",\"kind\":\"ready\"}\n";
const TASK: &str = "{\"schema\":2,\"id\":\"test\",\"kind\":\"task\",\"outcome\":\"ok\",\"changed\":true,\"censored\":false}\n";
const TERMINAL: &str = "{\"schema\":2,\"id\":\"test\",\"kind\":\"terminal\",\"status\":\"successful\",\"rc\":0,\"changed\":true,\"tasks\":{\"ok\":1,\"failed\":0,\"unreachable\":0,\"skipped\":0},\"censored\":false,\"complete\":true}\n";
const ROLE_TASK: &str = "{\"schema\":2,\"id\":\"test\",\"kind\":\"role_task\",\"outcome\":\"failed\",\"changed\":true,\"censored\":false,\"ignored\":false}\n";
const ROLE_TERMINAL: &str = "{\"schema\":2,\"id\":\"test\",\"kind\":\"role_terminal\",\"status\":\"successful\",\"rc\":0,\"changed\":true,\"tasks\":{\"ok\":0,\"failed\":0,\"unreachable\":0,\"skipped\":0,\"rescued\":1,\"ignored\":0},\"censored\":false,\"complete\":true}\n";

#[derive(Default, Deserialize)]
#[serde(default)]
struct Input {
    fixture: u8,
    mode: u8,
    id: String,
    lines: Vec<String>,
    repeat: usize,
    padding: usize,
    chunk: usize,
    stop: Option<usize>,
    error: u8,
    started: bool,
    cleanup: u8,
    plan: Option<Value>,
    raw: Option<String>,
    prefix_ready: bool,
}

fn completion(input: &Input) -> Completion {
    Completion {
        started_child: input.started,
        error: match input.error % 8 {
            1 => Some("timeout"),
            2 => Some("cancelled"),
            3 => Some("resource_limit"),
            4 => Some("io_error"),
            5 => Some("spawn_failed"),
            6 => Some("cleanup_incomplete"),
            7 => Some("command_failed"),
            _ => None,
        },
        duration_ms: 17,
        group_cleanup: match input.cleanup % 3 {
            1 => reply::GroupCleanup::Incomplete,
            2 => reply::GroupCleanup::NotStarted,
            _ => reply::GroupCleanup::SignalledAndReaped,
        },
    }
}

fn decode(
    bytes: &[u8],
    input: &Input,
    chunk: usize,
    plan: Option<&projection::Plan>,
) -> (Value, (bool, u32, bool)) {
    let mode = match input.mode % 3 {
        1 => ExecutionMode::Role,
        2 => ExecutionMode::Playbook,
        _ => ExecutionMode::Module,
    };
    let mut evidence = Evidence::new(
        if input.id.is_empty() {
            "test".into()
        } else {
            input.id.clone()
        },
        mode,
    );
    let mut observations = Observations::default();
    let stop = input.stop.map(|offset| offset.min(bytes.len()));
    let mut cursor = 0;
    while cursor < bytes.len() {
        if stop == Some(cursor) {
            evidence.stop();
        }
        let mut end = cursor.saturating_add(chunk.max(1)).min(bytes.len());
        if let Some(stop) = stop.filter(|stop| *stop > cursor) {
            end = end.min(stop);
        }
        let delta = evidence.feed(&bytes[cursor..end]);
        observations.ready |= delta.ready;
        observations.tasks += delta.tasks;
        observations.terminal |= delta.terminal;
        cursor = end;
    }
    if stop == Some(bytes.len()) {
        evidence.stop();
    }
    evidence.finish();
    let result =
        protocol::reduce(Some(evidence), "logical".into(), plan, completion(input));
    (
        serde_json::to_value(result).unwrap(),
        (
            observations.ready,
            observations.tasks,
            observations.terminal,
        ),
    )
}

// Literal result expectations, not a second decoder or reducer. Exercise each
// selected fixture unchanged before allowing arbitrary suffixes/contexts below.
fn fixture(index: u8) -> (String, Input, Option<projection::Plan>) {
    let mut input = Input {
        started: true,
        ..Input::default()
    };
    let full = || [READY, TASK, TERMINAL].concat();
    let mut plan = None;
    let (stream, status, complete, changed, unknown, error, tasks, milestones) = match index % 15 {
        0 => (
            full(),
            "successful",
            true,
            json!(true),
            false,
            None,
            json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
            (true, 1, true),
        ),
        1 => (
            String::new(),
            "worker_lost",
            false,
            Value::Null,
            true,
            Some("invalid_result"),
            json!({"ok":0,"failed":0,"unreachable":0,"skipped":0}),
            (false, 0, false),
        ),
        2 => (
            [READY, TASK].concat(),
            "worker_lost",
            false,
            json!(true),
            true,
            Some("invalid_result"),
            json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
            (true, 1, false),
        ),
        3 => (
            [full(), "garbage\n".into()].concat(),
            "invalid_result",
            true,
            json!(true),
            false,
            Some("invalid_result"),
            json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
            (true, 1, true),
        ),
        4 => {
            input.error = 1;
            input.stop = Some(0);
            (
                full(),
                "timeout",
                true,
                json!(true),
                false,
                Some("timeout"),
                json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
                (true, 1, true),
            )
        }
        5 => {
            input.error = 2;
            input.stop = Some(full().len());
            (
                full(),
                "successful",
                true,
                json!(true),
                false,
                None,
                json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
                (true, 1, true),
            )
        }
        6 => {
            input.mode = 1;
            (
                [READY, ROLE_TASK, ROLE_TERMINAL].concat(),
                "successful",
                true,
                json!(true),
                false,
                None,
                json!({"ok":0,"failed":0,"unreachable":0,"skipped":0,"rescued":1}),
                (true, 1, true),
            )
        }
        7 => {
            input.mode = 2;
            (
                [READY, ROLE_TASK, ROLE_TERMINAL].concat(),
                "successful",
                true,
                json!(true),
                false,
                None,
                json!({"ok":0,"failed":0,"unreachable":0,"skipped":0,"rescued":1}),
                (true, 1, true),
            )
        }
        8 => (
            [READY, ROLE_TASK].concat(),
            "invalid_result",
            false,
            Value::Null,
            true,
            Some("invalid_result"),
            json!({"ok":0,"failed":0,"unreachable":0,"skipped":0}),
            (true, 0, false),
        ),
        9 => {
            plan = Some(projection::compile(json!({"fields":{"text":["stdout"]},"schema":{"type":"object","properties":{"text":{"type":"string","maxLength":16}},"required":["text"],"additionalProperties":false},"max_bytes":128,"max_items":8,"max_depth":2})).unwrap());
            (
                [
                    READY,
                    TASK,
                    "{\"schema\":2,\"id\":\"test\",\"kind\":\"projection\"}\n",
                    TERMINAL,
                ]
                .concat(),
                "successful",
                true,
                json!(true),
                false,
                Some("invalid_result"),
                json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
                (true, 1, true),
            )
        }
        10 => {
            let stream = full()
                .replace("\"changed\":true", "\"changed\":null")
                .replace("\"censored\":false", "\"censored\":true");
            (
                stream,
                "successful",
                true,
                Value::Null,
                false,
                None,
                json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
                (true, 1, true),
            )
        }
        11 => (
            full().replace("\"id\":\"test\"", "\"id\":\"other\""),
            "invalid_result",
            false,
            Value::Null,
            true,
            Some("invalid_result"),
            json!({"ok":0,"failed":0,"unreachable":0,"skipped":0}),
            (false, 0, false),
        ),
        12 => (
            full().replace("\"changed\":true,", ""),
            "invalid_result",
            false,
            Value::Null,
            true,
            Some("invalid_result"),
            json!({"ok":0,"failed":0,"unreachable":0,"skipped":0}),
            (true, 0, false),
        ),
        13 => (
            full().replace("\"rc\":0", "\"rc\":2"),
            "invalid_result",
            false,
            json!(true),
            true,
            Some("invalid_result"),
            json!({"ok":1,"failed":0,"unreachable":0,"skipped":0}),
            (true, 1, false),
        ),
        _ => {
            input.error = 1;
            ("{\"schema\":2,\"id\":\"test\",\"kind\":\"terminal\",\"status\":\"invalid_result\",\"rc\":null,\"changed\":null,\"tasks\":{\"ok\":0,\"failed\":0,\"unreachable\":0,\"skipped\":0},\"censored\":false,\"complete\":false}\n".into(), "timeout", false, Value::Null, false, Some("timeout"), json!({"ok":0,"failed":0,"unreachable":0,"skipped":0}), (false, 0, true))
        }
    };
    let (actual, observations) = decode(
        stream.as_bytes(),
        &input,
        stream.len().max(1),
        plan.as_ref(),
    );
    assert_eq!(actual["data"]["status"], status);
    assert_eq!(actual["data"]["complete"], complete);
    assert_eq!(actual["data"]["changed"], changed);
    assert_eq!(actual["data"]["tasks"], tasks);
    assert_eq!(actual["data"]["censored"], index % 15 == 10);
    assert_eq!(
        actual["error"]["code"],
        error.map_or(Value::Null, |code| json!(code))
    );
    if error.is_some() {
        assert_eq!(actual["error"]["remote_state_unknown"], unknown);
    }
    if index % 15 == 9 {
        assert_eq!(actual["data"]["projection"], json!({"status":"invalid"}));
    }
    assert_eq!(observations, milestones);
    let fragmented = decode(stream.as_bytes(), &input, 1, plan.as_ref());
    assert_eq!((actual, observations), fragmented);
    (stream, input, plan)
}

fuzz_target!(|data: &[u8]| {
    if data.len() > RAW_CAP {
        return;
    }
    let Ok(input) = serde_json::from_slice::<Input>(data) else {
        let input = Input {
            started: true,
            ..Input::default()
        };
        assert_eq!(
            decode(data, &input, RAW_CAP, None),
            decode(data, &input, 7, None)
        );
        return;
    };
    if input.lines.len() > 128 || input.repeat > 1024 || input.padding > EXPANDED_CAP {
        return;
    }
    let (base, _, _) = fixture(input.fixture);
    let unit = if let Some(raw) = &input.raw {
        raw.len()
    } else {
        let Some(size) = input.lines.iter().try_fold(0usize, |size, line| {
            size.checked_add(line.len().checked_add(1)?)
        }) else {
            return;
        };
        size
    };
    let prefix = if input.prefix_ready { READY.len() } else { 0 };
    let Some(expanded) = unit
        .checked_mul(input.repeat.max(1))
        .and_then(|size| size.checked_add(input.padding))
        .and_then(|size| size.checked_add(prefix))
        .and_then(|size| {
            size.checked_add(if input.raw.is_none() && input.lines.is_empty() {
                base.len()
            } else {
                0
            })
        })
    else {
        return;
    };
    if expanded > EXPANDED_CAP {
        return;
    }
    // All controlled repetition and padding are checked before constructing bytes.
    let mut stream = Vec::with_capacity(expanded);
    if input.prefix_ready {
        stream.extend_from_slice(READY.as_bytes());
    }
    if input.raw.is_none() && input.lines.is_empty() {
        stream.extend_from_slice(base.as_bytes());
    }
    for _ in 0..input.repeat.max(1) {
        if let Some(raw) = &input.raw {
            stream.extend_from_slice(raw.as_bytes());
        } else {
            for line in &input.lines {
                stream.extend_from_slice(line.as_bytes());
                stream.push(b'\n');
            }
        }
    }
    stream.resize(expanded, b'x');
    let plan = input.plan.and_then(|value| projection::compile(value).ok());
    let input = Input {
        plan: None,
        ..input
    };
    let whole = decode(&stream, &input, EXPANDED_CAP, plan.as_ref());
    let fragmented = decode(&stream, &input, input.chunk.clamp(1, 8192), plan.as_ref());
    // Stream preflight rejects a crossing chunk before consuming its prefix;
    // over-cap chunking may preserve different independently accepted metadata.
    if stream.len() <= 65_536 {
        assert_eq!(whole, fragmented);
    }
    assert!(serde_json::to_vec(&whole.0).unwrap().len() <= EXPANDED_CAP);
    assert!(serde_json::to_vec(&fragmented.0).unwrap().len() <= EXPANDED_CAP);
});
