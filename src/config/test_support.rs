use std::ffi::OsString;

use super::*;

pub(super) fn named_authority_text(global: &str, target: &str, enabled: bool) -> String {
    automation_text(global, target, enabled)
        .replace("authority='automation'", "authority='automation:ops'")
        + r#"
[automation.authorities.ops]
ssh_config_file='/private-authority/config'
runtime='/private-authority/runtime'
become={method='sudo',user='root'}
[automation.authorities.ops.targets.server]
destination='private-authority-alias'
python='/private-authority/python'
"#
}

pub(super) fn automation_text(global: &str, target: &str, enabled: bool) -> String {
    format!(
        r#"
profile={global:?}
enabled_tools={}
[targets.server]
ssh_host='native-alias'
profile={target:?}
[automation]
runtime='/unavailable/runtime.json'
workspace_root='/unavailable/workspace'
[automation.targets.server]
destination='automation-alias'
python='/unavailable/python'
[tools.probe]
description='Reviewed probe'
revision='review-1'
targets=['server']
authority='automation'
effects=['probe']
execution={{kind='ansible_module',snapshot='/unavailable/snapshot.json'}}
result={{kind='ansible_summary'}}
input_schema={{type='object',additionalProperties=false,required=[],properties={{}}}}
"#,
        if enabled { "['probe']" } else { "[]" }
    )
}

pub(super) fn cli() -> Cli {
    Cli {
        config: None,
        ssh_config: None,
        ssh: Some(std::env::current_exe().unwrap()),
        command: None,
    }
}

// Deliberately unrelated to production wire names and declaration order.
pub(super) fn catalog() -> ToolCatalog {
    ToolCatalog::new(
        [
            (ToolId::Exec, "z-exec"),
            (ToolId::Targets, "0-global-discovery"),
            (ToolId::Sudo, "m-elevate"),
            (ToolId::ReadFile, "n-read"),
            (ToolId::WriteFile, "c-write"),
            (ToolId::Stat, "q-stat"),
            (ToolId::ListDirectory, "b-list"),
            (ToolId::Run, "a-run"),
        ]
        .into_iter()
        .map(|(id, name)| ToolEntry {
            id: ToolKey::Builtin(id),
            name: name.into(),
        })
        .collect(),
    )
    .unwrap()
}

pub(super) fn builtin(key: ToolKey) -> ToolId {
    match key {
        ToolKey::Builtin(id) => id,
        ToolKey::Binding(_) => panic!("builtin-only test catalogue"),
    }
}

pub(super) fn binding_definition() -> &'static str {
    r#"
[tools.observe]
description = "Observe a fixed account"
revision = "1"
targets = ["one"]
authority = "ordinary"
effects = ["read"]
execution = { kind = "native_argv", program = "/usr/bin/id", argv = ["--", { input = "account" }] }
input_schema = { type = "object", additionalProperties = false, required = ["account"], properties = { account = { type = "string", minLength = 1, maxLength = 32 } } }
result = { kind = "command" }
"#
}

pub(super) fn load_text(text: &str, vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, text).unwrap();
    Config::load_with(
        Cli {
            config: Some(path),
            ssh_config: None,
            ssh: Some(std::env::current_exe().unwrap()),
            command: None,
        },
        dir.path(),
        |key| {
            vars.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| OsString::from(*value))
        },
    )
}

