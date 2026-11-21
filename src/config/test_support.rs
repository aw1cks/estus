use std::ffi::OsString;

use super::*;

pub(super) fn named_authority_text(global: &str, target: &str, enabled: bool) -> String {
    automation_text(global, target, enabled)
        .replace("authority='automation'", "authority='automation:ops'")
        + r#"
[automation.authorities.ops]
ssh_config_file='/private-authority/config'
bundle='/private-authority/bundle'
become={method='sudo',user='root'}
[automation.authorities.ops.targets.server]
destination='private-authority-alias'
python='/private-authority/python'
"#
}

/// Per-target narrowing for the old profile names. A profile that kept named
/// tools subtracts the builtin kinds it dropped (`deny` keeps the inherited
/// list), and a profile that dropped named tools lists the builtins it kept.
pub(super) fn target_narrowing(profile: &str) -> &'static str {
    match profile {
        "baseline" => "",
        "actions-only" => {
            "selection = { deny = [\"inspect_file\", \"inspect_directory\", \"change_file_write\", \"change_mkdir\", \"change_rename\", \"change_file_remove\", \"change_directory_remove\", \"change_file_replace\", \"exec_command\", \"exec_argv\", \"exec_sudo\"] }"
        }
        "read-only-files" => {
            "selection = { allow = [\"observe_stat\", \"inspect_file\", \"inspect_directory\"] }"
        }
        "files-only" => {
            "selection = { allow = [\"observe_stat\", \"inspect_file\", \"inspect_directory\", \"change_file_write\", \"change_mkdir\", \"change_rename\", \"change_file_remove\", \"change_directory_remove\", \"change_file_replace\"] }"
        }
        _ => panic!("unknown test target profile {profile}"),
    }
}

pub(super) fn capabilities_toml(profile: &str) -> &'static str {
    match profile {
        "baseline" => {
            "capabilities = { named = true, file_read = true, file_write = true, exec = true, sudo = true }"
        }
        "actions-only" => {
            "capabilities = { named = true, file_read = false, file_write = false, exec = false, sudo = false }"
        }
        "read-only-files" => {
            "capabilities = { named = false, file_read = true, file_write = false, exec = false, sudo = false }"
        }
        "files-only" => {
            "capabilities = { named = false, file_read = true, file_write = true, exec = false, sudo = false }"
        }
        _ => panic!("unknown test capability preset {profile}"),
    }
}

pub(super) fn automation_text(global: &str, target: &str, enabled: bool) -> String {
    format!(
        r#"
{global_caps}
[selection]
allow={enabled}
[targets.server]
ssh_host='native-alias'
{target_caps}
[automation]
bundle='/unavailable/bundle'
[automation.targets.server]
destination='automation-alias'
python='/unavailable/python'
[tools.probe]
description='Reviewed probe'
revision='review-1'
targets=['server']
authority='automation'
effects=['probe']
execution={{kind='ansible_module',module='ansible.builtin.stat'}}
result={{kind='ansible_summary'}}
input_schema={{type='object',additionalProperties=false,required=[],properties={{}}}}
"#,
        global_caps = capabilities_toml(global),
        target_caps = target_narrowing(target),
        enabled = if enabled { "['probe']" } else { "[]" }
    )
}

pub(super) fn cli() -> Cli {
    Cli {
        config: None,
        ssh_config: None,
        ssh: Some(std::env::current_exe().unwrap()),
        command: None,
        workstation: false,
        yolo: false,
        include_lab: false,
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
            workstation: false,
            yolo: false,
            include_lab: false,
        },
        dir.path(),
        |key| {
            vars.iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| OsString::from(*value))
        },
    )
}
