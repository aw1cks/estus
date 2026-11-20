use crate::bindings::AutomationAuthority;

use super::*;

const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_LABELS: usize = 16;
const MAX_LABEL_KEY_BYTES: usize = 64;
const MAX_LABEL_VALUE_BYTES: usize = 256;
const MAX_METADATA_BYTES: usize = 65_536;

fn authority_path(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid(field, "must be a bounded absolute path"));
    }
    Ok(())
}

/// Retired sections need their own message: serde would report them as an
/// unknown field, which is true but does not tell an operator what to do.
pub(super) fn validate_schema(value: &toml::Value) -> Result<(), ConfigError> {
    if value.get("directory").is_some() {
        return Err(invalid(
            "directory",
            "is no longer supported; remove the [directory] section",
        ));
    }
    Ok(())
}

fn validate_automation_targets(
    mappings: &BTreeMap<String, AutomationTarget>,
    targets: Option<&BTreeMap<String, Target>>,
    field: &'static str,
) -> Result<(), ConfigError> {
    for (name, target) in mappings {
        if !targets.is_some_and(|targets| targets.contains_key(name)) {
            return Err(invalid(field, "must name configured logical targets"));
        }
        destination(&target.destination, field)?;
        if !target.python.is_empty() {
            authority_path(&target.python, field)?;
        }
    }
    Ok(())
}

pub(super) fn validate_runtime_path(value: &str) -> Result<(), ConfigError> {
    if !Path::new(value).is_absolute() || value.len() > 4096 || value.contains('\0') {
        return Err(invalid(
            "automation.bundle",
            "must be a bounded absolute path",
        ));
    }
    Ok(())
}

// Named POSIX-style accounts only, not sudo's numeric-ID syntax or options.
pub(crate) fn account_name(user: &str) -> bool {
    !user.is_empty()
        && user.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || byte == b'_'
                || (index > 0 && (byte.is_ascii_digit() || byte == b'-' || byte == b'.'))
        })
}

pub(super) fn validate_targets(targets: &BTreeMap<String, Target>) -> Result<(), ConfigError> {
    let ordinary: BTreeSet<&str> = targets
        .values()
        .map(|target| target.ssh_host.as_str())
        .collect();
    let mut metadata_remaining = MAX_METADATA_BYTES;
    for target in targets.values() {
        destination(&target.ssh_host, "targets.*.ssh_host")?;
        if target
            .description
            .as_ref()
            .is_some_and(|description| description.len() > MAX_DESCRIPTION_BYTES)
        {
            return Err(invalid("targets.*.description", "exceeds UTF-8 byte limit"));
        }
        if target.labels.len() > MAX_LABELS {
            return Err(invalid("targets.*.labels", "exceeds label count limit"));
        }
        for (key, value) in &target.labels {
            if key.is_empty() || key.len() > MAX_LABEL_KEY_BYTES {
                return Err(invalid(
                    "targets.*.labels",
                    "keys must be nonempty and within UTF-8 byte limit",
                ));
            }
            if value.len() > MAX_LABEL_VALUE_BYTES {
                return Err(invalid("targets.*.labels.*", "exceeds UTF-8 byte limit"));
            }
        }
        for bytes in target.description.iter().map(String::len).chain(
            target
                .labels
                .iter()
                .map(|(key, value)| key.len() + value.len()),
        ) {
            metadata_remaining = metadata_remaining
                .checked_sub(bytes)
                .ok_or_else(|| invalid("targets", "exceeds aggregate metadata UTF-8 byte limit"))?;
        }
        let (users, programs) = match &target.sudo {
            Sudo::Disabled => continue,
            Sudo::SameAccount { users, programs } => (users, programs),
            Sudo::SeparateIdentity {
                ssh_host,
                users,
                programs,
            } => {
                destination(ssh_host, "targets.*.sudo.ssh_host")?;
                if ordinary.contains(ssh_host.as_str()) {
                    return Err(invalid(
                        "targets.*.sudo.ssh_host",
                        "privileged alias must not be any configured ordinary alias",
                    ));
                }
                (users, programs)
            }
        };
        if users.is_empty() {
            return Err(invalid(
                "targets.*.sudo.users",
                "must contain at least one user",
            ));
        }
        let mut seen = BTreeSet::new();
        for user in users {
            if !account_name(user) {
                return Err(invalid(
                    "targets.*.sudo.users",
                    "must contain valid account names",
                ));
            }
            if !seen.insert(user) {
                return Err(invalid("targets.*.sudo.users", "duplicate policy entry"));
            }
        }
        if let Some(programs) = programs {
            let mut seen = BTreeSet::new();
            for program in programs {
                if !program.starts_with('/') || program.ends_with('/') || program.contains('\0') {
                    return Err(invalid(
                        "targets.*.sudo.programs",
                        "must contain absolute executable paths without NUL or a trailing slash",
                    ));
                }
                if !seen.insert(program) {
                    return Err(invalid("targets.*.sudo.programs", "duplicate policy entry"));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn destination(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.starts_with('-')
        || value
            .chars()
            .any(|character| character == '\0' || character.is_whitespace())
    {
        return Err(invalid(
            field,
            "destination must be nonempty, contain no NUL or whitespace, and not start with '-'",
        ));
    }
    Ok(())
}

pub(super) fn validate_limits(limits: &Limits) -> Result<(), ConfigError> {
    for (field, value) in [
        ("limits.connect_timeout_secs", limits.connect_timeout_secs),
        (
            "limits.operation_timeout_secs",
            limits.operation_timeout_secs,
        ),
        ("limits.max_timeout_secs", limits.max_timeout_secs),
        ("limits.max_output_bytes", limits.max_output_bytes),
        ("limits.max_file_bytes", limits.max_file_bytes),
    ] {
        if value == 0 {
            return Err(invalid(field, "must be strictly positive"));
        }
    }
    for (field, timeout) in [
        ("limits.connect_timeout_secs", limits.connect_timeout_secs),
        (
            "limits.operation_timeout_secs",
            limits.operation_timeout_secs,
        ),
    ] {
        if timeout > limits.max_timeout_secs {
            return Err(invalid(field, "must not exceed limits.max_timeout_secs"));
        }
    }
    Ok(())
}

pub(super) fn validate_automation(
    controller_root: Option<&str>,
    automation: &Automation,
    targets: Option<&BTreeMap<String, Target>>,
) -> Result<(), ConfigError> {
    if let Some(root) = controller_root
        && (!root.starts_with('/') || root.len() > 1024 || root.contains('\0'))
    {
        return Err(invalid(
            "controller.workspace_root",
            "must be a bounded absolute path",
        ));
    }
    if !(1..=16).contains(&automation.max_concurrent) {
        return Err(invalid("automation", "invalid concurrency bounds"));
    }
    if let Some(bundle) = &automation.bundle {
        let bundle = bundle
            .to_str()
            .ok_or_else(|| invalid("automation.bundle", "must be a bounded absolute path"))?;
        validate_runtime_path(bundle)?;
    }
    if automation.authorities.len() > 16 {
        return Err(invalid(
            "automation.authorities",
            "must contain at most 16 authorities",
        ));
    }
    for (name, authority) in &automation.authorities {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphabetic()
                    || byte == b'_'
                    || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
            })
        {
            return Err(invalid(
                "automation.authorities",
                "invalid authority identifier",
            ));
        }
        let config = authority.ssh_config_file.to_str().ok_or_else(|| {
            invalid(
                "automation.authorities.*.ssh_config_file",
                "must be a bounded absolute path",
            )
        })?;
        authority_path(config, "automation.authorities.*.ssh_config_file")?;
        if let Some(socket) = &authority.ssh_auth_sock {
            let socket = socket.to_str().ok_or_else(|| {
                invalid(
                    "automation.authorities.*.ssh_auth_sock",
                    "must be a bounded absolute path",
                )
            })?;
            authority_path(socket, "automation.authorities.*.ssh_auth_sock")?;
        }
        // The only authority kind today is sudo; a new variant must be
        // validated here or the compiler will flag this destructure.
        let AutomationBecome::Sudo { user, executable } = &authority.r#become;
        if user.len() > 64 || !account_name(user) {
            return Err(invalid(
                "automation.authorities.*.become.user",
                "must be a named POSIX account",
            ));
        }
        authority_path(executable, "automation.authorities.*.become.executable")?;
    }
    for (name, target) in &automation.targets {
        if !targets
            .as_ref()
            .is_some_and(|targets| targets.contains_key(name))
        {
            return Err(invalid(
                "automation.targets",
                "must name configured logical targets",
            ));
        }
        destination(&target.destination, "automation.targets.destination")?;
        if !target.python.is_empty() {
            validate_runtime_path(&target.python)?;
        }
    }
    for authority in automation.authorities.values() {
        validate_automation_targets(
            &authority.targets,
            targets,
            "automation.authorities.*.targets",
        )?;
    }
    Ok(())
}

pub(super) fn validate_bindings(
    bindings: &Bindings,
    targets: Option<&BTreeMap<String, Target>>,
    automation: &Automation,
) -> Result<(), ConfigError> {
    // Definitions are operator capabilities even when hidden or disabled.
    // Validate their authority before exposure profiles select callable tools.
    for (_, binding) in bindings.entries() {
        if let Some((user, program)) = binding.sudo() {
            for name in &binding.targets {
                if !targets
                    .and_then(|targets| targets.get(name))
                    .is_some_and(|target| target.sudo.permits(user, program))
                {
                    return Err(invalid(
                        "tools",
                        "binding authority exceeds target sudo policy",
                    ));
                }
            }
        }
    }
    for (_, binding) in bindings
        .entries()
        .filter(|(_, binding)| binding.automation_authority().is_some())
    {
        if binding.has_dynamic_targets() {
            continue;
        }
        let targets = match binding.automation_authority() {
            Some(AutomationAuthority::Ordinary) => &automation.targets,
            Some(AutomationAuthority::Named(name)) => {
                &automation
                    .authorities
                    .get(name)
                    .ok_or_else(|| invalid("tools", "automation authority is not configured"))?
                    .targets
            }
            None => unreachable!("automation binding has a typed authority"),
        };
        if binding
            .targets
            .iter()
            .any(|name| !targets.contains_key(name))
        {
            return Err(invalid(
                "tools",
                "automation targets require explicit automation authority",
            ));
        }
        if binding.is_automation()
            && binding.targets.iter().any(|name| {
                targets
                    .get(name)
                    .is_none_or(|target| target.python.is_empty())
            })
        {
            return Err(invalid(
                "tools",
                "Ansible targets require an explicit Python interpreter",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        automation_text, binding_definition, load_text, named_authority_text,
    };
    use super::*;

    #[test]
    fn named_authorities_require_complete_private_capabilities_and_bounded_count() {
        let text = named_authority_text("baseline", "baseline", false);
        for invalid_text in [
            text.replace("ssh_config_file='/private-authority/config'\n", ""),
            text.replace("become={method='sudo',user='root'}\n", ""),
            text.replace(
                "[automation.authorities.ops.targets.server]\ndestination='private-authority-alias'\npython='/private-authority/python'\n",
                "",
            ),
            (0..17).fold(text.clone(), |text, index| text + &format!(
                "\n[automation.authorities.extra{index}]\nssh_config_file='/private-authority/config'\nbecome={{method='sudo',user='root'}}\ntargets={{}}\n"
            )),
        ] {
            let error = load_text(&invalid_text, &[]).err().unwrap();
            // Missing members and unknown keys are serde's; only the typed
            // bounds keep their own paths.
            assert!(
                error.field == "config" || error.field.starts_with("automation."),
                "{:?}",
                error.field
            );
            assert!(!error.to_string().contains("private-authority"));
        }
    }

    #[test]
    fn named_sudo_executable_is_operator_pinned_and_absolute() {
        let text = named_authority_text("actions-only", "actions-only", false);
        let configured = text.replace(
            "become={method='sudo',user='root'}",
            "become={method='sudo',user='root',executable='/run/wrappers/bin/sudo'}",
        );
        let config = load_text(&configured, &[]).unwrap();
        let AutomationBecome::Sudo { executable, .. } =
            &config.automation.authorities["ops"].r#become;
        assert_eq!(executable, "/run/wrappers/bin/sudo");
        for value in ["'sudo'", "''", "42", "\"/private\\u0000sudo\""] {
            let invalid_text = text.replace(
                "become={method='sudo',user='root'}",
                &format!("become={{method='sudo',user='root',executable={value}}}"),
            );
            assert!(load_text(&invalid_text, &[]).is_err());
        }
    }

    #[test]
    fn missing_named_authority_or_mapping_rejects_even_disabled_bindings() {
        let text = named_authority_text("baseline", "baseline", false);
        for invalid_text in [
            automation_text("baseline", "baseline", false)
                .replace("authority='automation'", "authority='automation:ops'"),
            text.replace(
                "automation.authorities.ops.targets.server",
                "automation.authorities.ops.targets.other",
            ),
            text.replace("targets=['server']", "targets=['server','second']")
                + "\n[targets.second]\nssh_host='second-native'\n",
        ] {
            let error = load_text(&invalid_text, &[]).err().unwrap();
            assert!(!error.to_string().contains("private-authority"));
        }
    }

    #[test]
    fn named_authority_invalid_private_values_have_fixed_diagnostics() {
        let text = named_authority_text("baseline", "baseline", false);
        for replacement in [
            (
                "ssh_config_file='/private-authority/config'",
                "ssh_config_file='private-secret'",
            ),
            (
                "bundle='/private-authority/bundle'",
                "bundle=['private-secret']",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='private-secret',user='root'}",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='sudo',user='#private-secret'}",
            ),
            (
                "become={method='sudo',user='root'}",
                "become={method='sudo',user='root',password='private-secret'}",
            ),
            (
                "destination='private-authority-alias'",
                "destination='private-secret invalid'",
            ),
            (
                "python='/private-authority/python'",
                "python='private-secret'",
            ),
            (
                "[automation.authorities.ops]",
                "[automation.authorities.'private-secret!']",
            ),
        ] {
            let error = load_text(&text.replace(replacement.0, replacement.1), &[])
                .err()
                .unwrap();
            let diagnostic = error.to_string();
            assert!(
                error.field == "config" || error.field.starts_with("automation."),
                "{:?}",
                error.field
            );
            assert!(!diagnostic.contains("private-secret"));
            assert!(!diagnostic.contains("private-authority"));
        }
    }

    #[test]
    fn automation_destinations_share_explicit_ssh_destination_grammar() {
        for alias in [
            "_alias",
            "2001:db8::1",
            "[2001:db8::1]",
            "user@_alias",
            "é-alias",
        ] {
            assert!(destination(alias, "automation.targets.destination").is_ok());
        }
        for alias in ["", "-option", "a b", "a\0b", "a\u{2003}b"] {
            assert!(destination(alias, "automation.targets.destination").is_err());
        }
    }

    #[test]
    fn automation_defaults_and_bounds_are_explicit() {
        let config = load_text("", &[]).unwrap();
        assert_eq!(config.automation_concurrency(), 8);
        for field in ["max_concurrent=0", "max_concurrent=17"] {
            assert!(load_text(&format!("[automation]\n{field}"), &[]).is_err());
        }
    }

    #[test]
    fn every_fixed_sudo_definition_must_narrow_every_declared_target_policy() {
        let definition = binding_definition().replace(
            "authority = \"ordinary\"",
            "authority = { sudo = \"root\" }",
        );
        for (mode, alias) in [
            ("same-account", ""),
            ("separate-identity", "ssh_host='secret_elevated'\n"),
        ] {
            for (policy, permitted) in [
                ("", true),
                ("users=['root']\nprograms=['/usr/bin/id']", true),
                ("users=['service']\nprograms=['/usr/bin/id']", false),
                ("programs=[]", false),
                ("programs=['/bin/id']", false),
                ("programs=['/usr/bin/id-other']", false),
            ] {
                for profile in ["baseline", "actions-only", "files-only", "read-only-files"] {
                    let caps = super::super::test_support::capabilities_toml(profile);
                    for enabled in ["[]", "['observe']"] {
                        for bad_second in [false, true] {
                            let definition = if bad_second {
                                definition
                                    .replace("targets = [\"one\"]", "targets = [\"one\", \"two\"]")
                            } else {
                                definition.clone()
                            };
                            let result = load_text(
                                &format!(
                                    "{caps}\nenabled_tools={enabled}\n\
                                     [targets.one]\nssh_host='secret_ordinary'\n{caps}\n\
                                     [targets.one.sudo]\nmode='{mode}'\n{alias}{policy}\n\
                                     [targets.two]\nssh_host='secret_second'\n{definition}",
                                ),
                                &[],
                            );
                            assert_eq!(
                                result.is_ok(),
                                permitted && !bad_second,
                                "{mode}/{policy}/{profile}/{enabled}/{bad_second}",
                            );
                            if let Err(error) = result {
                                assert_eq!(error.field, "tools");
                                assert!(std::error::Error::source(&error).is_none());
                                let diagnostic = format!("{error:?} {error}");
                                for secret in ["secret_", "/usr/bin/id", "/bin/id", "service"] {
                                    assert!(!diagnostic.contains(secret), "{diagnostic}");
                                }
                            }
                        }
                    }
                }
            }
        }
        for enabled in ["[]", "['observe']"] {
            let error = load_text(
                &format!(
                    "enabled_tools={enabled}\n\
                     [targets.one]\nssh_host='secret_ordinary'\n{definition}",
                ),
                &[],
            )
            .err()
            .expect("disabled sudo cannot authorize a definition");
            assert_eq!(error.field, "tools");
        }
    }

    #[test]
    fn binding_startup_rejects_missing_targets_selection_and_invalid_disabled_definitions() {
        let definition = binding_definition();
        for text in [
            format!("enabled_tools=['observe']\n{definition}"),
            format!("enabled_tools=['observe']\n[targets.two]\nssh_host='private'\n{definition}"),
            format!("enabled_tools=['missing']\n[targets.one]\nssh_host='private'\n{definition}"),
            format!(
                "enabled_tools=['observe','observe']\n[targets.one]\nssh_host='private'\n{definition}"
            ),
            format!(
                "[targets.one]\nssh_host='private'\n{}",
                definition.replace("authority = \"ordinary\"", "authority = \"secret_payload\"")
            ),
        ] {
            let error = load_text(&text, &[])
                .err()
                .expect("invalid binding must fail startup");
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn unknown_and_wrong_type_capabilities_and_legacy_profiles_use_fixed_secret_free_paths() {
        for (text, field) in [
            ("profile='baseline'".to_owned(), "config"),
            (
                "[targets.secret_target]\nssh_host='secret_alias'\nprofile='baseline'".to_owned(),
                "config",
            ),
            ("mode='secret_payload'".to_owned(), "config"),
            ("mode=42".to_owned(), "config"),
            (
                "capabilities={secret_payload=true}".to_owned(),
                "config",
            ),
            (
                "capabilities={exec='secret_payload'}".to_owned(),
                "config",
            ),
            (
                "[targets.secret_target]\nssh_host='secret_alias'\ncapabilities={exec='secret_payload'}".to_owned(),
                "config",
            ),
            (
                "[rules.'*']\nunknown_rule_key=true".to_owned(),
                "config",
            ),
            (
                "[rules.'*']\nrequire_preview='secret_payload'".to_owned(),
                "config",
            ),
            (
                "[rules.'*']\ndeny_tiers=['secret_payload']".to_owned(),
                "config",
            ),
        ] {
            let error = load_text(&text, &[]).err().unwrap();
            assert_eq!(error.field, field, "{text}");
            for secret in ["secret_payload", "secret_target", "secret_alias"] {
                assert!(!error.to_string().contains(secret));
                assert!(!format!("{error:?}").contains(secret));
            }
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn metadata_bounds_count_utf8_bytes_and_accept_exact_limits() {
        let text = |description: &str, key: &str, value: &str| {
            format!(
                "[targets.one]\nssh_host='ordinary'\ndescription='{description}'\n\
                 [targets.one.labels]\n'{key}'='{value}'"
            )
        };
        let description = "é".repeat(512);
        let key = "é".repeat(32);
        let value = "é".repeat(128);
        assert!(load_text(&text(&description, &key, &value), &[]).is_ok());
        for (text, field) in [
            (
                text(&format!("{description}a"), &key, &value),
                "targets.*.description",
            ),
            (
                text(&description, &format!("{key}a"), &value),
                "targets.*.labels",
            ),
            (
                text(&description, &key, &format!("{value}a")),
                "targets.*.labels.*",
            ),
            (text("", "", ""), "targets.*.labels"),
        ] {
            assert_eq!(load_text(&text, &[]).err().unwrap().field, field);
        }
        let mut labels = String::from(
            "[targets.one]\nssh_host='ordinary'\ndescription=''\n[targets.one.labels]\n",
        );
        for index in 0..16 {
            labels.push_str(&format!("label{index}=''\n"));
        }
        assert!(load_text(&labels, &[]).is_ok());
        labels.push_str("extra=''\n");
        assert_eq!(
            load_text(&labels, &[]).err().unwrap().field,
            "targets.*.labels"
        );
    }

    #[test]
    fn aggregate_metadata_bounds_include_all_targets_keys_and_values() {
        let mut text = String::new();
        for index in 0..48 {
            text.push_str(&format!(
                "[targets.target{index}]\nssh_host='ordinary'\ndescription='{}'\n\
                 [targets.target{index}.labels]\n'{}'='{}'\n",
                "é".repeat(512),
                "é".repeat(32),
                "é".repeat(128),
            ));
        }
        text.push_str(&format!(
            "[targets.last]\nssh_host='ordinary'\ndescription='{}'\n",
            "é".repeat(512),
        ));
        // 48 * (1024 + 64 + 256) + 1024 = 65536 bytes, all sudo disabled.
        assert!(load_text(&text, &[]).is_ok());
        text.push_str("[targets.last.labels]\na=''\n");
        assert_eq!(load_text(&text, &[]).err().unwrap().field, "targets");
    }

    #[test]
    fn metadata_schema_and_bound_failures_never_echo_operator_content() {
        // Wrong types are serde's; byte bounds stay in the typed pass.
        for (metadata, field) in [
            ("description=42".to_owned(), "config"),
            ("labels='secret_payload'".to_owned(), "config"),
            (
                "labels={secret_payload=['secret_payload']}".to_owned(),
                "config",
            ),
            (
                format!("description='secret_payload{}'", "é".repeat(512)),
                "targets.*.description",
            ),
            (
                format!(
                    "labels={{'secret_payload{}'='secret_payload'}}",
                    "é".repeat(32)
                ),
                "targets.*.labels",
            ),
            (
                format!(
                    "labels={{secret_payload='secret_payload{}'}}",
                    "é".repeat(128)
                ),
                "targets.*.labels.*",
            ),
        ] {
            let text = format!(
                "[targets.secret_payload]\nssh_host='private_alias'\n{metadata}\n\
                 [targets.secret_payload.sudo]\nmode='disabled'"
            );
            let error = load_text(&text, &[]).err().unwrap();
            assert_eq!(error.field, field, "{metadata}");
            for secret in ["secret_payload", "private_alias"] {
                assert!(!error.to_string().contains(secret));
                assert!(!format!("{error:?}").contains(secret));
            }
        }
    }

    #[test]
    fn directory_section_rejects_unknown_keys_without_value_reflection() {
        for policy in [
            "max_cursors=8",
            "idle_timeout_secs=60",
            "max_cursors='DIRECTORY_PRIVATE_VALUE'",
            "DIRECTORY_PRIVATE_KEY='DIRECTORY_PRIVATE_VALUE'",
        ] {
            let error = load_text(&format!("[directory]\n{policy}"), &[])
                .err()
                .expect("directory section key must fail");
            assert!(error.to_string().contains("directory"), "{error:?}");
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("DIRECTORY_PRIVATE"));
        }
        // An empty section is still a table with an unknown scope: it fails.
        let error = load_text("[directory]\n", &[])
            .err()
            .expect("empty directory section must fail");
        assert!(error.to_string().contains("directory"), "{error:?}");
    }

    #[test]
    fn automation_schema_rejects_private_invalid_shapes_without_disclosure() {
        for (text, field) in [
            ("automation='secret_payload'", "config"),
            ("[automation]\nsecret_payload=true", "config"),
            ("[automation]\nrequired='secret_payload'", "config"),
            ("[automation]\nbundle=['secret_payload']", "config"),
            ("[automation]\nbundle='secret_payload'", "automation.bundle"),
            ("[automation]\nbundle=''", "automation.bundle"),
            (
                "[automation]\nbundle=\"/secret_payload\\u0000\"",
                "automation.bundle",
            ),
        ] {
            let error = load_text(text, &[]).err().unwrap();
            assert_eq!(error.field, field, "{text}");
            assert!(!error.to_string().contains("secret_payload"));
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
        let oversized = format!("[automation]\nbundle='/{}'", "x".repeat(4096));
        assert_eq!(
            load_text(&oversized, &[]).err().unwrap().field,
            "automation.bundle"
        );
    }

    #[test]
    fn unknown_fields_and_parser_errors_are_sanitized_at_every_level() {
        for text in [
            "secret_payload='secret_payload'",
            "[ssh]\nsecret_payload='secret_payload'",
            "[limits]\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='disabled'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='same-account'\nsecret_payload=1",
            "[targets.secret_payload]\nssh_host='ordinary'\n[targets.secret_payload.sudo]\nmode='separate-identity'\nssh_host='privileged'\nsecret_payload=1",
            "secret_payload = [broken",
            "[targets.secret_payload]\nssh_host='a'\nssh_host='secret_payload'",
            "[targets.secret_payload]\nssh_host='a'\n[targets.secret_payload.sudo]\nmode='secret_payload'",
        ] {
            let error = load_text(text, &[])
                .err()
                .expect("must reject malformed configuration");
            assert!(!error.to_string().contains("secret_payload"));
            assert!(!format!("{error:?}").contains("secret_payload"));
            assert!(std::error::Error::source(&error).is_none());
        }
    }

    #[test]
    fn destination_safety_and_authority_separation_are_enforced() {
        for host in [
            "",
            "-option",
            "two words",
            "tab\there",
            "line\nhere",
            "nul\0here",
            "unicode\u{a0}space",
        ] {
            let text = format!(
                "[targets.one]\nssh_host={}",
                serde_json::to_string(host).unwrap()
            );
            assert!(load_text(&text, &[]).is_err(), "{host:?}");
        }
        for text in [
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nssh_host='privileged'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'\nssh_host='ordinary'",
            "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='separate-identity'\nssh_host='privileged'\n[targets.two]\nssh_host='privileged'",
        ] {
            assert!(load_text(text, &[]).is_err());
        }
        assert!(load_text("[targets.one]\nssh_host='user@host:22'", &[]).is_ok());
    }

    #[test]
    fn sudo_policy_rejects_invalid_and_duplicate_entries() {
        for policy in [
            "users=[]",
            "users=['root','root']",
            "users=['']",
            "users=['-root']",
            "users=['#0']",
            "users=['two words']",
            "users=['root\\n']",
            "programs=['relative']",
            "programs=['/']",
            "programs=['/bin/sh','/bin/sh']",
            "programs=['/bin/']",
        ] {
            let text = format!(
                "[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\n{policy}"
            );
            assert!(load_text(&text, &[]).is_err(), "{policy}");
        }
        let config = load_text("[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nusers=['root','service-user','_service']\nprograms=[]", &[]).unwrap();
        match &config.targets.as_ref().unwrap()["one"].sudo {
            Sudo::SameAccount { programs, .. } => {
                assert!(programs.as_ref().is_some_and(Vec::is_empty))
            }
            _ => panic!("incorrect sudo mode"),
        }
        assert!(load_text("[targets.one]\nssh_host='ordinary'\n[targets.one.sudo]\nmode='same-account'\nprograms=['/opt/My Program/run']", &[]).is_ok());
    }
}
