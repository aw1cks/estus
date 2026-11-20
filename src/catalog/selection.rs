//! Presets select names; they never supply definitions, targets or authority.
use super::assets::Manifest;
use std::collections::BTreeSet;

/// `definitions` holds every known name: locally authored definitions and the
/// installed catalog's templates.
pub(crate) fn expand(
    definitions: &BTreeSet<String>,
    manifest: Option<&Manifest>,
    included: &[String],
    presets: &[String],
    disabled: &[String],
) -> Result<BTreeSet<String>, &'static str> {
    if included.len() > 256 || disabled.len() > 256 || presets.len() > 32 {
        return Err("selection exceeds supported bounds");
    }
    let known = |name: &str| {
        definitions.contains(name) || manifest.is_some_and(|m| m.tools.contains_key(name))
    };
    for names in [included, disabled] {
        let mut seen = BTreeSet::new();
        for name in names {
            if !known(name) || !seen.insert(name.as_str()) {
                return Err("tool names must be known and unique");
            }
        }
    }
    let mut names: BTreeSet<String> = included.iter().cloned().collect();
    let mut seen = BTreeSet::new();
    for preset in presets {
        if !seen.insert(preset.as_str()) {
            return Err("preset names must be unique");
        }
        let members = manifest
            .and_then(|m| m.presets.get(preset))
            .ok_or("unknown tool preset")?;
        names.extend(members.iter().cloned());
    }
    for name in disabled {
        names.remove(name);
    }
    if names.len() > 256 {
        return Err("at most 256 named tools may be selected");
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }
    #[test]
    fn disable_wins_without_forcing_a_disabled_definition() {
        let definitions = BTreeSet::from(["one".to_owned(), "two".to_owned()]);
        let selected = expand(
            &definitions,
            None,
            &strings(&["one", "two"]),
            &[],
            &strings(&["one"]),
        )
        .unwrap();
        assert_eq!(selected, BTreeSet::from(["two".to_owned()]));
        assert!(expand(&definitions, None, &[], &[], &strings(&["unknown"])).is_err());
        assert!(expand(&definitions, None, &strings(&["one", "one"]), &[], &[]).is_err());
        assert!(expand(&definitions, None, &[], &strings(&["missing"]), &[]).is_err());
    }
}
