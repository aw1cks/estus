//! Canonical identifiers shared by offline runtime selection and authoring.
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()))
}

pub(crate) fn valid_fqcn(value: &str) -> bool {
    value.len() <= 256
        && value.split('.').count() >= 3
        && value
            .split('.')
            .all(|part| name(part) && part.bytes().all(|c| !c.is_ascii_uppercase()))
}

