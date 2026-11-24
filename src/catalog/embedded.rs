//! The catalog this binary was built with. The server still reads an on-disk
//! root, because compiled bindings hold collector paths and re-verify those
//! bytes before every dispatch; `estus catalog install` writes this copy out.

include!(concat!(env!("OUT_DIR"), "/embedded_catalog.rs"));

pub(crate) fn files() -> &'static [(&'static str, &'static [u8])] {
    FILES
}

/// The inventory version recorded in the bundled `catalog.json`.
pub(crate) fn version() -> Option<String> {
    let manifest = FILES
        .iter()
        .find(|(relative, _)| *relative == "catalog.json")?
        .1;
    serde_json::from_slice::<serde_json::Value>(manifest)
        .ok()?
        .get("version")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::*;

    fn disk_files(directory: &Path, relative: &str, out: &mut Vec<String>) {
        for entry in fs::read_dir(directory).expect("read catalog directory") {
            let entry = entry.expect("catalog entry");
            let name = entry.file_name().into_string().expect("utf-8 name");
            if name.starts_with('.')
                || name == "__pycache__"
                || name.ends_with(".pyc")
                || name.ends_with(".pyo")
            {
                continue;
            }
            let path = entry.path();
            let child = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            if path.is_dir() {
                disk_files(&path, &child, out);
            } else {
                out.push(child);
            }
        }
    }

    #[test]
    fn embedded_files_are_exactly_the_catalog_on_disk() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let mut on_disk = Vec::new();
        disk_files(&root, "", &mut on_disk);
        on_disk.sort();
        let embedded: Vec<&str> = files().iter().map(|(relative, _)| *relative).collect();
        assert_eq!(embedded, on_disk, "embedded file set differs from catalog/");
        for (relative, bytes) in files() {
            assert_eq!(
                fs::read(root.join(relative)).expect("read catalog file"),
                *bytes,
                "{relative} differs from its embedded copy"
            );
        }
    }

    #[test]
    fn embedded_catalog_has_a_manifest_version() {
        assert!(version().is_some_and(|version| !version.is_empty()));
    }
}
