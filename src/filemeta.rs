use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openssh_sftp_client::metadata::MetaData;
use schemars::JsonSchema;
use serde::Serialize;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ListEntry {
    pub(crate) name: Option<String>,
    pub(crate) name_base64: String,
    pub(crate) metadata: StatData,
}

impl ListEntry {
    pub(crate) fn from_filename(filename: &OsStr, metadata: MetaData) -> Self {
        let bytes = filename.as_bytes();
        Self {
            name: std::str::from_utf8(bytes).ok().map(str::to_owned),
            name_base64: STANDARD.encode(bytes),
            metadata: metadata_data(metadata),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub(crate) struct StatData {
    pub(crate) kind: FileKind,
    pub(crate) size: Option<u64>,
    pub(crate) permissions: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) modified_unix_secs: Option<u64>,
}

pub(crate) fn metadata_data(metadata: MetaData) -> StatData {
    let kind = match metadata.file_type() {
        Some(kind) if kind.is_file() => FileKind::File,
        Some(kind) if kind.is_dir() => FileKind::Directory,
        Some(kind) if kind.is_symlink() => FileKind::Symlink,
        Some(_) => FileKind::Other,
        None => FileKind::Unknown,
    };
    StatData {
        kind,
        size: metadata.len(),
        permissions: metadata
            .permissions()
            .map(|mode| mode.as_raw().bits() & 0o7777),
        uid: metadata.uid(),
        gid: metadata.gid(),
        modified_unix_secs: metadata.modified().map(|time| u64::from(time.into_raw())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_metadata_stays_null_and_does_not_imply_a_file_kind() {
        let data = metadata_data(openssh_sftp_client::metadata::MetaDataBuilder::new().create());
        assert_eq!(
            serde_json::to_value(data).unwrap(),
            json!({
                "kind": "unknown",
                "size": null,
                "permissions": null,
                "uid": null,
                "gid": null,
                "modified_unix_secs": null,
            })
        );
    }

    #[test]
    fn explicit_zero_metadata_is_not_treated_as_missing() {
        use openssh_sftp_client::{
            UnixTimeStamp,
            metadata::{MetaDataBuilder, Permissions},
        };
        let metadata = MetaDataBuilder::new()
            .len(0)
            .id((0, 0))
            .permissions(Permissions::from(0u16))
            .time(UnixTimeStamp::unix_epoch(), UnixTimeStamp::unix_epoch())
            .create();
        let data = metadata_data(metadata);
        assert_eq!(data.size, Some(0));
        assert_eq!(data.uid, Some(0));
        assert_eq!(data.gid, Some(0));
        assert_eq!(data.permissions, Some(0));
        assert_eq!(data.modified_unix_secs, Some(0));
    }

    #[test]
    fn metadata_preserves_special_mode_bits_and_unsigned_modification_seconds() {
        use openssh_sftp_client::{
            UnixTimeStamp,
            metadata::{MetaDataBuilder, Permissions},
        };
        for (mode, seconds) in [(0o7777u16, u32::MAX), (0o4750, 2_147_483_648)] {
            let metadata = MetaDataBuilder::new()
                .len(u64::MAX)
                .id((u32::MAX, 0))
                .permissions(Permissions::from(mode))
                .time(
                    UnixTimeStamp::unix_epoch(),
                    UnixTimeStamp::from_raw(seconds).unwrap(),
                )
                .create();
            let data = metadata_data(metadata);
            assert_eq!(data.permissions, Some(u32::from(mode)));
            assert_eq!(data.modified_unix_secs, Some(u64::from(seconds)));
            assert_eq!(data.size, Some(u64::MAX));
            assert_eq!(data.uid, Some(u32::MAX));
            assert_eq!(data.gid, Some(0));
        }
    }
}
