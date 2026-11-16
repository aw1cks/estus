#![no_main]
#![allow(dead_code)]

use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use libfuzzer_sys::fuzz_target;
use openssh_sftp_client::{
    UnixTimeStamp,
    metadata::{MetaDataBuilder, Permissions, RawPermissions},
};
use openssh_sftp_protocol::{
    response::{Response, ResponseInner},
    ssh_format,
};
use serde::Deserialize;
use serde_json::json;

#[path = "../../src/filesystem/metadata.rs"]
mod metadata;

use metadata::{FileKind, ListEntry, StatData, metadata_data};

// The raw JSON cap bounds initial serde allocations. Check atom size and
// multiplication before allocating the expanded filename.
const MAX_INPUT_BYTES: usize = 16_384;
const MAX_ATOM_BYTES: usize = 1_024;
const MAX_FILENAME_BYTES: usize = 65_536;
const TYPE_MASK: u32 = 0o170000;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Atom {
    Text(String),
    Bytes(Vec<u8>),
}

impl Atom {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Bytes(bytes) => bytes.as_slice(),
        }
    }
}

fn one() -> usize {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    filename: Atom,
    #[serde(default = "one")]
    repeat: usize,
    size: Option<u64>,
    ids: Option<[u32; 2]>,
    mode: Option<u32>,
    times: Option<[u32; 2]>,
}

// Independent POSIX type oracle. Arbitrary raw attributes first pass through
// the real decoder: reserved nonzero type patterns are rejected there, before
// constructing the SDK's trusted metadata value. No transport is simulated.
fn expected_kind(mode: Option<u32>) -> FileKind {
    match mode.map(|mode| mode & TYPE_MASK).unwrap_or(0) {
        0 => FileKind::Unknown,
        0o100000 => FileKind::File,
        0o040000 => FileKind::Directory,
        0o120000 => FileKind::Symlink,
        0o010000 | 0o020000 | 0o060000 | 0o140000 => FileKind::Other,
        _ => FileKind::Unknown,
    }
}

fn wire_metadata(fixture: &Fixture) -> Option<Response> {
    let mut packet = Vec::with_capacity(37);
    packet.push(105); // SSH_FXP_ATTRS, without the outer packet length.
    packet.extend_from_slice(&17u32.to_be_bytes());
    let flags = u32::from(fixture.size.is_some())
        | (u32::from(fixture.ids.is_some()) << 1)
        | (u32::from(fixture.mode.is_some()) << 2)
        | (u32::from(fixture.times.is_some()) << 3);
    packet.extend_from_slice(&flags.to_be_bytes());
    if let Some(size) = fixture.size {
        packet.extend_from_slice(&size.to_be_bytes());
    }
    if let Some([uid, gid]) = fixture.ids {
        packet.extend_from_slice(&uid.to_be_bytes());
        packet.extend_from_slice(&gid.to_be_bytes());
    }
    if let Some(mode) = fixture.mode {
        packet.extend_from_slice(&mode.to_be_bytes());
    }
    if let Some([accessed, modified]) = fixture.times {
        packet.extend_from_slice(&accessed.to_be_bytes());
        packet.extend_from_slice(&modified.to_be_bytes());
    }
    let valid_type = matches!(
        fixture.mode.unwrap_or(0) & TYPE_MASK,
        0 | 0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
    );
    match ssh_format::from_bytes::<Response>(&packet) {
        Ok((response, rest)) => {
            assert!(valid_type);
            assert!(rest.is_empty());
            assert_eq!(response.response_id, 17);
            Some(response)
        }
        Err(_) => {
            assert!(!valid_type);
            None
        }
    }
}

fn exercise(fixture: Fixture) -> Option<()> {
    let kind = expected_kind(fixture.mode);
    let atom = fixture.filename.as_bytes();
    if atom.len() > MAX_ATOM_BYTES || fixture.repeat > MAX_FILENAME_BYTES {
        return None;
    }
    let len = atom.len().checked_mul(fixture.repeat)?;
    if len > MAX_FILENAME_BYTES {
        return None;
    }
    let filename = atom.repeat(fixture.repeat);

    let ResponseInner::Attrs(attrs) = wire_metadata(&fixture)?.response_inner else {
        panic!("attributes packet decoded as another response type");
    };
    // MetaData's raw constructor is private. Its public builder carries the
    // actual decoded attributes into the real production conversion.
    let mut builder = MetaDataBuilder::new();
    if let Some(size) = attrs.get_size() {
        builder.len(size);
    }
    if let Some(ids) = attrs.get_id() {
        builder.id(ids);
    }
    if let Some(permissions) = attrs.get_permissions() {
        let mode = permissions.bits() | attrs.get_filetype().map_or(0, |kind| kind as u32);
        builder.permissions(Permissions::from_raw(RawPermissions::from_bits_retain(
            mode,
        )));
    }
    if let Some((accessed, modified)) = attrs.get_time() {
        builder.time(
            UnixTimeStamp::from_raw(accessed.into_raw())?,
            UnixTimeStamp::from_raw(modified.into_raw())?,
        );
    }
    let metadata = builder.create();
    let expected = StatData {
        kind,
        size: fixture.size,
        permissions: fixture.mode.map(|mode| mode & 0o7777),
        uid: fixture.ids.map(|ids| ids[0]),
        gid: fixture.ids.map(|ids| ids[1]),
        modified_unix_secs: fixture.times.map(|times| u64::from(times[1])),
    };
    assert_eq!(metadata_data(metadata), expected);

    let entry = ListEntry::from_filename(OsStr::from_bytes(&filename), metadata);
    assert_eq!(entry.metadata, expected);
    assert_eq!(entry.name.as_deref(), std::str::from_utf8(&filename).ok());
    assert_eq!(STANDARD.decode(&entry.name_base64).unwrap(), filename);
    assert_eq!(entry.name_base64, STANDARD.encode(&filename));

    // Check the actual wire representation too: absent fields must be present
    // JSON nulls, not fabricated zeros, omitted fields, strings or lossy names.
    let expected_metadata = json!({
        "kind": kind,
        "size": fixture.size,
        "permissions": fixture.mode.map(|mode| mode & 0o7777),
        "uid": fixture.ids.map(|ids| ids[0]),
        "gid": fixture.ids.map(|ids| ids[1]),
        "modified_unix_secs": fixture.times.map(|times| u64::from(times[1])),
    });
    assert_eq!(
        serde_json::to_value(metadata_data(metadata)).unwrap(),
        expected_metadata
    );
    assert_eq!(
        serde_json::to_value(&entry).unwrap(),
        json!({
            "name": std::str::from_utf8(&filename).ok(),
            "name_base64": STANDARD.encode(&filename),
            "metadata": expected_metadata,
        })
    );
    Some(())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    if let Ok(fixture) = serde_json::from_slice::<Fixture>(data) {
        let _ = exercise(fixture);
    }
});
