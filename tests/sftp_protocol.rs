//! Regressions for lossless Unix filename decoding in the upstream SFTP protocol.
use std::os::unix::ffi::OsStrExt;

use openssh_sftp_protocol::{
    response::{NameEntry, Response, ResponseInner},
    ssh_format,
};

fn entry_bytes(name: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(name.len() as u32).to_be_bytes());
    bytes.extend_from_slice(name);
    // The human-oriented longname is not a filename and need not be UTF-8.
    bytes.extend_from_slice(&3u32.to_be_bytes());
    bytes.extend_from_slice(b"\xff -");
    bytes.extend_from_slice(&0u32.to_be_bytes()); // No metadata attributes supplied.
    bytes
}

#[test]
fn sftp_name_packets_preserve_non_utf8_filename_bytes() {
    let names: [&[u8]; 3] = [b"raw-\xff\xfe", b"quote'\"\\\n\x01", "é-雪".as_bytes()];
    let mut packet = vec![104]; // SSH_FXP_NAME, without the outer packet length.
    packet.extend_from_slice(&17u32.to_be_bytes());
    packet.extend_from_slice(&3u32.to_be_bytes());
    for name in names {
        packet.extend_from_slice(&entry_bytes(name));
    }
    let (response, rest) = ssh_format::from_bytes::<Response>(&packet)
        .expect("SFTP filenames are raw Unix bytes, not UTF-8 strings");
    assert!(rest.is_empty());
    assert_eq!(response.response_id, 17);
    let ResponseInner::Name(entries) = response.response_inner else {
        panic!("name packet decoded as another response type");
    };
    let actual: Vec<_> = entries
        .iter()
        .map(|entry| entry.filename.as_os_str().as_bytes())
        .collect();
    assert_eq!(actual, names);
    for entry in entries.iter() {
        assert_eq!(&*entry.longname, b"\xff -");
        assert_eq!(entry.attrs.get_size(), None);
    }
}

#[test]
fn standalone_name_entries_use_the_same_lossless_decoder() {
    let bytes = entry_bytes(b"raw-\xff\xfe");
    let (entry, rest) = ssh_format::from_bytes::<NameEntry>(&bytes)
        .expect("standalone directory entries must also preserve raw names");
    assert!(rest.is_empty());
    assert_eq!(entry.filename.as_os_str().as_bytes(), b"raw-\xff\xfe");
}
