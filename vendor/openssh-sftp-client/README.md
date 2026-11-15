# openssh-sftp-client

## Estus local integration

Vendored from crates.io `openssh-sftp-client` 0.15.12, upstream commit
`1633973b6591d9ba3d34ee442919ec94472669ec`; published archive SHA-256:
`d2fb225c266230c52084575d53e7219c95c334a7460a1d8d42924cde7fb43ae8`.
The MIT license is retained in `LICENSE`.

Local delta: `OpenOptions::create_permissions` forwards mode attributes in the
original create OPEN; internal helper callers retain empty creation attributes.
Upstream-only example/test targets are omitted from this runtime source copy.
Estus protocol and real-SFTP acceptance covers initial permissions, payloads,
acknowledgements and cleanup. Upstream submission is deferred until this
integration has settled; `openssh-sftp-protocol` remains an upstream dependency.


[![Rust](https://github.com/openssh-rust/openssh-sftp-client/actions/workflows/rust.yml/badge.svg)](https://github.com/openssh-rust/openssh-sftp-client/actions/workflows/rust.yml)

[![crate.io downloads](https://img.shields.io/crates/d/openssh-sftp-client)](https://crates.io/crates/openssh-sftp-client)

[![crate.io version](https://img.shields.io/crates/v/openssh-sftp-client)](https://crates.io/crates/openssh-sftp-client)

[![docs](https://docs.rs/openssh-sftp-client/badge.svg)](https://docs.rs/openssh-sftp-client)

openssh-sftp-client, implements [sftp v3] according to
[`openssh-portable/sftp-client.c`] in rust using `tokio` and `serde`.

It exposes highlevel `async` APIs that models closely after `std::fs` that are
easy to use.

[sftp v3]: https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt
[`openssh-portable/sftp-client.c`]: https://github.com/openssh/openssh-portable/blob/19b3d846f06697c85957ab79a63454f57f8e22d6/sftp-client.c

## Extensions

This crate support the following extensions:
 - limits
 - expand path
 - fsync
 - hardlink
 - posix rename
 - copy-data

## How to run tests

For macOS, please install latest rsync from homebrew.

```
./run_tests.sh
```
