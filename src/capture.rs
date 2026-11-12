use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) struct Capture {
    pub(crate) bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl Capture {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            truncated: false,
        }
    }

    pub(crate) fn retain(&mut self, bytes: &[u8]) {
        let retained = bytes.len().min(self.limit - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
        self.truncated |= retained < bytes.len();
    }

    pub(crate) fn decode(self) -> (String, bool, bool) {
        match String::from_utf8(self.bytes) {
            Ok(text) => (text, self.truncated, false),
            Err(error) => (
                String::from_utf8_lossy(error.as_bytes()).into_owned(),
                self.truncated,
                true,
            ),
        }
    }
}

pub(crate) async fn drain<R: AsyncRead + Unpin>(
    mut stream: R,
    capture: &mut Capture,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        capture.retain(&buffer[..count]);
    }
}
