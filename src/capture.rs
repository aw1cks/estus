use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) struct Capture {
    pub(crate) bytes: Vec<u8>,
    limit: usize,
    raw_limit: Option<usize>,
    total_bytes: u64,
    incomplete: bool,
    raw_incomplete: bool,
    progress: crate::progress::Reporter,
}

impl Capture {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
            raw_limit: None,
            total_bytes: 0,
            incomplete: false,
            raw_incomplete: false,
            progress: crate::progress::Reporter::default(),
        }
    }

    pub(crate) fn with_retention(inline_limit: u64, raw_limit: u64) -> Self {
        if raw_limit == 0 {
            return Self::new(inline_limit);
        }
        let mut capture = Self::new(inline_limit);
        let raw_limit = usize::try_from(raw_limit).unwrap_or(usize::MAX);
        capture.bytes = Vec::with_capacity(capture.limit.max(raw_limit));
        capture.raw_limit = Some(raw_limit);
        capture
    }

    pub(crate) fn report_to(&mut self, progress: crate::progress::Reporter) {
        self.progress = progress;
    }

    pub(crate) fn retain(&mut self, bytes: &[u8]) {
        self.progress.bytes(bytes.len());
        self.total_bytes = self
            .total_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let limit = self.limit.max(self.raw_limit.unwrap_or(0));
        let retained = bytes.len().min(limit - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..retained]);
    }

    // A closed drain may have missed bytes even when the byte cap was not reached.
    pub(crate) fn incomplete(&mut self) {
        self.incomplete = true;
    }

    // Native channel interruption historically leaves inline flags unchanged.
    // Record its missing tail separately for explicitly requested raw output.
    pub(crate) fn retention_incomplete(&mut self) {
        self.raw_incomplete = true;
    }

    pub(crate) fn decode(mut self) -> (String, bool, bool) {
        let truncated = self.total_bytes > self.limit as u64 || self.incomplete;
        self.bytes.truncate(self.limit);
        match String::from_utf8(self.bytes) {
            Ok(text) => (text, truncated, false),
            Err(error) => (
                String::from_utf8_lossy(error.as_bytes()).into_owned(),
                truncated,
                true,
            ),
        }
    }

    pub(crate) fn finish(mut self) -> (String, bool, bool, Option<crate::output::RetainedBytes>) {
        let raw = self.raw_limit.map(|limit| {
            // Keep the original allocation for the larger consumer. The raw
            // payload must never carry an inline-sized allocation into storage.
            let bytes = if limit >= self.limit {
                let inline = self.bytes[..self.bytes.len().min(self.limit)].to_vec();
                let mut raw = std::mem::replace(&mut self.bytes, inline);
                raw.truncate(limit);
                raw
            } else {
                self.bytes[..self.bytes.len().min(limit)].to_vec()
            };
            crate::output::RetainedBytes {
                bytes,
                total_bytes: self.total_bytes,
                truncated: self.total_bytes > limit as u64
                    || self.incomplete
                    || self.raw_incomplete,
            }
        });
        let (text, truncated, lossy) = self.decode();
        (text, truncated, lossy, raw)
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

#[cfg(test)]
mod tests {
    use super::Capture;

    #[test]
    fn raw_prefix_preserves_invalid_bytes_beyond_inline_limit() {
        let mut capture = Capture::with_retention(2, 8);
        capture.retain(b"a\xe2");
        capture.retain(b"\x82\xac\0\xff");
        let (text, truncated, lossy, raw) = capture.finish();
        assert_eq!(text, "a\u{fffd}");
        assert!(truncated);
        assert!(lossy);
        let raw = raw.unwrap();
        assert_eq!(raw.bytes, b"a\xe2\x82\xac\0\xff");
        assert_eq!(raw.total_bytes, 6);
        assert!(!raw.truncated);
        assert!(raw.bytes.capacity() <= 8);
    }

    #[test]
    fn smaller_raw_prefix_does_not_truncate_inline_or_keep_its_allocation() {
        let mut capture = Capture::with_retention(64, 3);
        capture.retain(b"abcdef");
        let (text, truncated, lossy, raw) = capture.finish();
        assert_eq!(text, "abcdef");
        assert!(!truncated);
        assert!(!lossy);
        let raw = raw.unwrap();
        assert_eq!(raw.bytes, b"abc");
        assert_eq!(raw.total_bytes, 6);
        assert!(raw.truncated);
        assert!(raw.bytes.capacity() <= 3);
    }

    #[test]
    fn interrupted_raw_capture_does_not_change_legacy_inline_flags() {
        let mut capture = Capture::with_retention(8, 8);
        capture.retain(b"abc");
        capture.retention_incomplete();
        let (text, truncated, lossy, raw) = capture.finish();
        assert_eq!(text, "abc");
        assert!(!truncated);
        assert!(!lossy);
        assert!(raw.unwrap().truncated);

        let mut capture = Capture::new(8);
        capture.retain(b"abc");
        capture.incomplete();
        let (_, truncated, _, raw) = capture.finish();
        assert!(truncated);
        assert!(raw.is_none());
    }
}
