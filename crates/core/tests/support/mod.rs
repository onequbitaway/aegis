//! Helpers that the telemetry tests share.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io;
use std::sync::{Arc, Mutex};

/// A log destination in memory. All clones write to the same buffer.
#[derive(Clone, Default)]
pub struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Capture {
    /// Returns a writer factory for `aegis_core::telemetry::subscriber`.
    pub fn writer(&self) -> impl Fn() -> Capture + Send + Sync + 'static {
        let capture = self.clone();
        move || capture.clone()
    }

    /// Returns the lines that the subscriber wrote.
    pub fn lines(&self) -> Vec<String> {
        let bytes = self.bytes.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl io::Write for Capture {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
