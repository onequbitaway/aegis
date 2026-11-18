//! Tests for `telemetry::init`.
//!
//! `init` installs the global subscriber of the process. This file has one test, so that no
//! other test runs in the same process.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use aegis_contracts::Error;
use aegis_core::telemetry::{self, LogLevel, TelemetryConfig};
use tracing::Level;

#[test]
fn init_installs_the_global_subscriber_one_time() {
    assert!(!tracing::dispatcher::has_been_set());
    let config = TelemetryConfig {
        log_level: LogLevel::Error,
        ..TelemetryConfig::default()
    };

    let guard = telemetry::init(&config).unwrap();

    assert!(tracing::dispatcher::has_been_set());
    assert!(!guard.exports_traces());
    assert!(tracing::enabled!(Level::ERROR));
    assert!(!tracing::enabled!(Level::WARN));

    match telemetry::init(&config) {
        Err(Error::Other { context, .. }) => {
            assert_eq!(context, "install the global tracing subscriber");
        }
        other => panic!("expected Error::Other, got {other:?}"),
    }
    guard.shutdown().unwrap();
}
