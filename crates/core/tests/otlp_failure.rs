//! Tests that a failed trace export goes to the log.
//!
//! The exporter reports a failure from its own thread. Only a global subscriber receives
//! that event. This file has one test, so that no other test runs in the same process.
#![cfg(feature = "otlp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_core::telemetry::{self, TelemetryConfig};
use support::Capture;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_collector_that_rejects_the_data_gives_an_error_event_and_no_shutdown_error() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let capture = Capture::default();
    let config = TelemetryConfig {
        otlp_endpoint: Some(server.uri()),
        ..TelemetryConfig::default()
    };
    let (dispatch, guard) = telemetry::subscriber(&config, capture.writer()).unwrap();
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    drop(tracing::info_span!("contain-incident"));
    guard.shutdown().unwrap();

    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let errors: Vec<String> = capture
        .lines()
        .into_iter()
        .filter(|line| line.contains(" ERROR "))
        .collect();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("ExportError"), "{}", errors[0]);
    assert!(errors[0].contains("400"), "{}", errors[0]);
}
