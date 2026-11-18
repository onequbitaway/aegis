//! Tests for the OTLP trace exporter. The collector is a mock HTTP server on this computer.
#![cfg(feature = "otlp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_contracts::Error;
use aegis_core::telemetry::{self, LogLevel, TelemetryConfig};
use support::Capture;
use tracing::dispatcher::with_default;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SERVICE_NAME: &str = "aegis-otlp-test";

fn config_for(endpoint: &str) -> TelemetryConfig {
    TelemetryConfig {
        service_name: SERVICE_NAME.to_owned(),
        otlp_endpoint: Some(endpoint.to_owned()),
        ..TelemetryConfig::default()
    }
}

fn config_error(endpoint: &str) -> String {
    let capture = Capture::default();
    match telemetry::subscriber(&config_for(endpoint), capture.writer()) {
        Err(Error::Config(message)) => message,
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

/// Returns `true` if `needle` occurs in `haystack`. OTLP protobuf holds strings as plain bytes.
fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Starts a collector that accepts trace data at the standard path.
async fn collector() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/traces"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Returns the body of the one request that the collector received.
async fn one_export(server: &MockServer) -> Vec<u8> {
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/v1/traces");
    assert_eq!(
        request.headers.get("content-type").unwrap(),
        "application/x-protobuf"
    );
    request.body.clone()
}

#[tokio::test]
async fn a_span_reaches_the_collector_when_the_guard_shuts_down() {
    let server = collector().await;
    let capture = Capture::default();
    let (dispatch, guard) =
        telemetry::subscriber(&config_for(&server.uri()), capture.writer()).unwrap();
    assert!(guard.exports_traces());

    with_default(&dispatch, || {
        let span = tracing::info_span!("contain-incident", incident = "inc-42");
        span.in_scope(|| tracing::info!("revoked a credential"));
    });
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    guard.shutdown().unwrap();

    let body = one_export(&server).await;
    assert!(contains(&body, SERVICE_NAME));
    assert!(contains(&body, "contain-incident"));
    assert!(contains(&body, "inc-42"));
    assert!(contains(&body, "revoked a credential"));

    let lines = capture.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].ends_with("revoked a credential"), "{}", lines[0]);
}

#[tokio::test]
async fn the_guard_sends_the_spans_when_it_is_dropped() {
    let server = collector().await;
    let (dispatch, guard) =
        telemetry::subscriber(&config_for(&server.uri()), Capture::default().writer()).unwrap();

    with_default(&dispatch, || drop(tracing::info_span!("hunt-sweep")));
    drop(guard);

    let body = one_export(&server).await;
    assert!(contains(&body, "hunt-sweep"));
}

#[tokio::test]
async fn an_endpoint_with_the_trace_path_or_a_final_slash_goes_to_the_same_path() {
    for suffix in ["/", "/v1/traces"] {
        let server = collector().await;
        let endpoint = format!("{}{suffix}", server.uri());
        let (dispatch, guard) =
            telemetry::subscriber(&config_for(&endpoint), Capture::default().writer()).unwrap();
        with_default(&dispatch, || drop(tracing::info_span!("triage")));
        guard.shutdown().unwrap();
        assert!(contains(&one_export(&server).await, "triage"), "{suffix}");
    }
}

#[tokio::test]
async fn the_log_level_also_selects_the_spans_for_the_collector() {
    let server = collector().await;
    let config = TelemetryConfig {
        log_level: LogLevel::Info,
        ..config_for(&server.uri())
    };
    let (dispatch, guard) = telemetry::subscriber(&config, Capture::default().writer()).unwrap();

    with_default(&dispatch, || {
        drop(tracing::debug_span!("debug-detail"));
        drop(tracing::info_span!("info-summary"));
    });
    guard.shutdown().unwrap();

    let body = one_export(&server).await;
    assert!(contains(&body, "info-summary"));
    assert!(!contains(&body, "debug-detail"));
}

#[tokio::test]
async fn spans_of_the_export_path_do_not_go_to_the_collector() {
    let server = collector().await;
    let capture = Capture::default();
    let (dispatch, guard) =
        telemetry::subscriber(&config_for(&server.uri()), capture.writer()).unwrap();

    with_default(&dispatch, || {
        let transport = tracing::info_span!(target: "h2::codec::framed_write", "framed-write");
        transport.in_scope(|| tracing::info!(target: "hyper_util::client", "pooled connection"));
        let work = tracing::info_span!("correlate-detections");
        work.in_scope(|| tracing::info!(target: "reqwest::connect", "client event in a span"));
    });
    guard.shutdown().unwrap();

    let body = one_export(&server).await;
    assert!(contains(&body, "correlate-detections"));
    assert!(!contains(&body, "framed-write"));
    assert!(!contains(&body, "client event in a span"));
    // The log keeps the events of all crates.
    assert_eq!(capture.lines().len(), 2);
}

#[tokio::test]
async fn no_span_gives_no_request_to_the_collector() {
    let server = collector().await;
    let (dispatch, guard) =
        telemetry::subscriber(&config_for(&server.uri()), Capture::default().writer()).unwrap();
    with_default(&dispatch, || tracing::info!("an event with no span"));
    guard.shutdown().unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[test]
fn the_exporter_does_not_need_a_tokio_runtime() {
    // The runtime is only for the mock collector. The subscriber code runs outside it.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let server = runtime.block_on(collector());
    assert!(tokio::runtime::Handle::try_current().is_err());

    let (dispatch, guard) =
        telemetry::subscriber(&config_for(&server.uri()), Capture::default().writer()).unwrap();
    with_default(&dispatch, || drop(tracing::info_span!("replay-fixture")));
    guard.shutdown().unwrap();

    let body = runtime.block_on(one_export(&server));
    assert!(contains(&body, "replay-fixture"));
}

#[test]
fn an_https_endpoint_builds_an_exporter() {
    // The top-level domain `invalid` is reserved. The test sends no span, thus no request.
    let (_dispatch, guard) = telemetry::subscriber(
        &config_for("https://collector.invalid:4318"),
        Capture::default().writer(),
    )
    .unwrap();
    assert!(guard.exports_traces());
    guard.shutdown().unwrap();
}

#[test]
fn an_endpoint_that_is_not_an_http_url_is_a_configuration_error() {
    assert_eq!(
        config_error("grpc://collector.internal:4317"),
        "telemetry.otlp_endpoint is not valid: the URL must start with http:// or https://"
    );
    assert_eq!(
        config_error(""),
        "telemetry.otlp_endpoint is not valid: the URL must start with http:// or https://"
    );
    assert_eq!(
        config_error("http://[not-an-address"),
        "the OTLP trace exporter configuration is not valid: examine telemetry.otlp_endpoint \
         and the OTEL_EXPORTER_OTLP_* environment variables"
    );
}

#[test]
fn an_endpoint_with_credentials_is_a_configuration_error_that_does_not_show_them() {
    assert_eq!(
        config_error("https://operator:hunter2-s3cret@collector.internal"),
        "telemetry.otlp_endpoint is not valid: the URL must not contain credentials; set \
         OTEL_EXPORTER_OTLP_HEADERS to authenticate"
    );
    assert_eq!(
        config_error("https://collector.internal/?token=hunter2-s3cret"),
        "telemetry.otlp_endpoint is not valid: the URL must not have a query or a fragment"
    );
}
