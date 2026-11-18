//! Tests for the telemetry configuration and the subscriber.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use aegis_contracts::Error;
use aegis_core::Config;
use aegis_core::telemetry::{self, LogFormat, LogLevel, TelemetryConfig};
use serde_json::{Value, json};
use support::Capture;
use tracing::dispatcher::with_default;

fn config_error<T: std::fmt::Debug>(result: aegis_contracts::Result<T>) -> String {
    match result {
        Err(Error::Config(message)) => message,
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

/// Builds a subscriber for `config`, emits one event at each level, and returns the log lines.
fn lines_for(config: &TelemetryConfig) -> Vec<String> {
    let capture = Capture::default();
    let (dispatch, guard) = telemetry::subscriber(config, capture.writer()).unwrap();
    with_default(&dispatch, || {
        tracing::trace!("trace event");
        tracing::debug!("debug event");
        tracing::info!("info event");
        tracing::warn!("warn event");
        tracing::error!("error event");
    });
    guard.shutdown().unwrap();
    capture.lines()
}

fn with_level(log_level: LogLevel) -> TelemetryConfig {
    TelemetryConfig {
        log_level,
        ..TelemetryConfig::default()
    }
}

#[test]
fn a_log_event_reaches_the_writer_as_one_text_line() {
    let capture = Capture::default();
    let (dispatch, guard) =
        telemetry::subscriber(&TelemetryConfig::default(), capture.writer()).unwrap();
    assert!(!guard.exports_traces());

    with_default(&dispatch, || {
        tracing::info!(user = "alice", attempts = 3, "sign-in checked");
    });

    let lines = capture.lines();
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert!(line.contains(" INFO "), "{line}");
    assert!(
        line.ends_with("sign-in checked user=\"alice\" attempts=3"),
        "{line}"
    );
    assert!(!line.contains('\u{1b}'), "{line}");
}

#[test]
fn a_log_event_reaches_the_writer_as_one_json_object() {
    let capture = Capture::default();
    let config = TelemetryConfig {
        log_format: LogFormat::Json,
        ..TelemetryConfig::default()
    };
    let (dispatch, _guard) = telemetry::subscriber(&config, capture.writer()).unwrap();

    with_default(&dispatch, || {
        tracing::warn!(user = "alice", attempts = 3, "sign-in checked");
    });

    let lines = capture.lines();
    assert_eq!(lines.len(), 1);
    let event: Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(event["level"], "WARN");
    assert_eq!(event["target"], "telemetry");
    assert_eq!(
        event["fields"],
        json!({"message": "sign-in checked", "user": "alice", "attempts": 3})
    );
    assert!(event["timestamp"].is_string(), "{event}");
}

#[test]
fn an_event_in_a_span_shows_the_span_and_its_fields() {
    let capture = Capture::default();
    let config = TelemetryConfig {
        log_format: LogFormat::Json,
        ..TelemetryConfig::default()
    };
    let (dispatch, _guard) = telemetry::subscriber(&config, capture.writer()).unwrap();

    with_default(&dispatch, || {
        let span = tracing::info_span!("triage", incident = "inc-42");
        span.in_scope(|| tracing::info!("verdict ready"));
    });

    let lines = capture.lines();
    assert_eq!(lines.len(), 1);
    let event: Value = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(
        event["span"],
        json!({"name": "triage", "incident": "inc-42"})
    );
}

#[test]
fn the_log_level_selects_the_events() {
    let messages = |level| -> Vec<String> {
        lines_for(&with_level(level))
            .iter()
            .map(|line| line.rsplit(": ").next().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        messages(LogLevel::Trace),
        [
            "trace event",
            "debug event",
            "info event",
            "warn event",
            "error event"
        ]
    );
    assert_eq!(
        messages(LogLevel::Debug),
        ["debug event", "info event", "warn event", "error event"]
    );
    assert_eq!(
        messages(LogLevel::Info),
        ["info event", "warn event", "error event"]
    );
    assert_eq!(messages(LogLevel::Warn), ["warn event", "error event"]);
    assert_eq!(messages(LogLevel::Error), ["error event"]);
    assert_eq!(messages(LogLevel::Off), Vec::<String>::new());
}

#[test]
fn the_default_configuration_has_text_format_info_level_and_no_endpoint() {
    assert_eq!(
        TelemetryConfig::default(),
        TelemetryConfig {
            service_name: "aegis".to_owned(),
            log_format: LogFormat::Text,
            log_level: LogLevel::Info,
            otlp_endpoint: None,
        }
    );
}

#[test]
fn a_missing_section_and_an_empty_section_give_the_default_configuration() {
    let missing = Config::from_toml_str("").unwrap();
    assert_eq!(
        TelemetryConfig::from_config(&missing).unwrap(),
        TelemetryConfig::default()
    );
    let empty = Config::from_toml_str("[telemetry]\n").unwrap();
    assert_eq!(
        TelemetryConfig::from_config(&empty).unwrap(),
        TelemetryConfig::default()
    );
}

#[test]
fn the_section_sets_each_key_and_an_override_wins() {
    let config = Config::from_toml_str(
        r#"
        [telemetry]
        service_name = "aegis-edge"
        log_format = "json"
        log_level = "debug"
        otlp_endpoint = "http://localhost:4318"
        "#,
    )
    .unwrap();
    assert_eq!(
        TelemetryConfig::from_config(&config).unwrap(),
        TelemetryConfig {
            service_name: "aegis-edge".to_owned(),
            log_format: LogFormat::Json,
            log_level: LogLevel::Debug,
            otlp_endpoint: Some("http://localhost:4318".to_owned()),
        }
    );

    let config = config
        .with_overrides([
            (
                "AEGIS__TELEMETRY__SERVICE_NAME".to_owned(),
                "aegis-dev".to_owned(),
            ),
            ("AEGIS__TELEMETRY__LOG_LEVEL".to_owned(), "error".to_owned()),
        ])
        .unwrap();
    let telemetry = TelemetryConfig::from_config(&config).unwrap();
    assert_eq!(telemetry.service_name, "aegis-dev");
    assert_eq!(telemetry.log_level, LogLevel::Error);
    assert_eq!(telemetry.log_format, LogFormat::Json);
}

#[test]
fn an_unknown_key_or_an_unknown_name_in_the_section_is_an_error() {
    let unknown_key = Config::from_toml_str("[telemetry]\nlog_levl = \"debug\"\n").unwrap();
    assert_eq!(
        config_error(TelemetryConfig::from_config(&unknown_key)),
        "the section `telemetry` is not valid: unknown field `log_levl`, expected one of \
         `service_name`, `log_format`, `log_level`, `otlp_endpoint`"
    );
    let unknown_level = Config::from_toml_str("[telemetry]\nlog_level = \"verbose\"\n").unwrap();
    assert_eq!(
        config_error(TelemetryConfig::from_config(&unknown_level)),
        "the section `telemetry` is not valid: key `log_level`: unknown variant, expected one \
         of `trace`, `debug`, `info`, `warn`, `error`, `off`"
    );
    let unknown_format = Config::from_toml_str("[telemetry]\nlog_format = \"xml\"\n").unwrap();
    assert_eq!(
        config_error(TelemetryConfig::from_config(&unknown_format)),
        "the section `telemetry` is not valid: key `log_format`: unknown variant, expected one \
         of `text`, `json`"
    );
}

#[test]
fn the_configuration_serializes_without_an_empty_endpoint() {
    let value = serde_json::to_value(TelemetryConfig::default()).unwrap();
    assert_eq!(
        value,
        json!({"service_name": "aegis", "log_format": "text", "log_level": "info"})
    );
    let decoded: TelemetryConfig = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, TelemetryConfig::default());
}

#[test]
fn an_empty_service_name_is_a_configuration_error() {
    for service_name in ["", "   "] {
        let config = TelemetryConfig {
            service_name: service_name.to_owned(),
            ..TelemetryConfig::default()
        };
        let result = telemetry::subscriber(&config, Capture::default().writer());
        assert_eq!(
            config_error(result),
            "telemetry.service_name must not be empty"
        );
    }
}

#[cfg(not(feature = "otlp"))]
#[test]
fn an_endpoint_without_the_otlp_feature_is_a_configuration_error() {
    let config = TelemetryConfig {
        otlp_endpoint: Some("http://collector.internal:4318".to_owned()),
        ..TelemetryConfig::default()
    };
    let capture = Capture::default();
    let message = config_error(telemetry::subscriber(&config, capture.writer()));
    assert_eq!(
        message,
        "telemetry.otlp_endpoint has a value, but this build cannot export traces: build with \
         the Cargo feature `otlp`, or remove the key"
    );
    assert_eq!(capture.lines(), Vec::<String>::new());
}
