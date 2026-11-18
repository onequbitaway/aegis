//! The OpenTelemetry OTLP trace exporter.

use aegis_contracts::{Error, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{ExporterBuildError, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::Layer;

use super::BoxedLayer;

/// The name of the instrumentation scope of all AEGIS spans.
const TRACER_NAME: &str = "aegis";

/// The path of the trace receiver below the base URL of a collector.
const TRACES_PATH: &str = "/v1/traces";

/// The crates that do the export. Their spans and events do not go to the collector.
///
/// The export of a span makes HTTP activity. If that activity made spans for the collector,
/// each export would cause one more export.
const EXPORT_PATH_CRATES: [&str; 5] = ["h2", "hyper", "opentelemetry", "reqwest", "rustls"];

/// Builds the layer that sends spans to the collector at `endpoint`.
///
/// The exporter sends batches from its own thread. It does not need a Tokio runtime.
pub(super) fn layer(service_name: &str, endpoint: &str) -> Result<(BoxedLayer, SdkTracerProvider)> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(traces_url(endpoint)?)
        .build()
        .map_err(|error| match error {
            // The text of this variant can contain values from the environment.
            ExporterBuildError::InvalidConfiguration(_) => Error::Config(
                "the OTLP trace exporter configuration is not valid: examine \
                 telemetry.otlp_endpoint and the OTEL_EXPORTER_OTLP_* environment variables"
                    .to_owned(),
            ),
            other => Error::other("build the OTLP trace exporter", other),
        })?;
    let resource = Resource::builder()
        .with_service_name(service_name.to_owned())
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let layer = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(TRACER_NAME))
        .with_filter(filter_fn(|metadata| !is_export_path(metadata.target())))
        .boxed();
    Ok((layer, provider))
}

/// Returns `true` if `target` is a module of a crate in [`EXPORT_PATH_CRATES`].
///
/// A crate name can have `-` where its module path has `_`. Some crates use the crate name
/// as the target.
fn is_export_path(target: &str) -> bool {
    let crate_name = target.split("::").next().unwrap_or(target);
    EXPORT_PATH_CRATES.iter().any(|excluded| {
        crate_name == *excluded
            || crate_name
                .strip_prefix(excluded)
                .is_some_and(|rest| rest.starts_with(['_', '-']))
    })
}

/// Sends the spans that remain and stops the exporter.
pub(super) fn shutdown(provider: &SdkTracerProvider) -> Result<()> {
    match provider.shutdown() {
        Ok(()) | Err(OTelSdkError::AlreadyShutdown) => Ok(()),
        Err(OTelSdkError::Timeout(limit)) => Err(Error::Timeout(format!(
            "the OTLP trace exporter did not stop in {limit:?}"
        ))),
        Err(OTelSdkError::InternalFailure(cause)) => Err(Error::Unavailable(format!(
            "the OTLP trace exporter did not stop correctly: {cause}"
        ))),
    }
}

/// Checks the base URL of a collector and returns the URL of its trace receiver.
///
/// The errors do not contain the URL.
fn traces_url(endpoint: &str) -> Result<String> {
    let invalid = |cause: &str| {
        Err(Error::Config(format!(
            "telemetry.otlp_endpoint is not valid: {cause}"
        )))
    };
    let Some(after_scheme) = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
    else {
        return invalid("the URL must start with http:// or https://");
    };
    if endpoint
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return invalid("the URL must not contain white space or control characters");
    }
    if after_scheme.contains(['?', '#']) {
        return invalid("the URL must not have a query or a fragment");
    }
    let authority = after_scheme.split('/').next().unwrap_or_default();
    if authority.contains('@') {
        return invalid(
            "the URL must not contain credentials; set OTEL_EXPORTER_OTLP_HEADERS to authenticate",
        );
    }
    if authority.is_empty() {
        return invalid("the URL must have a host");
    }
    let base = endpoint.trim_end_matches('/');
    if base.ends_with(TRACES_PATH) {
        Ok(base.to_owned())
    } else {
        Ok(format!("{base}{TRACES_PATH}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_error(endpoint: &str) -> String {
        match traces_url(endpoint) {
            Err(Error::Config(message)) => message,
            other => panic!("expected a configuration error, got {other:?}"),
        }
    }

    #[test]
    fn is_export_path_matches_the_crates_that_do_the_export() {
        for target in [
            "h2",
            "h2::proto::streams",
            "hyper::client",
            "hyper_util::client::legacy::pool",
            "hyper_rustls::connector",
            "opentelemetry",
            "opentelemetry_sdk",
            "opentelemetry-otlp",
            "reqwest::blocking::client",
            "rustls::client::hs",
        ] {
            assert!(is_export_path(target), "{target}");
        }
        for target in [
            "aegis_core::telemetry",
            "aegis_detection",
            "h2o::server",
            "hyperion",
            "my_crate::h2",
            "telemetry",
            "",
        ] {
            assert!(!is_export_path(target), "{target}");
        }
    }

    #[test]
    fn traces_url_adds_the_trace_path_to_a_base_url() {
        assert_eq!(
            traces_url("http://localhost:4318").unwrap(),
            "http://localhost:4318/v1/traces"
        );
        assert_eq!(
            traces_url("https://collector.example/otlp/").unwrap(),
            "https://collector.example/otlp/v1/traces"
        );
    }

    #[test]
    fn traces_url_keeps_a_url_that_has_the_trace_path() {
        assert_eq!(
            traces_url("http://localhost:4318/v1/traces").unwrap(),
            "http://localhost:4318/v1/traces"
        );
    }

    #[test]
    fn traces_url_rejects_a_scheme_that_is_not_http() {
        assert_eq!(
            config_error("grpc://localhost:4317"),
            "telemetry.otlp_endpoint is not valid: the URL must start with http:// or https://"
        );
        assert_eq!(
            config_error("localhost:4318"),
            "telemetry.otlp_endpoint is not valid: the URL must start with http:// or https://"
        );
    }

    #[test]
    fn traces_url_rejects_credentials_and_does_not_show_them() {
        let message = config_error("https://operator:hunter2@collector.example");
        assert_eq!(
            message,
            "telemetry.otlp_endpoint is not valid: the URL must not contain credentials; set \
             OTEL_EXPORTER_OTLP_HEADERS to authenticate"
        );
    }

    #[test]
    fn traces_url_rejects_a_query_a_fragment_and_white_space() {
        assert_eq!(
            config_error("https://collector.example?token=hunter2"),
            "telemetry.otlp_endpoint is not valid: the URL must not have a query or a fragment"
        );
        assert_eq!(
            config_error("https://collector.example/#part"),
            "telemetry.otlp_endpoint is not valid: the URL must not have a query or a fragment"
        );
        assert_eq!(
            config_error("https://collector.example/a b"),
            "telemetry.otlp_endpoint is not valid: the URL must not contain white space or \
             control characters"
        );
    }

    #[test]
    fn traces_url_rejects_a_url_with_no_host() {
        assert_eq!(
            config_error("http://"),
            "telemetry.otlp_endpoint is not valid: the URL must have a host"
        );
        assert_eq!(
            config_error("https:///v1/traces"),
            "telemetry.otlp_endpoint is not valid: the URL must have a host"
        );
    }
}
