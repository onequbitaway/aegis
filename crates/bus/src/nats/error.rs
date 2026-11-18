//! The mapping from NATS client errors to contract errors.
//!
//! No message from this module contains a credential or a payload.

use std::error::Error as StdError;
use std::io;

use aegis_contracts::Error;
use async_nats::jetstream::context::{
    ConsumerInfoError, ConsumerInfoErrorKind, CreateStreamError, CreateStreamErrorKind,
    GetStreamError, GetStreamErrorKind, PublishError, PublishErrorKind, RequestError,
    RequestErrorKind,
};
use async_nats::jetstream::stream::{ConsumerError, ConsumerErrorKind};
use async_nats::jetstream::{self, ErrorCode};
use async_nats::rustls::{self, AlertDescription};
use async_nats::{ConnectError, ConnectErrorKind};

const HTTP_REQUEST_TIMEOUT: usize = 408;
const HTTP_TOO_MANY_REQUESTS: usize = 429;
const HTTP_SERVICE_UNAVAILABLE: usize = 503;

/// The JetStream error codes that mean "try again later".
const TRANSIENT_CODES: [ErrorCode; 9] = [
    ErrorCode::CLUSTER_NOT_AVAILABLE,
    ErrorCode::CLUSTER_NO_PEERS,
    ErrorCode::CLUSTER_NOT_LEADER,
    ErrorCode::CLUSTER_NOT_ASSIGNED,
    ErrorCode::CLUSTER_NOT_ACTIVE,
    ErrorCode::STREAM_OFFLINE,
    ErrorCode::CONSUMER_OFFLINE,
    ErrorCode::STREAM_NOT_FOUND,
    ErrorCode::STREAM_STORE_FAILED,
];

/// The JetStream error codes that mean "the server has no capacity for this request".
const RESOURCE_CODES: [ErrorCode; 6] = [
    ErrorCode::INSUFFICIENT_RESOURCES,
    ErrorCode::ACCOUNT_RESOURCES_EXCEEDED,
    ErrorCode::MEMORY_RESOURCES_EXCEEDED,
    ErrorCode::STORAGE_RESOURCES_EXCEEDED,
    ErrorCode::MAXIMUM_STREAMS_LIMIT,
    ErrorCode::MAXIMUM_CONSUMERS_LIMIT,
];

/// The JetStream error codes that mean "the pattern or the name from the caller is not valid".
const CALLER_INPUT_CODES: [ErrorCode; 7] = [
    ErrorCode::CONSUMER_FILTER_NOT_SUBSET,
    ErrorCode::CONSUMER_EMPTY_FILTER,
    ErrorCode::CONSUMER_BAD_DURABLE_NAME,
    ErrorCode::CONSUMER_NAME_TOO_LONG,
    ErrorCode::CONSUMER_NAME_CONTAINS_PATH_SEPARATORS,
    ErrorCode::STREAM_MESSAGE_EXCEEDS_MAXIMUM,
    ErrorCode::STREAM_HEADER_EXCEEDS_MAXIMUM,
];

/// What the request changes. An error that has no more specific mapping uses this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// The stream. The request holds only values from the configuration.
    Stream,
    /// A consumer or a message.
    Other,
}

/// Why a JetStream request failed, before the mapping to a contract error.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The server did not answer in the permitted time.
    TimedOut,
    /// No JetStream service listens for the request.
    NoResponders,
    /// The request did not reach the server, or the answer was not readable.
    Transport(String),
    /// JetStream answered with an error.
    Api(jetstream::Error),
    /// The client library rejected the request before it sent it.
    Rejected(String),
    /// The stream or the consumer that the request names does not exist.
    Missing(&'static str),
}

impl Failure {
    /// Returns `true` if JetStream answered with this error code.
    pub(crate) fn has_code(&self, code: ErrorCode) -> bool {
        matches!(self, Self::Api(error) if error.error_code() == code)
    }

    /// Returns `true` if the request got no answer. A server that denies permission for a
    /// request gives no answer to it.
    pub(crate) fn is_no_answer(&self) -> bool {
        matches!(self, Self::TimedOut | Self::NoResponders)
    }

    /// Maps the failure to a contract error. `operation` says what the bus did.
    pub(crate) fn into_error(self, operation: &str, target: Target) -> Error {
        match self {
            Self::TimedOut => Error::Timeout(format!(
                "{operation}: the NATS server did not answer in time"
            )),
            Self::NoResponders => Error::Unavailable(format!(
                "{operation}: JetStream did not answer; it is not enabled or not ready"
            )),
            Self::Transport(detail) => Error::Unavailable(format!(
                "{operation}: the request to the NATS server failed: {detail}"
            )),
            Self::Rejected(detail) => Error::InvalidInput(format!("{operation}: {detail}")),
            Self::Missing(what) => Error::Unavailable(format!(
                "{operation}: the {what} does not exist on the NATS server"
            )),
            Self::Api(error) => api_error(operation, error, target),
        }
    }
}

fn api_error(operation: &str, error: jetstream::Error, target: Target) -> Error {
    let code = error.error_code();
    let message = format!("{operation}: {error}");
    if code == ErrorCode::JETSTREAM_NOT_ENABLED
        || code == ErrorCode::JETSTREAM_NOT_ENABLED_FOR_ACCOUNT
    {
        return Error::Config(message);
    }
    if RESOURCE_CODES.contains(&code) {
        // A stream request that asks for too much is a configuration error. For other
        // requests, the server can have capacity again later.
        return match target {
            Target::Stream => Error::Config(message),
            Target::Other => Error::Unavailable(message),
        };
    }
    if code == ErrorCode::STREAM_TOO_MANY_REQUESTS || error.code() == HTTP_TOO_MANY_REQUESTS {
        return Error::RateLimited(message);
    }
    if TRANSIENT_CODES.contains(&code) {
        return Error::Unavailable(message);
    }
    if CALLER_INPUT_CODES.contains(&code) {
        return Error::InvalidInput(message);
    }
    match (error.code(), target) {
        (HTTP_REQUEST_TIMEOUT, _) => Error::Timeout(message),
        (_, Target::Stream) => Error::Config(message),
        (HTTP_SERVICE_UNAVAILABLE, Target::Other) => Error::Unavailable(message),
        (_, Target::Other) => Error::other(operation, error),
    }
}

/// Finds the transport failure in the source of a client error.
fn source_failure(error: &(dyn StdError + 'static)) -> Failure {
    let kind = error
        .source()
        .and_then(|source| source.downcast_ref::<RequestError>())
        .map(RequestError::kind);
    match kind {
        Some(RequestErrorKind::TimedOut) => Failure::TimedOut,
        Some(RequestErrorKind::NoResponders) => Failure::NoResponders,
        Some(RequestErrorKind::InvalidSubject) => Failure::Rejected(error.to_string()),
        Some(RequestErrorKind::Other) | None => Failure::Transport(error.to_string()),
    }
}

impl From<RequestError> for Failure {
    fn from(error: RequestError) -> Self {
        match error.kind() {
            RequestErrorKind::TimedOut => Self::TimedOut,
            RequestErrorKind::NoResponders => Self::NoResponders,
            RequestErrorKind::InvalidSubject => Self::Rejected(error.to_string()),
            RequestErrorKind::Other => {
                let api = error
                    .source()
                    .and_then(|source| source.downcast_ref::<jetstream::Error>());
                match api {
                    Some(api) => Self::Api(api.clone()),
                    None => Self::Transport(error.to_string()),
                }
            }
        }
    }
}

impl From<GetStreamError> for Failure {
    fn from(error: GetStreamError) -> Self {
        match error.kind() {
            GetStreamErrorKind::JetStream(api) => Self::Api(api),
            GetStreamErrorKind::Request => source_failure(&error),
            GetStreamErrorKind::EmptyName | GetStreamErrorKind::InvalidStreamName => {
                Self::Rejected(error.to_string())
            }
        }
    }
}

impl From<CreateStreamError> for Failure {
    fn from(error: CreateStreamError) -> Self {
        match error.kind() {
            CreateStreamErrorKind::JetStream(api) => Self::Api(api),
            CreateStreamErrorKind::TimedOut => Self::TimedOut,
            CreateStreamErrorKind::JetStreamUnavailable => Self::NoResponders,
            CreateStreamErrorKind::Response
            | CreateStreamErrorKind::ResponseParse
            | CreateStreamErrorKind::NotFound => Self::Transport(error.to_string()),
            CreateStreamErrorKind::EmptyStreamName
            | CreateStreamErrorKind::InvalidStreamName
            | CreateStreamErrorKind::DomainAndExternalSet => Self::Rejected(error.to_string()),
        }
    }
}

impl From<ConsumerInfoError> for Failure {
    fn from(error: ConsumerInfoError) -> Self {
        match error.kind() {
            ConsumerInfoErrorKind::JetStream(api) => Self::Api(api),
            ConsumerInfoErrorKind::TimedOut => Self::TimedOut,
            ConsumerInfoErrorKind::NoResponders => Self::NoResponders,
            ConsumerInfoErrorKind::InvalidName => Self::Rejected(error.to_string()),
            ConsumerInfoErrorKind::NotFound => Self::Missing("consumer"),
            ConsumerInfoErrorKind::StreamNotFound => Self::Missing("stream"),
            ConsumerInfoErrorKind::Offline | ConsumerInfoErrorKind::Request => {
                Self::Transport(error.to_string())
            }
        }
    }
}

impl From<ConsumerError> for Failure {
    fn from(error: ConsumerError) -> Self {
        match error.kind() {
            ConsumerErrorKind::JetStream(api) => Self::Api(api),
            ConsumerErrorKind::TimedOut => Self::TimedOut,
            ConsumerErrorKind::Request => source_failure(&error),
            ConsumerErrorKind::InvalidName => Self::Rejected(error.to_string()),
            ConsumerErrorKind::InvalidConsumerType | ConsumerErrorKind::Other => {
                Self::Transport(error.to_string())
            }
        }
    }
}

/// The TLS alerts that a server sends when it does not accept the client certificate.
const CLIENT_CERTIFICATE_ALERTS: [AlertDescription; 8] = [
    AlertDescription::CertificateRequired,
    AlertDescription::BadCertificate,
    AlertDescription::UnsupportedCertificate,
    AlertDescription::CertificateRevoked,
    AlertDescription::CertificateExpired,
    AlertDescription::CertificateUnknown,
    AlertDescription::UnknownCA,
    AlertDescription::AccessDenied,
];

/// Maps an error of the first connection.
///
/// A TLS failure is not retryable. A second attempt gets the same certificates.
pub(crate) fn connect_error(error: &ConnectError) -> Error {
    let message = format!("connect to NATS: {error}");
    match error.kind() {
        ConnectErrorKind::ServerParse | ConnectErrorKind::Tls => Error::Config(message),
        ConnectErrorKind::Authentication | ConnectErrorKind::AuthorizationViolation => {
            Error::Unauthorized(message)
        }
        ConnectErrorKind::TimedOut => Error::Timeout(message),
        ConnectErrorKind::Io => match tls_failure(error) {
            Some(rustls::Error::AlertReceived(alert))
                if CLIENT_CERTIFICATE_ALERTS.contains(alert) =>
            {
                Error::Unauthorized(format!(
                    "connect to NATS: the server did not accept the TLS client certificate \
                     (alert {alert:?})"
                ))
            }
            Some(failure) => Error::Config(format!(
                "connect to NATS: the TLS handshake failed: {failure}"
            )),
            None => Error::Unavailable(message),
        },
        ConnectErrorKind::Dns | ConnectErrorKind::MaxReconnects => Error::Unavailable(message),
    }
}

/// Finds the TLS error in an I/O error of the connection, if the TLS library made it.
fn tls_failure(error: &ConnectError) -> Option<&rustls::Error> {
    error
        .source()?
        .downcast_ref::<io::Error>()?
        .get_ref()?
        .downcast_ref::<rustls::Error>()
}

/// The result of a publish operation that failed, before the mapping to a contract error.
pub(crate) fn publish_failure(error: PublishError) -> PublishFailure {
    match error.kind() {
        PublishErrorKind::TimedOut => PublishFailure::NoAnswer(Failure::TimedOut),
        PublishErrorKind::StreamNotFound => PublishFailure::NoStream,
        PublishErrorKind::BrokenPipe => PublishFailure::Mapped(Error::Unavailable(
            "the connection to the NATS server closed before the acknowledgement".to_owned(),
        )),
        PublishErrorKind::MaxAckPending => PublishFailure::Mapped(Error::RateLimited(
            "too many publish operations wait for an acknowledgement".to_owned(),
        )),
        PublishErrorKind::MaxPayloadExceeded => {
            let detail = error
                .source()
                .map_or_else(|| error.to_string(), ToString::to_string);
            PublishFailure::Mapped(Error::InvalidInput(format!(
                "the message is too large for the NATS server: {detail}"
            )))
        }
        PublishErrorKind::WrongLastMessageId
        | PublishErrorKind::WrongLastSequence
        | PublishErrorKind::Other => {
            let api = error
                .source()
                .and_then(|source| source.downcast_ref::<jetstream::Error>())
                .cloned();
            match api {
                Some(api) => PublishFailure::Api(api),
                None => PublishFailure::Mapped(Error::other("publish to NATS", error)),
            }
        }
    }
}

/// Why a publish operation failed.
#[derive(Debug)]
pub(crate) enum PublishFailure {
    /// The server sent no acknowledgement.
    NoAnswer(Failure),
    /// No stream stores the subject.
    NoStream,
    /// JetStream refused to store the message.
    Api(jetstream::Error),
    /// The error has its final form.
    Mapped(Error),
}

impl PublishFailure {
    /// Maps the failure to a contract error.
    pub(crate) fn into_error(self, subject: &str, stream: &str) -> Error {
        let operation = format!("publish to {subject:?}");
        match self {
            Self::NoAnswer(failure) => failure.into_error(&operation, Target::Other),
            Self::NoStream => Error::Unavailable(format!(
                "{operation}: no JetStream stream stores this subject; make sure that the \
                 stream {stream:?} exists"
            )),
            Self::Api(api) => api_error(&operation, api, Target::Other),
            Self::Mapped(error) => error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(code: usize, err_code: u64, description: &str) -> jetstream::Error {
        serde_json::from_value(serde_json::json!({
            "code": code,
            "err_code": err_code,
            "description": description,
        }))
        .expect("the error must parse")
    }

    #[test]
    fn connect_errors_map_to_the_documented_variants() {
        let cases = [
            (ConnectErrorKind::ServerParse, "config"),
            (ConnectErrorKind::Tls, "config"),
            (ConnectErrorKind::Authentication, "unauthorized"),
            (ConnectErrorKind::AuthorizationViolation, "unauthorized"),
            (ConnectErrorKind::TimedOut, "timeout"),
            (ConnectErrorKind::Dns, "unavailable"),
            (ConnectErrorKind::Io, "unavailable"),
            (ConnectErrorKind::MaxReconnects, "unavailable"),
        ];
        for (kind, expected) in cases {
            let error = connect_error(&ConnectError::new(kind));
            let found = match &error {
                Error::Config(_) => "config",
                Error::Unauthorized(_) => "unauthorized",
                Error::Timeout(_) => "timeout",
                Error::Unavailable(_) => "unavailable",
                _ => "other",
            };
            assert_eq!(found, expected, "{kind:?} gave {error:?}");
            assert_eq!(
                error.is_retryable(),
                matches!(expected, "timeout" | "unavailable"),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_tls_failure_of_the_connection_is_not_retryable() {
        let tls = |failure: rustls::Error| {
            ConnectError::with_source(
                ConnectErrorKind::Io,
                io::Error::new(io::ErrorKind::InvalidData, failure),
            )
        };
        let untrusted = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let error = connect_error(&tls(untrusted));
        assert!(
            matches!(&error, Error::Config(message) if message
                == "connect to NATS: the TLS handshake failed: invalid peer certificate: UnknownIssuer"),
            "{error:?}"
        );

        for alert in CLIENT_CERTIFICATE_ALERTS {
            let error = connect_error(&tls(rustls::Error::AlertReceived(alert)));
            let expected = format!(
                "connect to NATS: the server did not accept the TLS client certificate (alert \
                 {alert:?})"
            );
            assert!(
                matches!(&error, Error::Unauthorized(message) if *message == expected),
                "{error:?}"
            );
        }
        let error = connect_error(&tls(rustls::Error::AlertReceived(
            AlertDescription::ProtocolVersion,
        )));
        assert!(
            matches!(&error, Error::Config(message) if message
                == "connect to NATS: the TLS handshake failed: received fatal alert: ProtocolVersion"),
            "{error:?}"
        );

        // An I/O error that the TLS library did not make stays retryable.
        let refused = ConnectError::with_source(
            ConnectErrorKind::Io,
            io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused"),
        );
        let error = connect_error(&refused);
        assert!(
            matches!(&error, Error::Unavailable(message)
                if message == "connect to NATS: IO error: connection refused"),
            "{error:?}"
        );
    }

    #[test]
    fn a_request_with_no_answer_is_retryable() {
        let error = Failure::TimedOut.into_error("read the stream", Target::Stream);
        assert!(
            matches!(&error, Error::Timeout(message)
                if message == "read the stream: the NATS server did not answer in time"),
            "{error:?}"
        );
        let error = Failure::NoResponders.into_error("read the stream", Target::Stream);
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
        let error =
            Failure::Transport("broken".to_owned()).into_error("read the stream", Target::Other);
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
        assert!(Failure::TimedOut.is_no_answer());
        assert!(Failure::NoResponders.is_no_answer());
        assert!(!Failure::Transport(String::new()).is_no_answer());
    }

    #[test]
    fn jetstream_error_codes_map_to_the_documented_variants() {
        let not_enabled = Failure::Api(api(503, 10039, "jetstream not enabled for account"));
        let error = not_enabled.into_error("create the stream", Target::Other);
        assert!(matches!(error, Error::Config(_)), "{error:?}");

        let no_leader = Failure::Api(api(503, 10008, "JetStream system temporarily unavailable"));
        let error = no_leader.into_error("create the stream", Target::Stream);
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");

        let too_many = Failure::Api(api(429, 10167, "too many requests"));
        let error = too_many.into_error("create a consumer", Target::Other);
        assert!(matches!(error, Error::RateLimited(_)), "{error:?}");

        let bad_filter = Failure::Api(api(400, 10093, "filter is not a subset"));
        let error = bad_filter.into_error("create a consumer", Target::Other);
        assert!(matches!(error, Error::InvalidInput(_)), "{error:?}");

        let unknown = Failure::Api(api(500, 99999, "something new"));
        let error = unknown.into_error("create a consumer", Target::Other);
        assert!(
            matches!(&error, Error::Other { context, .. } if context == "create a consumer"),
            "{error:?}"
        );
        assert!(error.to_string().contains("something new"), "{error}");
    }

    #[test]
    fn a_resource_error_depends_on_the_target() {
        let error = Failure::Api(api(503, 10023, "insufficient storage resources available"))
            .into_error("create the stream", Target::Stream);
        assert!(
            matches!(&error, Error::Config(message)
                if message.contains("insufficient storage resources available")),
            "{error:?}"
        );
        let error = Failure::Api(api(503, 10023, "insufficient resources"))
            .into_error("publish", Target::Other);
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
    }

    #[test]
    fn a_stream_request_that_the_server_refuses_is_a_configuration_error() {
        let error = Failure::Api(api(
            500,
            10052,
            "stream configuration update can not change storage type",
        ))
        .into_error("update the stream", Target::Stream);
        assert!(
            matches!(&error, Error::Config(message) if message.contains("storage type")),
            "{error:?}"
        );
        let overlap = Failure::Api(api(400, 10065, "subjects overlap with an existing stream"));
        assert!(overlap.has_code(ErrorCode::STREAM_SUBJECT_OVERLAP));
        assert!(!overlap.has_code(ErrorCode::STREAM_NOT_FOUND));
        let error = overlap.into_error("create the stream", Target::Stream);
        assert!(matches!(error, Error::Config(_)), "{error:?}");
    }

    #[test]
    fn publish_errors_map_to_the_documented_variants() {
        let error = publish_failure(PublishError::new(PublishErrorKind::TimedOut))
            .into_error("aegis.audit", "AEGIS");
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");

        let error = publish_failure(PublishError::new(PublishErrorKind::StreamNotFound))
            .into_error("aegis.audit", "AEGIS");
        assert!(
            matches!(&error, Error::Unavailable(message)
                if message.contains("\"aegis.audit\"") && message.contains("\"AEGIS\"")),
            "{error:?}"
        );

        let error = publish_failure(PublishError::new(PublishErrorKind::BrokenPipe))
            .into_error("aegis.audit", "AEGIS");
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");

        let error = publish_failure(PublishError::new(PublishErrorKind::MaxAckPending))
            .into_error("aegis.audit", "AEGIS");
        assert!(matches!(error, Error::RateLimited(_)), "{error:?}");

        let too_large = PublishError::with_source(
            PublishErrorKind::MaxPayloadExceeded,
            "Payload size limit of 1048576 exceeded by message size of 2000000",
        );
        let error = publish_failure(too_large).into_error("aegis.audit", "AEGIS");
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.contains("1048576")),
            "{error:?}"
        );

        let refused = PublishError::with_source(
            PublishErrorKind::Other,
            api(503, 10077, "error storing the message"),
        );
        let error = publish_failure(refused).into_error("aegis.audit", "AEGIS");
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");

        let local = PublishError::with_source(PublishErrorKind::Other, "the client is closed");
        let error = publish_failure(local).into_error("aegis.audit", "AEGIS");
        assert!(matches!(error, Error::Other { .. }), "{error:?}");
    }

    #[test]
    fn a_client_error_with_a_request_source_keeps_the_transport_reason() {
        let timed_out = GetStreamError::with_source(
            GetStreamErrorKind::Request,
            RequestError::new(RequestErrorKind::TimedOut),
        );
        assert!(matches!(Failure::from(timed_out), Failure::TimedOut));

        let no_responders = ConsumerError::with_source(
            ConsumerErrorKind::Request,
            RequestError::new(RequestErrorKind::NoResponders),
        );
        assert!(matches!(
            Failure::from(no_responders),
            Failure::NoResponders
        ));

        let stream_missing =
            RequestError::with_source(RequestErrorKind::Other, api(404, 10059, "stream not found"));
        let failure = Failure::from(stream_missing);
        assert!(failure.has_code(ErrorCode::STREAM_NOT_FOUND), "{failure:?}");

        let not_found = Failure::from(GetStreamError::new(GetStreamErrorKind::JetStream(api(
            404,
            10059,
            "stream not found",
        ))));
        assert!(not_found.has_code(ErrorCode::STREAM_NOT_FOUND));
        let created = Failure::from(CreateStreamError::new(CreateStreamErrorKind::TimedOut));
        assert!(matches!(created, Failure::TimedOut));
        let unavailable = Failure::from(CreateStreamError::new(
            CreateStreamErrorKind::JetStreamUnavailable,
        ));
        assert!(matches!(unavailable, Failure::NoResponders));
        let info = Failure::from(ConsumerInfoError::new(ConsumerInfoErrorKind::NoResponders));
        assert!(matches!(info, Failure::NoResponders));
        let missing = Failure::from(ConsumerInfoError::new(
            ConsumerInfoErrorKind::StreamNotFound,
        ));
        let error = missing.into_error("read the consumer \"detect\"", Target::Other);
        assert!(
            matches!(&error, Error::Unavailable(message)
                if message == "read the consumer \"detect\": the stream does not exist on the NATS server"),
            "{error:?}"
        );
    }
}
