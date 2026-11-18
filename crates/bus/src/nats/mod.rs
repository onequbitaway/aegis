//! The message bus on NATS JetStream.

mod error;
mod subscription;

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use aegis_contracts::bus::{BusStream, MessageBus};
use aegis_contracts::{Error, Result};
use async_nats::jetstream::stream::{
    Config as JetStreamConfig, DiscardPolicy, RetentionPolicy, StorageType,
};
use async_nats::jetstream::{self, ErrorCode};
use async_nats::{ConnectOptions, Event, ServerError};
use async_trait::async_trait;
use secrecy::ExposeSecret;

use self::error::{Failure, PublishFailure, Target, connect_error, publish_failure};
use crate::config::{BusConfig, ConsumerConfig, NatsAuth, StorageKind, StreamConfig};
use crate::subject::SubjectPolicy;

/// What [`NatsBus::ensure_stream`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamStatus {
    /// The stream did not exist. The bus created it.
    Created,
    /// The stream had a different configuration. The bus updated it.
    Updated,
    /// The stream already had the correct configuration.
    Unchanged,
}

/// The production message bus. It stores messages in a NATS JetStream stream.
///
/// A successful [`publish`](MessageBus::publish) means that the server stored the message.
/// A durable subscription gets each message at least once. Refer to the crate README for
/// the delivery rules.
pub struct NatsBus {
    link: Arc<Link>,
    policy: SubjectPolicy,
    stream: StreamConfig,
}

impl fmt::Debug for NatsBus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsBus")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

/// The data that the bus and its subscriptions share.
pub(crate) struct Link {
    pub(crate) context: jetstream::Context,
    /// The name of the stream.
    pub(crate) stream: String,
    pub(crate) consumer: ConsumerConfig,
    denials: Arc<DenialMonitor>,
}

impl Link {
    /// Maps a request that failed to a contract error.
    pub(crate) fn error(
        &self,
        started: Instant,
        operation: &str,
        target: Target,
        failure: impl Into<Failure>,
    ) -> Error {
        self.denials
            .error(started, operation, target, failure.into())
    }
}

fn denied(operation: &str) -> Error {
    Error::Unauthorized(format!(
        "{operation}: the NATS server denied permission to this account"
    ))
}

/// Remembers when the server last reported a permission error.
#[derive(Default)]
struct DenialMonitor {
    last: Mutex<Option<Instant>>,
}

impl DenialMonitor {
    fn record(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
    }

    fn denied_since(&self, start: Instant) -> bool {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some_and(|last| last >= start)
    }

    /// Maps a request that failed to a contract error.
    ///
    /// The server gives no answer to a request that it does not permit. It reports the
    /// permission error on the connection. Thus, a request with no answer is an
    /// authorization failure if such a report arrived after the request started.
    fn error(&self, started: Instant, operation: &str, target: Target, failure: Failure) -> Error {
        if failure.is_no_answer() && self.denied_since(started) {
            return denied(operation);
        }
        failure.into_error(operation, target)
    }
}

/// Returns `true` if the server error says that the account has no permission.
fn is_denial(error: &ServerError) -> bool {
    match error {
        ServerError::AuthorizationViolation => true,
        ServerError::Other(text) => {
            let text = text.to_lowercase();
            text.contains("permissions violation") || text.contains("authorization violation")
        }
        ServerError::SlowConsumer(_) => false,
    }
}

/// Writes a connection event to the log and records permission errors.
fn observe(event: &Event, denials: &DenialMonitor) {
    match event {
        Event::Connected => tracing::info!("connected to the NATS server"),
        Event::Disconnected => {
            tracing::warn!("lost the connection to the NATS server; the client connects again");
        }
        Event::ServerError(error) => {
            if is_denial(error) {
                denials.record();
            }
            tracing::warn!(%error, "the NATS server reported an error");
        }
        Event::LameDuckMode
        | Event::Draining
        | Event::Closed
        | Event::SlowConsumer(_)
        | Event::ClientError(_) => tracing::warn!(%event, "NATS connection event"),
    }
}

/// Makes sure that the TLS library has a cryptography provider.
///
/// The NATS client uses the provider of the process. If the process has more than one
/// provider compiled in and none selected, the TLS library cannot choose one. This function
/// selects `aws-lc-rs` only if the application did not select a provider. All AEGIS crates
/// use `aws-lc-rs`, so that the process has one provider.
fn select_crypto_provider() {
    use async_nats::rustls::crypto::{CryptoProvider, aws_lc_rs};
    if CryptoProvider::get_default().is_none() {
        // A different thread can select a provider at the same time. Then the call
        // returns that provider as an error, which is also a correct result.
        let _ = aws_lc_rs::default_provider().install_default();
    }
}

impl NatsBus {
    /// Connects to the NATS servers in the configuration.
    ///
    /// This function does not create the stream. Call [`NatsBus::ensure_stream`], or use
    /// [`connect`](crate::connect), which does the two steps.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`]: the configuration is not valid, a file is not readable, or the
    ///   TLS handshake failed. A server certificate that is not trusted is such a failure.
    /// - [`Error::Unauthorized`]: the server rejected the credentials or the TLS client
    ///   certificate.
    /// - [`Error::Unavailable`] or [`Error::Timeout`]: no server answered. A retry can
    ///   succeed. The function makes one attempt for each URL.
    pub async fn connect(config: &BusConfig) -> Result<Self> {
        config.validate_for_nats()?;
        let addresses = config.nats.server_addresses()?;
        select_crypto_provider();

        let denials = Arc::new(DenialMonitor::default());
        let observer = denials.clone();
        let mut options = ConnectOptions::new()
            .name(&config.nats.connection_name)
            .connection_timeout(config.nats.connect_timeout)
            .request_timeout(Some(config.nats.request_timeout))
            .require_tls(config.nats.requires_tls())
            .event_callback(move |event| {
                observe(&event, &observer);
                std::future::ready(())
            });
        let tls = &config.nats.tls;
        if let Some(ca_file) = &tls.ca_file {
            check_readable("nats.tls.ca_file", ca_file).await?;
            options = options.add_root_certificates(ca_file.clone());
        }
        if let (Some(certificate), Some(key)) = (&tls.client_cert_file, &tls.client_key_file) {
            check_readable("nats.tls.client_cert_file", certificate).await?;
            check_readable("nats.tls.client_key_file", key).await?;
            options = options.add_client_certificate(certificate.clone(), key.clone());
        }
        options = match &config.nats.auth {
            NatsAuth::None => options,
            NatsAuth::UserPassword { user, password } => {
                options.user_and_password(user.clone(), password.expose_secret().to_owned())
            }
            NatsAuth::Token { token } => options.token(token.expose_secret().to_owned()),
            NatsAuth::CredentialsFile { path } => {
                check_readable("nats.auth.path", path).await?;
                options.credentials_file(path).await.map_err(|error| {
                    // The text of the error can come from the file. Do not show it.
                    let reason = match error.kind() {
                        std::io::ErrorKind::InvalidData => {
                            "the file has no valid user JWT and NKey seed".to_owned()
                        }
                        kind => format!("cannot read the file {}: {kind}", path.display()),
                    };
                    Error::Config(format!("nats.auth.path: {reason}"))
                })?
            }
        };
        if matches!(
            config.nats.auth,
            NatsAuth::UserPassword { .. } | NatsAuth::Token { .. }
        ) && !config.nats.requires_tls()
            && !addresses.iter().all(async_nats::ServerAddr::tls_required)
        {
            tracing::warn!(
                "the NATS credentials can go over a connection without TLS; set nats.tls.required"
            );
        }

        let client = options
            .connect(addresses)
            .await
            .map_err(|error| connect_error(&error))?;
        let mut context = jetstream::new(client);
        context.set_timeout(config.nats.request_timeout);
        Ok(Self {
            link: Arc::new(Link {
                context,
                stream: config.stream.name.clone(),
                consumer: config.consumer.clone(),
                denials,
            }),
            policy: SubjectPolicy::new(&config.stream.subjects),
            stream: config.stream.clone(),
        })
    }

    /// Makes sure that the stream exists and has the configured settings.
    ///
    /// The function creates the stream when it is missing. When the stream has different
    /// subjects, retention limits, or replicas, the function updates it. Settings that the
    /// configuration does not have stay as they are. You can call the function again at any
    /// time.
    ///
    /// With `stream.manage = false`, the function changes nothing. It only checks that the
    /// stream exists and stores the configured subjects.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`]: the server refused the settings, the stream has a different
    ///   storage type or retention policy, or `stream.manage` is `false` and the stream is
    ///   missing.
    /// - [`Error::Unauthorized`]: the account has no permission for the request.
    /// - [`Error::Unavailable`] or [`Error::Timeout`]: JetStream did not answer. A retry can
    ///   succeed.
    pub async fn ensure_stream(&self) -> Result<StreamStatus> {
        let context = &self.link.context;
        let name = &self.stream.name;
        let read = format!("read the stream {name:?}");
        let started = Instant::now();
        let current = match context.get_stream(name).await {
            Ok(stream) => Some(stream.cached_info().config.clone()),
            Err(error) => {
                let failure = Failure::from(error);
                if !failure.has_code(ErrorCode::STREAM_NOT_FOUND) {
                    return Err(self.link.error(started, &read, Target::Stream, failure));
                }
                None
            }
        };
        if let Some(current) = current {
            return self.reconcile(current).await;
        }
        if !self.stream.manage {
            return Err(Error::Config(format!(
                "the stream {name:?} does not exist and stream.manage is false; create the \
                 stream on the NATS server"
            )));
        }

        let started = Instant::now();
        match context.create_stream(self.desired()).await {
            Ok(_) => {
                tracing::info!(stream = %name, "created the JetStream stream");
                Ok(StreamStatus::Created)
            }
            Err(error) => {
                let failure = Failure::from(error);
                if !failure.has_code(ErrorCode::STREAM_NAME_EXIST) {
                    let create = format!("create the stream {name:?}");
                    return Err(self.link.error(started, &create, Target::Stream, failure));
                }
                // A different process created the stream with other settings at the same time.
                let started = Instant::now();
                let stream = context
                    .get_stream(name)
                    .await
                    .map_err(|error| self.link.error(started, &read, Target::Stream, error))?;
                self.reconcile(stream.cached_info().config.clone()).await
            }
        }
    }

    /// The stream settings that come from the configuration.
    fn desired(&self) -> JetStreamConfig {
        JetStreamConfig {
            name: self.stream.name.clone(),
            subjects: self.stream.subjects.clone(),
            max_age: self.stream.max_age,
            max_bytes: desired_max_bytes(&self.stream),
            storage: desired_storage(&self.stream),
            num_replicas: self.stream.replicas,
            retention: RetentionPolicy::Limits,
            discard: DiscardPolicy::Old,
            ..JetStreamConfig::default()
        }
    }

    /// Compares the stream on the server with the configuration, and updates the stream if
    /// that is necessary and permitted.
    async fn reconcile(&self, current: JetStreamConfig) -> Result<StreamStatus> {
        let name = &self.stream.name;
        if current.retention != RetentionPolicy::Limits {
            return Err(Error::Config(format!(
                "the stream {name:?} has the retention policy {:?}; AEGIS needs the policy Limits",
                current.retention
            )));
        }
        let has_same_subjects = same_set(&current.subjects, &self.stream.subjects);
        if !self.stream.manage {
            if !has_same_subjects {
                return Err(Error::Config(format!(
                    "the stream {name:?} stores the subjects [{}], but stream.subjects is [{}]",
                    current.subjects.join(", "),
                    self.stream.subjects.join(", ")
                )));
            }
            return Ok(StreamStatus::Unchanged);
        }
        let storage = desired_storage(&self.stream);
        if current.storage != storage {
            return Err(Error::Config(format!(
                "the stream {name:?} has the storage {:?}, but stream.storage is {storage:?}; \
                 JetStream cannot change the storage of a stream",
                current.storage
            )));
        }
        let max_bytes = desired_max_bytes(&self.stream);
        if has_same_subjects
            && current.max_age == self.stream.max_age
            && current.max_bytes == max_bytes
            && current.num_replicas == self.stream.replicas
        {
            return Ok(StreamStatus::Unchanged);
        }

        let updated = JetStreamConfig {
            subjects: self.stream.subjects.clone(),
            max_age: self.stream.max_age,
            max_bytes,
            num_replicas: self.stream.replicas,
            ..current
        };
        let started = Instant::now();
        self.link
            .context
            .update_stream(&updated)
            .await
            .map_err(|error| {
                let update = format!("update the stream {name:?}");
                self.link.error(started, &update, Target::Stream, error)
            })?;
        tracing::info!(stream = %name, "updated the JetStream stream");
        Ok(StreamStatus::Updated)
    }
}

/// Checks that a file of the configuration is readable. Thus, the error names the setting.
async fn check_readable(setting: &str, path: &Path) -> Result<()> {
    tokio::fs::File::open(path)
        .await
        .map(drop)
        .map_err(|error| {
            Error::Config(format!(
                "{setting}: cannot read the file {}: {error}",
                path.display()
            ))
        })
}

/// JetStream uses -1 for "no size limit".
fn desired_max_bytes(stream: &StreamConfig) -> i64 {
    stream
        .byte_limit()
        .map_or(-1, |bytes| i64::try_from(bytes).unwrap_or(i64::MAX))
}

fn desired_storage(stream: &StreamConfig) -> StorageType {
    match stream.storage {
        StorageKind::File => StorageType::File,
        StorageKind::Memory => StorageType::Memory,
    }
}

/// Returns `true` if the two lists have the same items, in any sequence.
fn same_set(left: &[String], right: &[String]) -> bool {
    left.iter().all(|item| right.contains(item)) && right.iter().all(|item| left.contains(item))
}

#[async_trait]
impl MessageBus for NatsBus {
    /// Publishes one message and waits until the server confirms that it stored the message.
    ///
    /// When the function returns a retryable error, the server possibly stored the message.
    /// A second publish can then make a duplicate.
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        self.policy.check_publish(subject)?;
        let context = &self.link.context;
        let started = Instant::now();
        let result = match context.publish(subject.to_owned(), payload.into()).await {
            Ok(acknowledgement) => acknowledgement.await,
            Err(error) => Err(error),
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                let failure = publish_failure(error);
                let got_no_answer = matches!(
                    failure,
                    PublishFailure::NoAnswer(_) | PublishFailure::NoStream
                );
                if got_no_answer && self.link.denials.denied_since(started) {
                    return Err(denied(&format!("publish to {subject:?}")));
                }
                Err(failure.into_error(subject, &self.link.stream))
            }
        }
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        self.policy.check_subscribe(pattern, durable)?;
        match durable {
            Some(name) => subscription::durable(self.link.clone(), pattern, name).await,
            None => subscription::ephemeral(self.link.clone(), pattern).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_permission_report_counts_only_after_the_request_started() {
        let denials = DenialMonitor::default();
        let before = Instant::now();
        assert!(!denials.denied_since(before));
        denials.record();
        assert!(denials.denied_since(before));
        let later = Instant::now() + Duration::from_secs(1);
        assert!(!denials.denied_since(later));
    }

    #[test]
    fn only_permission_errors_are_denials() {
        assert!(is_denial(&ServerError::AuthorizationViolation));
        assert!(is_denial(&ServerError::Other(
            "Permissions Violation for Publish to \"aegis.audit\"".to_owned()
        )));
        assert!(is_denial(&ServerError::Other(
            "Permissions Violation for Subscription to \"_INBOX.x\"".to_owned()
        )));
        assert!(!is_denial(&ServerError::Other(
            "Maximum Payload Violation".to_owned()
        )));
        assert!(!is_denial(&ServerError::SlowConsumer(7)));
    }

    #[test]
    fn the_observer_records_a_permission_error() {
        let denials = DenialMonitor::default();
        let start = Instant::now();
        observe(&Event::Disconnected, &denials);
        observe(&Event::ServerError(ServerError::SlowConsumer(1)), &denials);
        assert!(!denials.denied_since(start));
        observe(
            &Event::ServerError(ServerError::Other(
                "Permissions Violation for Publish to \"aegis.audit\"".to_owned(),
            )),
            &denials,
        );
        assert!(denials.denied_since(start));
    }

    #[test]
    fn a_request_with_no_answer_after_a_permission_report_is_unauthorized() {
        let denials = DenialMonitor::default();
        let started = Instant::now();
        let error = denials.error(
            started,
            "create the stream",
            Target::Stream,
            Failure::TimedOut,
        );
        assert!(matches!(error, Error::Timeout(_)), "{error:?}");

        denials.record();
        let error = denials.error(
            started,
            "create the stream",
            Target::Stream,
            Failure::TimedOut,
        );
        assert!(
            matches!(&error, Error::Unauthorized(message)
                if message == "create the stream: the NATS server denied permission to this account"),
            "{error:?}"
        );
        let error = denials.error(
            started,
            "create the stream",
            Target::Stream,
            Failure::NoResponders,
        );
        assert!(matches!(error, Error::Unauthorized(_)), "{error:?}");
        // A failure that is not "no answer" keeps its own mapping.
        let error = denials.error(
            started,
            "create the stream",
            Target::Stream,
            Failure::Transport("broken".to_owned()),
        );
        assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
    }

    #[test]
    fn subject_lists_compare_as_sets() {
        let list = |items: &[&str]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(same_set(&list(&["a.>", "b.>"]), &list(&["b.>", "a.>"])));
        assert!(!same_set(&list(&["a.>"]), &list(&["a.>", "b.>"])));
        assert!(!same_set(&list(&["a.>", "b.>"]), &list(&["a.>"])));
    }

    #[test]
    fn zero_bytes_means_no_limit_for_jetstream() {
        let mut stream = StreamConfig::default();
        assert_eq!(desired_max_bytes(&stream), 1_073_741_824);
        stream.max_bytes = 0;
        assert_eq!(desired_max_bytes(&stream), -1);
    }
}
