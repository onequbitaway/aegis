//! The decoy service: the listener, the limits, and the source connector.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aegis_contracts::common::TimeRange;
use aegis_contracts::source::{ConnectorInfo, EventBatch, EventStream, SourceConnector};
use aegis_contracts::{Error, Event, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::{CAPTURE_BYTES, DecoyConfig, PersonaKind, REPLY_BUFFER_BYTES};
use crate::connection;
use crate::events::{ClientRecord, ContactFacts, EventFactory, EventQueue, Priority};
use crate::gate::{Gate, MemoryGauge, Permit, Refusal, canonical};
use crate::names::result;
use crate::persona::{KeyRing, Personas};
use crate::seed::{MAX_SEED_BYTES, MIN_SEED_BYTES, Seed};

/// The wait after a failed accept, before the listener accepts again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    refused: AtomicU64,
    requests: AtomicU64,
    canary_hits: AtomicU64,
    honeytoken_trips: AtomicU64,
}

/// A connection that the gate admitted.
pub(crate) struct Admission {
    /// The address of the client.
    pub(crate) address: IpAddr,
    /// The place of the connection below the limits.
    pub(crate) permit: Permit,
}

/// The state that all connections of one decoy share.
pub(crate) struct Shared {
    pub(crate) config: DecoyConfig,
    pub(crate) personas: Personas,
    pub(crate) factory: EventFactory,
    pub(crate) gauge: Arc<MemoryGauge>,
    queue: EventQueue,
    gate: Arc<Gate>,
    counters: Counters,
}

impl Shared {
    /// Admits a connection below the limits, or refuses it and records the refusal.
    fn admit(&self, peer: SocketAddr) -> Option<Admission> {
        let address = canonical(peer.ip());
        match self.gate.enter(address) {
            Ok(permit) => {
                self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                Some(Admission { address, permit })
            }
            Err(refusal) => {
                self.counters.refused.fetch_add(1, Ordering::Relaxed);
                let reason = match refusal {
                    Refusal::Total => result::REFUSED_CONNECTION_LIMIT,
                    Refusal::Address => result::REFUSED_ADDRESS_LIMIT,
                };
                tracing::debug!(
                    decoy = %self.config.id,
                    client = %address,
                    reason,
                    "decoy connection refused"
                );
                let facts = ContactFacts {
                    result: reason,
                    status: None,
                    held: Duration::ZERO,
                    bytes_received: 0,
                    bytes_sent: 0,
                    planted_canary: None,
                };
                let event = self.factory.contact(&ClientRecord::new(address), &facts);
                // A flood of refused connections must not push out other events.
                self.emit(event, Priority::Low);
                None
            }
        }
    }

    /// Puts an event into the queue. A full queue drops the event and counts it.
    pub(crate) fn emit(&self, event: Event, priority: Priority) {
        if self.queue.push(event, priority) {
            return;
        }
        // The log gets a line only at 1, 2, 4, 8, ... drops, so a flood cannot fill it.
        let dropped = self.queue.dropped_total();
        if dropped.is_power_of_two() {
            tracing::warn!(
                decoy = %self.config.id,
                dropped_events_total = dropped,
                "the event queue of the decoy is full: events are dropped"
            );
        }
    }

    pub(crate) fn count_request(&self) {
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_canary_hit(&self) {
        self.counters.canary_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_honeytoken_trip(&self) {
        self.counters
            .honeytoken_trips
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// A snapshot of the counters of one [`DecoyService`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DecoyStats {
    /// The number of connections that the decoy admitted.
    pub connections_accepted: u64,
    /// The number of connections that the decoy refused because of a connection limit.
    pub connections_refused: u64,
    /// The number of connections that are open now.
    pub active_connections: usize,
    /// The largest number of connections that were open at the same time.
    pub peak_connections: usize,
    /// The number of complete requests that the decoy read.
    pub requests: u64,
    /// The number of requests to a valid canary path.
    pub canary_hits: u64,
    /// The number of requests with a planted decoy key.
    pub honeytoken_trips: u64,
    /// The number of events that wait in the queue.
    pub events_queued: usize,
    /// The number of events that the decoy dropped because the queue was full.
    pub events_dropped: u64,
    /// The bytes that the decoy keeps now for connections and for queued events.
    pub tracked_bytes: usize,
    /// The largest value of `tracked_bytes` that occurred.
    pub peak_tracked_bytes: usize,
}

/// A decoy service: a tarpit, a maze, a decoy model API, or a mix of them.
///
/// The service is a [`SourceConnector`]. Give it to the ingestion runner, and the runner
/// publishes each contact as a normalized event.
///
/// A clone is a handle to the same service.
///
/// # Example
///
/// ```
/// use aegis_contracts::SourceConnector;
/// use aegis_decoy::{DecoyConfig, DecoyService, PersonaKind};
/// use tokio_util::sync::CancellationToken;
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> aegis_contracts::Result<()> {
/// let config = DecoyConfig::new(
///     "decoy-lab",
///     "127.0.0.1:0".parse().expect("a socket address"),
///     [PersonaKind::Maze],
///     "AEGIS_DECOY_SEED",
/// );
/// // A program uses `DecoyService::bind`, which reads the real environment.
/// let bound = DecoyService::bind_with_env(config, |name| {
///     (name == "AEGIS_DECOY_SEED").then(|| "0123456789abcdef0123456789abcdef".to_owned())
/// })
/// .await?;
/// let service = bound.service();
/// assert_eq!(service.info().name, "decoy-lab");
///
/// let cancel = CancellationToken::new();
/// let server = tokio::spawn(bound.serve(cancel.clone()));
/// cancel.cancel();
/// server.await.expect("the server task ends");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DecoyService {
    shared: Arc<Shared>,
}

impl fmt::Debug for DecoyService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecoyService")
            .field("id", &self.shared.config.id)
            .field("personas", &self.shared.config.personas)
            .finish_non_exhaustive()
    }
}

/// Reads one secret from the environment. The error names the variable only.
fn read_variable(
    lookup: &dyn Fn(&str) -> Option<String>,
    decoy_id: &str,
    name: &str,
) -> Result<String> {
    lookup(name).ok_or_else(|| {
        Error::Config(format!(
            "decoy {decoy_id}: the environment variable {name} is not set"
        ))
    })
}

impl DecoyService {
    /// Makes a service that has no listener. Secrets come from the process environment.
    ///
    /// Use [`serve_connection`](Self::serve_connection) to give connections to the
    /// service. Most callers use [`bind`](Self::bind).
    ///
    /// # Errors
    ///
    /// Refer to [`with_env`](Self::with_env).
    pub fn new(config: DecoyConfig) -> Result<Self> {
        Self::with_env(config, |name| std::env::var(name).ok())
    }

    /// Makes a service that has no listener. `lookup` reads an environment variable.
    ///
    /// Use this function in a test, where the process environment must not change.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] in these conditions:
    ///
    /// - The configuration is not valid.
    /// - The seed variable or a key variable is not set.
    /// - The seed does not have 32 to 1024 bytes.
    /// - A decoy key does not have 16 to 512 visible ASCII characters.
    /// - Two decoy keys have the same value.
    ///
    /// The message names the variable or the key identifier. It never shows a secret.
    pub fn with_env(config: DecoyConfig, lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        config.validate()?;
        let secret = read_variable(&lookup, &config.id, &config.seed_env)?;
        let seed = Seed::new(secret.as_bytes()).ok_or_else(|| {
            Error::Config(format!(
                "decoy {}: the seed in {} must have {MIN_SEED_BYTES} to {MAX_SEED_BYTES} bytes",
                config.id, config.seed_env
            ))
        })?;
        let mut keys = Vec::new();
        if config.has_persona(PersonaKind::ModelApi) {
            for key in &config.model_api.keys {
                let value = read_variable(&lookup, &config.id, &key.value_env)?;
                keys.push((key.id.clone(), value));
            }
        }
        let keys = KeyRing::new(keys).map_err(|error| match error {
            Error::Config(message) => Error::Config(format!("decoy {}: {message}", config.id)),
            other => other,
        })?;
        let gauge = Arc::new(MemoryGauge::default());
        let shared = Shared {
            personas: Personas::new(&config, seed, keys),
            factory: EventFactory::new(&config.id),
            queue: EventQueue::new(
                config.events.max_queued,
                config.events.max_queued_bytes,
                Arc::clone(&gauge),
            ),
            gate: Gate::new(
                config.limits.max_connections,
                config.limits.max_connections_per_address,
            ),
            gauge,
            counters: Counters::default(),
            config,
        };
        Ok(Self {
            shared: Arc::new(shared),
        })
    }

    /// Makes a service and listens on the address in the configuration.
    ///
    /// Secrets come from the process environment. With port 0, the operating system
    /// selects the port. Read it with [`BoundDecoy::local_addr`].
    ///
    /// The function does not examine the other listeners of the process. The caller must
    /// make sure that the address is not the address of a different configured listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] for the conditions of [`with_env`](Self::with_env), and
    /// [`Error::Unavailable`] if the service cannot listen on the address.
    pub async fn bind(config: DecoyConfig) -> Result<BoundDecoy> {
        Self::bind_with_env(config, |name| std::env::var(name).ok()).await
    }

    /// Makes a service and listens. `lookup` reads an environment variable.
    ///
    /// # Errors
    ///
    /// Refer to [`bind`](Self::bind).
    pub async fn bind_with_env(
        config: DecoyConfig,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<BoundDecoy> {
        let service = Self::with_env(config, lookup)?;
        let config = &service.shared.config;
        let unavailable = |error: std::io::Error| {
            Error::Unavailable(format!(
                "the decoy {} cannot listen on {}: {error}",
                config.id, config.bind
            ))
        };
        let listener = TcpListener::bind(config.bind).await.map_err(unavailable)?;
        let local_addr = listener.local_addr().map_err(unavailable)?;
        Ok(BoundDecoy {
            listener,
            service,
            local_addr,
        })
    }

    /// Returns the configuration of the service.
    #[must_use]
    pub fn config(&self) -> &DecoyConfig {
        &self.shared.config
    }

    /// Returns a snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> DecoyStats {
        let shared = &self.shared;
        let counter = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        DecoyStats {
            connections_accepted: counter(&shared.counters.accepted),
            connections_refused: counter(&shared.counters.refused),
            active_connections: shared.gate.active(),
            peak_connections: shared.gate.peak(),
            requests: counter(&shared.counters.requests),
            canary_hits: counter(&shared.counters.canary_hits),
            honeytoken_trips: counter(&shared.counters.honeytoken_trips),
            events_queued: shared.queue.len(),
            events_dropped: shared.queue.dropped_total(),
            tracked_bytes: shared.gauge.current(),
            peak_tracked_bytes: shared.gauge.peak(),
        }
    }

    /// Returns the largest number of bytes that the service can keep at one time.
    ///
    /// The value is the limit for [`DecoyStats::tracked_bytes`]. It comes only from the
    /// configuration:
    ///
    /// `max_connections × (2 × max_header_bytes + max_body_bytes + 65536) + max_queued_bytes`
    ///
    /// The 65536 bytes are for the largest generated answer and for the recorded text of
    /// one request. The count covers the request buffers, the answer buffers, the recorded
    /// text, and the queued events. It does not cover the fixed data of each connection
    /// task, which is a few kilobytes.
    #[must_use]
    pub fn memory_bound(&self) -> usize {
        let config = &self.shared.config;
        let limits = &config.limits;
        let per_connection = limits
            .max_header_bytes
            .saturating_mul(2)
            .saturating_add(limits.max_body_bytes)
            .saturating_add(REPLY_BUFFER_BYTES)
            .saturating_add(CAPTURE_BYTES);
        limits
            .max_connections
            .saturating_mul(per_connection)
            .saturating_add(config.events.max_queued_bytes)
    }

    /// Serves one connection on a stream that the caller accepted.
    ///
    /// `peer` is the address of the client. The function applies all limits of the
    /// service. Above a connection limit, it closes the stream immediately. The function
    /// returns when the connection ends. A drop of the future closes the connection, and
    /// the service still records the contact.
    ///
    /// Use this function for a listener that the caller owns, or in a test.
    pub async fn serve_connection<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Some(admission) = self.shared.admit(peer) {
            connection::serve(Arc::clone(&self.shared), stream, admission).await;
        }
    }

    /// Ends the event stream after the events that remain in the queue.
    ///
    /// [`BoundDecoy::serve`] calls this function when it stops. A caller that uses only
    /// [`serve_connection`](Self::serve_connection) calls it after the last connection.
    pub fn close(&self) {
        self.shared.queue.close();
    }
}

#[async_trait]
impl SourceConnector for DecoyService {
    fn info(&self) -> ConnectorInfo {
        ConnectorInfo {
            name: self.shared.config.id.clone(),
            vendor: "aegis".to_owned(),
            product: "decoy".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Returns [`Error::Unavailable`] after the service stopped.
    async fn check(&self) -> Result<()> {
        if self.shared.queue.is_closed() {
            return Err(Error::Unavailable(format!(
                "the decoy {} stopped",
                self.shared.config.id
            )));
        }
        Ok(())
    }

    /// Opens the live stream of the decoy events.
    ///
    /// The events are in memory only, so the stream has no cursor: each batch has
    /// `next_cursor` set to `None`, and the function ignores `cursor`. Open one stream at
    /// a time. Two streams divide the events between them.
    ///
    /// When the queue dropped events, the batch ends with one `decoy.events_dropped`
    /// event that holds the count. The stream ends after the service stopped and the
    /// queue is empty.
    async fn stream(&self, _cursor: Option<String>) -> Result<EventStream> {
        let shared = Arc::clone(&self.shared);
        let stream = futures::stream::unfold(shared, |shared| async move {
            let drained = shared.queue.next(shared.config.events.batch_size).await?;
            let mut events = drained.events;
            if drained.dropped > 0 {
                let total = shared.queue.dropped_total();
                tracing::warn!(
                    decoy = %shared.config.id,
                    dropped_events = drained.dropped,
                    dropped_events_total = total,
                    "the decoy dropped events because its queue was full"
                );
                events.push(shared.factory.dropped(drained.dropped, total));
            }
            let batch = EventBatch {
                events,
                next_cursor: None,
            };
            Some((Ok(batch), shared))
        });
        Ok(Box::pin(stream))
    }

    /// Returns an empty batch. The decoy keeps no past events.
    async fn fetch(&self, _range: TimeRange, _cursor: Option<String>) -> Result<EventBatch> {
        Ok(EventBatch {
            events: Vec::new(),
            next_cursor: None,
        })
    }
}

/// A decoy service with a bound listener that does not accept connections yet.
pub struct BoundDecoy {
    listener: TcpListener,
    service: DecoyService,
    local_addr: SocketAddr,
}

impl fmt::Debug for BoundDecoy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundDecoy")
            .field("id", &self.service.shared.config.id)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl BoundDecoy {
    /// Returns the address on which the decoy listens.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a handle to the service. The handle is the source connector.
    #[must_use]
    pub fn service(&self) -> DecoyService {
        self.service.clone()
    }

    /// Accepts connections until `cancel` fires.
    ///
    /// Above a connection limit, the decoy closes a new connection immediately. When
    /// `cancel` fires, the decoy stops the listener, closes each open connection, records
    /// each of these contacts, and ends the event stream.
    ///
    /// A drop of the future also closes each connection and ends the event stream. Then
    /// the stream can end before the last contacts are in the queue. Use `cancel` for a
    /// stop that loses no event.
    pub async fn serve(self, cancel: CancellationToken) {
        let Self {
            listener,
            service,
            local_addr,
        } = self;
        // The guard ends the event stream when this function returns or is dropped. It is
        // the first local value, so it drops after the connection tasks.
        let _end_of_stream = EndOfStream(&service);
        let shared = &service.shared;
        tracing::info!(
            decoy = %shared.config.id,
            address = %local_addr,
            personas = ?shared.config.personas,
            "the decoy listens"
        );
        let mut connections = JoinSet::new();
        let mut accept_failures = 0_u64;
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                // Remove each task that ended, so the set stays small.
                Some(ended) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = ended {
                        tracing::error!(decoy = %shared.config.id, %error, "a decoy connection task failed");
                    }
                }
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        accept_failures = 0;
                        if let Err(error) = stream.set_nodelay(true) {
                            tracing::debug!(decoy = %shared.config.id, %error, "set_nodelay failed");
                        }
                        // A refused connection closes here, when `stream` drops.
                        if let Some(admission) = shared.admit(peer) {
                            connections.spawn(connection::serve(
                                Arc::clone(shared),
                                stream,
                                admission,
                            ));
                        }
                    }
                    Err(error) => {
                        // For example, the process has no free file descriptor. Wait a
                        // short time, so a fault that stays cannot use all processor time.
                        // The log gets a line only at 1, 2, 4, 8, ... failures in sequence.
                        accept_failures = accept_failures.saturating_add(1);
                        if accept_failures.is_power_of_two() {
                            tracing::warn!(
                                decoy = %shared.config.id,
                                %error,
                                failures = accept_failures,
                                "the decoy cannot accept a connection"
                            );
                        }
                        tokio::select! {
                            () = cancel.cancelled() => break,
                            () = tokio::time::sleep(ACCEPT_BACKOFF) => {}
                        }
                    }
                },
            }
        }
        drop(listener);
        // The drop of each task closes its connection and records the contact.
        connections.shutdown().await;
        tracing::info!(decoy = %shared.config.id, "the decoy stopped");
    }
}

/// Ends the event stream of a service when the listener stops.
struct EndOfStream<'a>(&'a DecoyService);

impl Drop for EndOfStream<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
}
