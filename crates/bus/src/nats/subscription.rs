//! Subscription streams on JetStream consumers.
//!
//! A durable subscription uses a durable pull consumer. The server keeps its position.
//! An ephemeral subscription uses a consumer with no acknowledgements. The subscription
//! keeps its position, and makes a new consumer at that position after a failure.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_contracts::bus::{BusMessage, BusStream};
use aegis_contracts::{Error, Result};
use async_nats::jetstream::consumer::pull::{self, MessagesError, MessagesErrorKind};
use async_nats::jetstream::consumer::{AckPolicy, Consumer, DeliverPolicy, FromConsumer};
use async_nats::jetstream::context::ConsumerInfoErrorKind;
use async_nats::jetstream::message::Acker;
use async_nats::jetstream::{self, AckKind};
use futures::StreamExt;
use futures::stream;
use tokio::runtime::Handle;

use super::Link;
use super::error::{Failure, Target};

/// The number of messages that an ephemeral subscription takes in one request. These
/// messages need no acknowledgement, so a large value has no effect on redelivery.
const EPHEMERAL_PULL_BATCH: usize = 100;
/// The server deletes an ephemeral consumer that sent no request for this time.
const EPHEMERAL_INACTIVE_THRESHOLD: Duration = Duration::from_secs(300);
/// The first delay before an ephemeral subscription makes a new consumer after a failure.
const RETRY_DELAY_MIN: Duration = Duration::from_millis(250);
/// The longest delay between two attempts to make a new consumer.
const RETRY_DELAY_MAX: Duration = Duration::from_secs(5);

/// Opens a subscription that shares the durable consumer `name`.
pub(crate) async fn durable(link: Arc<Link>, pattern: &str, name: &str) -> Result<BusStream> {
    let consumer = durable_consumer(&link, pattern, name).await?;
    let messages = open(&link, &consumer, link.consumer.pull_batch).await?;
    let subscription = Durable {
        link,
        name: name.to_owned(),
        messages,
        in_flight: None,
        ended: false,
    };
    Ok(Box::pin(stream::unfold(subscription, Durable::next)))
}

/// Opens a subscription that gets only the messages that the stream stores from now on.
pub(crate) async fn ephemeral(link: Arc<Link>, pattern: &str) -> Result<BusStream> {
    // The inbox name of the client is a unique token.
    let inbox = link.context.client().new_inbox();
    let unique = inbox.rsplit('.').next().unwrap_or(&inbox);
    let mut subscription = Ephemeral {
        base_name: format!("aegis-ephemeral-{unique}"),
        link,
        pattern: pattern.to_owned(),
        generation: 0,
        next_sequence: 1,
        live: None,
        failures: 0,
        ended: false,
    };
    let live = subscription.create(DeliverPolicy::New).await?;
    subscription.live = Some(live);
    Ok(Box::pin(stream::unfold(subscription, Ephemeral::next)))
}

/// Finds or creates the durable consumer `name`.
async fn durable_consumer(
    link: &Link,
    pattern: &str,
    name: &str,
) -> Result<Consumer<pull::Config>> {
    let operation = format!("open the durable consumer {name:?}");
    let started = Instant::now();
    let failed = |failure: Failure| link.error(started, &operation, Target::Other, failure);

    let stream = link
        .context
        .get_stream_no_info(&link.stream)
        .await
        .map_err(|error| failed(error.into()))?;
    let config = match stream.consumer_info(name).await {
        Ok(info) => {
            let existing = existing_durable(name, pattern, info.config.clone())?;
            if existing.ack_wait == link.consumer.ack_wait {
                return Ok(Consumer::new(existing, info, link.context.clone()));
            }
            pull::Config {
                ack_wait: link.consumer.ack_wait,
                ..existing
            }
        }
        Err(error) if error.kind() == ConsumerInfoErrorKind::NotFound => pull::Config {
            durable_name: Some(name.to_owned()),
            filter_subject: pattern.to_owned(),
            deliver_policy: DeliverPolicy::All,
            ack_policy: AckPolicy::Explicit,
            ack_wait: link.consumer.ack_wait,
            ..pull::Config::default()
        },
        Err(error) => return Err(failed(error.into())),
    };
    link.context
        .create_consumer_on_stream(config, &link.stream)
        .await
        .map_err(|error| failed(error.into()))
}

/// Checks that a consumer that already has the durable name is usable for this subscription.
fn existing_durable(
    name: &str,
    pattern: &str,
    config: jetstream::consumer::Config,
) -> Result<pull::Config> {
    let is_durable = config.durable_name.as_deref() == Some(name);
    let has_explicit_ack = config.ack_policy == AckPolicy::Explicit;
    let filters = if config.filter_subjects.is_empty() {
        vec![config.filter_subject.clone()]
    } else {
        config.filter_subjects.clone()
    };
    let existing = pull::Config::try_from_consumer_config(config).ok();
    let Some(existing) = existing.filter(|_| is_durable && has_explicit_ack) else {
        return Err(Error::InvalidInput(format!(
            "a consumer with the name {name:?} exists on the stream, but it is not a durable \
             pull consumer with explicit acknowledgement; use a different durable name"
        )));
    };
    if filters != [pattern] {
        return Err(Error::InvalidInput(format!(
            "durable name {name:?} already reads the pattern {:?}; use one pattern for each \
             durable name",
            filters.join(", ")
        )));
    }
    Ok(existing)
}

/// Starts the message stream of a consumer.
async fn open(
    link: &Link,
    consumer: &Consumer<pull::Config>,
    batch: usize,
) -> Result<pull::Stream> {
    // The server rejects a request that is larger than the limits of the consumer.
    let limits = &consumer.cached_info().config;
    let batch = match usize::try_from(limits.max_batch) {
        Ok(max_batch) if max_batch > 0 => batch.min(max_batch),
        _ => batch,
    };
    let expires = if limits.max_expires.is_zero() {
        link.consumer.pull_expires
    } else {
        link.consumer.pull_expires.min(limits.max_expires)
    };
    consumer
        .stream()
        .max_messages_per_batch(batch)
        .expires(expires)
        .heartbeat(expires / 2)
        .messages()
        .await
        .map_err(|error| Error::Unavailable(format!("cannot start the subscription: {error}")))
}

fn bus_message(message: async_nats::Message) -> BusMessage {
    BusMessage {
        subject: message.subject.to_string(),
        payload: message.payload.into(),
    }
}

fn connection_closed() -> Error {
    Error::Unavailable(
        "the connection to the NATS server is closed; the subscription ends".to_owned(),
    )
}

/// The message that the caller of a durable subscription got last.
struct InFlight {
    acker: Acker,
    /// When the subscription gave the message to the caller.
    delivered: Instant,
}

/// The state of a durable subscription.
struct Durable {
    link: Arc<Link>,
    name: String,
    messages: pull::Stream,
    /// The message that the caller got last. The next poll acknowledges it.
    in_flight: Option<InFlight>,
    ended: bool,
}

impl Durable {
    async fn next(mut self) -> Option<(Result<BusMessage>, Self)> {
        if self.ended {
            return None;
        }
        // The caller asks for the next message, so the work on the last message is complete.
        if let Some(in_flight) = self.in_flight.take()
            && let Err(error) = in_flight.acker.ack().await
        {
            let error = Error::Unavailable(format!(
                "cannot acknowledge a message of the durable consumer {:?}; the server sends \
                 the message again: {error}",
                self.name
            ));
            return Some((Err(error), self));
        }
        let item = match self.messages.next().await {
            Some(Ok(message)) => {
                let (message, acker) = message.split();
                self.in_flight = Some(InFlight {
                    acker,
                    delivered: Instant::now(),
                });
                Ok(bus_message(message))
            }
            Some(Err(error)) => Err(self.stream_error(error).await),
            None => {
                self.ended = true;
                Err(connection_closed())
            }
        };
        Some((item, self))
    }

    /// Maps an error of the message stream. Sets `ended` if the stream cannot continue.
    async fn stream_error(&mut self, error: MessagesError) -> Error {
        let name = &self.name;
        match error.kind() {
            MessagesErrorKind::MissingHeartbeat => Error::Unavailable(format!(
                "no heartbeat from the NATS server for the durable consumer {name:?}; the \
                 subscription continues when the connection is back"
            )),
            MessagesErrorKind::Pull => Error::Unavailable(format!(
                "a pull request of the durable consumer {name:?} failed; the subscription \
                 tries again: {error}"
            )),
            MessagesErrorKind::ConsumerDeleted => {
                self.ended = true;
                consumer_gone(name)
            }
            MessagesErrorKind::NoResponders => {
                if self.consumer_is_gone().await {
                    self.ended = true;
                    consumer_gone(name)
                } else {
                    Error::Unavailable(format!(
                        "JetStream did not answer a pull request of the durable consumer \
                         {name:?}; the subscription tries again"
                    ))
                }
            }
            MessagesErrorKind::PushBasedConsumer => {
                self.ended = true;
                Error::Config(format!(
                    "the consumer {name:?} is a push consumer; the subscription ends"
                ))
            }
            MessagesErrorKind::RequestLimitExceeded => {
                self.ended = true;
                Error::Config(format!(
                    "a pull request is larger than the limits of the consumer {name:?}; \
                     decrease consumer.pull_batch or consumer.pull_expires: {error}"
                ))
            }
            MessagesErrorKind::Other => {
                self.ended = true;
                Error::other(
                    format!("read from the durable consumer {name:?}; the subscription ends"),
                    error,
                )
            }
        }
    }

    /// Returns `true` if the server says that the consumer or the stream does not exist.
    async fn consumer_is_gone(&self) -> bool {
        let Ok(stream) = self
            .link
            .context
            .get_stream_no_info(&self.link.stream)
            .await
        else {
            return false;
        };
        match stream.consumer_info(&self.name).await {
            Ok(_) => false,
            Err(error) => matches!(
                error.kind(),
                ConsumerInfoErrorKind::NotFound | ConsumerInfoErrorKind::StreamNotFound
            ),
        }
    }
}

fn consumer_gone(name: &str) -> Error {
    Error::Unavailable(format!(
        "the NATS server no longer has the durable consumer {name:?}; the subscription ends; \
         subscribe again"
    ))
}

impl Drop for Durable {
    /// Gives the last message back to the server, because the caller did not ask for a
    /// next message. Without this step, the server waits for `ack_wait` before it sends
    /// the message again.
    fn drop(&mut self) {
        let Some(in_flight) = self.in_flight.take() else {
            return;
        };
        // After `ack_wait`, the server already sent the message again. A late negative
        // acknowledgement would cause one more delivery.
        if in_flight.delivered.elapsed() >= self.link.consumer.ack_wait {
            return;
        }
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        let name = std::mem::take(&mut self.name);
        runtime.spawn(async move {
            if let Err(error) = in_flight.acker.ack_with(AckKind::Nak(None)).await {
                tracing::debug!(
                    consumer = %name,
                    %error,
                    "cannot give a message back; the server sends it again after ack_wait"
                );
            }
        });
    }
}

/// One consumer of an ephemeral subscription.
struct Live {
    name: String,
    messages: pull::Stream,
    /// The consumer sequence of the last message from this consumer.
    delivered: u64,
}

/// The state of an ephemeral subscription.
struct Ephemeral {
    link: Arc<Link>,
    pattern: String,
    base_name: String,
    /// The number of consumers that this subscription made.
    generation: u64,
    /// The stream sequence of the first message that the caller did not get.
    next_sequence: u64,
    live: Option<Live>,
    /// The number of failures since the last message.
    failures: u32,
    ended: bool,
}

impl Ephemeral {
    /// Makes a consumer and starts its message stream.
    async fn create(&mut self, deliver_policy: DeliverPolicy) -> Result<Live> {
        self.generation += 1;
        let name = format!("{}-{}", self.base_name, self.generation);
        let config = pull::Config {
            name: Some(name.clone()),
            filter_subject: self.pattern.clone(),
            deliver_policy,
            ack_policy: AckPolicy::None,
            inactive_threshold: EPHEMERAL_INACTIVE_THRESHOLD,
            num_replicas: 1,
            memory_storage: true,
            ..pull::Config::default()
        };
        let started = Instant::now();
        let consumer = self
            .link
            .context
            .create_consumer_on_stream(config, &self.link.stream)
            .await
            .map_err(|error| {
                self.link
                    .error(started, "open an ephemeral consumer", Target::Other, error)
            })?;
        if deliver_policy == DeliverPolicy::New {
            // For this policy, the server reports the last sequence that the stream had
            // when it made the consumer.
            self.next_sequence = consumer.cached_info().delivered.stream_sequence + 1;
        }
        let messages = open(&self.link, &consumer, EPHEMERAL_PULL_BATCH).await?;
        Ok(Live {
            name,
            messages,
            delivered: 0,
        })
    }

    /// Makes a new consumer at the saved position.
    async fn resume(&mut self) -> Result<Live> {
        let started = Instant::now();
        let stream = self
            .link
            .context
            .get_stream(&self.link.stream)
            .await
            .map_err(|error| {
                self.link.error(
                    started,
                    "read the stream for an ephemeral consumer",
                    Target::Other,
                    error,
                )
            })?;
        // If someone deleted the stream and made it again, its sequences start again. A
        // start position after the end of the stream would then never get a message.
        let after_last = stream.cached_info().state.last_sequence + 1;
        self.next_sequence = self.next_sequence.min(after_last);
        self.create(DeliverPolicy::ByStartSequence {
            start_sequence: self.next_sequence,
        })
        .await
    }

    async fn next(mut self) -> Option<(Result<BusMessage>, Self)> {
        if self.ended {
            return None;
        }
        loop {
            if self.live.is_none() {
                if self.failures > 0 {
                    tokio::time::sleep(retry_delay(self.failures)).await;
                }
                match self.resume().await {
                    Ok(live) => self.live = Some(live),
                    Err(error) => {
                        self.failures = self.failures.saturating_add(1);
                        return Some((Err(error), self));
                    }
                }
            }
            let Some(live) = self.live.as_mut() else {
                continue;
            };
            let Some(item) = live.messages.next().await else {
                self.ended = true;
                return Some((Err(connection_closed()), self));
            };
            let error = match item {
                Ok(message) => {
                    let sequences = message
                        .info()
                        .map(|info| (info.consumer_sequence, info.stream_sequence));
                    match sequences {
                        Ok((consumer_sequence, stream_sequence))
                            if consumer_sequence == live.delivered + 1
                                && stream_sequence >= self.next_sequence =>
                        {
                            live.delivered = consumer_sequence;
                            self.next_sequence = stream_sequence + 1;
                            self.failures = 0;
                            let (message, _) = message.split();
                            return Some((Ok(bus_message(message)), self));
                        }
                        Ok((consumer_sequence, stream_sequence)) => {
                            // The consumer skipped or repeated a message. A new consumer at
                            // the saved position puts the subscription back in sequence.
                            tracing::warn!(
                                consumer = %live.name,
                                consumer_sequence,
                                stream_sequence,
                                "an ephemeral consumer is out of sequence; a new consumer replaces it"
                            );
                            None
                        }
                        Err(error) => Some(Error::Unavailable(format!(
                            "an ephemeral consumer sent a message with no sequence data; a \
                             new consumer continues at the same position: {error}"
                        ))),
                    }
                }
                Err(error) => Some(Error::Unavailable(format!(
                    "an ephemeral subscription lost its consumer; a new consumer continues at \
                     the same position: {error}"
                ))),
            };
            self.discard_consumer();
            self.failures = self.failures.saturating_add(1);
            if let Some(error) = error {
                return Some((Err(error), self));
            }
        }
    }

    /// Stops the consumer and asks the server to delete it.
    fn discard_consumer(&mut self) {
        let Some(live) = self.live.take() else {
            return;
        };
        let Ok(runtime) = Handle::try_current() else {
            return;
        };
        let link = self.link.clone();
        runtime.spawn(async move {
            let deleted = link
                .context
                .delete_consumer_from_stream(&live.name, &link.stream)
                .await;
            if let Err(error) = deleted {
                tracing::debug!(
                    consumer = %live.name,
                    %error,
                    "cannot delete an ephemeral consumer; the server deletes it when it is inactive"
                );
            }
        });
    }
}

impl Drop for Ephemeral {
    fn drop(&mut self) {
        self.discard_consumer();
    }
}

/// The delay before attempt number `failures + 1`. The delay doubles with each failure.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    RETRY_DELAY_MIN
        .saturating_mul(1 << doublings)
        .min(RETRY_DELAY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consumer_config(
        change: impl FnOnce(&mut jetstream::consumer::Config),
    ) -> jetstream::consumer::Config {
        let mut config = jetstream::consumer::Config {
            durable_name: Some("detect".to_owned()),
            ack_policy: AckPolicy::Explicit,
            filter_subject: "aegis.events.>".to_owned(),
            ack_wait: Duration::from_secs(30),
            ..jetstream::consumer::Config::default()
        };
        change(&mut config);
        config
    }

    fn invalid_input(result: Result<pull::Config>) -> String {
        match result {
            Err(Error::InvalidInput(message)) => message,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn an_existing_durable_consumer_with_the_same_pattern_is_usable() {
        let existing = existing_durable("detect", "aegis.events.>", consumer_config(|_| {}))
            .expect("the consumer must be usable");
        assert_eq!(existing.durable_name.as_deref(), Some("detect"));
        assert_eq!(existing.filter_subject, "aegis.events.>");
        assert_eq!(existing.ack_wait, Duration::from_secs(30));
    }

    #[test]
    fn an_existing_durable_consumer_with_a_different_pattern_is_an_error() {
        let message = invalid_input(existing_durable(
            "detect",
            "aegis.detections.>",
            consumer_config(|_| {}),
        ));
        assert_eq!(
            message,
            "durable name \"detect\" already reads the pattern \"aegis.events.>\"; use one \
             pattern for each durable name"
        );

        let many_filters = consumer_config(|config| {
            config.filter_subject = String::new();
            config.filter_subjects = vec!["aegis.events.>".to_owned(), "aegis.audit".to_owned()];
        });
        let message = invalid_input(existing_durable("detect", "aegis.events.>", many_filters));
        assert!(
            message.contains("\"aegis.events.>, aegis.audit\""),
            "{message}"
        );
    }

    #[test]
    fn an_existing_consumer_of_a_different_type_is_an_error() {
        let changes: [fn(&mut jetstream::consumer::Config); 3] = [
            |config| config.deliver_subject = Some("push.here".to_owned()),
            |config| config.ack_policy = AckPolicy::None,
            |config| config.durable_name = None,
        ];
        for change in changes {
            let message = invalid_input(existing_durable(
                "detect",
                "aegis.events.>",
                consumer_config(change),
            ));
            assert!(
                message.contains("is not a durable pull consumer with explicit acknowledgement"),
                "{message}"
            );
        }
    }

    #[test]
    fn the_retry_delay_doubles_to_a_maximum() {
        assert_eq!(retry_delay(1), Duration::from_millis(250));
        assert_eq!(retry_delay(2), Duration::from_millis(500));
        assert_eq!(retry_delay(3), Duration::from_secs(1));
        assert_eq!(retry_delay(5), Duration::from_secs(4));
        assert_eq!(retry_delay(6), Duration::from_secs(5));
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(5));
    }
}
