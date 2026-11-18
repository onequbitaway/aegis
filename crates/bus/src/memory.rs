//! The in-process bus, for a deployment that has no NATS server.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, subject_matches};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::BusConfig;
use crate::subject::SubjectPolicy;

/// A message bus that keeps all messages in the memory of this process.
///
/// The bus obeys the same rules as [`NatsBus`](crate::NatsBus): the same subject checks, the
/// same subscription semantics, and delivery at least once for durable names. The bus
/// keeps no state after the process stops.
///
/// The retention limits `stream.max_age` and `stream.max_bytes` apply. The size of a
/// message is the length of its subject plus the length of its payload.
pub struct InProcessBus {
    inner: Arc<Inner>,
}

impl fmt::Debug for InProcessBus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InProcessBus")
            .field("max_age", &self.inner.max_age)
            .field("max_bytes", &self.inner.max_bytes)
            .finish_non_exhaustive()
    }
}

struct Inner {
    policy: SubjectPolicy,
    max_age: Option<Duration>,
    max_bytes: Option<u64>,
    state: Mutex<State>,
    /// Changes when a message arrives or when a message becomes available again.
    changes: watch::Sender<u64>,
}

#[derive(Default)]
struct State {
    /// The stored messages, oldest first. Sequences have no gaps.
    log: VecDeque<Stored>,
    /// The sequence that the next message gets. Sequences start at 1.
    next_sequence: u64,
    bytes: u64,
    durables: HashMap<String, Durable>,
}

struct Stored {
    sequence: u64,
    message: BusMessage,
    size: u64,
    stored_at: Instant,
}

/// The shared position of all consumers that use one durable name.
struct Durable {
    pattern: String,
    /// The sequence of the next message that no consumer has examined.
    next: u64,
    /// Messages that a consumer got, but did not acknowledge before it went away.
    redeliver: BTreeSet<u64>,
}

impl InProcessBus {
    /// Makes an empty bus. The bus uses only the `stream` section of the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the `stream` section is not valid.
    pub fn new(config: &BusConfig) -> Result<Self> {
        config.stream.validate()?;
        Ok(Self {
            inner: Arc::new(Inner {
                policy: SubjectPolicy::new(&config.stream.subjects),
                max_age: config.stream.age_limit(),
                max_bytes: config.stream.byte_limit(),
                state: Mutex::new(State {
                    next_sequence: 1,
                    ..State::default()
                }),
                changes: watch::Sender::new(0),
            }),
        })
    }
}

impl Inner {
    /// Locks the state. A panic in a different thread does not make the bus unavailable.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn wake_subscribers(&self) {
        self.changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }
}

impl State {
    /// Returns the sequence of the oldest stored message.
    fn first_sequence(&self) -> u64 {
        self.log
            .front()
            .map_or(self.next_sequence, |stored| stored.sequence)
    }

    fn get(&self, sequence: u64) -> Option<&Stored> {
        let offset = sequence.checked_sub(self.first_sequence())?;
        self.log.get(usize::try_from(offset).ok()?)
    }

    fn remove_oldest(&mut self) {
        if let Some(stored) = self.log.pop_front() {
            self.bytes = self.bytes.saturating_sub(stored.size);
        }
    }

    fn remove_expired(&mut self, max_age: Option<Duration>, now: Instant) {
        let Some(max_age) = max_age else { return };
        while self
            .log
            .front()
            .is_some_and(|stored| now.duration_since(stored.stored_at) >= max_age)
        {
            self.remove_oldest();
        }
    }
}

#[async_trait]
impl MessageBus for InProcessBus {
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        let inner = &self.inner;
        inner.policy.check_publish(subject)?;
        let size = u64::try_from(subject.len().saturating_add(payload.len())).unwrap_or(u64::MAX);
        if let Some(max_bytes) = inner.max_bytes
            && size > max_bytes
        {
            return Err(Error::InvalidInput(format!(
                "a message of {size} bytes is larger than stream.max_bytes ({max_bytes})"
            )));
        }
        let now = Instant::now();
        {
            let mut state = inner.lock();
            state.remove_expired(inner.max_age, now);
            let sequence = state.next_sequence;
            state.next_sequence += 1;
            state.bytes = state.bytes.saturating_add(size);
            state.log.push_back(Stored {
                sequence,
                message: BusMessage {
                    subject: subject.to_owned(),
                    payload,
                },
                size,
                stored_at: now,
            });
            if let Some(max_bytes) = inner.max_bytes {
                while state.bytes > max_bytes {
                    state.remove_oldest();
                }
            }
        }
        inner.wake_subscribers();
        Ok(())
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        let inner = &self.inner;
        inner.policy.check_subscribe(pattern, durable)?;
        let position = {
            let mut state = inner.lock();
            match durable {
                None => Position::Ephemeral {
                    next: state.next_sequence,
                },
                Some(name) => {
                    let first = state.first_sequence();
                    let group = state
                        .durables
                        .entry(name.to_owned())
                        .or_insert_with(|| Durable {
                            pattern: pattern.to_owned(),
                            next: first,
                            redeliver: BTreeSet::new(),
                        });
                    if group.pattern != pattern {
                        return Err(Error::InvalidInput(format!(
                            "durable name {name:?} already reads the pattern {:?}; use one \
                             pattern for each durable name",
                            group.pattern
                        )));
                    }
                    Position::Durable {
                        name: name.to_owned(),
                        in_flight: None,
                    }
                }
            }
        };
        let subscription = Subscription {
            bus: Arc::downgrade(inner),
            changes: inner.changes.subscribe(),
            pattern: pattern.to_owned(),
            position,
        };
        Ok(Box::pin(futures::stream::unfold(
            subscription,
            |mut subscription| async move {
                loop {
                    match subscription.claim() {
                        Claim::Message(message) => return Some((Ok(message), subscription)),
                        Claim::Closed => return None,
                        Claim::Empty => {}
                    }
                    if subscription.changes.changed().await.is_err() {
                        return None;
                    }
                }
            },
        )))
    }
}

enum Position {
    /// The consumer keeps its own position.
    Ephemeral { next: u64 },
    /// The bus keeps the position. `in_flight` is the message that this consumer got last.
    /// The next poll of the stream acknowledges it.
    Durable {
        name: String,
        in_flight: Option<u64>,
    },
}

enum Claim {
    Message(BusMessage),
    Empty,
    Closed,
}

struct Subscription {
    bus: Weak<Inner>,
    changes: watch::Receiver<u64>,
    pattern: String,
    position: Position,
}

impl Subscription {
    /// Takes the next message for this consumer, if the bus has one.
    fn claim(&mut self) -> Claim {
        let Some(bus) = self.bus.upgrade() else {
            return Claim::Closed;
        };
        let mut state = bus.lock();
        state.remove_expired(bus.max_age, Instant::now());
        let first = state.first_sequence();
        let end = state.next_sequence;
        let State { log, durables, .. } = &mut *state;
        let stored_at = |sequence: u64| {
            let offset = usize::try_from(sequence.checked_sub(first)?).ok()?;
            log.get(offset)
        };
        match &mut self.position {
            Position::Ephemeral { next } => {
                let mut sequence = (*next).max(first);
                while sequence < end {
                    let found = stored_at(sequence);
                    sequence += 1;
                    if let Some(stored) = found
                        && subject_matches(&self.pattern, &stored.message.subject)
                    {
                        *next = sequence;
                        return Claim::Message(stored.message.clone());
                    }
                }
                *next = sequence;
                Claim::Empty
            }
            Position::Durable { name, in_flight } => {
                // This poll acknowledges the message that the consumer got before.
                *in_flight = None;
                let Some(group) = durables.get_mut(name.as_str()) else {
                    return Claim::Closed;
                };
                while let Some(sequence) = group.redeliver.pop_first() {
                    if let Some(stored) = stored_at(sequence) {
                        *in_flight = Some(sequence);
                        return Claim::Message(stored.message.clone());
                    }
                }
                let mut sequence = group.next.max(first);
                while sequence < end {
                    let found = stored_at(sequence);
                    sequence += 1;
                    if let Some(stored) = found
                        && subject_matches(&self.pattern, &stored.message.subject)
                    {
                        group.next = sequence;
                        *in_flight = Some(sequence - 1);
                        return Claim::Message(stored.message.clone());
                    }
                }
                group.next = sequence;
                Claim::Empty
            }
        }
    }
}

impl Drop for Subscription {
    /// Gives a message that has no acknowledgement back to the durable name.
    fn drop(&mut self) {
        let Position::Durable {
            name,
            in_flight: Some(sequence),
        } = &self.position
        else {
            return;
        };
        let Some(bus) = self.bus.upgrade() else {
            return;
        };
        let is_queued = {
            let mut state = bus.lock();
            let is_stored = state.get(*sequence).is_some();
            match state.durables.get_mut(name.as_str()) {
                Some(group) if is_stored => group.redeliver.insert(*sequence),
                _ => false,
            }
        };
        if is_queued {
            bus.wake_subscribers();
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    fn bus_with(change: impl FnOnce(&mut BusConfig)) -> InProcessBus {
        let mut config = BusConfig::default();
        change(&mut config);
        InProcessBus::new(&config).expect("the configuration must be valid")
    }

    async fn next(stream: &mut BusStream) -> BusMessage {
        tokio::time::timeout(WAIT, stream.next())
            .await
            .expect("the bus must deliver a message")
            .expect("the stream must stay open")
            .expect("the message must be valid")
    }

    async fn payloads(stream: &mut BusStream, count: usize) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();
        for _ in 0..count {
            payloads.push(next(stream).await.payload);
        }
        payloads
    }

    #[tokio::test]
    async fn new_rejects_a_configuration_that_is_not_valid() {
        let mut config = BusConfig::default();
        config.stream.subjects = Vec::new();
        let error = InProcessBus::new(&config).expect_err("must fail");
        assert!(
            matches!(&error, Error::Config(message) if message.contains("stream.subjects")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn the_size_limit_removes_the_oldest_messages() {
        // Each message has a subject of 9 bytes and a payload of 1 byte.
        let bus = bus_with(|config| config.stream.max_bytes = 25);
        for payload in [b"1", b"2", b"3", b"4"] {
            bus.publish("aegis.one", payload.to_vec()).await.unwrap();
        }
        let mut stream = bus.subscribe("aegis.>", Some("reader")).await.unwrap();
        assert_eq!(
            payloads(&mut stream, 2).await,
            [b"3".to_vec(), b"4".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_message_larger_than_the_size_limit_is_an_error() {
        let bus = bus_with(|config| config.stream.max_bytes = 16);
        let error = bus
            .publish("aegis.one", vec![0; 8])
            .await
            .expect_err("17 bytes must not fit in 16");
        assert!(
            matches!(&error, Error::InvalidInput(message)
                if message == "a message of 17 bytes is larger than stream.max_bytes (16)"),
            "{error:?}"
        );
        bus.publish("aegis.one", vec![0; 7]).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_age_limit_removes_old_messages() {
        let bus = bus_with(|config| config.stream.max_age = Duration::from_secs(60));
        bus.publish("aegis.one", b"old".to_vec()).await.unwrap();
        tokio::time::advance(Duration::from_secs(59)).await;
        bus.publish("aegis.one", b"recent".to_vec()).await.unwrap();

        let mut before = bus.subscribe("aegis.>", Some("before")).await.unwrap();
        assert_eq!(next(&mut before).await.payload, b"old");

        tokio::time::advance(Duration::from_secs(1)).await;
        let mut after = bus.subscribe("aegis.>", Some("after")).await.unwrap();
        assert_eq!(next(&mut after).await.payload, b"recent");
    }

    #[tokio::test]
    async fn no_limits_keep_all_messages() {
        let bus = bus_with(|config| {
            config.stream.max_bytes = 0;
            config.stream.max_age = Duration::ZERO;
        });
        for index in 0..200_u8 {
            bus.publish("aegis.one", vec![index; 64]).await.unwrap();
        }
        let mut stream = bus.subscribe("aegis.>", Some("reader")).await.unwrap();
        let received = payloads(&mut stream, 200).await;
        assert_eq!(received.first(), Some(&vec![0; 64]));
        assert_eq!(received.last(), Some(&vec![199; 64]));
    }

    #[tokio::test]
    async fn a_slow_ephemeral_consumer_skips_removed_messages() {
        let bus = bus_with(|config| config.stream.max_bytes = 25);
        let mut stream = bus.subscribe("aegis.>", None).await.unwrap();
        for payload in [b"1", b"2", b"3", b"4"] {
            bus.publish("aegis.one", payload.to_vec()).await.unwrap();
        }
        assert_eq!(
            payloads(&mut stream, 2).await,
            [b"3".to_vec(), b"4".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_removed_message_is_not_delivered_again() {
        let bus = bus_with(|config| config.stream.max_bytes = 25);
        bus.publish("aegis.one", b"1".to_vec()).await.unwrap();
        let mut first = bus.subscribe("aegis.>", Some("reader")).await.unwrap();
        assert_eq!(next(&mut first).await.payload, b"1");
        // Three more messages push message 1 out of the bus.
        for payload in [b"2", b"3", b"4"] {
            bus.publish("aegis.one", payload.to_vec()).await.unwrap();
        }
        drop(first);
        let mut second = bus.subscribe("aegis.>", Some("reader")).await.unwrap();
        assert_eq!(
            payloads(&mut second, 2).await,
            [b"3".to_vec(), b"4".to_vec()]
        );
    }

    #[tokio::test]
    async fn a_stream_ends_when_the_bus_goes_away() {
        let bus = bus_with(|_| {});
        let mut ephemeral = bus.subscribe("aegis.>", None).await.unwrap();
        let mut durable = bus.subscribe("aegis.>", Some("reader")).await.unwrap();
        drop(bus);
        let end = tokio::time::timeout(WAIT, ephemeral.next()).await.unwrap();
        assert!(end.is_none());
        let end = tokio::time::timeout(WAIT, durable.next()).await.unwrap();
        assert!(end.is_none());
    }

    #[tokio::test]
    async fn a_waiting_consumer_gets_a_message_that_a_different_consumer_gives_back() {
        let bus = bus_with(|_| {});
        bus.publish("aegis.one", b"1".to_vec()).await.unwrap();
        let mut holder = bus.subscribe("aegis.>", Some("workers")).await.unwrap();
        assert_eq!(next(&mut holder).await.payload, b"1");

        let mut waiter = bus.subscribe("aegis.>", Some("workers")).await.unwrap();
        let waiting = tokio::spawn(async move { next(&mut waiter).await.payload });
        tokio::task::yield_now().await;
        drop(holder);
        let payload = tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap();
        assert_eq!(payload, b"1");
    }
}
