//! The events of a decoy and the bounded queue that holds them.

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aegis_contracts::common::{EntityKind, EntityRef, Severity};
use aegis_contracts::event::{self, Actor, Event, EventClass, EventSource, Outcome};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::Notify;

use crate::canary::CanaryHit;
use crate::config::PersonaKind;
use crate::gate::MemoryGauge;
use crate::names::{LISTENER_KIND, UNTRUSTED_CLIENT_DATA, action, attr};

/// The vendor name in the source of each event.
const VENDOR: &str = "aegis";
/// The product name in the source of each event.
const PRODUCT: &str = "decoy";

/// What the decoy knows about the client of one connection.
///
/// Each text value is clean and has a length limit.
#[derive(Debug, Clone)]
pub(crate) struct ClientRecord {
    /// The address of the client.
    pub(crate) address: IpAddr,
    /// The user agent of the request.
    pub(crate) user_agent: Option<String>,
    /// The fingerprint of the client.
    pub(crate) fingerprint: Option<String>,
    /// The method of the request.
    pub(crate) method: Option<String>,
    /// The path of the request, without the query.
    pub(crate) path: Option<String>,
    /// The persona that handled the request.
    pub(crate) kind: Option<PersonaKind>,
    /// More text of the request, for [`Event::raw`].
    pub(crate) request_text: Map<String, Value>,
}

impl ClientRecord {
    pub(crate) fn new(address: IpAddr) -> Self {
        Self {
            address,
            user_agent: None,
            fingerprint: None,
            method: None,
            path: None,
            kind: None,
            request_text: Map::new(),
        }
    }

    /// Returns the number of bytes that the text of the record uses, as JSON.
    pub(crate) fn size(&self) -> usize {
        let text = |value: &Option<String>| value.as_ref().map_or(0, String::len);
        text(&self.user_agent)
            + text(&self.fingerprint)
            + text(&self.method)
            + text(&self.path)
            + json_size(&self.request_text)
    }
}

/// The facts of one contact that are known when the connection ends.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ContactFacts<'a> {
    /// How the contact ended. A value of [`crate::result`].
    pub(crate) result: &'static str,
    /// The status of the response, if the decoy sent one.
    pub(crate) status: Option<u16>,
    /// The time from the accept to the close.
    pub(crate) held: Duration,
    /// The number of bytes that the client sent.
    pub(crate) bytes_received: u64,
    /// The number of bytes that the decoy sent.
    pub(crate) bytes_sent: u64,
    /// The canary that the answer carried.
    pub(crate) planted_canary: Option<&'a str>,
}

/// Makes the events of one decoy.
#[derive(Debug, Clone)]
pub(crate) struct EventFactory {
    decoy_id: String,
    source: EventSource,
}

impl EventFactory {
    pub(crate) fn new(decoy_id: &str) -> Self {
        Self {
            decoy_id: decoy_id.to_owned(),
            source: EventSource::new(decoy_id, VENDOR, PRODUCT),
        }
    }

    /// Makes an event about one client with the attributes that all such events share.
    ///
    /// The text of the client goes below [`UNTRUSTED_CLIENT_DATA`] in `raw`.
    fn client_event(
        &self,
        action: &str,
        class: EventClass,
        client: &ClientRecord,
        kind: &str,
        more_text: Map<String, Value>,
    ) -> Event {
        let mut actor =
            Actor::new(EntityKind::IpAddress, client.address.to_string()).with_ip(client.address);
        if let Some(user_agent) = &client.user_agent {
            actor = actor.with_user_agent(user_agent.clone());
        }
        let target =
            EntityRef::new(EntityKind::Resource, self.decoy_id.clone()).with_name("decoy service");
        let mut event = Event::new(Utc::now(), self.source.clone(), class, action, actor)
            .with_target(target)
            .with_attribute(event::attr::DECOY_ID, self.decoy_id.clone())
            .with_attribute(event::attr::DECOY_KIND, kind);
        if let Some(fingerprint) = &client.fingerprint {
            event = event.with_attribute(event::attr::CLIENT_FINGERPRINT, fingerprint.clone());
        }
        if let Some(method) = &client.method {
            event = event.with_attribute(event::attr::HTTP_METHOD, method.clone());
        }
        if let Some(path) = &client.path {
            event = event.with_attribute(event::attr::HTTP_PATH, path.clone());
        }
        let mut text = client.request_text.clone();
        text.extend(more_text);
        if !text.is_empty() {
            let mut raw = Map::new();
            raw.insert(UNTRUSTED_CLIENT_DATA.to_owned(), Value::Object(text));
            event = event.with_raw(Value::Object(raw));
        }
        event
    }

    /// Makes the `decoy.contact` event of one connection.
    pub(crate) fn contact(&self, client: &ClientRecord, facts: &ContactFacts<'_>) -> Event {
        let kind = client.kind.map_or(LISTENER_KIND, PersonaKind::as_str);
        let answered = facts.status.is_some_and(|status| status < 400);
        let mut event = self
            .client_event(
                event::action::DECOY_CONTACT,
                EventClass::NetworkActivity,
                client,
                kind,
                Map::new(),
            )
            .with_attribute(event::attr::HELD_MILLISECONDS, milliseconds(facts.held))
            .with_attribute(event::attr::BYTES_RECEIVED, facts.bytes_received)
            .with_attribute(attr::BYTES_SENT, facts.bytes_sent)
            .with_attribute(attr::DECOY_RESULT, facts.result)
            .with_outcome(if answered {
                Outcome::Success
            } else {
                Outcome::Failure
            })
            .with_severity(if client.method.is_some() {
                Severity::Medium
            } else {
                Severity::Low
            });
        if let Some(status) = facts.status {
            event = event.with_attribute(event::attr::HTTP_STATUS, status);
        }
        if let Some(canary) = facts.planted_canary {
            event = event.with_attribute(attr::PLANTED_CANARY_ID, canary);
        }
        event
    }

    /// Makes the `decoy.canary_hit` event of one request to a canary path.
    pub(crate) fn canary_hit(&self, client: &ClientRecord, hit: &CanaryHit) -> Event {
        self.client_event(
            event::action::DECOY_CANARY_HIT,
            EventClass::NetworkActivity,
            client,
            hit.planted_by.as_str(),
            Map::new(),
        )
        .with_attribute(event::attr::CANARY_ID, hit.id.clone())
        .with_outcome(Outcome::Success)
        .with_severity(Severity::High)
    }

    /// Makes the `honeytoken.trip` event of one use of a planted decoy key.
    ///
    /// The event names the key by its identifier. It never holds the key.
    pub(crate) fn honeytoken_trip(
        &self,
        client: &ClientRecord,
        key_id: &str,
        captured: Map<String, Value>,
    ) -> Event {
        self.client_event(
            event::action::HONEYTOKEN_TRIP,
            EventClass::Authentication,
            client,
            PersonaKind::ModelApi.as_str(),
            captured,
        )
        .with_target(EntityRef::new(EntityKind::Secret, key_id))
        .with_attribute(event::attr::HONEYTOKEN_ID, key_id)
        .with_outcome(Outcome::Success)
        .with_severity(Severity::High)
    }

    /// Makes the event that reports dropped events.
    pub(crate) fn dropped(&self, count: u64, total: u64) -> Event {
        let actor = Actor::new(EntityKind::Other, self.decoy_id.clone()).with_name("decoy service");
        Event::new(
            Utc::now(),
            self.source.clone(),
            EventClass::Other,
            action::DECOY_EVENTS_DROPPED,
            actor,
        )
        .with_attribute(event::attr::DECOY_ID, self.decoy_id.clone())
        .with_attribute(event::attr::DECOY_KIND, LISTENER_KIND)
        .with_attribute(attr::DROPPED_EVENTS, count)
        .with_attribute(attr::DROPPED_EVENTS_TOTAL, total)
        .with_outcome(Outcome::Failure)
        .with_severity(Severity::Medium)
    }
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Counts the bytes that a serializer writes.
struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns the size of `value` as JSON, in bytes.
///
/// A value that cannot be JSON has the largest size, so no queue accepts it.
pub(crate) fn json_size<T: Serialize + ?Sized>(value: &T) -> usize {
    let mut counter = ByteCounter(0);
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => counter.0,
        Err(_) => usize::MAX,
    }
}

/// How important an event is when the queue is almost full.
///
/// A client can make many contacts in a short time. The priorities make sure that such
/// a flood cannot push out the event of a canary hit or a honeytoken trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Priority {
    /// A canary hit or a honeytoken trip. The queue accepts the event until it is full.
    High,
    /// A contact with a request. The queue accepts the event in its first three
    /// quarters.
    Normal,
    /// A contact with no request, or a refused connection. The queue accepts the event
    /// in its first half.
    Low,
}

/// The events that one read of the queue returns.
#[derive(Debug)]
pub(crate) struct Drained {
    /// The events, oldest first.
    pub(crate) events: Vec<Event>,
    /// The number of events that the queue dropped after the last read.
    pub(crate) dropped: u64,
}

#[derive(Default)]
struct QueueState {
    events: VecDeque<(Event, usize)>,
    bytes: usize,
    unreported_drops: u64,
    closed: bool,
}

/// A queue of events with a limit for the count and a limit for the size.
///
/// A full queue drops each new event and counts it. The queue never grows above its
/// limits, so a client cannot make the decoy use more memory.
pub(crate) struct EventQueue {
    state: Mutex<QueueState>,
    wake: Notify,
    max_events: usize,
    max_bytes: usize,
    dropped: AtomicU64,
    gauge: Arc<MemoryGauge>,
}

impl EventQueue {
    pub(crate) fn new(max_events: usize, max_bytes: usize, gauge: Arc<MemoryGauge>) -> Self {
        Self {
            state: Mutex::default(),
            wake: Notify::new(),
            max_events,
            max_bytes,
            dropped: AtomicU64::new(0),
            gauge,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds an event. Returns `false` if the queue dropped the event.
    pub(crate) fn push(&self, event: Event, priority: Priority) -> bool {
        let size = json_size(&event);
        let (max_events, max_bytes) = match priority {
            Priority::High => (self.max_events, self.max_bytes),
            Priority::Normal => (
                self.max_events - self.max_events / 4,
                self.max_bytes - self.max_bytes / 4,
            ),
            Priority::Low => (self.max_events / 2, self.max_bytes / 2),
        };
        let accepted = {
            let mut state = self.lock();
            let fits = state.events.len() < max_events
                && state
                    .bytes
                    .checked_add(size)
                    .is_some_and(|bytes| bytes <= max_bytes);
            if fits {
                state.bytes += size;
                state.events.push_back((event, size));
                self.gauge.add(size);
            } else {
                state.unreported_drops = state.unreported_drops.saturating_add(1);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            fits
        };
        // A drop also wakes the reader, so the report of the drop is not late.
        self.wake.notify_one();
        accepted
    }

    /// Waits for events and removes `max` events at most.
    ///
    /// Returns `None` when the queue is closed and empty.
    pub(crate) async fn next(&self, max: usize) -> Option<Drained> {
        loop {
            {
                let mut state = self.lock();
                if !state.events.is_empty() || state.unreported_drops > 0 {
                    let count = max.max(1).min(state.events.len());
                    let mut events = Vec::with_capacity(count);
                    let mut freed = 0_usize;
                    for (event, size) in state.events.drain(..count) {
                        events.push(event);
                        freed = freed.saturating_add(size);
                    }
                    state.bytes = state.bytes.saturating_sub(freed);
                    self.gauge.sub(freed);
                    let dropped = std::mem::take(&mut state.unreported_drops);
                    if !state.events.is_empty() || state.closed {
                        // More work is ready for this reader or for a different one.
                        self.wake.notify_one();
                    }
                    return Some(Drained { events, dropped });
                }
                if state.closed {
                    self.wake.notify_one();
                    return None;
                }
            }
            self.wake.notified().await;
        }
    }

    /// Closes the queue. A reader gets the events that remain and then the end.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.wake.notify_one();
    }

    /// Returns `true` after [`close`](Self::close).
    pub(crate) fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Returns the number of events in the queue.
    pub(crate) fn len(&self) -> usize {
        self.lock().events.len()
    }

    /// Returns the number of events that the queue dropped after its start.
    pub(crate) fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use serde_json::json;

    use super::*;
    use crate::names::result;

    fn address() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
    }

    fn client() -> ClientRecord {
        let mut request_text = Map::new();
        request_text.insert("target".to_owned(), json!("/docs/a?x=1"));
        ClientRecord {
            address: address(),
            user_agent: Some("agent/1.0".to_owned()),
            fingerprint: Some("0123456789abcdef0123456789abcdef".to_owned()),
            method: Some("GET".to_owned()),
            path: Some("/docs/a".to_owned()),
            kind: Some(PersonaKind::Maze),
            request_text,
        }
    }

    fn facts() -> ContactFacts<'static> {
        ContactFacts {
            result: result::COMPLETED,
            status: Some(200),
            held: Duration::from_millis(1500),
            bytes_received: 120,
            bytes_sent: 3400,
            planted_canary: Some("00112233aabbccdd"),
        }
    }

    fn queue(max_events: usize, max_bytes: usize) -> (EventQueue, Arc<MemoryGauge>) {
        let gauge = Arc::new(MemoryGauge::default());
        (EventQueue::new(max_events, max_bytes, gauge.clone()), gauge)
    }

    fn small_event(factory: &EventFactory) -> Event {
        factory.contact(
            &ClientRecord::new(address()),
            &ContactFacts {
                result: result::NO_REQUEST,
                status: None,
                held: Duration::ZERO,
                bytes_received: 0,
                bytes_sent: 0,
                planted_canary: None,
            },
        )
    }

    #[test]
    fn a_contact_event_has_the_shared_attributes_and_the_client_as_the_actor() {
        let event = EventFactory::new("decoy-a").contact(&client(), &facts());
        assert_eq!(event.action, "decoy.contact");
        assert_eq!(event.class, EventClass::NetworkActivity);
        assert_eq!(event.source, EventSource::new("decoy-a", "aegis", "decoy"));
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(event.severity, Severity::Medium);
        assert_eq!(event.actor.kind, EntityKind::IpAddress);
        assert_eq!(event.actor.id, "203.0.113.7");
        assert_eq!(event.actor.ip, Some(address()));
        assert_eq!(event.actor.user_agent.as_deref(), Some("agent/1.0"));
        assert_eq!(
            event.target,
            Some(EntityRef::new(EntityKind::Resource, "decoy-a").with_name("decoy service"))
        );
        let expected: Map<String, Value> = [
            ("decoy_id", json!("decoy-a")),
            ("decoy_kind", json!("maze")),
            (
                "client_fingerprint",
                json!("0123456789abcdef0123456789abcdef"),
            ),
            ("http_method", json!("GET")),
            ("http_path", json!("/docs/a")),
            ("http_status", json!(200)),
            ("held_milliseconds", json!(1500)),
            ("bytes_received", json!(120)),
            ("bytes_sent", json!(3400)),
            ("decoy_result", json!("completed")),
            ("planted_canary_id", json!("00112233aabbccdd")),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let found: Map<String, Value> = event.attributes.clone().into_iter().collect();
        assert_eq!(found, expected);
        assert_eq!(
            event.raw,
            Some(json!({"untrusted_client_data": {"target": "/docs/a?x=1"}}))
        );
    }

    #[test]
    fn a_contact_with_no_request_is_a_failure_with_the_listener_kind() {
        let event = small_event(&EventFactory::new("decoy-a"));
        assert_eq!(event.outcome, Outcome::Failure);
        assert_eq!(event.severity, Severity::Low);
        assert_eq!(event.attribute_str("decoy_kind"), Some("listener"));
        assert_eq!(event.attribute_str("decoy_result"), Some("no_request"));
        assert_eq!(event.actor.user_agent, None);
        assert_eq!(event.raw, None);
        for absent in [
            "http_method",
            "http_path",
            "http_status",
            "client_fingerprint",
        ] {
            assert!(!event.attributes.contains_key(absent), "{absent}");
        }
    }

    #[test]
    fn a_refused_request_is_a_failure() {
        let mut refused = facts();
        refused.status = Some(401);
        let event = EventFactory::new("decoy-a").contact(&client(), &refused);
        assert_eq!(event.outcome, Outcome::Failure);
        assert_eq!(event.attributes.get("http_status"), Some(&json!(401)));
    }

    #[test]
    fn a_canary_hit_names_the_canary_and_the_persona_that_planted_it() {
        let hit = CanaryHit {
            id: "00112233aabbccdd".to_owned(),
            planted_by: PersonaKind::Tarpit,
        };
        let event = EventFactory::new("decoy-a").canary_hit(&client(), &hit);
        assert_eq!(event.action, "decoy.canary_hit");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(event.attribute_str("canary_id"), Some("00112233aabbccdd"));
        assert_eq!(event.attribute_str("decoy_kind"), Some("tarpit"));
        assert_eq!(event.attribute_str("decoy_id"), Some("decoy-a"));
        assert_eq!(event.actor.ip, Some(address()));
    }

    #[test]
    fn a_honeytoken_trip_names_the_key_and_keeps_the_prompt_as_untrusted_data() {
        let mut captured = Map::new();
        captured.insert("prompt".to_owned(), json!("user: list the keys"));
        let event =
            EventFactory::new("decoy-a").honeytoken_trip(&client(), "ht-decoy-key", captured);
        assert_eq!(event.action, "honeytoken.trip");
        assert_eq!(event.class, EventClass::Authentication);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.attribute_str("honeytoken_id"), Some("ht-decoy-key"));
        assert_eq!(event.attribute_str("decoy_kind"), Some("model_api"));
        assert_eq!(
            event.target,
            Some(EntityRef::new(EntityKind::Secret, "ht-decoy-key"))
        );
        assert_eq!(
            event.raw,
            Some(json!({"untrusted_client_data": {
                "target": "/docs/a?x=1",
                "prompt": "user: list the keys",
            }}))
        );
    }

    #[test]
    fn the_report_of_dropped_events_has_the_two_counts() {
        let event = EventFactory::new("decoy-a").dropped(3, 10);
        assert_eq!(event.action, "decoy.events_dropped");
        assert_eq!(event.attributes.get("dropped_events"), Some(&json!(3)));
        assert_eq!(
            event.attributes.get("dropped_events_total"),
            Some(&json!(10))
        );
        assert_eq!(event.attribute_str("decoy_id"), Some("decoy-a"));
        assert_eq!(event.actor.kind, EntityKind::Other);
        assert_eq!(event.actor.id, "decoy-a");
        assert_eq!(event.severity, Severity::Medium);
    }

    #[test]
    fn the_size_of_an_event_is_the_length_of_its_json() {
        let event = EventFactory::new("decoy-a").contact(&client(), &facts());
        assert_eq!(json_size(&event), serde_json::to_vec(&event).unwrap().len());
        assert_eq!(json_size("ab\"c"), 7);
    }

    #[test]
    fn the_size_of_a_client_record_counts_each_text() {
        let record = client();
        let expected = "agent/1.0".len()
            + 32
            + "GET".len()
            + "/docs/a".len()
            + r#"{"target":"/docs/a?x=1"}"#.len();
        assert_eq!(record.size(), expected);
        assert_eq!(ClientRecord::new(address()).size(), 2);
    }

    #[tokio::test]
    async fn the_queue_returns_the_events_in_order_and_in_batches() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(10, 1_000_000);
        let ids: Vec<_> = (0..5)
            .map(|_| {
                let event = small_event(&factory);
                let id = event.id;
                assert!(queue.push(event, Priority::Normal));
                id
            })
            .collect();
        assert_eq!(queue.len(), 5);
        let first = queue.next(3).await.unwrap();
        assert_eq!(first.dropped, 0);
        assert_eq!(
            first.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            ids[..3]
        );
        let second = queue.next(3).await.unwrap();
        assert_eq!(
            second.events.iter().map(|e| e.id).collect::<Vec<_>>(),
            ids[3..]
        );
        assert_eq!(queue.len(), 0);
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_new_event_and_reports_the_count_one_time() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(2, 1_000_000);
        assert!(queue.push(small_event(&factory), Priority::Normal));
        assert!(queue.push(small_event(&factory), Priority::Normal));
        assert!(!queue.push(small_event(&factory), Priority::Normal));
        assert!(!queue.push(small_event(&factory), Priority::Normal));
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_total(), 2);

        let drained = queue.next(10).await.unwrap();
        assert_eq!(drained.events.len(), 2);
        assert_eq!(drained.dropped, 2);
        // The next read does not report the same drops again.
        assert!(queue.push(small_event(&factory), Priority::Normal));
        let drained = queue.next(10).await.unwrap();
        assert_eq!(drained.events.len(), 1);
        assert_eq!(drained.dropped, 0);
        assert_eq!(queue.dropped_total(), 2);
    }

    #[tokio::test]
    async fn the_queue_never_holds_more_bytes_than_its_limit() {
        let factory = EventFactory::new("decoy-a");
        // One event, so each copy has the same size. The time of an event changes the
        // length of its JSON.
        let event = small_event(&factory);
        let size = json_size(&event);
        let (queue, gauge) = queue(1000, 3 * size + size / 2);
        let accepted = (0..10)
            .filter(|_| queue.push(event.clone(), Priority::High))
            .count();
        assert_eq!(accepted, 3);
        assert_eq!(gauge.current(), 3 * size);
        assert_eq!(gauge.peak(), 3 * size);
        assert_eq!(queue.dropped_total(), 7);
        let drained = queue.next(2).await.unwrap();
        assert_eq!(drained.events.len(), 2);
        assert_eq!(gauge.current(), size);
        // The freed space accepts new events.
        assert!(queue.push(event.clone(), Priority::High));
        assert_eq!(gauge.current(), 2 * size);
    }

    #[tokio::test]
    async fn each_priority_gets_its_part_of_the_queue() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(8, 1_000_000);
        // A low event gets the first half.
        for _ in 0..4 {
            assert!(queue.push(small_event(&factory), Priority::Low));
        }
        assert!(!queue.push(small_event(&factory), Priority::Low));
        // A normal event gets the first three quarters.
        for _ in 0..2 {
            assert!(queue.push(small_event(&factory), Priority::Normal));
        }
        assert!(!queue.push(small_event(&factory), Priority::Normal));
        assert!(!queue.push(small_event(&factory), Priority::Low));
        // A high event gets all of the queue.
        for _ in 0..2 {
            assert!(queue.push(small_event(&factory), Priority::High));
        }
        assert!(!queue.push(small_event(&factory), Priority::High));
        assert_eq!(queue.len(), 8);
        assert_eq!(queue.dropped_total(), 4);
    }

    #[tokio::test]
    async fn the_priorities_also_divide_the_bytes_of_the_queue() {
        let factory = EventFactory::new("decoy-a");
        let event = small_event(&factory);
        let size = json_size(&event);
        let (queue, _gauge) = queue(1000, 8 * size);
        let accepted = |priority| {
            (0..10)
                .filter(|_| queue.push(event.clone(), priority))
                .count()
        };
        assert_eq!(accepted(Priority::Low), 4);
        assert_eq!(accepted(Priority::Normal), 2);
        assert_eq!(accepted(Priority::High), 2);
    }

    #[tokio::test]
    async fn a_small_queue_still_accepts_a_contact_with_a_request() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(1, 1_000_000);
        assert!(queue.push(small_event(&factory), Priority::Normal));
        let (queue, _gauge) = queue_of(2);
        assert!(queue.push(small_event(&factory), Priority::Normal));
        assert!(queue.push(small_event(&factory), Priority::Normal));
        assert!(!queue.push(small_event(&factory), Priority::Normal));
    }

    fn queue_of(max_events: usize) -> (EventQueue, Arc<MemoryGauge>) {
        queue(max_events, 1_000_000)
    }

    #[tokio::test]
    async fn a_reader_waits_for_an_event_and_a_drop_wakes_it_too() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(1, 1_000_000);
        let queue = Arc::new(queue);
        let reader = {
            let queue = queue.clone();
            tokio::spawn(async move { queue.next(10).await })
        };
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());
        assert!(queue.push(small_event(&factory), Priority::Normal));
        let drained = reader.await.unwrap().unwrap();
        assert_eq!(drained.events.len(), 1);

        // With no space at all, a read returns only the count of the drops.
        let (full, _gauge) = queue_with_no_space();
        assert!(!full.push(small_event(&factory), Priority::Normal));
        let drained = full.next(10).await.unwrap();
        assert!(drained.events.is_empty());
        assert_eq!(drained.dropped, 1);
    }

    fn queue_with_no_space() -> (EventQueue, Arc<MemoryGauge>) {
        queue(1000, 1)
    }

    #[tokio::test]
    async fn a_closed_queue_gives_the_remaining_events_and_then_the_end() {
        let factory = EventFactory::new("decoy-a");
        let (queue, _gauge) = queue(10, 1_000_000);
        assert!(queue.push(small_event(&factory), Priority::Normal));
        assert!(!queue.is_closed());
        queue.close();
        assert!(queue.is_closed());
        assert_eq!(queue.next(10).await.unwrap().events.len(), 1);
        assert!(queue.next(10).await.is_none());
        assert!(queue.next(10).await.is_none());
    }

    #[tokio::test]
    async fn a_close_ends_a_reader_that_waits() {
        let (queue, _gauge) = queue(10, 1_000_000);
        let queue = Arc::new(queue);
        let reader = {
            let queue = queue.clone();
            tokio::spawn(async move { queue.next(10).await })
        };
        tokio::task::yield_now().await;
        queue.close();
        assert!(reader.await.unwrap().is_none());
    }
}
