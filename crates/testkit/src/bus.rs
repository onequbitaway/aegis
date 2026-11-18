use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, subject_matches};
use aegis_contracts::{Error, Result};
use async_trait::async_trait;
use tokio::sync::watch;

use crate::lock;

#[derive(Default)]
struct State {
    log: Vec<BusMessage>,
    durable_positions: HashMap<String, Arc<Mutex<usize>>>,
}

/// A message bus that keeps all messages in memory.
///
/// The bus holds each message for its full life, so a new durable name starts at the first
/// message.
pub struct MemoryBus {
    state: Arc<Mutex<State>>,
    length: watch::Sender<usize>,
}

impl Default for MemoryBus {
    fn default() -> Self {
        Self {
            state: Arc::default(),
            length: watch::Sender::new(0),
        }
    }
}

impl MemoryBus {
    /// Returns all messages, in the order in which the bus received them.
    #[must_use]
    pub fn published(&self) -> Vec<BusMessage> {
        lock(&self.state).log.clone()
    }

    /// Returns the messages with a subject that matches `pattern`.
    #[must_use]
    pub fn published_to(&self, pattern: &str) -> Vec<BusMessage> {
        lock(&self.state)
            .log
            .iter()
            .filter(|message| subject_matches(pattern, &message.subject))
            .cloned()
            .collect()
    }
}

struct Subscription {
    state: Arc<Mutex<State>>,
    changes: watch::Receiver<usize>,
    pattern: String,
    position: Arc<Mutex<usize>>,
}

impl Subscription {
    /// Takes the next message that matches the pattern, if the bus has one.
    fn claim(&self) -> Option<BusMessage> {
        let state = lock(&self.state);
        let mut position = lock(&self.position);
        while let Some(message) = state.log.get(*position) {
            *position += 1;
            if subject_matches(&self.pattern, &message.subject) {
                return Some(message.clone());
            }
        }
        None
    }
}

#[async_trait]
impl MessageBus for MemoryBus {
    async fn publish(&self, subject: &str, payload: Vec<u8>) -> Result<()> {
        let is_concrete = !subject.is_empty()
            && subject
                .split('.')
                .all(|token| !token.is_empty() && token != "*" && token != ">");
        if !is_concrete {
            return Err(Error::InvalidInput(format!(
                "subject {subject:?} must have non-empty tokens and no wildcards"
            )));
        }
        let length = {
            let mut state = lock(&self.state);
            state.log.push(BusMessage {
                subject: subject.to_owned(),
                payload,
            });
            state.log.len()
        };
        self.length.send_replace(length);
        Ok(())
    }

    async fn subscribe(&self, pattern: &str, durable: Option<&str>) -> Result<BusStream> {
        if pattern.is_empty() {
            return Err(Error::InvalidInput(
                "subscription pattern must not be empty".to_owned(),
            ));
        }
        let position = {
            let mut state = lock(&self.state);
            match durable {
                Some(name) => state
                    .durable_positions
                    .entry(name.to_owned())
                    .or_default()
                    .clone(),
                None => Arc::new(Mutex::new(state.log.len())),
            }
        };
        let subscription = Subscription {
            state: self.state.clone(),
            changes: self.length.subscribe(),
            pattern: pattern.to_owned(),
            position,
        };
        Ok(Box::pin(futures::stream::unfold(
            subscription,
            |mut subscription| async move {
                loop {
                    if let Some(message) = subscription.claim() {
                        return Some((Ok(message), subscription));
                    }
                    if subscription.changes.changed().await.is_err() {
                        return None;
                    }
                }
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aegis_contracts::bus::{publish_json, subject};
    use futures::StreamExt;

    use super::*;

    async fn next(stream: &mut BusStream) -> BusMessage {
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the bus must deliver a message")
            .expect("the stream must stay open")
            .expect("the message must be valid")
    }

    async fn is_idle(stream: &mut BusStream) -> bool {
        tokio::time::timeout(Duration::from_millis(50), stream.next())
            .await
            .is_err()
    }

    #[tokio::test]
    async fn an_ephemeral_subscription_gets_only_new_matching_messages() {
        let bus = MemoryBus::default();
        bus.publish("aegis.events.file", b"old".to_vec())
            .await
            .unwrap();
        let mut stream = bus.subscribe("aegis.events.*", None).await.unwrap();
        bus.publish("aegis.detections.deterministic", b"other".to_vec())
            .await
            .unwrap();
        bus.publish("aegis.events.entra", b"new".to_vec())
            .await
            .unwrap();

        let message = next(&mut stream).await;
        assert_eq!(message.subject, "aegis.events.entra");
        assert_eq!(message.payload, b"new");
        assert!(is_idle(&mut stream).await);
    }

    #[tokio::test]
    async fn a_subscription_wakes_when_a_message_arrives_later() {
        let bus = Arc::new(MemoryBus::default());
        let mut stream = bus.subscribe("aegis.>", None).await.unwrap();
        let publisher = bus.clone();
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            publish_json(publisher.as_ref(), subject::AUDIT, &"record").await
        });
        let message = next(&mut stream).await;
        assert_eq!(message.subject, "aegis.audit");
        assert_eq!(message.decode::<String>().unwrap(), "record");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_new_durable_name_starts_at_the_first_message_and_resumes_after_restart() {
        let bus = MemoryBus::default();
        for payload in [b"1", b"2", b"3"] {
            bus.publish("aegis.events.file", payload.to_vec())
                .await
                .unwrap();
        }
        let mut first = bus
            .subscribe("aegis.events.>", Some("detect"))
            .await
            .unwrap();
        assert_eq!(next(&mut first).await.payload, b"1");
        assert_eq!(next(&mut first).await.payload, b"2");
        drop(first);

        let mut resumed = bus
            .subscribe("aegis.events.>", Some("detect"))
            .await
            .unwrap();
        assert_eq!(next(&mut resumed).await.payload, b"3");
        assert!(is_idle(&mut resumed).await);

        let mut other_name = bus
            .subscribe("aegis.events.>", Some("archive"))
            .await
            .unwrap();
        assert_eq!(next(&mut other_name).await.payload, b"1");
    }

    #[tokio::test]
    async fn consumers_with_one_durable_name_share_the_messages() {
        let bus = MemoryBus::default();
        let mut left = bus
            .subscribe("aegis.events.>", Some("workers"))
            .await
            .unwrap();
        let mut right = bus
            .subscribe("aegis.events.>", Some("workers"))
            .await
            .unwrap();
        bus.publish("aegis.events.file", b"1".to_vec())
            .await
            .unwrap();
        bus.publish("aegis.events.file", b"2".to_vec())
            .await
            .unwrap();

        let mut payloads = vec![
            next(&mut left).await.payload,
            next(&mut right).await.payload,
        ];
        payloads.sort();
        assert_eq!(payloads, [b"1".to_vec(), b"2".to_vec()]);
        assert!(is_idle(&mut left).await);
        assert!(is_idle(&mut right).await);
    }

    #[tokio::test]
    async fn publish_rejects_wildcards_and_empty_tokens() {
        let bus = MemoryBus::default();
        for subject in ["", "aegis.*", "aegis.>", "aegis..events", ".aegis"] {
            let error = bus.publish(subject, Vec::new()).await.unwrap_err();
            assert!(matches!(error, Error::InvalidInput(_)), "{subject:?}");
        }
        assert!(bus.published().is_empty());
        let error = bus.subscribe("", None).await.err().unwrap();
        assert!(matches!(error, Error::InvalidInput(_)));
    }

    #[tokio::test]
    async fn published_to_filters_by_pattern() {
        let bus = MemoryBus::default();
        bus.publish("aegis.events.file", b"e".to_vec())
            .await
            .unwrap();
        bus.publish("aegis.audit", b"a".to_vec()).await.unwrap();
        assert_eq!(bus.published().len(), 2);
        let events = bus.published_to("aegis.events.>");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload, b"e");
    }
}
