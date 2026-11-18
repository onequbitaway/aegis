//! Shared helpers for the integration tests of the bus.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// Each test binary uses a different part of this module.
#![allow(dead_code, unused_imports, unused_macros)]

#[cfg(feature = "docker-tests")]
pub mod jwt;
#[cfg(feature = "docker-tests")]
pub mod nats_server;
pub mod suite;
#[cfg(feature = "docker-tests")]
pub mod tls;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::{BusMessage, BusStream};
use aegis_contracts::{Error, MessageBus};
use futures::StreamExt;

/// The longest time that a test waits for one message.
pub const WAIT: Duration = Duration::from_secs(20);

/// One bus under test, with the data that the shared test cases need.
pub struct Case {
    /// The bus under test.
    pub bus: Arc<dyn MessageBus>,
    /// The first token of all subjects of the test. A test on a shared NATS server uses a
    /// unique token, so that tests do not see the messages of other tests.
    pub root: String,
    /// `true` if the bus delivers again the last message of a durable consumer that went
    /// away before it polled for the next message.
    pub redelivers_unacknowledged: bool,
}

impl Case {
    /// Returns the subject `{root}.{rest}`.
    pub fn subject(&self, rest: &str) -> String {
        format!("{}.{rest}", self.root)
    }

    /// Publishes a text payload.
    pub async fn publish(&self, rest: &str, payload: &str) {
        self.bus
            .publish(&self.subject(rest), payload.as_bytes().to_vec())
            .await
            .expect("the publish must succeed");
    }

    /// Subscribes to the pattern `{root}.{rest}`.
    pub async fn subscribe(&self, rest: &str, durable: Option<&str>) -> BusStream {
        self.bus
            .subscribe(&self.subject(rest), durable)
            .await
            .expect("the subscription must start")
    }
}

/// Waits for the next item of the stream: a message, an error, or the end of the stream.
pub async fn next_item(stream: &mut BusStream) -> Option<Result<BusMessage, Error>> {
    tokio::time::timeout(WAIT, stream.next())
        .await
        .expect("the stream must give an item in time")
}

/// Waits for the next message. A stream error fails the test.
pub async fn next(stream: &mut BusStream) -> BusMessage {
    next_item(stream)
        .await
        .expect("the stream must stay open")
        .expect("the stream item must be a message")
}

/// Waits for the next message, and returns its payload as text.
pub async fn next_text(stream: &mut BusStream) -> String {
    text(&next(stream).await)
}

/// Waits for `count` messages, and returns their payloads as text.
pub async fn take_texts(stream: &mut BusStream, count: usize) -> Vec<String> {
    let mut texts = Vec::with_capacity(count);
    for _ in 0..count {
        texts.push(next_text(stream).await);
    }
    texts
}

/// Returns the payload of a message as text.
pub fn text(message: &BusMessage) -> String {
    String::from_utf8(message.payload.clone()).expect("the payload must be text")
}

/// Returns the message of an `InvalidInput` error. Other results fail the test.
pub fn invalid_input<T>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::InvalidInput(message)) => message,
        Err(other) => panic!("expected InvalidInput, got {other:?}"),
        Ok(_) => panic!("expected InvalidInput, got a success"),
    }
}

/// Makes one `#[tokio::test]` for each shared test case that all buses must pass.
///
/// `$setup` is an async function that returns a fixture. The fixture has the methods
/// `case()` and `finish()`.
macro_rules! core_semantic_tests {
    ($setup:path) => {
        $crate::support::semantic_tests!($setup;
            a_durable_subscription_gets_a_stored_message,
            an_ephemeral_subscription_gets_only_new_messages,
            each_ephemeral_subscription_gets_each_new_message,
            a_new_durable_name_starts_at_the_first_stored_message,
            a_durable_consumer_continues_after_a_restart,
            consumers_with_one_durable_name_share_the_messages,
            wildcards_select_the_correct_subjects,
            publish_rejects_a_subject_that_is_not_concrete,
            a_typed_event_makes_a_round_trip,
            the_attack_log_arrives_complete_and_in_sequence,
            concurrent_publishers_lose_no_message,
            a_waiting_subscriber_wakes_when_a_message_arrives,
        );
    };
}

/// Makes one `#[tokio::test]` for each shared test case that only the buses of this crate
/// must pass. These cases cover the delivery guarantee and the stricter input checks.
macro_rules! strict_semantic_tests {
    ($setup:path) => {
        $crate::support::semantic_tests!($setup;
            a_message_with_no_acknowledgement_goes_to_a_different_consumer,
            a_durable_name_reads_one_pattern_only,
            a_subject_outside_the_stream_is_not_valid,
            a_durable_name_has_a_limited_character_set,
            a_pattern_with_a_misplaced_wildcard_is_not_valid,
        );
    };
}

macro_rules! semantic_tests {
    ($setup:path; $($case:ident),+ $(,)?) => {
        $(
            #[tokio::test]
            async fn $case() {
                let fixture = $setup().await;
                $crate::support::suite::$case(&fixture.case()).await;
                fixture.finish().await;
            }
        )+
    };
}

pub(crate) use {core_semantic_tests, semantic_tests, strict_semantic_tests};
