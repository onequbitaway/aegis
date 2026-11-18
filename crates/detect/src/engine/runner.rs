//! The bus runner: events in, detections and incidents out.

use std::time::Duration;

use aegis_contracts::bus::{MessageBus, encode, subject};
use aegis_contracts::event::Event;
use aegis_contracts::{Error, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::DetectionEngine;
use crate::common::tier_token;

/// The durable consumer name that the runner uses by default.
pub const DEFAULT_DURABLE_NAME: &str = "aegis-detect";

/// The largest factor by which the wait between publish attempts grows.
const MAX_BACKOFF_FACTOR: u32 = 64;

/// The settings of [`DetectionEngine::run`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BusRunnerConfig {
    /// The durable consumer name of the event subscription. A runner that starts again
    /// with the same name continues after its last event.
    pub durable_name: String,
    /// The number of times that the runner tries to publish one message. The runner tries
    /// again only after an error that a retry can correct.
    pub publish_attempts: u32,
    /// The wait in milliseconds before the second attempt. The wait doubles for each
    /// attempt after that.
    pub publish_backoff_milliseconds: u64,
}

impl Default for BusRunnerConfig {
    fn default() -> Self {
        Self {
            durable_name: DEFAULT_DURABLE_NAME.to_owned(),
            publish_attempts: 5,
            publish_backoff_milliseconds: 50,
        }
    }
}

/// The counts of one call of [`DetectionEngine::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunSummary {
    /// The number of events that the engine examined.
    pub events: u64,
    /// The number of messages that the runner dropped because they were not events.
    pub rejected_messages: u64,
    /// The number of detections that the runner published.
    pub detections: u64,
    /// The number of incident states that the runner published.
    pub incidents: u64,
    /// The number of temporary errors that the event subscription gave. The runner
    /// continued after each of them.
    pub stream_errors: u64,
}

/// The number of temporary subscription errors in sequence that stops the runner.
const MAX_STREAM_ERRORS_IN_SEQUENCE: u32 = 16;

/// Publishes one message. Tries again after an error that a retry can correct.
async fn publish(
    bus: &dyn MessageBus,
    subject: &str,
    payload: Vec<u8>,
    config: &BusRunnerConfig,
) -> Result<()> {
    let mut attempt: u32 = 1;
    loop {
        match bus.publish(subject, payload.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) if error.is_retryable() && attempt < config.publish_attempts => {
                tracing::warn!(
                    subject,
                    attempt,
                    error = %error,
                    "the detection runner could not publish a message and tries again"
                );
                let factor = 2_u32
                    .saturating_pow(attempt.saturating_sub(1))
                    .min(MAX_BACKOFF_FACTOR);
                let wait = config
                    .publish_backoff_milliseconds
                    .saturating_mul(u64::from(factor));
                tokio::time::sleep(Duration::from_millis(wait)).await;
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

impl DetectionEngine {
    /// Connects the engine to the message bus until `cancel` is cancelled.
    ///
    /// The runner subscribes to `aegis.events.>` with the durable name of `config`. For
    /// each event, it calls [`DetectionEngine::process`], publishes each detection to
    /// `aegis.detections.{tier}`, and then publishes each new or changed incident to
    /// `aegis.incidents`. The runner examines one event at a time, in the order of the
    /// subscription.
    ///
    /// A message that is not an event is dropped. The runner writes a warning with the
    /// subject of the message, and counts the message in [`RunSummary::rejected_messages`].
    ///
    /// After a cancellation, the runner completes the event that it examines, and then
    /// returns the counts. Use one runner for each durable name: the velocity detectors
    /// must see all events of a stream.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the durable name is empty or `publish_attempts` is zero.
    /// - The error of the bus, if the subscription fails, or if the stream gives an error
    ///   that a retry cannot correct. The runner continues after an error that a retry
    ///   can correct (for example a lost connection), until the stream gives 16 such
    ///   errors in sequence.
    /// - [`Error::Unavailable`] if the bus closes the subscription.
    /// - The error of [`DetectionEngine::process`].
    /// - The error of the bus, if a message cannot be published after
    ///   `publish_attempts` attempts. The output of that event is then not complete on the
    ///   bus.
    pub async fn run(
        &self,
        bus: &dyn MessageBus,
        config: &BusRunnerConfig,
        cancel: CancellationToken,
    ) -> Result<RunSummary> {
        if config.durable_name.trim().is_empty() {
            return Err(Error::Config(
                "the durable name of the detection runner is empty".to_owned(),
            ));
        }
        if config.publish_attempts == 0 {
            return Err(Error::Config(
                "publish_attempts of the detection runner must be 1 or more, but it is 0"
                    .to_owned(),
            ));
        }
        let pattern = format!("{}.>", subject::EVENTS);
        let mut stream = bus.subscribe(&pattern, Some(&config.durable_name)).await?;
        let detection_subject = |tier| format!("{}.{}", subject::DETECTIONS, tier_token(tier));

        let mut summary = RunSummary::default();
        let mut stream_errors_in_sequence: u32 = 0;
        loop {
            let next = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                next = stream.next() => next,
            };
            let message = match next {
                Some(Ok(message)) => {
                    stream_errors_in_sequence = 0;
                    message
                }
                Some(Err(error)) => {
                    // A bus can report an outage as an error and then continue the same
                    // subscription. The durable consumer keeps the position.
                    stream_errors_in_sequence += 1;
                    if !error.is_retryable()
                        || stream_errors_in_sequence >= MAX_STREAM_ERRORS_IN_SEQUENCE
                    {
                        return Err(error);
                    }
                    tracing::warn!(%error, "the event subscription of the detection runner gave a temporary error");
                    summary.stream_errors = summary.stream_errors.saturating_add(1);
                    continue;
                }
                None => {
                    return Err(Error::Unavailable(
                        "the bus closed the event subscription of the detection runner".to_owned(),
                    ));
                }
            };
            let event: Event = match serde_json::from_slice(&message.payload) {
                Ok(event) => event,
                Err(error) => {
                    // The text of the parser error can hold a value from the payload, so
                    // the log line has only the position and the type of the error.
                    tracing::warn!(
                        subject = %message.subject,
                        bytes = message.payload.len(),
                        category = ?error.classify(),
                        line = error.line(),
                        column = error.column(),
                        "the detection runner dropped a message that is not an event"
                    );
                    summary.rejected_messages = summary.rejected_messages.saturating_add(1);
                    continue;
                }
            };

            let output = self.process(&event).await?;
            summary.events = summary.events.saturating_add(1);
            for detection in &output.detections {
                let subject = detection_subject(detection.tier);
                publish(bus, &subject, encode(detection)?, config).await?;
                summary.detections = summary.detections.saturating_add(1);
            }
            for incident in &output.incidents {
                publish(bus, subject::INCIDENTS, encode(incident)?, config).await?;
                summary.incidents = summary.incidents.saturating_add(1);
            }
        }
        Ok(summary)
    }
}
