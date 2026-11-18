//! The bus runner: events in, detections and incidents out.

use std::time::Duration;

use aegis_contracts::bus::{BusStream, MessageBus, encode, subject};
use aegis_contracts::event::Event;
use aegis_contracts::{Error, Incident, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::DetectionEngine;
use crate::common::tier_token;
use crate::flood::IncidentCoalescer;

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
    /// The largest number of states of one incident that the runner publishes in one
    /// window. The runner holds the newest state over the limit and publishes it when the
    /// window ends. Refer to [`IncidentCoalescer`].
    pub max_incident_updates: u32,
    /// The length in seconds of the window of `max_incident_updates`, in event time.
    pub incident_update_window_seconds: u64,
}

impl Default for BusRunnerConfig {
    fn default() -> Self {
        Self {
            durable_name: DEFAULT_DURABLE_NAME.to_owned(),
            publish_attempts: 5,
            publish_backoff_milliseconds: 50,
            max_incident_updates: 20,
            incident_update_window_seconds: 60,
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
    /// The number of incident states that the runner did not publish, because a newer
    /// state of the same incident replaced them. Refer to
    /// [`BusRunnerConfig::max_incident_updates`].
    pub coalesced_incident_updates: u64,
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

/// The state of one call of [`DetectionEngine::run`].
struct Run<'a> {
    bus: &'a dyn MessageBus,
    config: &'a BusRunnerConfig,
    summary: RunSummary,
    coalescer: IncidentCoalescer,
    /// The number of dropped states that the engine counters have.
    counted: u64,
}

impl Run<'_> {
    /// Publishes incident states, and adds the dropped states to the counts.
    async fn publish_incidents(
        &mut self,
        engine: &DetectionEngine,
        incidents: Vec<Incident>,
    ) -> Result<()> {
        let dropped = self.coalescer.coalesced();
        let new = dropped.saturating_sub(self.counted);
        if new > 0 {
            engine.meter.coalesced(new);
            self.counted = dropped;
            self.summary.coalesced_incident_updates = dropped;
        }
        for incident in &incidents {
            publish(self.bus, subject::INCIDENTS, encode(incident)?, self.config).await?;
            self.summary.incidents = self.summary.incidents.saturating_add(1);
        }
        Ok(())
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
    /// The runner publishes at most `max_incident_updates` states of one incident in one
    /// window of `incident_update_window_seconds`. It holds the newest state over the
    /// limit and drops the states that this state replaces. A held state goes to the bus
    /// when an event shows that the window is over, when the same time passed on the
    /// clock of the host with no such event, or when the runner stops. The first state of
    /// an incident, a state with a higher severity, and the last state of an incident that
    /// a merge replaced are not held.
    ///
    /// After a cancellation, the runner completes the event that it examines, publishes
    /// the incident states that it holds, and then returns the counts. Use one runner for
    /// each durable name: the velocity detectors must see all events of a stream.
    ///
    /// # Errors
    ///
    /// - [`Error::Config`] if the durable name is empty, or if `publish_attempts`,
    ///   `max_incident_updates`, or `incident_update_window_seconds` is zero.
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
        let coalescer = IncidentCoalescer::new(
            config.max_incident_updates,
            config.incident_update_window_seconds,
        )
        .map_err(|error| Error::Config(format!("the detection runner: {error}")))?;
        let pattern = format!("{}.>", subject::EVENTS);
        let stream = bus.subscribe(&pattern, Some(&config.durable_name)).await?;

        let mut run = Run {
            bus,
            config,
            summary: RunSummary::default(),
            coalescer,
            counted: 0,
        };
        let result = self.consume(&mut run, stream, cancel).await;
        // The runner stops. The held states are the newest states of their incidents.
        let held = run.coalescer.flush();
        let flushed = run.publish_incidents(self, held).await;
        result.and(flushed)?;
        Ok(run.summary)
    }

    /// Examines the events of the subscription until `cancel` is cancelled.
    async fn consume(
        &self,
        run: &mut Run<'_>,
        mut stream: BusStream,
        cancel: CancellationToken,
    ) -> Result<()> {
        let detection_subject = |tier| format!("{}.{}", subject::DETECTIONS, tier_token(tier));
        let hold_limit = Duration::from_secs(run.config.incident_update_window_seconds);
        // The instant of the host clock at which the runner started to hold a state.
        let mut held_since: Option<Instant> = None;
        let mut stream_errors_in_sequence: u32 = 0;
        loop {
            let next = tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                next = stream.next() => next,
                () = wait_until(held_since.and_then(|since| since.checked_add(hold_limit))) => {
                    // No event showed the end of the window in this time.
                    let held = run.coalescer.flush();
                    run.publish_incidents(self, held).await?;
                    held_since = None;
                    continue;
                }
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
                    run.summary.stream_errors = run.summary.stream_errors.saturating_add(1);
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
                    run.summary.rejected_messages = run.summary.rejected_messages.saturating_add(1);
                    continue;
                }
            };

            let output = self.process(&event).await?;
            run.summary.events = run.summary.events.saturating_add(1);
            for detection in &output.detections {
                let subject = detection_subject(detection.tier);
                publish(run.bus, &subject, encode(detection)?, run.config).await?;
                run.summary.detections = run.summary.detections.saturating_add(1);
            }
            // The new states go first. A new state replaces a held state of its incident.
            let mut leaving = Vec::with_capacity(output.incidents.len());
            for incident in output.incidents {
                leaving.extend(run.coalescer.offer(incident, event.time));
            }
            leaving.extend(run.coalescer.release_due(event.time));
            if held_since.is_some_and(|since| since.elapsed() >= hold_limit) {
                // Events arrive without a pause, and their times do not show the end of
                // the window. The timer of the loop thus gets no turn.
                leaving.extend(run.coalescer.flush());
                held_since = None;
            }
            run.publish_incidents(self, leaving).await?;
            held_since = if run.coalescer.has_held() {
                held_since.or_else(|| Some(Instant::now()))
            } else {
                None
            };
        }
        Ok(())
    }
}

/// Waits until `deadline`. With no deadline, the function never returns.
async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}
