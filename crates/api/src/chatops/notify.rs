//! The notification task: bus messages to chat webhooks.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::bus::{BusMessage, BusStream, MessageBus, subject};
use aegis_contracts::common::{ApprovalId, IncidentId, Severity};
use aegis_contracts::incident::{Incident, IncidentStatus};
use aegis_contracts::policy::{ApprovalRequest, ApprovalStatus};
use aegis_contracts::{Error, Result};
use aegis_core::Shutdown;
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use reqwest::StatusCode;
use serde_json::Value;
use url::Url;

use super::http::Outbound;
use super::{ChatOps, slack, teams};
use crate::auth::Authenticator;
use crate::config::{ApiConfig, NotificationConfig};
use crate::routes::Ctx;
use crate::state::ApiState;

/// The maximum number of approval requests and of incidents that the task remembers.
const MAX_REMEMBERED: usize = 4_096;

/// The maximum number of bus errors in sequence before the task stops.
const MAX_BUS_ERRORS_IN_SEQUENCE: u32 = 16;

/// The largest wait between two attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chat {
    Slack,
    Teams,
}

impl Chat {
    fn name(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
        }
    }
}

struct Target {
    chat: Chat,
    url: Url,
    /// `true` if the server has the endpoints that the buttons or the commands need.
    interactive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Topic {
    Approvals,
    Incidents,
}

/// The task that posts approval requests and incidents to Slack and Teams.
///
/// The task subscribes to `aegis.approvals` and `aegis.incidents`. For each new approval
/// request, each decision, and each new or changed incident, it posts one message to each
/// webhook of the configuration. A Slack message for a pending request has an approve
/// button and a reject button, if the server has the Slack endpoints.
///
/// The task sends an incident again only when its state or its severity changes.
pub struct Notifier {
    bus: Arc<dyn MessageBus>,
    targets: Vec<Target>,
    outbound: Outbound,
    settings: NotificationConfig,
    approvals: BTreeMap<ApprovalId, ApprovalStatus>,
    incidents: BTreeMap<IncidentId, (IncidentStatus, Severity)>,
}

impl Notifier {
    /// Makes the task from the state and the configuration.
    ///
    /// `None` means that the configuration has no webhook, so there is nothing to run.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the configuration is not valid or a secret is missing.
    pub fn from_config(state: &ApiState, config: &ApiConfig) -> Result<Option<Self>> {
        config.validate()?;
        let auth = Authenticator::from_config(&config.principals, state.env())?;
        let chat = ChatOps::from_config(&config.chatops, &auth, state.env())?;
        Self::new(state, &chat, &config.chatops.notifications)
    }

    /// Makes the task from the request data of a server.
    pub(crate) fn from_context(ctx: &Ctx, settings: &NotificationConfig) -> Result<Option<Self>> {
        Self::new(&ctx.state, &ctx.chat, settings)
    }

    fn new(
        state: &ApiState,
        chat: &ChatOps,
        settings: &NotificationConfig,
    ) -> Result<Option<Self>> {
        let mut targets = Vec::new();
        if let Some(url) = &chat.slack_webhook {
            targets.push(Target {
                chat: Chat::Slack,
                url: url.clone(),
                interactive: chat.slack.is_some(),
            });
        }
        if let Some(url) = &chat.teams_webhook {
            targets.push(Target {
                chat: Chat::Teams,
                url: url.clone(),
                interactive: chat.teams.is_some(),
            });
        }
        if targets.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            bus: state.parts().bus.clone(),
            targets,
            outbound: Outbound::new(Duration::from_secs(settings.request_timeout_seconds))?,
            settings: settings.clone(),
            approvals: BTreeMap::new(),
            incidents: BTreeMap::new(),
        }))
    }

    /// Subscribes to the bus. After this function returns, the task gets each new message.
    ///
    /// # Errors
    ///
    /// Returns the error of the bus.
    pub async fn subscribe(self) -> Result<SubscribedNotifier> {
        let consumer = |topic: &str| {
            self.settings
                .durable_consumer
                .as_ref()
                .map(|name| format!("{name}-{topic}"))
        };
        let approvals = self
            .bus
            .subscribe(subject::APPROVALS, consumer("approvals").as_deref())
            .await?;
        let incidents = self
            .bus
            .subscribe(subject::INCIDENTS, consumer("incidents").as_deref())
            .await?;
        let tagged = |topic: Topic, messages: BusStream| messages.map(move |item| (topic, item));
        Ok(SubscribedNotifier {
            messages: stream::select(
                tagged(Topic::Approvals, approvals),
                tagged(Topic::Incidents, incidents),
            )
            .boxed(),
            notifier: self,
        })
    }

    /// Subscribes to the bus and posts messages until `shutdown` is triggered.
    ///
    /// # Errors
    ///
    /// Returns the error of the bus if the task cannot subscribe, and
    /// [`Error::Unavailable`] if the subscriptions end before the shutdown.
    pub async fn run(self, shutdown: Shutdown) -> Result<()> {
        self.subscribe().await?.run(shutdown).await
    }

    /// Returns the messages for one bus message, or nothing if the message needs none.
    fn messages_for(&mut self, topic: Topic, message: &BusMessage) -> Vec<(Chat, Value)> {
        match topic {
            Topic::Approvals => {
                let request: ApprovalRequest = match message.decode() {
                    Ok(request) => request,
                    Err(error) => {
                        tracing::warn!(%error, "an approval message on the bus is not valid");
                        return Vec::new();
                    }
                };
                if !remember(&mut self.approvals, request.id, request.status) {
                    return Vec::new();
                }
                self.targets
                    .iter()
                    .map(|target| {
                        let body = match target.chat {
                            Chat::Slack => slack::approval_message(&request, target.interactive),
                            Chat::Teams => teams::approval_message(&request, target.interactive),
                        };
                        (target.chat, body)
                    })
                    .collect()
            }
            Topic::Incidents => {
                let incident: Incident = match message.decode() {
                    Ok(incident) => incident,
                    Err(error) => {
                        tracing::warn!(%error, "an incident message on the bus is not valid");
                        return Vec::new();
                    }
                };
                let state = (incident.status, incident.severity);
                if !remember(&mut self.incidents, incident.id, state)
                    || incident.severity < self.settings.min_severity
                {
                    return Vec::new();
                }
                self.targets
                    .iter()
                    .map(|target| {
                        let body = match target.chat {
                            Chat::Slack => slack::incident_message(&incident),
                            Chat::Teams => teams::incident_message(&incident),
                        };
                        (target.chat, body)
                    })
                    .collect()
            }
        }
    }

    fn url_of(&self, chat: Chat) -> Option<&Url> {
        self.targets
            .iter()
            .find(|target| target.chat == chat)
            .map(|target| &target.url)
    }

    /// Posts one message. Tries again after a failure that can be temporary.
    ///
    /// Returns `false` if the shutdown stopped the attempts.
    async fn deliver(&self, chat: Chat, body: &Value, shutdown: &Shutdown) -> bool {
        let Some(url) = self.url_of(chat) else {
            return true;
        };
        let mut backoff = Duration::from_millis(self.settings.retry_backoff_ms);
        for attempt in 1..=self.settings.max_attempts {
            let request = self.outbound.client_for(url).post(url.clone()).json(body);
            let retry = match request.send().await {
                Ok(response) if response.status().is_success() => return true,
                Ok(response) => {
                    let status = response.status();
                    tracing::warn!(chat = chat.name(), %status, attempt, "a chat webhook refused a notification");
                    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
                }
                Err(error) => {
                    tracing::warn!(
                        chat = chat.name(),
                        error = %error.without_url(),
                        attempt,
                        "a notification request failed"
                    );
                    true
                }
            };
            if !retry || attempt == self.settings.max_attempts {
                break;
            }
            tokio::select! {
                () = shutdown.wait() => return false,
                () = tokio::time::sleep(backoff) => {}
            }
            backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
        }
        tracing::error!(chat = chat.name(), "a notification was not delivered");
        true
    }
}

/// Records the state of an item. Returns `false` if the task already sent this state.
fn remember<K: Ord + Copy, V: PartialEq>(seen: &mut BTreeMap<K, V>, key: K, state: V) -> bool {
    if seen.get(&key) == Some(&state) {
        return false;
    }
    seen.insert(key, state);
    // The identifiers sort by time, so the first entry is the oldest item.
    while seen.len() > MAX_REMEMBERED {
        seen.pop_first();
    }
    true
}

/// A [`Notifier`] that has its bus subscriptions.
pub struct SubscribedNotifier {
    notifier: Notifier,
    messages: BoxStream<'static, (Topic, Result<BusMessage>)>,
}

impl SubscribedNotifier {
    /// Posts messages until `shutdown` is triggered.
    ///
    /// A webhook failure goes to the log. The task continues with the next message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unavailable`] if the bus subscriptions end, or fail many times in
    /// sequence, before the shutdown.
    pub async fn run(mut self, shutdown: Shutdown) -> Result<()> {
        let mut errors_in_sequence: u32 = 0;
        loop {
            let item = tokio::select! {
                () = shutdown.wait() => return Ok(()),
                item = self.messages.next() => item,
            };
            let (topic, message) = match item {
                Some((topic, Ok(message))) => (topic, message),
                Some((topic, Err(error))) => {
                    errors_in_sequence += 1;
                    tracing::warn!(?topic, %error, "a bus subscription of the notification task failed");
                    if errors_in_sequence >= MAX_BUS_ERRORS_IN_SEQUENCE {
                        return Err(Error::Unavailable(
                            "the bus subscriptions of the notification task failed too many \
                             times"
                                .to_owned(),
                        ));
                    }
                    continue;
                }
                None => {
                    return Err(Error::Unavailable(
                        "the bus subscriptions of the notification task ended".to_owned(),
                    ));
                }
            };
            errors_in_sequence = 0;
            for (chat, body) in self.notifier.messages_for(topic, &message) {
                if !self.notifier.deliver(chat, &body, &shutdown).await {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_is_sent_one_time() {
        let mut seen = BTreeMap::new();
        assert!(remember(&mut seen, 1, "open"));
        assert!(!remember(&mut seen, 1, "open"));
        assert!(remember(&mut seen, 1, "contained"));
        assert!(!remember(&mut seen, 1, "contained"));
        assert!(remember(&mut seen, 2, "open"));
    }

    #[test]
    fn the_memory_has_a_limit_and_drops_the_oldest_item() {
        let mut seen = BTreeMap::new();
        for key in 0..=MAX_REMEMBERED {
            assert!(remember(&mut seen, key, ()));
        }
        assert_eq!(seen.len(), MAX_REMEMBERED);
        assert!(!seen.contains_key(&0));
        assert!(seen.contains_key(&1));
        assert!(seen.contains_key(&MAX_REMEMBERED));
    }
}
