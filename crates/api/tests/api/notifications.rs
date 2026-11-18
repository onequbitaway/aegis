//! The notification task: bus messages to the chat webhooks.

use std::collections::BTreeMap;
use std::time::Duration;

use aegis_api::chatops::Notifier;
use aegis_api::{ApiConfig, SlackConfig, TeamsConfig};
use aegis_contracts::bus::{MessageBus, publish_json, subject};
use aegis_contracts::common::Severity;
use aegis_contracts::incident::IncidentStatus;
use aegis_contracts::policy::ApprovalStatus;
use aegis_core::Shutdown;
use serde_json::{Value, json};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::chat::{SLACK_ALICE, chat_env};
use crate::support::{TestApi, approval_request, config, incident};

/// A webhook that sends the body of each request to the test.
struct Capture {
    bodies: UnboundedSender<Value>,
    status: u16,
}

impl Respond for Capture {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        // The test can end before the task stops. A closed channel is not an error.
        let _ = self.bodies.send(body);
        ResponseTemplate::new(self.status)
    }
}

/// The webhooks of one test and the bodies that they received.
struct Webhooks {
    server: MockServer,
    slack: UnboundedReceiver<Value>,
    teams: UnboundedReceiver<Value>,
}

impl Webhooks {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let (slack_sender, slack) = unbounded_channel();
        let (teams_sender, teams) = unbounded_channel();
        for (route, bodies) in [("/slack-hook", slack_sender), ("/teams-hook", teams_sender)] {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(Capture {
                    bodies,
                    status: 200,
                })
                .mount(&server)
                .await;
        }
        Self {
            server,
            slack,
            teams,
        }
    }

    /// Returns the environment variables of the webhook URLs.
    fn env(&self) -> Vec<(&'static str, String)> {
        let mut env = chat_env();
        env.push((
            "SLACK_WEBHOOK_URL",
            format!("{}/slack-hook", self.server.uri()),
        ));
        env.push((
            "TEAMS_WEBHOOK_URL",
            format!("{}/teams-hook", self.server.uri()),
        ));
        env
    }
}

/// Waits for the next body that a webhook received.
async fn next(bodies: &mut UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(Duration::from_secs(10), bodies.recv())
        .await
        .expect("the webhook got no request in time")
        .expect("the webhook closed")
}

/// Returns a configuration with the two webhooks. With `endpoints`, the server also has
/// the Slack endpoints and the Teams endpoint.
fn notify_config(endpoints: bool) -> ApiConfig {
    let mut config = config();
    config.chatops.slack = Some(SlackConfig {
        signing_secret_env: endpoints.then(|| "SLACK_SIGNING_SECRET".to_owned()),
        users: BTreeMap::from([(SLACK_ALICE.to_owned(), "alice@example.com".to_owned())]),
        webhook_url_env: Some("SLACK_WEBHOOK_URL".to_owned()),
        ..SlackConfig::default()
    });
    config.chatops.teams = Some(TeamsConfig {
        shared_secret_env: endpoints.then(|| "TEAMS_SECRET".to_owned()),
        webhook_url_env: Some("TEAMS_WEBHOOK_URL".to_owned()),
        ..TeamsConfig::default()
    });
    config.chatops.notifications.retry_backoff_ms = 0;
    config
}

/// One running notification task.
struct Running {
    api: TestApi,
    shutdown: Shutdown,
    task: JoinHandle<aegis_contracts::Result<()>>,
}

impl Running {
    /// Starts the task. The task has its bus subscriptions when this function returns.
    async fn start(webhooks: &Webhooks, config: &ApiConfig) -> Self {
        let env = webhooks.env();
        let env: Vec<(&str, &str)> = env
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        let api = TestApi::with_env(&env);
        let notifier = Notifier::from_config(&api.state, config)
            .unwrap()
            .expect("the configuration has a webhook");
        let subscribed = notifier.subscribe().await.unwrap();
        let shutdown = Shutdown::new();
        let task = tokio::spawn(subscribed.run(shutdown.clone()));
        Self {
            api,
            shutdown,
            task,
        }
    }

    async fn publish<T: serde::Serialize + Sync>(&self, subject: &str, value: &T) {
        publish_json(self.api.bus.as_ref(), subject, value)
            .await
            .unwrap();
    }

    /// Stops the task and returns its result.
    async fn stop(self) -> aegis_contracts::Result<()> {
        self.shutdown.trigger();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("the task did not stop in time")
            .unwrap()
    }
}

fn plain(text: &str) -> Value {
    json!({ "type": "plain_text", "text": text, "emoji": false })
}

fn slack_card(title: &str, headline: Option<&str>, facts: &str, reference: &str) -> Vec<Value> {
    let mut blocks = vec![json!({ "type": "header", "text": plain(title) })];
    if let Some(headline) = headline {
        blocks.push(json!({ "type": "section", "text": plain(headline) }));
    }
    blocks.push(json!({ "type": "section", "text": plain(facts) }));
    blocks.push(json!({ "type": "context", "elements": [plain(reference)] }));
    blocks
}

fn teams_card(body: Vec<Value>) -> Value {
    json!({
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": null,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body
            }
        }]
    })
}

fn title_block(text: &str) -> Value {
    json!({ "type": "TextBlock", "text": text, "weight": "Bolder", "size": "Medium", "wrap": true })
}

fn text_block(text: &str) -> Value {
    json!({ "type": "TextBlock", "text": text, "wrap": true })
}

fn fact(title: &str, value: &str) -> Value {
    json!({ "title": title, "value": value })
}

#[tokio::test]
async fn a_new_approval_request_reaches_the_webhooks_with_the_expected_json() {
    let mut webhooks = Webhooks::start().await;
    let running = Running::start(&webhooks, &notify_config(true)).await;
    let request = approval_request();
    running.publish(subject::APPROVALS, &request).await;

    let id = request.id;
    let mut blocks = slack_card(
        "AEGIS approval needed",
        None,
        "Action: disable_user\n\
         Target: user victim@example.com (user-1)\n\
         Reason: The account signed in from the spray address.\n\
         Requested by: responder\n\
         Policy: The action is in the gated tier.",
        &format!("Approval {id}"),
    );
    blocks.push(json!({
        "type": "actions",
        "block_id": format!("aegis_approval_{id}"),
        "elements": [
            {
                "type": "button",
                "action_id": "aegis_approve",
                "style": "primary",
                "text": plain("Approve"),
                "value": id.to_string(),
                "confirm": {
                    "title": plain("Approve the action?"),
                    "text": plain("AEGIS runs the action after the approval."),
                    "confirm": plain("Approve"),
                    "deny": plain("Cancel")
                }
            },
            {
                "type": "button",
                "action_id": "aegis_reject",
                "style": "danger",
                "text": plain("Reject"),
                "value": id.to_string()
            }
        ]
    }));
    assert_eq!(
        next(&mut webhooks.slack).await,
        json!({ "text": "AEGIS approval needed", "blocks": blocks })
    );

    assert_eq!(
        next(&mut webhooks.teams).await,
        teams_card(vec![
            title_block("AEGIS approval needed"),
            json!({ "type": "FactSet", "facts": [
                fact("Action", "disable\\_user"),
                fact("Target", "user victim\\@example\\.com \\(user\\-1\\)"),
                fact("Reason", "The account signed in from the spray address\\."),
                fact("Requested by", "responder"),
                fact("Policy", "The action is in the gated tier\\."),
                fact("Approval", &id.to_string()),
            ] }),
            text_block(&format!("To decide, send: approve {id} or reject {id}")),
        ])
    );
    running.stop().await.unwrap();
}

#[tokio::test]
async fn a_message_has_no_buttons_when_the_server_has_no_chat_endpoints() {
    let mut webhooks = Webhooks::start().await;
    let running = Running::start(&webhooks, &notify_config(false)).await;
    let request = approval_request();
    running.publish(subject::APPROVALS, &request).await;

    let slack = next(&mut webhooks.slack).await;
    let kinds: Vec<&str> = slack["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|block| block["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["header", "section", "context"]);

    let teams = next(&mut webhooks.teams).await;
    let body = teams["attachments"][0]["content"]["body"]
        .as_array()
        .unwrap();
    let kinds: Vec<&str> = body
        .iter()
        .map(|item| item["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["TextBlock", "FactSet"]);
    running.stop().await.unwrap();
}

#[tokio::test]
async fn a_decision_gives_a_message_with_no_buttons() {
    let mut webhooks = Webhooks::start().await;
    let running = Running::start(&webhooks, &notify_config(true)).await;
    let mut request = approval_request();
    running.publish(subject::APPROVALS, &request).await;
    assert_eq!(
        next(&mut webhooks.slack).await["text"],
        "AEGIS approval needed"
    );
    assert_eq!(
        next(&mut webhooks.teams).await["attachments"][0]["content"]["body"][0]["text"],
        "AEGIS approval needed"
    );

    // The bus gets the same pending request again, and then the decision.
    running.publish(subject::APPROVALS, &request).await;
    request.status = ApprovalStatus::Approved;
    request.decided_by = Some("alice@example.com".to_owned());
    request.note = Some("Checked <with> the owner.".to_owned());
    running.publish(subject::APPROVALS, &request).await;

    assert_eq!(
        next(&mut webhooks.slack).await,
        json!({
            "text": "AEGIS action approved",
            "blocks": slack_card(
                "AEGIS action approved",
                None,
                "Action: disable_user\n\
                 Target: user victim@example.com (user-1)\n\
                 Reason: The account signed in from the spray address.\n\
                 Requested by: responder\n\
                 Policy: The action is in the gated tier.\n\
                 Decided by: alice@example.com\n\
                 Note: Checked &lt;with&gt; the owner.",
                &format!("Approval {}", request.id),
            )
        })
    );
    let teams = next(&mut webhooks.teams).await;
    let body = teams["attachments"][0]["content"]["body"]
        .as_array()
        .unwrap();
    assert_eq!(body.len(), 2);
    assert_eq!(body[0]["text"], "AEGIS action approved");
    assert_eq!(
        body[1]["facts"][6],
        fact("Note", "Checked &lt;with&gt; the owner\\.")
    );
    running.stop().await.unwrap();
}

#[tokio::test]
async fn incident_text_with_markup_characters_is_escaped_for_each_format() {
    let mut webhooks = Webhooks::start().await;
    let running = Running::start(&webhooks, &notify_config(true)).await;
    let mut hostile = incident(
        "<!here> [reset your password](https://evil.example) *now*\n<@U0ALICE>",
        Severity::Critical,
    );
    hostile.summary = "<https://evil.example|Open the report> & `rm -rf` ![x](y)".to_owned();
    hostile.tenant = Some("tenant <b>contoso</b>".to_owned());
    running.publish(subject::INCIDENTS, &hostile).await;

    assert_eq!(
        next(&mut webhooks.slack).await,
        json!({
            "text": "AEGIS incident: &lt;!here&gt; [reset your password](https://evil.example) \
                     *now* &lt;@U0ALICE&gt;",
            "blocks": slack_card(
                "AEGIS incident",
                Some(
                    "&lt;!here&gt; [reset your password](https://evil.example) *now* \
                     &lt;@U0ALICE&gt;"
                ),
                "Severity: critical\n\
                 Status: open\n\
                 Tenant: tenant &lt;b&gt;contoso&lt;/b&gt;\n\
                 Techniques: T1110.003\n\
                 Entities: 3\n\
                 Summary: &lt;https://evil.example|Open the report&gt; &amp; `rm -rf` ![x](y)",
                &format!("Incident {}", hostile.id),
            )
        })
    );

    assert_eq!(
        next(&mut webhooks.teams).await,
        teams_card(vec![
            title_block("AEGIS incident"),
            text_block(
                "&lt;\\!here&gt; \\[reset your password\\]\\(https\\:\\/\\/evil\\.example\\) \
                 \\*now\\* &lt;\\@U0ALICE&gt;"
            ),
            json!({ "type": "FactSet", "facts": [
                fact("Severity", "critical"),
                fact("Status", "open"),
                fact("Tenant", "tenant &lt;b&gt;contoso&lt;\\/b&gt;"),
                fact("Techniques", "T1110\\.003"),
                fact("Entities", "3"),
                fact(
                    "Summary",
                    "&lt;https\\:\\/\\/evil\\.example\\|Open the report&gt; &amp; \
                     \\`rm \\-rf\\` \\!\\[x\\]\\(y\\)"
                ),
                fact("Incident", &hostile.id.to_string()),
            ] }),
        ])
    );
    running.stop().await.unwrap();
}

#[tokio::test]
async fn an_incident_is_sent_one_time_for_each_state_and_only_at_the_minimum_severity() {
    let mut webhooks = Webhooks::start().await;
    let running = Running::start(&webhooks, &notify_config(true)).await;

    // The default minimum severity is medium. A low incident gives no message.
    let low = incident("Low noise", Severity::Low);
    running.publish(subject::INCIDENTS, &low).await;
    let mut high = incident("Password spray", Severity::High);
    running.publish(subject::INCIDENTS, &high).await;
    // The same state again gives no message.
    running.publish(subject::INCIDENTS, &high).await;
    high.status = IncidentStatus::Contained;
    running.publish(subject::INCIDENTS, &high).await;
    // A message that is not an incident gives no message and does not stop the task.
    running
        .api
        .bus
        .publish(subject::INCIDENTS, b"not json".to_vec())
        .await
        .unwrap();
    let last = incident("Rogue application", Severity::Medium);
    running.publish(subject::INCIDENTS, &last).await;

    let facts = |body: &Value| {
        body["blocks"][2]["text"]["text"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let first = next(&mut webhooks.slack).await;
    assert_eq!(first["text"], "AEGIS incident: Password spray");
    assert!(facts(&first).contains("Status: open"), "{first}");
    let second = next(&mut webhooks.slack).await;
    assert_eq!(second["text"], "AEGIS incident: Password spray");
    assert!(facts(&second).contains("Status: contained"), "{second}");
    let third = next(&mut webhooks.slack).await;
    assert_eq!(third["text"], "AEGIS incident: Rogue application");

    running.stop().await.unwrap();
    // The task stopped. The webhook got the three messages and no more.
    assert!(webhooks.slack.try_recv().is_err());
}

#[tokio::test]
async fn a_webhook_fault_is_tried_again_and_a_refusal_is_not() {
    let server = MockServer::start().await;
    let (sender, mut bodies) = unbounded_channel();
    // The first two requests fail. The mock with the smaller priority number wins.
    Mock::given(method("POST"))
        .and(path("/slack-hook"))
        .respond_with(Capture {
            bodies: sender.clone(),
            status: 503,
        })
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/slack-hook"))
        .respond_with(Capture {
            bodies: sender,
            status: 200,
        })
        .with_priority(5)
        .mount(&server)
        .await;

    let hook = format!("{}/slack-hook", server.uri());
    let api = TestApi::with_env(&[("SLACK_WEBHOOK_URL", &hook)]);
    let mut config = config();
    config.chatops.slack = Some(SlackConfig {
        webhook_url_env: Some("SLACK_WEBHOOK_URL".to_owned()),
        ..SlackConfig::default()
    });
    config.chatops.notifications.retry_backoff_ms = 0;
    config.chatops.notifications.max_attempts = 3;
    let notifier = Notifier::from_config(&api.state, &config).unwrap().unwrap();
    let shutdown = Shutdown::new();
    let task = tokio::spawn(notifier.subscribe().await.unwrap().run(shutdown.clone()));

    let first = incident("Password spray", Severity::High);
    publish_json(api.bus.as_ref(), subject::INCIDENTS, &first)
        .await
        .unwrap();
    // Two failed attempts and one success: the same body three times.
    let attempt = next(&mut bodies).await;
    assert_eq!(attempt["text"], "AEGIS incident: Password spray");
    assert_eq!(next(&mut bodies).await, attempt);
    assert_eq!(next(&mut bodies).await, attempt);

    let second = incident("Rogue application", Severity::High);
    publish_json(api.bus.as_ref(), subject::INCIDENTS, &second)
        .await
        .unwrap();
    assert_eq!(
        next(&mut bodies).await["text"],
        "AEGIS incident: Rogue application"
    );

    shutdown.trigger();
    task.await.unwrap().unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn a_refused_notification_is_sent_one_time_and_the_task_continues() {
    let server = MockServer::start().await;
    let (sender, mut bodies) = unbounded_channel();
    Mock::given(method("POST"))
        .and(path("/teams-hook"))
        .respond_with(Capture {
            bodies: sender,
            status: 400,
        })
        .mount(&server)
        .await;
    let hook = format!("{}/teams-hook", server.uri());
    let api = TestApi::with_env(&[("TEAMS_WEBHOOK_URL", &hook)]);
    let mut config = config();
    config.chatops.teams = Some(TeamsConfig {
        webhook_url_env: Some("TEAMS_WEBHOOK_URL".to_owned()),
        ..TeamsConfig::default()
    });
    config.chatops.notifications.retry_backoff_ms = 0;
    let notifier = Notifier::from_config(&api.state, &config).unwrap().unwrap();
    let shutdown = Shutdown::new();
    let task = tokio::spawn(notifier.subscribe().await.unwrap().run(shutdown.clone()));

    for title in ["First", "Second"] {
        let incident = incident(title, Severity::High);
        publish_json(api.bus.as_ref(), subject::INCIDENTS, &incident)
            .await
            .unwrap();
        let body = next(&mut bodies).await;
        assert_eq!(body["attachments"][0]["content"]["body"][1]["text"], title);
    }
    shutdown.trigger();
    task.await.unwrap().unwrap();
    // One request for each incident: a 400 is not tried again.
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_configuration_with_no_webhook_has_no_task() {
    let api = TestApi::new();
    assert!(
        Notifier::from_config(&api.state, &config())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_webhook_url_that_is_not_safe_is_a_configuration_error() {
    let api = TestApi::with_env(&[(
        "SLACK_WEBHOOK_URL",
        "http://hooks.example.com/services/secret-part",
    )]);
    let mut config = config();
    config.chatops.slack = Some(SlackConfig {
        webhook_url_env: Some("SLACK_WEBHOOK_URL".to_owned()),
        ..SlackConfig::default()
    });
    for error in [
        Notifier::from_config(&api.state, &config).err().unwrap(),
        aegis_api::router(api.state.clone(), &config).err().unwrap(),
    ] {
        assert!(
            matches!(&error, aegis_contracts::Error::Config(message)
                if message == "the webhook URL in the environment variable SLACK_WEBHOOK_URL must use HTTPS. Only a loopback address can use HTTP. The URL must not hold credentials"),
            "{error}"
        );
    }
}
