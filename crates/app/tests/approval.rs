//! The approval path: a gated action waits, a person decides, and the action runs one
//! time.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;

use aegis_agents::ledger::{ActionState, tracked_actions};
use aegis_app::actions::DispatchResult;
use aegis_app::{APPROVAL_REJECTED_POLICY, App};
use aegis_contracts::Error;
use aegis_contracts::action::{ActionDisposition, ActionKind, ActionStatus};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::common::ApprovalId;
use aegis_contracts::incident::{Incident, IncidentStatus, IncidentStore};
use aegis_contracts::policy::{
    ApprovalRequest, ApprovalStatus, PolicyEffect, Principal, PrincipalKind,
};
use aegis_testkit::{RecordingConnector, fixtures};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use support::{Starter, live, spray_events, with_modules};

const MODULES: [&str; 5] = ["ingest", "detection", "monitor", "analyst", "responder"];

fn alice() -> Principal {
    Principal::new("alice@example.com", PrincipalKind::Human, &["approver"])
}

/// A live application with a recording firewall connector, after the password spray.
struct Scenario {
    _starter: Starter,
    app: App,
    firewall: Arc<RecordingConnector>,
    incident: Incident,
    approval: ApprovalRequest,
}

impl Scenario {
    async fn new() -> Self {
        let starter = Starter::new();
        let config = starter.config_with(|text| with_modules(&live(&text), &MODULES));
        let firewall = Arc::new(RecordingConnector::new(
            "firewall",
            vec![ActionKind::BlockIp],
        ));
        let app = starter
            .build(&config, |builder| {
                builder.action_connector(firewall.clone())
            })
            .await;

        let report = app.replay(spray_events()).await.unwrap();

        // The spray gives one incident. The Responder proposes one action: block the
        // spray address. The default policy gates this action, so it waits.
        assert!(!report.dry_run);
        assert_eq!(report.incidents.len(), 1);
        assert_eq!(report.actions.len(), 1);
        let action = &report.actions[0];
        assert_eq!(action.request.kind, ActionKind::BlockIp);
        assert_eq!(action.request.target.id, fixtures::SPRAY_IP.to_string());
        assert!(!action.request.dry_run);
        let DispatchResult::Disposition(ActionDisposition::PendingApproval {
            approval_id,
            decision,
        }) = &action.result
        else {
            panic!("the action must wait for approval: {:?}", action.result);
        };
        assert_eq!(decision.effect, PolicyEffect::RequireApproval);
        let pending = app.approvals().pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, *approval_id);
        assert_eq!(pending[0].action.id, action.request.id);
        assert_eq!(pending[0].status, ApprovalStatus::Pending);
        assert_eq!(firewall.executed(), []);
        let incident = report.incidents[0].clone();
        assert_eq!(incident.status, IncidentStatus::Investigating);
        assert_eq!(states(&incident), [ActionState::PendingApproval]);
        Self {
            _starter: starter,
            app,
            firewall,
            incident,
            approval: pending[0].clone(),
        }
    }

    async fn stored(&self) -> Incident {
        self.app
            .incidents()
            .get(self.incident.id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn audit_kinds(&self) -> Vec<AuditKind> {
        self.app
            .audit()
            .read(1, 10_000)
            .await
            .unwrap()
            .iter()
            .map(|record| record.kind)
            .collect()
    }
}

fn states(incident: &Incident) -> Vec<ActionState> {
    tracked_actions(incident)
        .iter()
        .map(|action| action.state)
        .collect()
}

#[tokio::test]
async fn an_approval_runs_the_action_one_time_and_the_incident_is_contained() {
    let scenario = Scenario::new().await;
    let id = scenario.approval.id;

    let outcome = scenario
        .app
        .decide_approval(
            id,
            true,
            &alice(),
            Some("Confirmed with the network team.".to_owned()),
        )
        .await
        .unwrap();

    assert_eq!(outcome.approval.status, ApprovalStatus::Approved);
    assert_eq!(
        outcome.approval.decided_by.as_deref(),
        Some("alice@example.com")
    );
    let Some(ActionDisposition::Executed(result)) = &outcome.disposition else {
        panic!("the action must run: {:?}", outcome.disposition);
    };
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.connector, "firewall");
    assert_eq!(result.action_id, scenario.approval.action.id);

    // The connector got the request one time, and the request was not a dry run.
    let executed = scenario.firewall.executed();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].id, scenario.approval.action.id);
    assert!(!executed[0].dry_run);

    // The Responder got the result. Its one action ran, so the incident is contained.
    let stored = scenario.stored().await;
    assert_eq!(stored.status, IncidentStatus::Contained);
    assert_eq!(states(&stored), [ActionState::Succeeded]);
    assert!(
        stored
            .timeline
            .iter()
            .any(|entry| entry.author == "responder"
                && entry.description == "Containment is complete. All 1 actions ran."),
        "{:?}",
        stored.timeline
    );

    // The journal has the new result, and the audit log has the decision and the run.
    let record = scenario
        .app
        .actions()
        .get(scenario.approval.action.id)
        .unwrap();
    assert_eq!(
        record.result,
        DispatchResult::Disposition(ActionDisposition::Executed(result.clone()))
    );
    assert!(record.result.changed_the_environment());
    let kinds = scenario.audit_kinds().await;
    let count = |kind: AuditKind| kinds.iter().filter(|found| **found == kind).count();
    assert_eq!(count(AuditKind::ApprovalRequested), 1);
    assert_eq!(count(AuditKind::ApprovalDecided), 1);
    assert_eq!(count(AuditKind::ActionExecuted), 1);
    assert!(scenario.app.audit().verify().await.unwrap().valid);

    // One approval permits one action. A second decision and a second run are errors.
    let again = scenario
        .app
        .decide_approval(id, true, &alice(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(&again, Error::InvalidInput(message) if message.contains("already has a decision")),
        "{again:?}"
    );
    let resumed = scenario.app.dispatcher().resume(id).await.unwrap_err();
    assert!(
        matches!(&resumed, Error::InvalidInput(message) if message.contains("already ran")),
        "{resumed:?}"
    );
    assert_eq!(scenario.firewall.executed().len(), 1);
    assert_eq!(scenario.stored().await.status, IncidentStatus::Contained);
}

#[tokio::test]
async fn a_rejection_does_not_run_the_action() {
    let scenario = Scenario::new().await;
    let id = scenario.approval.id;

    let outcome = scenario
        .app
        .decide_approval(
            id,
            false,
            &alice(),
            Some("This address is our scanner.".to_owned()),
        )
        .await
        .unwrap();

    assert_eq!(outcome.approval.status, ApprovalStatus::Rejected);
    assert_eq!(outcome.disposition, None);
    assert_eq!(scenario.firewall.executed(), []);
    assert_eq!(scenario.app.approvals().pending().await.unwrap(), []);

    // The Responder knows about the rejection. The action is denied in the timeline, the
    // incident is not contained, and the Responder does not propose the action again.
    let stored = scenario.stored().await;
    assert_eq!(stored.status, IncidentStatus::Investigating);
    assert_eq!(states(&stored), [ActionState::Denied]);
    assert!(
        stored
            .timeline
            .iter()
            .any(|entry| entry.author == "responder"
                && entry.description
                    == format!(
                        "block_ip on ip_address:203.0.113.50: denied by policy. alice@example.com \
                     rejected the approval request {id}. Note: This address is our scanner."
                    )),
        "{:?}",
        stored.timeline
    );
    let record = scenario
        .app
        .actions()
        .get(scenario.approval.action.id)
        .unwrap();
    let DispatchResult::Disposition(ActionDisposition::Denied(decision)) = &record.result else {
        panic!("the journal must have the denial: {:?}", record.result);
    };
    assert_eq!(decision.effect, PolicyEffect::Deny);
    assert_eq!(decision.policy.as_deref(), Some(APPROVAL_REJECTED_POLICY));

    let kinds = scenario.audit_kinds().await;
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == AuditKind::ApprovalDecided)
            .count(),
        1
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == AuditKind::ActionExecuted)
            .count(),
        0
    );

    // A rejected request cannot run later.
    let resumed = scenario.app.dispatcher().resume(id).await.unwrap_err();
    assert!(matches!(resumed, Error::Denied(_)), "{resumed:?}");
    assert_eq!(scenario.firewall.executed(), []);
}

#[tokio::test]
async fn a_principal_without_the_permission_or_against_a_rule_is_refused() {
    let scenario = Scenario::new().await;
    let id = scenario.approval.id;
    let refused = [
        // The role `analyst` can view incidents. It cannot approve.
        Principal::new("bob@example.com", PrincipalKind::Human, &["analyst"]),
        // A role that the configuration does not name gives no permission.
        Principal::new("eve@example.com", PrincipalKind::Human, &["owner"]),
        Principal::new("mallory@example.com", PrincipalKind::Human, &[]),
        // Only a person can decide, also when the principal has the role.
        Principal::new("responder", PrincipalKind::Agent, &["approver"]),
        Principal::new("automation", PrincipalKind::System, &["approver"]),
    ];
    for principal in &refused {
        for approve in [true, false] {
            let error = scenario
                .app
                .decide_approval(id, approve, principal, None)
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::Unauthorized(_)),
                "{}: {error:?}",
                principal.id
            );
        }
    }

    // Nothing changed: the request waits, the connector got nothing, and the audit log
    // has no decision.
    let pending = scenario.app.approvals().pending().await.unwrap();
    assert_eq!(pending, std::slice::from_ref(&scenario.approval));
    assert_eq!(scenario.firewall.executed(), []);
    let stored = scenario.stored().await;
    assert_eq!(stored.status, IncidentStatus::Investigating);
    assert_eq!(states(&stored), [ActionState::PendingApproval]);
    assert!(
        !scenario
            .audit_kinds()
            .await
            .contains(&AuditKind::ApprovalDecided)
    );

    // A request that does not exist is a different error.
    let missing = scenario
        .app
        .decide_approval(ApprovalId::new(), true, &alice(), None)
        .await
        .unwrap_err();
    assert!(matches!(missing, Error::NotFound(_)), "{missing:?}");

    // A person with the permission can still decide.
    let outcome = scenario
        .app
        .decide_approval(id, true, &alice(), None)
        .await
        .unwrap();
    assert!(matches!(
        outcome.disposition,
        Some(ActionDisposition::Executed(_))
    ));
    assert_eq!(scenario.firewall.executed().len(), 1);
}

#[tokio::test]
async fn an_approved_action_goes_to_the_webhook_connector_of_the_configuration() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/aegis/block"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "rule-17" })),
        )
        .mount(&server)
        .await;
    let starter = Starter::new();
    let config = starter.config_with(|text| {
        let text = with_modules(&live(&text), &MODULES);
        support::replace_once(
            &text,
            "playbook_dir = \"playbooks\"",
            &format!(
                "playbook_dir = \"playbooks\"\n\n[response.webhook]\nname = \"soc-bridge\"\n\
                 secret = \"a-test-secret-of-32-bytes-long!!\"\n\n[[response.webhook.endpoints]]\n\
                 kind = \"block_ip\"\nurl = \"{}/aegis/block\"\n\n[[response.routes]]\n\
                 kind = \"block_ip\"\nconnector = \"soc-bridge\"\n",
                server.uri()
            ),
        )
    });
    let app = starter.build(&config, |builder| builder).await;
    assert_eq!(app.action_registry().names(), ["soc-bridge", "honeytokens"]);

    let report = app.replay(spray_events()).await.unwrap();
    assert_eq!(report.actions.len(), 1);
    let pending = app.approvals().pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    // A gated action sends no request before the approval.
    assert_eq!(server.received_requests().await.unwrap().len(), 0);

    let outcome = app
        .decide_approval(pending[0].id, true, &alice(), None)
        .await
        .unwrap();

    let Some(ActionDisposition::Executed(result)) = &outcome.disposition else {
        panic!("the action must run: {:?}", outcome.disposition);
    };
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.connector, "soc-bridge");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["operation"], "execute");
    assert_eq!(body["action"]["kind"], "block_ip");
    assert_eq!(
        body["action"]["target"]["id"],
        fixtures::SPRAY_IP.to_string()
    );
    assert_eq!(body["action"]["dry_run"], false);
    assert!(requests[0].headers.contains_key("x-aegis-signature"));
    let stored = app
        .incidents()
        .get(report.incidents[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, IncidentStatus::Contained);
}

#[tokio::test]
async fn a_connector_failure_after_the_approval_goes_to_the_caller_and_to_the_agent() {
    let starter = Starter::new();
    let config = starter.config_with(|text| with_modules(&live(&text), &MODULES));
    let firewall = Arc::new(
        RecordingConnector::new("firewall", vec![ActionKind::BlockIp]).failing("firewall is down"),
    );
    let app = starter
        .build(&config, |builder| {
            builder.action_connector(firewall.clone())
        })
        .await;
    let report = app.replay(spray_events()).await.unwrap();
    let pending = app.approvals().pending().await.unwrap();
    assert_eq!(pending.len(), 1);

    let error = app
        .decide_approval(pending[0].id, true, &alice(), None)
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unavailable(message) if message == "firewall is down"),
        "{error:?}"
    );
    assert_eq!(firewall.executed().len(), 1);
    // The decision stays, the journal has the failure, and the Responder recorded it.
    let decided = app.approvals().get(pending[0].id).await.unwrap().unwrap();
    assert_eq!(decided.status, ApprovalStatus::Approved);
    let record = app.actions().get(pending[0].action.id).unwrap();
    assert_eq!(
        record.result,
        DispatchResult::Failed {
            kind: "unavailable".to_owned(),
            message: "unavailable: firewall is down".to_owned(),
            retryable: true,
        }
    );
    let stored = app
        .incidents()
        .get(report.incidents[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, IncidentStatus::Investigating);
    assert_eq!(states(&stored), [ActionState::Failed]);
    // One approval permits one attempt.
    let resumed = app.dispatcher().resume(pending[0].id).await.unwrap_err();
    assert!(matches!(resumed, Error::InvalidInput(_)), "{resumed:?}");
    assert_eq!(firewall.executed().len(), 1);
}
