//! Integration tests for the friction actions: `restrict_user_consent` in Microsoft Graph,
//! `raise_friction` through the webhook connector, the routing, and the response draft.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use aegis_contracts::action::{
    ActionConnector, ActionDispatcher, ActionDisposition, ActionKind, ActionOutcome, ActionRequest,
    ActionStatus,
};
use aegis_contracts::audit::{AuditKind, AuditLog};
use aegis_contracts::common::{EntityKind, EntityRef};
use aegis_contracts::{Error, Result};
use aegis_respond::connectors::graph::detail;
use aegis_respond::connectors::webhook::WebhookPayload;
use aegis_respond::friction::{self, RAISE_FRICTION, RESTRICT_USER_CONSENT};
use aegis_respond::playbook::{DEFAULT_FRICTION_REVERT_AFTER, TargetSelector, draft_response_with};
use aegis_respond::revert::{EXECUTION_DETAILS_PARAMETER, REVERT_AFTER_PARAMETER};
use aegis_respond::{
    ActionRegistry, Dispatcher, DraftError, DraftOptions, GraphActionConnector, GraphConfig,
    MemoryRevertStore, MemorySecretSink, PlaybookEngine, RevertScheduler, Route, RunMode,
    WebhookConfig, WebhookConnector, draft_response,
};
use aegis_testkit::fixtures::{OTHER_TENANT, TENANT};
use aegis_testkit::{
    MemoryApprovals, MemoryAuditLog, RecordingConnector, ScriptedModel, StaticPolicy,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{
    ToggleConnector, alice, playbook_engine, request, responder, revert_records, rogue_incident,
    timed,
};

const TOKEN_PATH: &str = "/tenant-contoso/oauth2/v2.0/token";
const POLICY_PATH: &str = "/v1.0/policies/authorizationPolicy";
const USER_DEFAULT: &str = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy";
const USER_LOW: &str = "managePermissionGrantsForSelf.microsoft-user-default-low";
const OWNED: &str =
    "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team";
const WEBHOOK_SECRET: &str = "webhook-secret-0123456789abcdef";

fn graph_config(server: &MockServer) -> GraphConfig {
    let mut config = GraphConfig::new(TENANT, "client-aegis", SecretString::from("client-secret"));
    config.graph_base_url = format!("{}/v1.0", server.uri());
    config.login_base_url = server.uri();
    config
}

fn graph(server: &MockServer) -> GraphActionConnector {
    GraphActionConnector::new(graph_config(server), Arc::new(MemorySecretSink::default())).unwrap()
}

async fn mount_token(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(TOKEN_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "access_token": "access-token",
        })))
        .mount(server)
        .await;
}

/// Returns the authorization policy document with this list of permission grant policies.
fn authorization_policy(policies: &[&str]) -> Value {
    json!({
        "id": "authorizationPolicy",
        "displayName": "Authorization Policy",
        "allowInvitesFrom": "everyone",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": true,
            "permissionGrantPoliciesAssigned": policies,
        },
    })
}

/// Mounts one answer to the next read of the authorization policy.
async fn mount_policy_once(server: &MockServer, policies: &[&str]) {
    Mock::given(method("GET"))
        .and(path(POLICY_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(authorization_policy(policies)))
        .up_to_n_times(1)
        .mount(server)
        .await;
}

async fn mount_policy_write(server: &MockServer) {
    Mock::given(method("PATCH"))
        .and(path(POLICY_PATH))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

/// One request that the mock server received: the method, the path, and the JSON body.
#[derive(Debug, PartialEq)]
struct Seen {
    method: String,
    path: String,
    body: Value,
}

fn seen(method: &str, body: Value) -> Seen {
    Seen {
        method: method.to_owned(),
        path: POLICY_PATH.to_owned(),
        body,
    }
}

fn write_of(policies: &[&str]) -> Seen {
    seen(
        "PATCH",
        json!({ "defaultUserRolePermissions": { "permissionGrantPoliciesAssigned": policies } }),
    )
}

/// Returns the requests to Microsoft Graph, without the token requests.
async fn graph_requests(server: &MockServer) -> Vec<Seen> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() != TOKEN_PATH)
        .map(|request| Seen {
            method: request.method.to_string(),
            path: request.url.path().to_owned(),
            body: if request.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&request.body).unwrap()
            },
        })
        .collect()
}

fn tenant() -> EntityRef {
    EntityRef::new(EntityKind::Tenant, TENANT)
}

fn restrict_request() -> ActionRequest {
    request(friction::restrict_user_consent(), tenant())
}

/// Returns the request that the dispatcher gives to `revert` after `outcome`.
fn revert_of(action: &ActionRequest, outcome: &ActionOutcome) -> ActionRequest {
    let mut revert = action.clone();
    revert.parameters.insert(
        EXECUTION_DETAILS_PARAMETER.to_owned(),
        outcome.details.clone(),
    );
    revert
}

fn executed(disposition: &ActionDisposition) -> &ActionOutcome {
    match disposition {
        ActionDisposition::Executed(outcome) => outcome,
        other => panic!("expected an executed action, found {other:?}"),
    }
}

#[tokio::test]
async fn restrict_user_consent_removes_the_user_consent_policies_and_keeps_the_others() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_policy_once(&server, &[USER_DEFAULT, OWNED, USER_LOW]).await;
    mount_policy_write(&server).await;
    let connector = graph(&server);
    let action = restrict_request();

    let outcome = connector.execute(&action).await.unwrap();

    // The exact requests: one read, then one write of the list without the two policies
    // that let a user consent for itself.
    assert_eq!(
        graph_requests(&server).await,
        [seen("GET", Value::Null), write_of(&[OWNED])]
    );
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.action_id, action.id);
    assert_eq!(outcome.connector, "entra-graph");
    assert!(outcome.reversible);
    assert_eq!(
        outcome.message,
        "Did stop user consent to applications in tenant tenant-contoso."
    );
    // The outcome holds the earlier value for the revert.
    assert_eq!(
        outcome.details,
        json!({
            "requests": [
                { "method": "GET", "path": "/policies/authorizationPolicy", "body": null },
                {
                    "method": "PATCH",
                    "path": "/policies/authorizationPolicy",
                    "body": {
                        "defaultUserRolePermissions": {
                            "permissionGrantPoliciesAssigned": [OWNED]
                        }
                    },
                },
            ],
            "user_consent": {
                "previous_permission_grant_policies": [USER_DEFAULT, OWNED, USER_LOW],
                "applied_permission_grant_policies": [OWNED],
            },
        })
    );
    assert_eq!(detail::USER_CONSENT, "user_consent");
    assert_eq!(detail::PREVIOUS, "previous_permission_grant_policies");
    assert_eq!(detail::APPLIED, "applied_permission_grant_policies");
}

#[tokio::test]
async fn a_dry_run_of_restrict_user_consent_sends_no_request() {
    let server = MockServer::start().await;
    let connector = graph(&server);
    let mut action = restrict_request();
    action.dry_run = true;

    let outcome = connector.execute(&action).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Simulated);
    assert!(outcome.reversible);
    assert_eq!(
        outcome.message,
        "Would stop user consent to applications in tenant tenant-contoso. This was a dry run. Nothing changed."
    );
    assert_eq!(
        outcome.details["planned_requests"][0],
        json!({ "method": "GET", "path": "/policies/authorizationPolicy", "body": null })
    );
    assert_eq!(outcome.details["planned_requests"][1]["method"], "PATCH");
    assert_eq!(
        outcome.details["planned_requests"][1]["path"],
        "/policies/authorizationPolicy"
    );
    // No token request and no Graph request.
    assert_eq!(server.received_requests().await.unwrap().len(), 0);

    // A dry run of the revert also sends no request.
    let executed_outcome = ActionOutcome {
        details: json!({
            "user_consent": {
                "previous_permission_grant_policies": [USER_DEFAULT, OWNED],
                "applied_permission_grant_policies": [OWNED],
            }
        }),
        ..outcome
    };
    let simulated = connector
        .revert(&revert_of(&action, &executed_outcome))
        .await
        .unwrap();
    assert_eq!(simulated.status, ActionStatus::Simulated);
    assert_eq!(
        simulated.details["planned_requests"][1]["body"],
        json!({
            "defaultUserRolePermissions": {
                "permissionGrantPoliciesAssigned": [USER_DEFAULT, OWNED]
            }
        })
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn revert_writes_the_saved_value_again() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    // The first read is from the action. The second read is from the revert: the tenant
    // then has the list that the action wrote.
    mount_policy_once(&server, &[OWNED, USER_DEFAULT, USER_LOW]).await;
    mount_policy_once(&server, &[OWNED]).await;
    mount_policy_write(&server).await;
    let connector = graph(&server);
    let action = restrict_request();
    let outcome = connector.execute(&action).await.unwrap();

    let reverted = connector
        .revert(&revert_of(&action, &outcome))
        .await
        .unwrap();

    // The revert writes the earlier list exactly, in the earlier order.
    assert_eq!(
        graph_requests(&server).await,
        [
            seen("GET", Value::Null),
            write_of(&[OWNED]),
            seen("GET", Value::Null),
            write_of(&[OWNED, USER_DEFAULT, USER_LOW]),
        ]
    );
    assert_eq!(reverted.status, ActionStatus::Succeeded);
    assert_eq!(reverted.action_id, action.id);
    assert_eq!(
        reverted.message,
        "Did restore the user consent settings of tenant tenant-contoso."
    );
    assert_eq!(
        reverted.details["user_consent"],
        json!({
            "previous_permission_grant_policies": [OWNED, USER_DEFAULT, USER_LOW],
            "applied_permission_grant_policies": [OWNED],
        })
    );
}

#[tokio::test]
async fn restrict_user_consent_makes_no_change_if_users_already_cannot_consent() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_policy_once(&server, &[OWNED]).await;
    mount_policy_write(&server).await;

    let outcome = graph(&server).execute(&restrict_request()).await.unwrap();

    assert_eq!(outcome.status, ActionStatus::Skipped);
    // The connector changed nothing, so there is nothing to undo.
    assert!(!outcome.reversible);
    assert_eq!(
        outcome.message,
        "Users of tenant tenant-contoso already cannot consent to applications. No change was necessary."
    );
    assert_eq!(graph_requests(&server).await, [seen("GET", Value::Null)]);
}

#[tokio::test]
async fn revert_does_not_replace_a_setting_that_a_different_administrator_changed() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_policy_once(&server, &[USER_DEFAULT, OWNED]).await;
    // After the action, an administrator permits consent for low-risk permissions only.
    mount_policy_once(&server, &[OWNED, USER_LOW]).await;
    // A later read finds the earlier value.
    mount_policy_once(&server, &[OWNED, USER_DEFAULT]).await;
    mount_policy_write(&server).await;
    let connector = graph(&server);
    let action = restrict_request();
    let outcome = connector.execute(&action).await.unwrap();
    let revert = revert_of(&action, &outcome);

    let changed = connector.revert(&revert).await.unwrap();

    assert_eq!(changed.status, ActionStatus::Skipped);
    assert!(
        changed
            .message
            .starts_with("A different administrator changed the user consent settings of tenant tenant-contoso after the action."),
        "{}",
        changed.message
    );
    assert_eq!(
        changed.details["user_consent"]["current_permission_grant_policies"],
        json!([OWNED, USER_LOW])
    );

    // The setting already has the earlier value, in a different order.
    let restored = connector.revert(&revert).await.unwrap();
    assert_eq!(restored.status, ActionStatus::Skipped);
    assert_eq!(
        restored.message,
        "The user consent settings of tenant tenant-contoso already have the earlier value. No change was necessary."
    );

    // One write in total: the write of the action. The two reverts wrote nothing.
    assert_eq!(
        graph_requests(&server).await,
        [
            seen("GET", Value::Null),
            write_of(&[OWNED]),
            seen("GET", Value::Null),
            seen("GET", Value::Null),
        ]
    );
}

#[tokio::test]
async fn restrict_user_consent_refuses_a_target_that_is_not_its_tenant() {
    let server = MockServer::start().await;
    let connector = graph(&server);

    let other_tenant = connector
        .execute(&request(
            friction::restrict_user_consent(),
            EntityRef::new(EntityKind::Tenant, OTHER_TENANT),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(&other_tenant, Error::InvalidInput(message) if message
            == "the target tenant tenant-fabrikam is not the tenant of connector entra-graph, which manages the tenant tenant-contoso only"),
        "{other_tenant:?}"
    );

    let not_a_tenant = connector
        .execute(&request(
            friction::restrict_user_consent(),
            EntityRef::new(EntityKind::User, "user-dana").with_tenant(TENANT),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(&not_a_tenant, Error::InvalidInput(message) if message
            == "the action custom:restrict_user_consent needs a target of the type tenant, not user"),
        "{not_a_tenant:?}"
    );

    // A different custom action is not an action of this connector.
    let unknown = connector
        .execute(&request(
            ActionKind::Custom("quarantine_mailbox".to_owned()),
            tenant(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(unknown, Error::Unsupported(_)), "{unknown:?}");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn a_policy_document_that_is_not_valid_stops_the_action_before_the_write() {
    for body in [
        json!({ "id": "authorizationPolicy" }),
        json!({ "defaultUserRolePermissions": { "allowedToCreateApps": true } }),
        json!({ "defaultUserRolePermissions": { "permissionGrantPoliciesAssigned": "all" } }),
        json!({ "defaultUserRolePermissions": {
            "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.x\nforged line"]
        } }),
    ] {
        let server = MockServer::start().await;
        mount_token(&server).await;
        Mock::given(method("GET"))
            .and(path(POLICY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;
        mount_policy_write(&server).await;

        let error = graph(&server)
            .execute(&restrict_request())
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::Serialization(message) if message
                == "Microsoft Graph returned an authorization policy that is not valid; the connector changed nothing"),
            "{body}: {error:?}"
        );
        assert_eq!(
            graph_requests(&server).await,
            [seen("GET", Value::Null)],
            "{body}"
        );
    }
}

#[tokio::test]
async fn a_graph_error_keeps_its_contract_error() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_policy_once(&server, &[USER_DEFAULT]).await;
    Mock::given(method("PATCH"))
        .and(path(POLICY_PATH))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": { "code": "Authorization_RequestDenied", "message": "Insufficient privileges." }
        })))
        .mount(&server)
        .await;

    let error = graph(&server)
        .execute(&restrict_request())
        .await
        .unwrap_err();

    assert!(
        matches!(&error, Error::Unauthorized(message) if message
            == "Microsoft Graph PATCH /policies/authorizationPolicy: HTTP 403 (Authorization_RequestDenied)"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_revert_with_no_saved_value_is_refused() {
    let server = MockServer::start().await;
    let connector = graph(&server);
    let action = restrict_request();
    let mut forged = action.clone();
    forged.parameters.insert(
        EXECUTION_DETAILS_PARAMETER.to_owned(),
        json!({ "user_consent": {
            "previous_permission_grant_policies": ["a/../b"],
            "applied_permission_grant_policies": [],
        } }),
    );

    for revert in [action, forged] {
        let error = connector.revert(&revert).await.unwrap_err();
        assert!(
            matches!(&error, Error::InvalidInput(message) if message.starts_with(
                "the revert of restrict_user_consent needs the parameter execution_details"
            )),
            "{error:?}"
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn the_dispatcher_gives_the_saved_value_from_the_audit_log_to_the_revert() {
    let server = MockServer::start().await;
    mount_token(&server).await;
    mount_policy_once(&server, &[USER_DEFAULT, OWNED]).await;
    mount_policy_once(&server, &[OWNED]).await;
    mount_policy_write(&server).await;
    let mut registry = ActionRegistry::new();
    registry.register(Arc::new(graph(&server))).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .revert_store(Arc::new(MemoryRevertStore::default()))
        .build(),
    );
    let scheduler = RevertScheduler::new(dispatcher.clone()).unwrap();
    let action = timed(restrict_request(), 7_200);

    // The registry routes the custom action to the Graph connector.
    let disposition = dispatcher
        .dispatch(action.clone(), &playbook_engine())
        .await
        .unwrap();

    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(executed(&disposition).connector, "entra-graph");
    assert_eq!(
        graph_requests(&server).await,
        [seen("GET", Value::Null), write_of(&[OWNED])]
    );
    let pending = scheduler.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action_id, action.id);
    assert_eq!(pending[0].kind, friction::restrict_user_consent());
    assert_eq!(pending[0].revert_after_seconds, 7_200);

    // A person reverts the friction now. The revert writes the earlier value.
    let reverted = scheduler.cancel(action.id, &alice()).await.unwrap();

    let outcome = executed(&reverted);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(
        graph_requests(&server).await,
        [
            seen("GET", Value::Null),
            write_of(&[OWNED]),
            seen("GET", Value::Null),
            write_of(&[USER_DEFAULT, OWNED]),
        ]
    );
    assert_eq!(scheduler.pending().await.unwrap(), []);
    let records = audit.records();
    let revert = revert_records(&records);
    assert_eq!(revert.len(), 3);
    assert_eq!(
        revert[2].payload["reverts"]["kind"],
        json!({ "custom": "restrict_user_consent" })
    );
    assert!(audit.verify().await.unwrap().valid);
}

fn webhook(server: &MockServer, reversible: bool) -> Result<WebhookConnector> {
    WebhookConnector::new(
        WebhookConfig::new("soc-bridge", SecretString::from(WEBHOOK_SECRET))
            .endpoint(
                friction::raise_friction(),
                format!("{}/hooks/friction", server.uri()),
                reversible,
            )
            .endpoint(
                ActionKind::Notify,
                format!("{}/hooks/chat", server.uri()),
                false,
            ),
    )
}

#[tokio::test]
async fn a_webhook_endpoint_for_a_friction_action_must_be_reversible() {
    let server = MockServer::start().await;

    let error = webhook(&server, false).err().unwrap();
    assert!(
        matches!(&error, Error::Config(message) if message
            == "the endpoint of webhook connector soc-bridge for the friction action custom:raise_friction must have reversible = true; a friction action must have an inverse"),
        "{error:?}"
    );
    let consent = WebhookConnector::new(
        WebhookConfig::new("soc-bridge", SecretString::from(WEBHOOK_SECRET)).endpoint(
            friction::restrict_user_consent(),
            format!("{}/hooks/consent", server.uri()),
            false,
        ),
    )
    .err()
    .unwrap();
    assert!(matches!(consent, Error::Config(_)), "{consent:?}");

    // A different custom action has no such rule.
    assert!(
        WebhookConnector::new(
            WebhookConfig::new("soc-bridge", SecretString::from(WEBHOOK_SECRET)).endpoint(
                ActionKind::Custom("quarantine_mailbox".to_owned()),
                format!("{}/hooks/mail", server.uri()),
                false,
            ),
        )
        .is_ok()
    );
    let connector = webhook(&server, true).unwrap();
    assert_eq!(
        connector.supported_actions(),
        [friction::raise_friction(), ActionKind::Notify]
    );
}

#[tokio::test]
async fn raise_friction_goes_to_the_routed_webhook_and_revert_returns_the_reference() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/friction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "freeze-7" })))
        .mount(&server)
        .await;
    // A second connector also supports the action. The routing table selects the webhook.
    let other = Arc::new(ToggleConnector::new(
        "other-automation",
        vec![friction::raise_friction()],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(other.clone()).unwrap();
    registry
        .register(Arc::new(webhook(&server, true).unwrap()))
        .unwrap();
    let route: Route = serde_json::from_value(json!({
        "kind": { "custom": "raise_friction" },
        "connector": "soc-bridge",
    }))
    .unwrap();
    registry.apply_routes([route]).unwrap();
    let audit = Arc::new(MemoryAuditLog::default());
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        audit.clone(),
    )
    .build();
    let mut action = request(friction::raise_friction(), tenant());
    action.parameters.insert(
        friction::parameter::CONTROL.to_owned(),
        json!("change_freeze"),
    );
    action
        .parameters
        .insert(friction::parameter::LEVEL.to_owned(), json!("high"));

    let disposition = dispatcher
        .dispatch(action.clone(), &responder())
        .await
        .unwrap();

    let outcome = executed(&disposition);
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(outcome.connector, "soc-bridge");
    assert!(outcome.reversible);
    assert_eq!(other.executed(), []);
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let sent: Value = serde_json::from_slice(&received[0].body).unwrap();
    assert_eq!(sent["operation"], "execute");
    assert_eq!(
        sent["action"]["kind"],
        json!({ "custom": "raise_friction" })
    );
    assert_eq!(
        sent["action"]["parameters"],
        json!({ "control": "change_freeze", "level": "high" })
    );
    assert_eq!(
        sent["action"]["target"],
        json!({ "kind": "tenant", "id": TENANT })
    );

    // The revert sends the same action with the reference that the receiver returned.
    let reverted = dispatcher
        .revert(action.id, &alice(), "The incident is contained.")
        .await
        .unwrap();

    assert_eq!(executed(&reverted).status, ActionStatus::Succeeded);
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 2);
    let payload: WebhookPayload = serde_json::from_slice(&received[1].body).unwrap();
    assert_eq!(serde_json::to_value(payload.operation).unwrap(), "revert");
    assert_eq!(payload.action.id, action.id);
    assert_eq!(payload.action.kind, friction::raise_friction());
    assert_eq!(payload.action.parameters["control"], "change_freeze");
    assert_eq!(
        payload.action.parameters[EXECUTION_DETAILS_PARAMETER]["external_reference"],
        json!({ "id": "freeze-7", "url": null })
    );
    assert_eq!(other.reverted(), []);
    assert!(audit.verify().await.unwrap().valid);
}

#[tokio::test]
async fn the_dispatcher_refuses_a_friction_action_that_the_connector_cannot_undo() {
    for kind in [
        friction::raise_friction(),
        friction::restrict_user_consent(),
    ] {
        let connector = Arc::new(ToggleConnector::new("one-way", vec![kind.clone()]));
        connector.set_reversible(false);
        let mut registry = ActionRegistry::new();
        registry.register(connector.clone()).unwrap();
        let audit = Arc::new(MemoryAuditLog::default());
        let dispatcher = Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::AllowAll),
            Arc::new(MemoryApprovals::default()),
            audit.clone(),
        )
        .build();
        // The request has no timed revert. The rule is for each friction action.
        let action = request(kind.clone(), tenant());

        let error = dispatcher
            .dispatch(action.clone(), &responder())
            .await
            .unwrap_err();

        assert!(
            matches!(&error, Error::InvalidInput(message)
                if message.starts_with("connector one-way cannot undo the action custom:")
                    && message.ends_with("a friction action must have an inverse; the action did not run")),
            "{kind:?}: {error:?}"
        );
        // The connector got only the dry run of the check.
        assert_eq!(connector.dry_runs().len(), 1, "{kind:?}");
        assert_eq!(connector.changes(), [], "{kind:?}");
        assert_eq!(audit.records()[2].kind, AuditKind::ActionExecuted);
        assert_eq!(audit.records()[2].payload["error"]["kind"], "invalid_input");

        // The same connector can undo the action. The friction then runs.
        connector.set_reversible(true);
        let disposition = dispatcher.dispatch(action, &responder()).await.unwrap();
        assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
        assert_eq!(connector.changes().len(), 1, "{kind:?}");
    }

    // A custom action that is not a friction action has no such check.
    let mail = ActionKind::Custom("quarantine_mailbox".to_owned());
    let connector = Arc::new(ToggleConnector::new("mail", vec![mail.clone()]));
    connector.set_reversible(false);
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let dispatcher = Dispatcher::builder(
        Arc::new(registry),
        Arc::new(StaticPolicy::AllowAll),
        Arc::new(MemoryApprovals::default()),
        Arc::new(MemoryAuditLog::default()),
    )
    .build();
    let disposition = dispatcher
        .dispatch(request(mail, tenant()), &responder())
        .await
        .unwrap();
    assert_eq!(executed(&disposition).status, ActionStatus::Succeeded);
    assert_eq!(connector.dry_runs(), []);
}

fn friction_step(action: &str, kind: &str, id: &str) -> Value {
    json!({
        "summary": "Raise friction.",
        "steps": [{
            "action": action,
            "target": { "kind": kind, "id": id },
            "reason": "An identity attack is in progress.",
        }],
    })
}

#[tokio::test]
async fn a_draft_cannot_use_a_friction_action_unless_the_operator_permits_it() {
    let incident = rogue_incident();
    assert_eq!(incident.tenant.as_deref(), Some(TENANT));

    // The default options do not permit a friction action.
    let defaults = DraftOptions::default();
    for name in [RESTRICT_USER_CONSENT, RAISE_FRICTION] {
        assert!(
            !defaults
                .allowed_actions
                .contains(&ActionKind::Custom(name.to_owned())),
            "{name}"
        );
        let model = ScriptedModel::new("router").reply_json(&friction_step(name, "tenant", TENANT));
        let error = draft_response(&incident, &model).await.unwrap_err();
        assert!(
            matches!(&error, DraftError::ActionNotPermitted { step: 1, action }
                if *action == format!("custom:{name}")),
            "{name}: {error:?}"
        );
        // The instructions do not offer the action.
        let instructions = &model.requests()[0].messages[0].content;
        assert!(!instructions.contains(name), "{instructions}");
        assert!(!instructions.contains("friction"), "{instructions}");
    }
    assert_eq!(defaults.friction_revert_after, Duration::from_secs(14_400));
    assert_eq!(DEFAULT_FRICTION_REVERT_AFTER, Duration::from_secs(14_400));

    // The operator permits one friction action.
    let mut permitted = DraftOptions::default();
    permitted
        .allowed_actions
        .push(friction::restrict_user_consent());
    permitted.friction_revert_after = Duration::from_secs(1_800);
    let model = ScriptedModel::new("router").reply_json(&friction_step(
        RESTRICT_USER_CONSENT,
        "tenant",
        TENANT,
    ));
    let draft = draft_response_with(&incident, &model, &permitted)
        .await
        .unwrap();

    assert_eq!(draft.steps().len(), 1);
    let step = &draft.steps()[0];
    assert_eq!(step.action(), &friction::restrict_user_consent());
    // The target is the tenant of the incident, and the step has the timed revert of the
    // options.
    assert_eq!(step.target(), &TargetSelector::Fixed(tenant()));
    assert_eq!(step.revert_after(), Some(Duration::from_secs(1_800)));
    let instructions = &model.requests()[0].messages[0].content;
    assert!(
        instructions.contains("rotate_secret, restrict_user_consent."),
        "{instructions}"
    );
    assert!(
        instructions.contains("9. These actions are friction actions: restrict_user_consent."),
        "{instructions}"
    );
    // The other friction action is still not permitted.
    assert!(!instructions.contains(RAISE_FRICTION), "{instructions}");
    let model =
        ScriptedModel::new("router").reply_json(&friction_step(RAISE_FRICTION, "tenant", TENANT));
    let error = draft_response_with(&incident, &model, &permitted)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, DraftError::ActionNotPermitted { step: 1, action } if action == "custom:raise_friction"),
        "{error:?}"
    );
    // A step that has no friction action has no timed revert.
    let model = ScriptedModel::new("router").reply_json(&friction_step(
        "block_ip",
        "ip_address",
        "203.0.113.50",
    ));
    let draft = draft_response_with(&incident, &model, &permitted)
        .await
        .unwrap();
    assert_eq!(draft.steps()[0].revert_after(), None);
}

#[tokio::test]
async fn a_friction_step_of_a_draft_is_strictly_validated() {
    let incident = rogue_incident();
    let mut permitted = DraftOptions::default();
    permitted.allowed_actions.extend([
        friction::restrict_user_consent(),
        friction::raise_friction(),
        ActionKind::Custom("wipe_device".to_owned()),
    ]);
    let rejection = |plan: Value| {
        let incident = incident.clone();
        let permitted = permitted.clone();
        async move {
            let model = ScriptedModel::new("router").reply_json(&plan);
            draft_response_with(&incident, &model, &permitted)
                .await
                .unwrap_err()
        }
    };

    // The target must be the tenant of the incident.
    let other_tenant =
        rejection(friction_step(RESTRICT_USER_CONSENT, "tenant", OTHER_TENANT)).await;
    assert!(
        matches!(&other_tenant, DraftError::TargetOutsideIncident { step: 1, kind, id }
            if kind == "tenant" && id == OTHER_TENANT),
        "{other_tenant:?}"
    );
    for name in [RESTRICT_USER_CONSENT, RAISE_FRICTION] {
        let not_a_tenant = rejection(friction_step(name, "user", "user-dana")).await;
        assert!(
            matches!(
                &not_a_tenant,
                DraftError::TargetKindMismatch { step: 1, .. }
            ),
            "{name}: {not_a_tenant:?}"
        );
    }
    // The tenant is a target only for a friction action.
    let notify_tenant = rejection(friction_step("notify", "tenant", TENANT)).await;
    assert!(
        matches!(
            &notify_tenant,
            DraftError::TargetOutsideIncident { step: 1, .. }
        ),
        "{notify_tenant:?}"
    );
    // The model cannot set a parameter, for example its own revert time.
    let mut with_parameter = friction_step(RESTRICT_USER_CONSENT, "tenant", TENANT);
    with_parameter["steps"][0]["parameters"] = json!({ "revert_after_seconds": 2_592_000 });
    let parameter = rejection(with_parameter).await;
    assert!(
        matches!(&parameter, DraftError::ParameterNotPermitted { step: 1, name, .. }
            if name == "revert_after_seconds"),
        "{parameter:?}"
    );
    // A different custom action is not known, also when the options name it.
    for name in ["wipe_device", "revert", "custom:restrict_user_consent"] {
        let unknown = rejection(friction_step(name, "tenant", TENANT)).await;
        assert!(
            matches!(&unknown, DraftError::UnknownAction { step: 1, action } if action == name),
            "{name}: {unknown:?}"
        );
    }

    // A revert time out of the range has the effect of the nearest limit.
    let mut long = permitted.clone();
    long.friction_revert_after = Duration::from_secs(u64::MAX);
    let model =
        ScriptedModel::new("router").reply_json(&friction_step(RAISE_FRICTION, "tenant", TENANT));
    let draft = draft_response_with(&incident, &model, &long).await.unwrap();
    assert_eq!(
        draft.steps()[0].revert_after(),
        Some(Duration::from_secs(2_592_000))
    );
    let mut zero = permitted.clone();
    zero.friction_revert_after = Duration::ZERO;
    let model =
        ScriptedModel::new("router").reply_json(&friction_step(RAISE_FRICTION, "tenant", TENANT));
    let draft = draft_response_with(&incident, &model, &zero).await.unwrap();
    assert_eq!(
        draft.steps()[0].revert_after(),
        Some(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn a_friction_draft_runs_through_the_dispatcher_with_its_timed_revert() {
    let incident = rogue_incident();
    let mut permitted = DraftOptions::default();
    permitted
        .allowed_actions
        .push(friction::restrict_user_consent());
    let model = ScriptedModel::new("router").reply_json(&friction_step(
        RESTRICT_USER_CONSENT,
        "tenant",
        TENANT,
    ));
    let draft = draft_response_with(&incident, &model, &permitted)
        .await
        .unwrap();
    let connector = Arc::new(RecordingConnector::new(
        "identity",
        vec![friction::restrict_user_consent()],
    ));
    let mut registry = ActionRegistry::new();
    registry.register(connector.clone()).unwrap();
    let approvals = Arc::new(MemoryApprovals::default());
    // The policy gates a custom action, so the friction of a draft waits for a person.
    let dispatcher = Arc::new(
        Dispatcher::builder(
            Arc::new(registry),
            Arc::new(StaticPolicy::ByTier),
            approvals.clone(),
            Arc::new(MemoryAuditLog::default()),
        )
        .build(),
    );

    let run = PlaybookEngine::new(dispatcher)
        .run(&draft, &incident, RunMode::Live)
        .await
        .unwrap();

    assert_eq!(run.failures(), 0);
    assert_eq!(connector.executed(), []);
    let queued = aegis_contracts::policy::ApprovalQueue::pending(approvals.as_ref())
        .await
        .unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].action.kind, friction::restrict_user_consent());
    assert_eq!(queued[0].action.target, tenant());
    assert_eq!(
        queued[0].action.parameters,
        std::collections::BTreeMap::from([(REVERT_AFTER_PARAMETER.to_owned(), json!(14_400))])
    );
    assert_eq!(queued[0].requested_by.id, "response-draft");
}
